#![forbid(unsafe_code)]

use rc_dom::{ArenaDom, ComputedStyle, Display, FlexDir, NodeData, NodeId, Stylesheet, compute_style};
use rc_ipc::{DisplayList, DrawCommand, HitRegion, ImageAsset, RegionKind};
use std::collections::HashMap;
use taffy::prelude::*;

const MAX_LAYOUT_DEPTH: usize = 256;

#[derive(Clone)]
enum LayoutNodeCtx {
    Element {
        dom_id: NodeId,
        tag: String,
        style: ComputedStyle,
        image_id: Option<u64>,
        input_placeholder: Option<String>,
    },
    Text {
        text: String,
        style: ComputedStyle,
        href: Option<String>,
        /// Memoized `(quantized_width_half_px, computed_size, wrapped_lines)` so Flexbox multi-pass
        /// intrinsic sizing and the subsequent Paint (`emit_display_list`) pass never thrash or
        /// recompute text wrapping (per https://web.dev/articles/avoid-large-complex-layouts-and-layout-thrashing
        /// and https://browser.engineering/layout.html).
        cached_layout: Option<(u32, Size<f32>, Vec<String>)>,
    },
}

/// Builds a flat, IPC-serializable DisplayList using Taffy Flexbox/Grid/Block layout.
///
/// Optimized using modern browser layout architecture principles:
/// 1. Pre-allocated layout arena (`TaffyTree::with_capacity`) to eliminate heap churn.
/// 2. Memoized text measurement (`cached_layout`) across Flexbox intrinsic sizing passes.
/// 3. Strict separation of the Layout phase (`compute_layout_with_measure`) and Paint phase
///    (`emit_display_list`), reusing wrapped lines from Layout during Paint with zero re-layout.
pub fn layout_to_display_list(
    dom: &ArenaDom,
    stylesheet: &Stylesheet,
    viewport_width: f32,
    images: &HashMap<String, ImageAsset>,
) -> DisplayList {
    let node_cap = dom.nodes.len().max(16);
    let mut list = DisplayList::default();
    list.commands.reserve(node_cap);
    let start_node = dom.find_first_tag("body").unwrap_or(dom.root);
    let root_style = compute_style(dom, start_node, stylesheet, None);
    list.background = root_style.background_color;

    let mut used_images: HashMap<u64, ImageAsset> = HashMap::new();
    let mut taffy: TaffyTree<LayoutNodeCtx> = TaffyTree::with_capacity(node_cap);

    let Some(root_taffy_id) = build_taffy_node(
        dom,
        start_node,
        stylesheet,
        None,
        None,
        images,
        &mut used_images,
        &mut taffy,
        0,
    ) else {
        list.content_height = 100.0;
        return list;
    };

    let avail_w = viewport_width.max(160.0);
    let _ = taffy.compute_layout_with_measure(
        root_taffy_id,
        Size {
            width: AvailableSpace::Definite(avail_w),
            height: AvailableSpace::MaxContent,
        },
        |inputs, _node_id, node_ctx, _style| {
            let size = measure_node(inputs.known_dimensions, inputs.available_space, node_ctx);
            taffy::LayoutOutput::from_outer_size(size)
        },
    );

    emit_display_list(&taffy, root_taffy_id, 0.0, 0.0, &mut list);
    let root_layout = taffy.layout(root_taffy_id).unwrap();
    list.content_height = root_layout.size.height.max(100.0);
    list.images = used_images.into_values().collect();
    list
}

#[allow(clippy::too_many_arguments)]
// Styles are built field by field from the computed CSS, many conditionally.
#[allow(clippy::field_reassign_with_default)]
fn build_taffy_node(
    dom: &ArenaDom,
    node_id: NodeId,
    stylesheet: &Stylesheet,
    parent_style: Option<&ComputedStyle>,
    active_href: Option<&str>,
    images: &HashMap<String, ImageAsset>,
    used_images: &mut HashMap<u64, ImageAsset>,
    taffy: &mut TaffyTree<LayoutNodeCtx>,
    depth: usize,
) -> Option<taffy::NodeId> {
    if depth > MAX_LAYOUT_DEPTH {
        return None;
    }

    match &dom.nodes[node_id].data {
        NodeData::Comment(_) => None,
        NodeData::Text(raw) => {
            let text = collapse_whitespace(raw);
            if text.is_empty() {
                return None;
            }
            let style = parent_style.cloned().unwrap_or_default();
            let ctx = LayoutNodeCtx::Text {
                text,
                style,
                href: active_href.map(|s| s.to_string()),
                cached_layout: None,
            };
            taffy
                .new_leaf_with_context(taffy::Style::default(), ctx)
                .ok()
        }
        NodeData::Document => {
            let mut children = Vec::new();
            for &c in &dom.nodes[node_id].children {
                if let Some(tid) = build_taffy_node(
                    dom,
                    c,
                    stylesheet,
                    parent_style,
                    active_href,
                    images,
                    used_images,
                    taffy,
                    depth + 1,
                ) {
                    children.push(tid);
                }
            }
            let t_style = taffy::Style {
                display: taffy::Display::Flex,
                flex_direction: FlexDirection::Column,
                ..Default::default()
            };
            taffy.new_with_children(t_style, &children).ok()
        }
        NodeData::Element { tag, attrs } => {
            let style = compute_style(dom, node_id, stylesheet, parent_style);
            if style.display == Display::None {
                return None;
            }

            let next_href = if tag == "a" {
                attrs.get("href").map(|s| s.as_str()).or(active_href)
            } else {
                active_href
            };

            let mut image_id = None;
            let mut img_dims: Option<(f32, f32)> = None;
            if tag == "img"
                && let Some(src) = attrs.get("src")
                && let Some(asset) = images.get(src.trim())
            {
                image_id = Some(asset.id);
                used_images.entry(asset.id).or_insert_with(|| asset.clone());
                img_dims = Some((asset.width as f32, asset.height as f32));
            }

            let input_placeholder = if tag == "input" {
                Some(
                    attrs
                        .get("value")
                        .or_else(|| attrs.get("placeholder"))
                        .cloned()
                        .unwrap_or_else(|| "Input...".to_string()),
                )
            } else {
                None
            };

            let mut children = Vec::new();
            for &c in &dom.nodes[node_id].children {
                if let Some(tid) = build_taffy_node(
                    dom,
                    c,
                    stylesheet,
                    Some(&style),
                    next_href,
                    images,
                    used_images,
                    taffy,
                    depth + 1,
                ) {
                    children.push(tid);
                }
            }

            let mut t_style = taffy::Style::default();
            t_style.display = match style.display {
                Display::None => taffy::Display::None,
                Display::Flex => taffy::Display::Flex,
                Display::Grid => taffy::Display::Grid,
                Display::Block | Display::Inline => taffy::Display::Flex,
            };
            t_style.flex_direction = match style.display {
                Display::Flex => match style.flex_direction {
                    FlexDir::Row => FlexDirection::Row,
                    FlexDir::Column => FlexDirection::Column,
                },
                _ => FlexDirection::Column,
            };
            if style.display == Display::Flex {
                t_style.flex_wrap = FlexWrap::Wrap;
            }
            if style.gap > 0.0 {
                t_style.gap = Size {
                    width: length(style.gap),
                    height: length(style.gap),
                };
            }
            t_style.padding = Rect {
                top: length(style.padding_top),
                right: length(style.padding_right),
                bottom: length(style.padding_bottom),
                left: length(style.padding_left),
            };
            t_style.margin = Rect {
                top: length(style.margin_top),
                right: length(style.margin_right),
                bottom: length(style.margin_bottom),
                left: length(style.margin_left),
            };
            let attr_w = attrs
                .get("width")
                .and_then(|v| v.trim_end_matches("px").trim().parse::<f32>().ok());
            let attr_h = attrs
                .get("height")
                .and_then(|v| v.trim_end_matches("px").trim().parse::<f32>().ok());

            if let Some(w) = style.width.or(attr_w) {
                t_style.size.width = length(w);
            } else if tag == "body" || tag == "html" {
                t_style.size.width = percent(1.0);
            } else if let Some((iw, _)) = img_dims {
                t_style.size.width = length(iw.min(640.0));
            }
            if let Some(h) = style.height.or(attr_h) {
                t_style.size.height = length(h);
            } else if let Some((iw, ih)) = img_dims {
                let scale = (iw.min(640.0)) / iw.max(1.0);
                t_style.size.height = length(ih * scale);
            } else if tag == "hr" {
                t_style.size.height = length(2.0);
            } else if tag == "input" {
                t_style.size.width = length(style.width.unwrap_or(240.0));
                t_style.size.height = length(style.height.unwrap_or(28.0));
            }

            let ctx = LayoutNodeCtx::Element {
                dom_id: node_id,
                tag: tag.clone(),
                style,
                image_id,
                input_placeholder,
            };

            if children.is_empty() {
                taffy.new_leaf_with_context(t_style, ctx).ok()
            } else {
                let tid = taffy.new_with_children(t_style, &children).ok()?;
                let _ = taffy.set_node_context(tid, Some(ctx));
                Some(tid)
            }
        }
    }
}

fn measure_node(
    known_dimensions: Size<Option<f32>>,
    available_space: Size<AvailableSpace>,
    node_ctx: Option<&mut LayoutNodeCtx>,
) -> Size<f32> {
    let Some(ctx) = node_ctx else {
        return Size::ZERO;
    };
    match ctx {
        LayoutNodeCtx::Text {
            text,
            style,
            cached_layout,
            ..
        } => {
            let max_w = known_dimensions
                .width
                .or(match available_space.width {
                    AvailableSpace::Definite(w) => Some(w),
                    _ => None,
                })
                .unwrap_or(720.0)
                .max(40.0);
            let width_key = (max_w * 2.0) as u32;
            if let Some((cached_key, cached_sz, _)) = cached_layout.as_ref()
                && *cached_key == width_key
            {
                return Size {
                    width: known_dimensions.width.unwrap_or(cached_sz.width),
                    height: cached_sz.height,
                };
            }
            let lines = wrap_text(text, max_w, style.font_size);
            let line_h = style.font_size * 1.5;
            let longest = lines
                .iter()
                .map(|l| (l.chars().count() as f32 * style.font_size * 0.62) + 8.0)
                .fold(0.0f32, f32::max);
            let computed = Size {
                width: longest.min(max_w),
                height: (lines.len().max(1) as f32) * line_h + 4.0,
            };
            *cached_layout = Some((width_key, computed, lines));
            Size {
                width: known_dimensions.width.unwrap_or(computed.width),
                height: computed.height,
            }
        }
        LayoutNodeCtx::Element {
            tag,
            input_placeholder,
            ..
        } => {
            if tag == "input" {
                Size {
                    width: known_dimensions.width.unwrap_or(240.0),
                    height: known_dimensions.height.unwrap_or(28.0),
                }
            } else if input_placeholder.is_some() {
                Size {
                    width: known_dimensions.width.unwrap_or(100.0),
                    height: known_dimensions.height.unwrap_or(24.0),
                }
            } else {
                Size {
                    width: known_dimensions.width.unwrap_or(0.0),
                    height: known_dimensions.height.unwrap_or(0.0),
                }
            }
        }
    }
}

fn emit_display_list(
    taffy: &TaffyTree<LayoutNodeCtx>,
    tid: taffy::NodeId,
    parent_x: f32,
    parent_y: f32,
    list: &mut DisplayList,
) {
    let Ok(layout) = taffy.layout(tid) else {
        return;
    };
    let x = parent_x + layout.location.x;
    let y = parent_y + layout.location.y;
    let w = layout.size.width;
    let h = layout.size.height;

    if let Some(ctx) = taffy.get_node_context(tid) {
        match ctx {
            LayoutNodeCtx::Text {
                text,
                style,
                href,
                cached_layout,
            } => {
                let fallback_lines;
                let lines: &[String] = if let Some((_, _, cached_lines)) = cached_layout {
                    cached_lines.as_slice()
                } else {
                    fallback_lines = wrap_text(text, w.max(60.0), style.font_size);
                    fallback_lines.as_slice()
                };
                let line_h = style.font_size * 1.45;
                let mut cur_y = y;
                for line in lines {
                    list.commands.push(DrawCommand::DrawText {
                        x,
                        y: cur_y,
                        text: line.clone(),
                        font_size: style.font_size,
                        color: style.color,
                        bold: style.bold,
                    });
                    cur_y += line_h;
                }
                if let Some(h_ref) = href {
                    list.hit_regions.push(HitRegion {
                        x,
                        y,
                        w: w.max(40.0),
                        h: h.max(line_h),
                        kind: RegionKind::Link {
                            href: h_ref.clone(),
                        },
                    });
                }
            }
            LayoutNodeCtx::Element {
                dom_id,
                tag,
                style,
                image_id,
                input_placeholder,
            } => {
                if let Some(bg) = style.background_color {
                    list.commands.push(DrawCommand::FillRect {
                        x,
                        y,
                        w,
                        h,
                        color: bg,
                    });
                }
                if style.border_width > 0.0 {
                    list.commands.push(DrawCommand::StrokeRect {
                        x,
                        y,
                        w,
                        h,
                        width: style.border_width,
                        color: style.border_color,
                    });
                }
                if tag == "hr" {
                    list.commands.push(DrawCommand::FillRect {
                        x,
                        y,
                        w,
                        h: 1.0,
                        color: style.border_color,
                    });
                }
                if let Some(img_id) = image_id {
                    list.commands.push(DrawCommand::DrawImage {
                        x,
                        y,
                        w,
                        h,
                        image_id: *img_id,
                    });
                }
                if let Some(placeholder) = input_placeholder {
                    list.commands.push(DrawCommand::DrawText {
                        x: x + 6.0,
                        y: y + 5.0,
                        text: placeholder.clone(),
                        font_size: style.font_size,
                        color: rc_ipc::Color::rgb(95, 99, 104),
                        bold: false,
                    });
                    list.hit_regions.push(HitRegion {
                        x,
                        y,
                        w,
                        h,
                        kind: RegionKind::Input { node_id: *dom_id },
                    });
                }
                if tag == "button" {
                    list.hit_regions.push(HitRegion {
                        x,
                        y,
                        w,
                        h,
                        kind: RegionKind::Button { node_id: *dom_id },
                    });
                }
            }
        }
    }

    if let Ok(children) = taffy.children(tid) {
        for child in children {
            emit_display_list(taffy, child, x, y, list);
        }
    }
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

fn wrap_text(text: &str, max_width: f32, font_size: f32) -> Vec<String> {
    let approx_char_w = (font_size * 0.62).max(4.0);
    let max_chars = ((max_width / approx_char_w).floor() as usize).max(12);
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= max_chars {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_dom::parse_html;

    #[test]
    fn generates_taffy_display_list_and_hit_regions() {
        let dom = parse_html(
            r#"<html><body><div style="display:flex;gap:10px"><h1>Hello</h1><a href="https://example.com">Click Me</a><button>Go</button></div></body></html>"#,
        );
        let sheet = Stylesheet::parse(&dom.collect_style_blocks());
        let list = layout_to_display_list(&dom, &sheet, 800.0, &HashMap::new());
        assert!(!list.commands.is_empty());
        assert!(list.hit_regions.iter().any(|r| matches!(&r.kind, RegionKind::Link { href } if href == "https://example.com")));
        assert!(list.hit_regions.iter().any(|r| matches!(&r.kind, RegionKind::Button { .. })));
    }
}
