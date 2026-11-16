use crate::dom::{ArenaDom, NodeData, NodeId};
use rc_ipc::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Display {
    Block,
    Inline,
    Flex,
    Grid,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexDir {
    Row,
    Column,
}

#[derive(Debug, Clone)]
pub struct ComputedStyle {
    pub display: Display,
    pub flex_direction: FlexDir,
    pub gap: f32,
    pub width: Option<f32>,
    pub height: Option<f32>,
    pub color: Color,
    pub background_color: Option<Color>,
    pub font_size: f32,
    pub bold: bool,
    pub padding_top: f32,
    pub padding_right: f32,
    pub padding_bottom: f32,
    pub padding_left: f32,
    pub margin_top: f32,
    pub margin_right: f32,
    pub margin_bottom: f32,
    pub margin_left: f32,
    pub border_width: f32,
    pub border_color: Color,
}

impl Default for ComputedStyle {
    fn default() -> Self {
        Self {
            display: Display::Block,
            flex_direction: FlexDir::Row,
            gap: 0.0,
            width: None,
            height: None,
            color: Color::rgb(32, 33, 36),
            background_color: None,
            font_size: 15.0,
            bold: false,
            padding_top: 0.0,
            padding_right: 0.0,
            padding_bottom: 0.0,
            padding_left: 0.0,
            margin_top: 0.0,
            margin_right: 0.0,
            margin_bottom: 0.0,
            margin_left: 0.0,
            border_width: 0.0,
            border_color: Color::rgb(218, 220, 224),
        }
    }
}

#[derive(Debug, Clone)]
struct CssRule {
    selector: String,
    declarations: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Stylesheet {
    rules: Vec<CssRule>,
}

impl Stylesheet {
    pub fn parse(css: &str) -> Self {
        let mut rules = Vec::new();
        let mut rest = css;
        while let Some(open) = rest.find('{') {
            let selector_part = rest[..open].trim();
            let after_open = &rest[open + 1..];
            let Some(close) = after_open.find('}') else {
                break;
            };
            let decls_part = &after_open[..close];
            let declarations = parse_declarations(decls_part);
            for sel in selector_part.split(',') {
                let s = sel.trim();
                if !s.is_empty() {
                    rules.push(CssRule {
                        selector: s.to_string(),
                        declarations: declarations.clone(),
                    });
                }
            }
            rest = &after_open[close + 1..];
        }
        Self { rules }
    }
}

fn parse_declarations(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for item in input.split(';') {
        if let Some((prop, val)) = item.split_once(':') {
            let p = prop.trim().to_ascii_lowercase();
            let v = val.trim().to_string();
            if !p.is_empty() && !v.is_empty() {
                out.push((p, v));
            }
        }
    }
    out
}

pub fn compute_style(
    dom: &ArenaDom,
    node_id: NodeId,
    stylesheet: &Stylesheet,
    parent_style: Option<&ComputedStyle>,
) -> ComputedStyle {
    let mut style = match parent_style {
        Some(p) => ComputedStyle {
            color: p.color,
            font_size: p.font_size,
            bold: p.bold,
            ..Default::default()
        },
        None => ComputedStyle::default(),
    };

    let NodeData::Element { tag, attrs } = &dom.nodes[node_id].data else {
        return style;
    };

    match tag.as_str() {
        "head" | "script" | "style" | "meta" | "link" | "title" | "noscript" | "template"
        | "svg" => {
            style.display = Display::None;
            return style;
        }
        "span" | "a" | "b" | "strong" | "em" | "i" | "code" => {
            style.display = Display::Inline;
        }
        "h1" => {
            style.font_size = 26.0;
            style.bold = true;
            style.margin_top = 8.0;
            style.margin_bottom = 10.0;
        }
        "h2" => {
            style.font_size = 21.0;
            style.bold = true;
            style.margin_top = 6.0;
            style.margin_bottom = 8.0;
        }
        "h3" => {
            style.font_size = 18.0;
            style.bold = true;
            style.margin_top = 4.0;
            style.margin_bottom = 6.0;
        }
        "p" | "div" | "ul" | "ol" | "li" => {
            style.display = Display::Block;
            if tag == "p" {
                style.margin_bottom = 8.0;
            }
        }
        "button" => {
            style.display = Display::Block;
            style.background_color = Some(Color::rgb(26, 115, 232));
            style.color = Color::WHITE;
            style.bold = true;
            style.padding_top = 6.0;
            style.padding_bottom = 6.0;
            style.padding_left = 12.0;
            style.padding_right = 12.0;
            style.margin_top = 4.0;
            style.margin_bottom = 4.0;
            style.border_width = 1.0;
            style.border_color = Color::rgb(26, 115, 232);
        }
        "input" => {
            style.display = Display::Block;
            style.background_color = Some(Color::WHITE);
            style.border_width = 1.0;
            style.border_color = Color::rgb(180, 184, 190);
            style.padding_top = 5.0;
            style.padding_bottom = 5.0;
            style.padding_left = 8.0;
            style.padding_right = 8.0;
            style.margin_top = 4.0;
            style.margin_bottom = 4.0;
        }
        "body" => {
            style.display = Display::Block;
            style.padding_top = 16.0;
            style.padding_right = 16.0;
            style.padding_bottom = 16.0;
            style.padding_left = 16.0;
        }
        _ => {}
    }

    if tag == "b" || tag == "strong" {
        style.bold = true;
    }
    if tag == "a" {
        style.color = Color::LINK_BLUE;
    }

    for rule in &stylesheet.rules {
        if selector_matches(&rule.selector, tag, attrs) {
            for (prop, val) in &rule.declarations {
                apply_declaration(&mut style, prop, val);
            }
        }
    }

    if let Some(inline) = attrs.get("style") {
        for (prop, val) in parse_declarations(inline) {
            apply_declaration(&mut style, &prop, &val);
        }
    }

    style
}

fn selector_matches(
    selector: &str,
    tag: &str,
    attrs: &std::collections::HashMap<String, String>,
) -> bool {
    if let Some(id_sel) = selector.strip_prefix('#') {
        return attrs.get("id").is_some_and(|v| v == id_sel);
    }
    if let Some(class_sel) = selector.strip_prefix('.') {
        return attrs
            .get("class")
            .is_some_and(|v| v.split_whitespace().any(|c| c == class_sel));
    }
    selector.eq_ignore_ascii_case(tag)
}

fn apply_declaration(style: &mut ComputedStyle, prop: &str, val: &str) {
    match prop {
        "display" => match val.to_ascii_lowercase().as_str() {
            "none" => style.display = Display::None,
            "inline" => style.display = Display::Inline,
            "block" => style.display = Display::Block,
            "flex" | "inline-flex" => style.display = Display::Flex,
            "grid" => style.display = Display::Grid,
            _ => {}
        },
        "flex-direction" => match val.to_ascii_lowercase().as_str() {
            "column" | "column-reverse" => style.flex_direction = FlexDir::Column,
            _ => style.flex_direction = FlexDir::Row,
        },
        "gap" | "grid-gap" => {
            if let Some(px) = parse_px(val) {
                style.gap = px;
            }
        }
        "width" => {
            if let Some(px) = parse_px(val) {
                style.width = Some(px);
            }
        }
        "height" => {
            if let Some(px) = parse_px(val) {
                style.height = Some(px);
            }
        }
        "color" => {
            if let Some(c) = parse_color(val) {
                style.color = c;
            }
        }
        "background-color" | "background" => {
            if let Some(c) = parse_color(val) {
                style.background_color = Some(c);
            }
        }
        "font-size" => {
            if let Some(px) = parse_px(val) {
                style.font_size = px.clamp(8.0, 72.0);
            }
        }
        "font-weight" => {
            let lower = val.to_ascii_lowercase();
            style.bold = lower == "bold" || lower == "700" || lower == "600";
        }
        "padding" => {
            let (t, r, b, l) = parse_four_sides(val);
            style.padding_top = t;
            style.padding_right = r;
            style.padding_bottom = b;
            style.padding_left = l;
        }
        "padding-top" => {
            if let Some(px) = parse_px(val) {
                style.padding_top = px;
            }
        }
        "padding-right" => {
            if let Some(px) = parse_px(val) {
                style.padding_right = px;
            }
        }
        "padding-bottom" => {
            if let Some(px) = parse_px(val) {
                style.padding_bottom = px;
            }
        }
        "padding-left" => {
            if let Some(px) = parse_px(val) {
                style.padding_left = px;
            }
        }
        "margin" => {
            let (t, r, b, l) = parse_four_sides(val);
            style.margin_top = t;
            style.margin_right = r;
            style.margin_bottom = b;
            style.margin_left = l;
        }
        "margin-top" => {
            if let Some(px) = parse_px(val) {
                style.margin_top = px;
            }
        }
        "margin-right" => {
            if let Some(px) = parse_px(val) {
                style.margin_right = px;
            }
        }
        "margin-bottom" => {
            if let Some(px) = parse_px(val) {
                style.margin_bottom = px;
            }
        }
        "margin-left" => {
            if let Some(px) = parse_px(val) {
                style.margin_left = px;
            }
        }
        "border" => {
            for token in val.split_whitespace() {
                if let Some(px) = parse_px(token) {
                    style.border_width = px;
                } else if let Some(c) = parse_color(token) {
                    style.border_color = c;
                }
            }
        }
        _ => {}
    }
}

fn parse_four_sides(val: &str) -> (f32, f32, f32, f32) {
    let nums: Vec<f32> = val.split_whitespace().filter_map(parse_px).collect();
    match nums.as_slice() {
        [a] => (*a, *a, *a, *a),
        [v, h] => (*v, *h, *v, *h),
        [t, h, b] => (*t, *h, *b, *h),
        [t, r, b, l, ..] => (*t, *r, *b, *l),
        _ => (0.0, 0.0, 0.0, 0.0),
    }
}

fn parse_px(val: &str) -> Option<f32> {
    let trimmed = val.trim().trim_end_matches("px").trim();
    trimmed.parse::<f32>().ok()
}

pub fn parse_color(val: &str) -> Option<Color> {
    let s = val.trim().to_ascii_lowercase();
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some(Color::rgb(r, g, b));
        } else if hex.len() == 3 {
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
            return Some(Color::rgb(r, g, b));
        }
    }
    match s.as_str() {
        "black" => Some(Color::BLACK),
        "white" => Some(Color::WHITE),
        "red" => Some(Color::rgb(217, 48, 37)),
        "green" => Some(Color::rgb(24, 128, 56)),
        "blue" => Some(Color::rgb(26, 115, 232)),
        "gray" | "grey" => Some(Color::rgb(95, 99, 104)),
        _ => None,
    }
}
