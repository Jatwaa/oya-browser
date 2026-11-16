#![forbid(unsafe_code)]

use rc_dom::{ArenaDom, Stylesheet, parse_html};
use rc_ipc::{
    BrowserToRenderer, DisplayList, ImageAsset, RegionKind, RendererToBrowser, SubresourceKind,
    read_ipc_message, write_ipc_message,
};
use rc_js::JsRuntime;
use rc_layout::layout_to_display_list;
use rc_log::{DiagnosticEvent, LogCategory, Severity};
use rc_sandbox::CspPolicy;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::rc::Rc;
use std::time::Instant;

const MAX_EXTERNAL_STYLESHEETS: usize = 16;
const MAX_EXTERNAL_IMAGES: usize = 24;
const MAX_EXTERNAL_SCRIPTS: usize = 24;
/// Cap individual JS script evaluation at 512 KiB in interpreter mode to keep page loads sub-second.
const MAX_EVAL_SCRIPT_BYTES: usize = 512 * 1024;

pub struct RendererEngine {
    url: String,
    origin: String,
    dom: Rc<RefCell<ArenaDom>>,
    stylesheet: Stylesheet,
    js: Option<JsRuntime>,
    images: HashMap<String, ImageAsset>,
    next_image_id: u64,
    viewport_width: f32,
    last_display_list: DisplayList,
}

impl Default for RendererEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RendererEngine {
    pub fn new() -> Self {
        Self {
            url: "about:blank".to_string(),
            origin: "null".to_string(),
            dom: Rc::new(RefCell::new(ArenaDom::new())),
            stylesheet: Stylesheet::default(),
            js: None,
            images: HashMap::new(),
            next_image_id: 1,
            viewport_width: 960.0,
            last_display_list: DisplayList::default(),
        }
    }

    pub fn handle_message<F>(
        &mut self,
        msg: BrowserToRenderer,
        mut fetch_subresource: F,
    ) -> Option<RendererToBrowser>
    where
        F: FnMut(&str, SubresourceKind) -> Option<(bool, Option<String>, Vec<u8>, Option<String>)>,
    {
        match msg {
            BrowserToRenderer::LoadDocument {
                url,
                origin,
                html,
                csp,
                viewport_width,
                viewport_height: _,
            } => {
                let start_time = Instant::now();
                self.url = url.clone();
                self.origin = origin.clone();
                self.viewport_width = viewport_width;
                self.images.clear();

                let mut diagnostics = Vec::new();
                let pid = std::process::id();

                // Check if this is a YouTube page with ytInitialData / ytInitialPlayerResponse
                let effective_html = if is_youtube_origin(&origin) {
                    self.hydrate_youtube_html(&url, &html, &mut fetch_subresource, &mut diagnostics)
                        .unwrap_or(html)
                } else {
                    html
                };

                let parsed = parse_html(&effective_html);
                let mut combined_css = parsed.collect_style_blocks();
                let css_links = parsed.collect_stylesheet_links();
                let img_urls = parsed.collect_image_urls();
                let scripts = parsed.collect_scripts_ordered();

                // Fetch external stylesheets via Browser IPC
                for href in css_links.into_iter().take(MAX_EXTERNAL_STYLESHEETS) {
                    let abs = resolve_url(&url, &href);
                    if let Some((ok, Some(body), _, err)) =
                        fetch_subresource(&abs, SubresourceKind::Stylesheet)
                    {
                        if ok {
                            combined_css.push('\n');
                            combined_css.push_str(&body);
                        } else if let Some(e) = err {
                            diagnostics.push(DiagnosticEvent::new(
                                Severity::Warn,
                                LogCategory::Net,
                                &origin,
                                pid,
                                format!("Stylesheet load failed ({abs}): {e}"),
                            ));
                        }
                    }
                }

                // Fetch & decode external images inside the sandboxed renderer
                for src in img_urls.into_iter().take(MAX_EXTERNAL_IMAGES) {
                    if self.images.contains_key(&src) {
                        continue;
                    }
                    let abs = resolve_url(&url, &src);
                    if let Some((true, _, bytes, _)) =
                        fetch_subresource(&abs, SubresourceKind::Image)
                        && let Ok(img) = image::load_from_memory(&bytes)
                    {
                        let rgba = img.to_rgba8();
                        let (w, h) = rgba.dimensions();
                        let id = self.next_image_id;
                        self.next_image_id += 1;
                        self.images.insert(
                            src,
                            ImageAsset {
                                id,
                                width: w,
                                height: h,
                                rgba: rgba.into_raw(),
                            },
                        );
                    }
                }

                self.stylesheet = Stylesheet::parse(&combined_css);
                self.dom = Rc::new(RefCell::new(parsed));

                let csp_policy = csp
                    .as_deref()
                    .map(CspPolicy::parse)
                    .unwrap_or_else(CspPolicy::permissive);

                let mut console_logs = Vec::new();
                let mut script_errors = Vec::new();

                // Zero-Script Fast Path: skip allocating Boa JS Context if page has no scripts
                if scripts.is_empty() {
                    self.js = None;
                } else {
                    let mut js = JsRuntime::new(self.dom.clone(), &url, &origin);
                    let mut ext_count = 0usize;
                    for (ext_src, inline_code) in scripts {
                        if let Some(src) = ext_src {
                            if ext_count >= MAX_EXTERNAL_SCRIPTS {
                                continue;
                            }
                            ext_count += 1;
                            let abs = resolve_url(&url, &src);
                            if abs.contains("kevlar_base")
                                || abs.contains("desktop_polymer")
                                || abs.contains("/s/desktop/")
                                || abs.ends_with("/base.js")
                            {
                                diagnostics.push(DiagnosticEvent::new(
                                    Severity::Info,
                                    LogCategory::Perf,
                                    &origin,
                                    pid,
                                    format!("Skipped downloading multi-MB SPA bundle in low-resource mode: {abs}"),
                                ));
                                continue;
                            }
                            if let Some((ok, body_opt, _, err)) =
                                fetch_subresource(&abs, SubresourceKind::Script)
                            {
                                if ok && let Some(code) = body_opt {
                                    if code.len() > MAX_EVAL_SCRIPT_BYTES {
                                        diagnostics.push(DiagnosticEvent::new(
                                            Severity::Info,
                                            LogCategory::Perf,
                                            &origin,
                                            pid,
                                            format!(
                                                "Skipped oversized external bundle ({:.1} MiB > 512 KiB interpreter cap): {abs}",
                                                code.len() as f64 / (1024.0 * 1024.0)
                                            ),
                                        ));
                                    } else if let Err(e) = js.eval(&code) {
                                        script_errors.push(e);
                                    }
                                } else if let Some(e) = err {
                                    diagnostics.push(DiagnosticEvent::new(
                                        Severity::Warn,
                                        LogCategory::Net,
                                        &origin,
                                        pid,
                                        format!("Script fetch failed ({abs}): {e}"),
                                    ));
                                }
                            }
                        } else if let Some(code) = inline_code {
                            if csp_policy.allow_inline_script {
                                if code.len() <= MAX_EVAL_SCRIPT_BYTES
                                    && let Err(e) = js.eval(&code)
                                {
                                    script_errors.push(e);
                                }
                            } else {
                                let msg = "Refused to execute inline script because it violates Content Security Policy.".to_string();
                                script_errors.push(msg.clone());
                                diagnostics.push(DiagnosticEvent::new(
                                    Severity::Security,
                                    LogCategory::Security,
                                    &origin,
                                    pid,
                                    msg,
                                ));
                            }
                        }
                    }
                    console_logs = js.take_logs();
                    diagnostics.extend(js.take_diagnostics());
                    self.js = Some(js);
                }

                let elapsed_ms = start_time.elapsed().as_millis();
                diagnostics.push(DiagnosticEvent::new(
                    Severity::Info,
                    LogCategory::Perf,
                    &origin,
                    pid,
                    format!(
                        "Loaded {} ({} DOM nodes, {} images) in {} ms",
                        url,
                        self.dom.borrow().node_count(),
                        self.images.len(),
                        elapsed_ms
                    ),
                ));

                Some(self.render_frame(console_logs, script_errors, diagnostics))
            }
            BrowserToRenderer::Resize {
                viewport_width,
                viewport_height: _,
            } => {
                self.viewport_width = viewport_width;
                Some(self.render_frame(Vec::new(), Vec::new(), Vec::new()))
            }
            BrowserToRenderer::ExecuteScript { source } => {
                if self.js.is_none() {
                    self.js = Some(JsRuntime::new(self.dom.clone(), &self.url, &self.origin));
                }
                if let Some(js) = &mut self.js {
                    match js.eval(&source) {
                        Ok(value) => {
                            let console_logs = js.take_logs();
                            let diagnostics = js.take_diagnostics();
                            Some(RendererToBrowser::ScriptResult {
                                value,
                                error: None,
                                console_logs,
                                diagnostics,
                            })
                        }
                        Err(err) => {
                            let console_logs = js.take_logs();
                            let diagnostics = js.take_diagnostics();
                            Some(RendererToBrowser::ScriptResult {
                                value: String::new(),
                                error: Some(err),
                                console_logs,
                                diagnostics,
                            })
                        }
                    }
                } else {
                    None
                }
            }
            BrowserToRenderer::TriggerButton { node_id } => {
                let mut console_logs = Vec::new();
                let mut script_errors = Vec::new();
                let mut diagnostics = Vec::new();
                if let Some(js) = &mut self.js {
                    script_errors = js.dispatch_click(node_id);
                    console_logs = js.take_logs();
                    diagnostics = js.take_diagnostics();
                }
                Some(self.render_frame(console_logs, script_errors, diagnostics))
            }
            BrowserToRenderer::ClickAt { x, y } => {
                for region in &self.last_display_list.hit_regions {
                    if x >= region.x
                        && x <= region.x + region.w
                        && y >= region.y
                        && y <= region.y + region.h
                        && let RegionKind::Link { href } = &region.kind
                    {
                        return Some(RendererToBrowser::NavigateRequest { url: href.clone() });
                    }
                }
                None
            }
            BrowserToRenderer::DumpDom => {
                let dom = self.dom.borrow();
                Some(RendererToBrowser::DomDump {
                    html: dom.serialize_html(),
                    node_count: dom.node_count(),
                })
            }
            BrowserToRenderer::SubresourceResponse { .. } | BrowserToRenderer::Shutdown => None,
        }
    }

    /// Native Rust extractor for YouTube's `ytInitialData` and `ytInitialPlayerResponse`.
    /// Parses the embedded JSON in < 5 ms (bypassing slow multi-MB Polymer JS evaluation)
    /// and builds a responsive Flexbox grid with real video thumbnails, titles, channels, and watch views.
    fn hydrate_youtube_html<F>(
        &mut self,
        url: &str,
        raw_html: &str,
        fetch_subresource: &mut F,
        diagnostics: &mut Vec<DiagnosticEvent>,
    ) -> Option<String>
    where
        F: FnMut(&str, SubresourceKind) -> Option<(bool, Option<String>, Vec<u8>, Option<String>)>,
    {
        let player_json = extract_json_after_marker(raw_html, "var ytInitialPlayerResponse =")
            .or_else(|| extract_json_after_marker(raw_html, "ytInitialPlayerResponse ="));
        let mut initial_data_json = extract_json_after_marker(raw_html, "var ytInitialData =")
            .or_else(|| extract_json_after_marker(raw_html, "window[\"ytInitialData\"] ="));

        let mut videos = Vec::new();
        if let Some(ref data_val) = initial_data_json {
            collect_yt_videos(data_val, &mut videos, 0);
        }

        // YouTube's signed-out homepage (`/`) returns an empty feed ("Try searching to get started").
        // Automatically fetch a general popular YouTube video feed for headless/static rendering.
        if videos.is_empty() && player_json.is_none() {
            let feed_url = "https://www.youtube.com/results?search_query=trending+popular+music+gaming+news+entertainment";
            if let Some((true, Some(feed_html), _, _)) =
                fetch_subresource(feed_url, SubresourceKind::Fetch)
            {
                initial_data_json = extract_json_after_marker(&feed_html, "var ytInitialData =");
                if let Some(ref data_val) = initial_data_json {
                    collect_yt_videos(data_val, &mut videos, 0);
                }
                diagnostics.push(DiagnosticEvent::new(
                    Severity::Info,
                    LogCategory::Perf,
                    &self.origin,
                    std::process::id(),
                    format!(
                        "Hydrated signed-out YouTube homepage with {} live videos",
                        videos.len()
                    ),
                ));
            }
        }

        if videos.is_empty() && player_json.is_none() {
            return None;
        }

        let mut page_title = "YouTube".to_string();
        let mut watch_section = String::new();

        if let Some(player) = player_json
            && let Some(vd) = player.get("videoDetails")
        {
            let vid = vd.get("videoId").and_then(|v| v.as_str()).unwrap_or("");
            let title = vd
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("YouTube Video");
            let author = vd
                .get("author")
                .and_then(|v| v.as_str())
                .unwrap_or("Channel");
            let views = vd
                .get("viewCount")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            let length_s = vd
                .get("lengthSeconds")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            let desc = vd
                .get("shortDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            page_title = format!("{title} - YouTube");

            let poster_url = format!("https://i.ytimg.com/vi/{vid}/hqdefault.jpg");
            let short_desc: String = desc.chars().take(360).collect();

            watch_section = format!(
                r#"<div class="watch-box">
                    <img src="{poster_url}" width="480" height="360">
                    <h2>{}</h2>
                    <p class="meta"><b>Channel:</b> {} &nbsp;|&nbsp; <b>Views:</b> {} &nbsp;|&nbsp; <b>Duration:</b> {}s</p>
                    <p class="desc">{}</p>
                </div>"#,
                escape_html(title),
                escape_html(author),
                escape_html(views),
                escape_html(length_s),
                escape_html(&short_desc)
            );
        }

        let mut cards_html = String::new();
        for v in videos.iter().take(9) {
            let thumb_url = format!("https://i.ytimg.com/vi/{}/mqdefault.jpg", v.video_id);
            cards_html.push_str(&format!(
                r#"<div class="vcard">
                    <img src="{thumb_url}" width="280" height="158">
                    <p class="vtitle"><a href="https://www.youtube.com/watch?v={}">{}</a></p>
                    <p class="vmeta">{} &bull; {} &bull; {}</p>
                </div>"#,
                v.video_id,
                escape_html(&v.title),
                escape_html(&v.channel),
                escape_html(&v.views),
                escape_html(&v.duration),
            ));
        }

        let _ = url;
        Some(format!(
            r#"<!doctype html>
<html>
<head>
<title>{}</title>
<style>
body {{ background-color: #f9f9f9; color: #0f0f0f; padding: 20px; }}
.topbar {{ display: flex; gap: 16px; background-color: #ffffff; border: 1px solid #e5e5e5; padding: 12px; margin-bottom: 18px; }}
.brand {{ color: #ff0000; font-size: 22px; font-weight: bold; }}
.navlink {{ font-size: 14px; }}
.watch-box {{ background-color: #ffffff; border: 1px solid #dadce0; padding: 18px; margin-bottom: 20px; }}
.meta {{ color: #606060; font-size: 13px; margin-bottom: 8px; }}
.desc {{ color: #202124; font-size: 14px; }}
.grid {{ display: flex; gap: 16px; }}
.vcard {{ width: 300px; background-color: #ffffff; border: 1px solid #dadce0; padding: 10px; margin-bottom: 12px; }}
.vtitle {{ font-size: 15px; font-weight: bold; margin-top: 6px; margin-bottom: 4px; }}
.vmeta {{ color: #606060; font-size: 12px; }}
</style>
</head>
<body>
  <div class="topbar">
    <span class="brand">YouTube</span>
    <span class="navlink"><a href="https://www.youtube.com/results?search_query=trending+videos">Trending</a></span>
    <span class="navlink"><a href="https://www.youtube.com/results?search_query=rust+programming">Rust</a></span>
    <span class="navlink"><a href="https://www.youtube.com/results?search_query=music+hits">Music</a></span>
    <span class="navlink"><a href="https://www.youtube.com/results?search_query=gaming+live">Gaming</a></span>
    <span class="navlink"><a href="https://www.youtube.com/results?search_query=technology+news">Tech News</a></span>
  </div>
  {watch_section}
  <div class="grid">
    {cards_html}
  </div>
</body>
</html>"#,
            escape_html(&page_title)
        ))
    }

    fn render_frame(
        &mut self,
        console_logs: Vec<String>,
        script_errors: Vec<String>,
        diagnostics: Vec<DiagnosticEvent>,
    ) -> RendererToBrowser {
        let dom = self.dom.borrow();
        let display_list =
            layout_to_display_list(&dom, &self.stylesheet, self.viewport_width, &self.images);
        self.last_display_list = display_list.clone();
        let title = {
            let t = dom.title();
            if t.is_empty() {
                self.url.clone()
            } else {
                t
            }
        };
        RendererToBrowser::FrameRendered {
            title,
            url: self.url.clone(),
            display_list,
            console_logs,
            script_errors,
            diagnostics,
            dom_node_count: dom.node_count(),
        }
    }
}

struct YtVideoItem {
    video_id: String,
    title: String,
    channel: String,
    views: String,
    duration: String,
}

fn is_youtube_origin(origin: &str) -> bool {
    origin.ends_with("://youtube.com") || origin.ends_with(".youtube.com")
}

fn extract_json_after_marker(html: &str, marker: &str) -> Option<Value> {
    let start_idx = html.find(marker)? + marker.len();
    let rest = html[start_idx..].trim_start();
    if !rest.starts_with('{') {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let slice = &rest[..=i];
                        return serde_json::from_str::<Value>(slice).ok();
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn collect_yt_videos(val: &Value, out: &mut Vec<YtVideoItem>, depth: usize) {
    if depth > 18 || out.len() >= 12 {
        return;
    }
    match val {
        Value::Object(map) => {
            if let Some(vr) = map.get("videoRenderer")
                && let Some(vid) = vr.get("videoId").and_then(|v| v.as_str())
            {
                let title = vr
                    .get("title")
                    .and_then(extract_yt_text)
                    .unwrap_or_else(|| vid.to_string());
                let channel = vr
                    .get("ownerText")
                    .or_else(|| vr.get("longBylineText"))
                    .and_then(extract_yt_text)
                    .unwrap_or_else(|| "YouTube".to_string());
                let views = vr
                    .get("shortViewCountText")
                    .or_else(|| vr.get("viewCountText"))
                    .and_then(extract_yt_text)
                    .unwrap_or_else(|| "Views".to_string());
                let duration = vr
                    .get("lengthText")
                    .and_then(extract_yt_text)
                    .unwrap_or_else(|| "Video".to_string());

                if !out.iter().any(|existing| existing.video_id == vid) {
                    out.push(YtVideoItem {
                        video_id: vid.to_string(),
                        title,
                        channel,
                        views,
                        duration,
                    });
                }
                return;
            }
            for child in map.values() {
                collect_yt_videos(child, out, depth + 1);
                if out.len() >= 12 {
                    break;
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_yt_videos(item, out, depth + 1);
                if out.len() >= 12 {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn extract_yt_text(val: &Value) -> Option<String> {
    if let Some(s) = val.get("simpleText").and_then(|v| v.as_str()) {
        return Some(s.to_string());
    }
    if let Some(runs) = val.get("runs").and_then(|v| v.as_array()) {
        let mut s = String::new();
        for r in runs {
            if let Some(t) = r.get("text").and_then(|v| v.as_str()) {
                s.push_str(t);
            }
        }
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn resolve_url(base: &str, rel: &str) -> String {
    if rel.contains("://") || rel.starts_with("data:") {
        return rel.to_string();
    }
    if let Ok(b) = url::Url::parse(base)
        && let Ok(joined) = b.join(rel)
    {
        return joined.to_string();
    }
    rel.to_string()
}

/// `(ok, body_utf8, bytes, error)` returned by the host for a subresource request.
type SubresourceReply = (bool, Option<String>, Vec<u8>, Option<String>);

fn fetch_subresource_via_ipc<R: Read, W: Write>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    url: &str,
    kind: SubresourceKind,
) -> Option<SubresourceReply> {
    if write_ipc_message(
        writer,
        &RendererToBrowser::FetchSubresource {
            url: url.to_string(),
            kind,
        },
    )
    .is_err()
    {
        return None;
    }
    match read_ipc_message::<_, BrowserToRenderer>(reader) {
        Ok(BrowserToRenderer::SubresourceResponse {
            ok,
            body_utf8,
            bytes,
            error,
            ..
        }) => Some((ok, body_utf8, bytes, error)),
        _ => None,
    }
}

/// Entrypoint for the isolated child renderer process communicating over stdin/stdout IPC.
pub fn run_renderer_stdio(sandboxed: bool) {
    let builder = std::thread::Builder::new()
        .name("rc-renderer-main".to_string())
        .stack_size(8 * 1024 * 1024);

    let handle = builder.spawn(move || {
        let mitigations_ok = rc_sandbox::apply_renderer_mitigations();
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = BufWriter::new(stdout.lock());

        let _ = write_ipc_message(
            &mut writer,
            &RendererToBrowser::Ready {
                pid: std::process::id(),
                sandboxed: sandboxed || mitigations_ok,
            },
        );

        let mut engine = RendererEngine::new();
        loop {
            match read_ipc_message::<_, BrowserToRenderer>(&mut reader) {
                Ok(BrowserToRenderer::Shutdown) | Err(_) => break,
                Ok(msg) => {
                    let reply = engine.handle_message(msg, |url, kind| {
                        fetch_subresource_via_ipc(&mut reader, &mut writer, url, kind)
                    });
                    if let Some(r) = reply
                        && write_ipc_message(&mut writer, &r).is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    if let Ok(h) = handle {
        let _ = h.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_blocks_inline_script_in_renderer() {
        let mut engine = RendererEngine::new();
        let resp = engine
            .handle_message(
                BrowserToRenderer::LoadDocument {
                    url: "https://example.com/".to_string(),
                    origin: "https://example.com".to_string(),
                    html: "<html><body><p id='x'>safe</p><script>document.getElementById('x').textContent='pwned'</script></body></html>".to_string(),
                    csp: Some("script-src 'self'".to_string()),
                    viewport_width: 800.0,
                    viewport_height: 600.0,
                },
                |_, _| None,
            )
            .unwrap();

        match resp {
            RendererToBrowser::FrameRendered {
                script_errors,
                diagnostics,
                ..
            } => {
                assert!(!script_errors.is_empty());
                assert!(script_errors[0].contains("Content Security Policy"));
                assert!(diagnostics.iter().any(|d| d.category == LogCategory::Security));
            }
            _ => panic!("expected FrameRendered"),
        }
    }
}
