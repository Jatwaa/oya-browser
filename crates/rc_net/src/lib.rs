#![forbid(unsafe_code)]

use rc_log::{DiagnosticEvent, LogCategory, Severity};
use rc_sandbox::{OriginKey, SecurityError, validate_and_extract_origin};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

pub const MAX_RESPONSE_BYTES: u64 = 24 * 1024 * 1024;
pub const MAX_SUBRESOURCE_BYTES: u64 = 24 * 1024 * 1024;
pub const CHROME_MAJOR_VERSION: &str = "142";
pub const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

#[derive(Debug, Error)]
pub enum NetError {
    #[error("Security policy blocked request: {0}")]
    Security(#[from] SecurityError),
    #[error("HTTP/TLS transport error: {0}")]
    Transport(String),
    #[error("Invalid data URL")]
    InvalidDataUrl,
}

#[derive(Debug, Clone)]
pub struct FetchedDocument {
    pub final_url: String,
    pub origin: OriginKey,
    pub status_code: u16,
    pub content_type: String,
    pub csp_header: Option<String>,
    pub body: String,
    pub diagnostics: Vec<DiagnosticEvent>,
}

/// Origin-partitioned in-memory Cookie Jar to prevent cross-site tracking leaks.
#[derive(Default)]
struct PartitionedCookieJar {
    buckets: Mutex<HashMap<(String, String), HashMap<String, String>>>,
}

impl PartitionedCookieJar {
    fn store_set_cookie(&self, top_origin: &str, req_origin: &str, header_val: &str) {
        let Some(pair) = header_val.split(';').next() else {
            return;
        };
        let Some((name, val)) = pair.split_once('=') else {
            return;
        };
        let mut guard = self.buckets.lock().unwrap();
        let map = guard
            .entry((top_origin.to_string(), req_origin.to_string()))
            .or_default();
        map.insert(name.trim().to_string(), val.trim().to_string());
    }

    fn cookie_header(&self, top_origin: &str, req_origin: &str) -> Option<String> {
        let guard = self.buckets.lock().unwrap();
        let map = guard.get(&(top_origin.to_string(), req_origin.to_string()))?;
        if map.is_empty() {
            return None;
        }
        let joined: Vec<String> = map.iter().map(|(k, v)| format!("{k}={v}")).collect();
        Some(joined.join("; "))
    }
}

pub struct NetworkService {
    agent: ureq::Agent,
    cookies: PartitionedCookieJar,
}

impl Default for NetworkService {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkService {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(5)
            .build();
        Self {
            agent: config.into(),
            cookies: PartitionedCookieJar::default(),
        }
    }

    pub fn fetch_document(&self, raw_url: &str) -> Result<FetchedDocument, NetError> {
        let trimmed = raw_url.trim();
        let origin = validate_and_extract_origin(trimmed)?;

        if trimmed == "about:blank" {
            return Ok(FetchedDocument {
                final_url: "about:blank".to_string(),
                origin,
                status_code: 200,
                content_type: "text/html; charset=utf-8".to_string(),
                csp_header: Some("default-src 'none'".to_string()),
                body: "<!doctype html><html><head><title>about:blank</title></head><body></body></html>"
                    .to_string(),
                diagnostics: Vec::new(),
            });
        }

        if let Some(internal) = trimmed.strip_prefix("rustchrome://") {
            return Ok(self.render_internal_page(trimmed, internal, origin));
        }

        if let Some(rest) = trimmed.strip_prefix("data:") {
            let (meta, data) = rest.split_once(',').ok_or(NetError::InvalidDataUrl)?;
            let decoded = percent_decode(data);
            return Ok(FetchedDocument {
                final_url: trimmed.to_string(),
                origin,
                status_code: 200,
                content_type: if meta.is_empty() {
                    "text/plain".to_string()
                } else {
                    meta.to_string()
                },
                csp_header: None,
                body: decoded,
                diagnostics: Vec::new(),
            });
        }

        let origin_str = origin.to_string();
        let mut req = self
            .agent
            .get(trimmed)
            .header("User-Agent", USER_AGENT)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            )
            .header("Accept-Language", "en-US,en;q=0.9")
            .header(
                "Sec-CH-UA",
                "\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not_A Brand\";v=\"99\"",
            )
            .header("Sec-CH-UA-Mobile", "?0")
            .header("Sec-CH-UA-Platform", "\"Windows\"")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "none")
            .header("Sec-Fetch-User", "?1")
            .header("Upgrade-Insecure-Requests", "1");

        if let Some(cookie) = self.cookies.cookie_header(&origin_str, &origin_str) {
            req = req.header("Cookie", &cookie);
        }

        let response = req.call().map_err(|e| NetError::Transport(e.to_string()))?;

        let status_code = response.status().as_u16();
        for val in response.headers().get_all("set-cookie") {
            if let Ok(s) = val.to_str() {
                self.cookies.store_set_cookie(&origin_str, &origin_str, s);
            }
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/html")
            .to_string();
        let csp_header = response
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut diagnostics = Vec::new();
        if status_code >= 400 {
            diagnostics.push(DiagnosticEvent::new(
                Severity::Warn,
                LogCategory::Net,
                &origin_str,
                0,
                format!("HTTP {status_code} for {trimmed}"),
            ));
        }

        let body = response
            .into_body()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| NetError::Transport(e.to_string()))?;

        Ok(FetchedDocument {
            final_url: trimmed.to_string(),
            origin,
            status_code,
            content_type,
            csp_header,
            body,
            diagnostics,
        })
    }

    /// Fetches a subresource (CSS, JS, Image, or fetch()) on behalf of a sandboxed renderer.
    pub fn fetch_subresource(
        &self,
        raw_url: &str,
        top_origin: &str,
        is_binary: bool,
    ) -> Result<(Option<String>, Vec<u8>), NetError> {
        let trimmed = raw_url.trim();
        let sub_origin = validate_and_extract_origin(trimmed)?;
        let sub_origin_str = sub_origin.to_string();

        if let Some(rest) = trimmed.strip_prefix("data:") {
            let (_meta, data) = rest.split_once(',').ok_or(NetError::InvalidDataUrl)?;
            let decoded = percent_decode(data);
            return if is_binary {
                Ok((None, decoded.into_bytes()))
            } else {
                Ok((Some(decoded), Vec::new()))
            };
        }

        let mut req = self
            .agent
            .get(trimmed)
            .header("User-Agent", USER_AGENT)
            .header("Accept-Language", "en-US,en;q=0.9");

        if let Some(cookie) = self.cookies.cookie_header(top_origin, &sub_origin_str) {
            req = req.header("Cookie", &cookie);
        }

        let response = req.call().map_err(|e| NetError::Transport(e.to_string()))?;
        for val in response.headers().get_all("set-cookie") {
            if let Ok(s) = val.to_str() {
                self.cookies.store_set_cookie(top_origin, &sub_origin_str, s);
            }
        }

        if is_binary {
            let bytes = response
                .into_body()
                .with_config()
                .limit(MAX_SUBRESOURCE_BYTES)
                .read_to_vec()
                .map_err(|e| NetError::Transport(e.to_string()))?;
            Ok((None, bytes))
        } else {
            let text = response
                .into_body()
                .with_config()
                .limit(MAX_SUBRESOURCE_BYTES)
                .read_to_string()
                .map_err(|e| NetError::Transport(e.to_string()))?;
            Ok((Some(text), Vec::new()))
        }
    }

    fn render_internal_page(
        &self,
        full_url: &str,
        page: &str,
        origin: OriginKey,
    ) -> FetchedDocument {
        let host = page.split('/').next().unwrap_or("newtab");
        let body = match host {
            "version" => r#"<!doctype html>
<html>
<head><title>RustChrome Version</title>
<style>
body { background-color: #f8f9fa; color: #202124; padding: 24px; }
h1 { color: #1a73e8; font-size: 26px; margin-bottom: 12px; }
.card { background-color: #ffffff; border: 1px solid #dadce0; padding: 16px; margin-bottom: 12px; }
</style>
</head>
<body>
  <h1>Oya Browser 0.1.0 — built-in page renderer</h1>
  <div class="card">
    <p><b>Architecture:</b> Multi-Process (Browser + Sandboxed Renderer + Partitioned Net)</p>
    <p><b>Memory Safety:</b> Pure Rust Core (#![forbid(unsafe_code)] in Log, IPC, Net, DOM, Layout, JS, CDP)</p>
    <p><b>Layout Engine:</b> Taffy Flexbox &amp; CSS Grid + ArenaDOM</p>
    <p><b>TLS Stack:</b> rustls (pure Rust, zero OpenSSL)</p>
    <p><b>JS Engine:</b> Boa (sandboxed pure-Rust ECMAScript + Zero-Script Fast Path)</p>
    <p><b>DevTools:</b> Chrome DevTools Protocol (CDP) WebSocket + Issue Logger</p>
  </div>
  <p><a href="rustchrome://newtab">Back to New Tab</a></p>
</body>
</html>"#.to_string(),
            "security" => r#"<!doctype html>
<html>
<head><title>RustChrome Security</title>
<style>
body { background-color: #f8f9fa; color: #202124; padding: 24px; }
h1 { color: #188038; font-size: 26px; margin-bottom: 12px; }
.card { background-color: #ffffff; border: 1px solid #dadce0; padding: 16px; margin-bottom: 12px; }
</style>
</head>
<body>
  <h1>Security-First Isolation</h1>
  <div class="card">
    <p><b>Site Isolation:</b> Origin-keyed renderer processes.</p>
    <p><b>OS Sandbox:</b> Windows Job Object (1 GiB memory cap, 1 active process, UI restrictions, kill-on-close) + Process Mitigation Policies (Strict Handle Check + Prohibit Dynamic RWX Code).</p>
    <p><b>Partitioned Storage:</b> Cookies &amp; localStorage keyed by top-level origin.</p>
    <p><b>IPC Validation:</b> Bounded 16 MiB frames; renderer has zero direct disk/network access.</p>
  </div>
  <p><a href="rustchrome://newtab">Back to New Tab</a></p>
</body>
</html>"#.to_string(),
            _ => r##"<!doctype html>
<html>
<head><title>New Tab - RustChrome</title>
<style>
body { background-color: #ffffff; color: #202124; padding: 28px; }
h1 { color: #1a73e8; font-size: 28px; margin-bottom: 8px; }
.subtitle { color: #5f6368; font-size: 14px; margin-bottom: 20px; }
.row { display: flex; gap: 12px; margin-bottom: 16px; }
.box { background-color: #f1f3f4; border: 1px solid #dadce0; padding: 16px; margin-bottom: 16px; }
#js-status { color: #188038; font-size: 15px; }
</style>
</head>
<body>
  <h1>RustChrome</h1>
  <p class="subtitle">Low-resource, Chrome-compatible, security-first browser built from the ground up in Rust.</p>
  <div class="row">
    <div class="box">
      <p><b>Quick Links</b></p>
      <p><a href="rustchrome://version">rustchrome://version</a></p>
      <p><a href="rustchrome://security">rustchrome://security</a></p>
      <p><a href="rustchrome://logs">rustchrome://logs</a></p>
      <p><a href="https://example.com">https://example.com</a></p>
    </div>
    <div class="box">
      <p><b>Sandboxed JS &amp; DOM Check</b></p>
      <p id="js-status">Waiting for JS...</p>
      <button id="ping-btn">Test Interactive Button</button>
    </div>
  </div>
  <script>
    const el = document.querySelector("#js-status");
    if (el) {
      el.textContent = "Sandboxed Boa JS active! Origin: " + window.location.href;
    }
    const btn = document.getElementById("ping-btn");
    if (btn) {
      btn.addEventListener("click", function() {
        el.textContent = "Button clicked via RustChrome EventTarget!";
        console.log("Button click handled in sandboxed JS.");
      });
    }
    console.log("RustChrome New Tab initialized.");
  </script>
</body>
</html>"##.to_string(),
        };

        FetchedDocument {
            final_url: full_url.to_string(),
            origin,
            status_code: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            csp_header: Some("script-src 'self' 'unsafe-inline'".to_string()),
            body,
            diagnostics: Vec::new(),
        }
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex, 16)
        {
            out.push(val);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_pages_work_offline() {
        let net = NetworkService::new();
        let doc = net.fetch_document("rustchrome://version").unwrap();
        assert_eq!(doc.status_code, 200);
        assert!(doc.body.contains("Oya Browser 0.1.0"));
    }

    #[test]
    fn blocks_unsafe_schemes() {
        let net = NetworkService::new();
        assert!(net.fetch_document("javascript:alert(1)").is_err());
    }

    #[test]
    fn decodes_data_url() {
        let net = NetworkService::new();
        let doc = net
            .fetch_document("data:text/html,<h1>Hi%20Rust</h1>")
            .unwrap();
        assert_eq!(doc.body, "<h1>Hi Rust</h1>");
    }

    #[test]
    fn cookie_jar_is_partitioned_by_top_origin() {
        let jar = PartitionedCookieJar::default();
        jar.store_set_cookie("https://site-a.com", "https://tracker.com", "id=111; Path=/");
        assert_eq!(
            jar.cookie_header("https://site-a.com", "https://tracker.com")
                .as_deref(),
            Some("id=111")
        );
        // Site B must NOT see Site A's tracker cookie
        assert_eq!(
            jar.cookie_header("https://site-b.com", "https://tracker.com"),
            None
        );
    }
}
