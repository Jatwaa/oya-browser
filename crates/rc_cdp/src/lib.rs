#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;
use tungstenite::Message;

#[derive(Debug, Clone)]
pub enum CdpAction {
    Navigate { url: String },
    Evaluate { expression: String },
    GetDom,
    GetTargetInfo,
}

#[derive(Debug)]
pub struct CdpRequest {
    pub action: CdpAction,
    pub reply: mpsc::Sender<Result<Value, String>>,
}

#[derive(Debug, Deserialize)]
struct CdpRpcRequest {
    id: u64,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct CdpRpcResponse {
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

pub struct CdpServerHandle {
    pub addr: SocketAddr,
    /// Unguessable secret that must appear in every WebSocket debugger URL.
    pub token: String,
    /// Clearing this refuses new connections and closes open ones.
    pub enabled: Arc<AtomicBool>,
}

impl CdpServerHandle {
    /// Stops accepting and serving debugger connections.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
}

impl CdpServerHandle {
    pub fn browser_ws_url(&self) -> String {
        format!("ws://{}/devtools/browser/{}", self.addr, self.token)
    }
}

/// Maximum simultaneous debugger connections; further connections are refused.
const MAX_CONNECTIONS: usize = 8;

/// Starts a lightweight Chrome DevTools Protocol (CDP) HTTP + WebSocket server on localhost.
///
/// Security model (mirrors Chrome's `--remote-debugging-port` hardening):
/// - Binds to 127.0.0.1 only.
/// - Rejects any request whose `Host` header is not a loopback name with this port, which stops
///   DNS-rebinding attacks from web pages.
/// - Rejects any request that carries an `Origin` header. Browsers always attach one to
///   cross-site `fetch` and WebSocket requests; command-line debugger clients do not.
/// - WebSocket endpoints require a random 128-bit token in the path.
pub fn start_cdp_server(
    port: u16,
    tx: mpsc::Sender<CdpRequest>,
) -> std::io::Result<CdpServerHandle> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let addr = listener.local_addr()?;
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| std::io::Error::other(e.to_string()))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    let active = Arc::new(AtomicUsize::new(0));
    let enabled = Arc::new(AtomicBool::new(true));
    let server_enabled = Arc::clone(&enabled);
    let server_token = token.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            if !server_enabled.load(Ordering::SeqCst) {
                drop(stream);
                continue;
            }
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                drop(stream);
                continue;
            }
            let tx_conn = tx.clone();
            let token = server_token.clone();
            let active_conn = Arc::clone(&active);
            let conn_enabled = Arc::clone(&server_enabled);
            thread::spawn(move || {
                handle_connection(stream, addr, &token, tx_conn, &conn_enabled);
                active_conn.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    Ok(CdpServerHandle {
        addr,
        token,
        enabled,
    })
}

/// Returns the value of `name` from the raw request head, case-insensitively.
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Host must be a loopback name with the server's own port.
fn host_is_allowed(head: &str, addr: SocketAddr) -> bool {
    let Some(host) = header_value(head, "host") else {
        return false;
    };
    let port = addr.port();
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
    .iter()
    .any(|h| host.eq_ignore_ascii_case(h))
}

fn write_status(stream: &mut TcpStream, status: &str) {
    let body = json!({ "error": status }).to_string();
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    token: &str,
    tx: mpsc::Sender<CdpRequest>,
    enabled: &AtomicBool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut peek_buf = [0u8; 4096];
    let Ok(n) = stream.peek(&mut peek_buf) else {
        return;
    };
    let head = String::from_utf8_lossy(&peek_buf[..n]).into_owned();

    if !host_is_allowed(&head, addr) {
        write_status(&mut stream, "403 Forbidden");
        return;
    }
    if header_value(&head, "origin").is_some() {
        write_status(&mut stream, "403 Forbidden");
        return;
    }

    let path = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let is_websocket = header_value(&head, "upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    if !is_websocket {
        let body = match path.as_str() {
            "/json/version" => json!({
                "Browser": "OyaBrowser/0.1.0",
                "Protocol-Version": "1.3",
                "User-Agent": "OyaBrowser/0.1.0",
                "V8-Version": "Boa-0.22.0",
                "webSocketDebuggerUrl": format!("ws://{addr}/devtools/browser/{token}")
            })
            .to_string(),
            "/json" | "/json/list" => {
                let info = dispatch_action(&tx, CdpAction::GetTargetInfo).unwrap_or_else(|_| {
                    json!({ "url": "about:blank", "title": "Oya Browser" })
                });
                json!([{
                    "id": "main",
                    "type": "page",
                    "title": info.get("title").and_then(|v| v.as_str()).unwrap_or("Oya Browser"),
                    "url": info.get("url").and_then(|v| v.as_str()).unwrap_or("about:blank"),
                    "webSocketDebuggerUrl": format!("ws://{addr}/devtools/page/{token}")
                }])
                .to_string()
            }
            _ => {
                write_status(&mut stream, "404 Not Found");
                return;
            }
        };

        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        return;
    }

    let allowed_paths = [
        format!("/devtools/browser/{token}"),
        format!("/devtools/page/{token}"),
    ];
    if !allowed_paths.iter().any(|p| p == &path) {
        write_status(&mut stream, "403 Forbidden");
        return;
    }

    let _ = stream.set_read_timeout(None);
    let Ok(mut ws) = tungstenite::accept(stream) else {
        return;
    };

    while let Ok(msg) = ws.read() {
        if !enabled.load(Ordering::SeqCst) {
            let _ = ws.close(None);
            break;
        }
        let Message::Text(text) = msg else {
            if msg.is_close() {
                break;
            }
            continue;
        };

        let Ok(req) = serde_json::from_str::<CdpRpcRequest>(&text) else {
            continue;
        };

        let rpc_resp = process_cdp_method(&req, &tx);
        if let Ok(payload) = serde_json::to_string(&rpc_resp)
            && ws.send(Message::Text(payload.into())).is_err()
        {
            break;
        }
    }
}

fn process_cdp_method(req: &CdpRpcRequest, tx: &mpsc::Sender<CdpRequest>) -> CdpRpcResponse {
    let result = match req.method.as_str() {
        "Browser.getVersion" => Ok(json!({
            "protocolVersion": "1.3",
            "product": "RustChrome/0.1.0",
            "revision": "rust-mvp",
            "userAgent": "RustChrome/0.1.0",
            "jsVersion": "Boa-0.22.0"
        })),
        "Target.getTargets" => dispatch_action(tx, CdpAction::GetTargetInfo).map(|info| {
            json!({
                "targetInfos": [{
                    "targetId": "main",
                    "type": "page",
                    "title": info.get("title").and_then(|v| v.as_str()).unwrap_or("RustChrome"),
                    "url": info.get("url").and_then(|v| v.as_str()).unwrap_or("about:blank"),
                    "attached": true
                }]
            })
        }),
        "Page.navigate" => {
            let url = req
                .params
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("about:blank")
                .to_string();
            dispatch_action(tx, CdpAction::Navigate { url })
        }
        "Runtime.evaluate" => {
            let expression = req
                .params
                .get("expression")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            dispatch_action(tx, CdpAction::Evaluate { expression })
        }
        "DOM.getDocument" => dispatch_action(tx, CdpAction::GetDom),
        other => Err(format!("Unsupported CDP method: {other}")),
    };

    match result {
        Ok(val) => CdpRpcResponse {
            id: req.id,
            result: Some(val),
            error: None,
        },
        Err(msg) => CdpRpcResponse {
            id: req.id,
            result: None,
            error: Some(json!({ "code": -32000, "message": msg })),
        },
    }
}

fn dispatch_action(tx: &mpsc::Sender<CdpRequest>, action: CdpAction) -> Result<Value, String> {
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(CdpRequest {
        action,
        reply: reply_tx,
    })
    .map_err(|_| "Browser controller closed".to_string())?;
    reply_rx
        .recv()
        .map_err(|_| "Browser controller dropped reply".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn request(addr: SocketAddr, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn rejects_foreign_host_origin_and_missing_token() {
        let (tx, rx) = mpsc::channel::<CdpRequest>();
        std::thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let _ = req.reply.send(Ok(json!({"url": "about:blank", "title": "t"})));
            }
        });
        let h = start_cdp_server(0, tx).unwrap();
        let port = h.addr.port();
        assert_eq!(h.token.len(), 32);

        let ok = request(h.addr, &format!("GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"));
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains(&h.token));

        // DNS rebinding: attacker-controlled host name.
        let rebind = request(h.addr, &format!("GET /json/version HTTP/1.1\r\nHost: evil.example:{port}\r\n\r\n"));
        assert!(rebind.starts_with("HTTP/1.1 403"), "{rebind}");

        // Request from a web page always carries an Origin header.
        let from_page = request(
            h.addr,
            &format!("GET /json/version HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: https://evil.example\r\n\r\n"),
        );
        assert!(from_page.starts_with("HTTP/1.1 403"), "{from_page}");

        // WebSocket without the token.
        let ws = request(
            h.addr,
            &format!(
                "GET /devtools/browser/main HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
        );
        assert!(ws.starts_with("HTTP/1.1 403"), "{ws}");
    }
}
