#![forbid(unsafe_code)]

use rc_log::DiagnosticEvent;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use thiserror::Error;

/// Hard cap on a single IPC message to prevent OOM attacks from compromised renderers.
pub const MAX_IPC_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("IPC message exceeded maximum size of {MAX_IPC_MESSAGE_BYTES} bytes")]
    MessageTooLarge,
    #[error("IPC channel closed")]
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const BLACK: Self = Self::rgb(0, 0, 0);
    pub const WHITE: Self = Self::rgb(255, 255, 255);
    pub const LINK_BLUE: Self = Self::rgb(26, 115, 232);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubresourceKind {
    Stylesheet,
    Script,
    Image,
    Fetch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAsset {
    pub id: u64,
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DrawCommand {
    FillRect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        color: Color,
    },
    StrokeRect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        width: f32,
        color: Color,
    },
    DrawText {
        x: f32,
        y: f32,
        text: String,
        font_size: f32,
        color: Color,
        bold: bool,
    },
    DrawImage {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        image_id: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegionKind {
    Link { href: String },
    Button { node_id: usize },
    Input { node_id: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitRegion {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub kind: RegionKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplayList {
    pub background: Option<Color>,
    pub content_height: f32,
    pub commands: Vec<DrawCommand>,
    pub hit_regions: Vec<HitRegion>,
    pub images: Vec<ImageAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrowserToRenderer {
    LoadDocument {
        url: String,
        origin: String,
        html: String,
        csp: Option<String>,
        viewport_width: f32,
        viewport_height: f32,
    },
    SubresourceResponse {
        url: String,
        kind: SubresourceKind,
        ok: bool,
        body_utf8: Option<String>,
        bytes: Vec<u8>,
        error: Option<String>,
    },
    Resize {
        viewport_width: f32,
        viewport_height: f32,
    },
    ExecuteScript {
        source: String,
    },
    ClickAt {
        x: f32,
        y: f32,
    },
    TriggerButton {
        node_id: usize,
    },
    DumpDom,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RendererToBrowser {
    Ready {
        pid: u32,
        sandboxed: bool,
    },
    FetchSubresource {
        url: String,
        kind: SubresourceKind,
    },
    FrameRendered {
        title: String,
        url: String,
        display_list: DisplayList,
        console_logs: Vec<String>,
        script_errors: Vec<String>,
        diagnostics: Vec<DiagnosticEvent>,
        dom_node_count: usize,
    },
    NavigateRequest {
        url: String,
    },
    ScriptResult {
        value: String,
        error: Option<String>,
        console_logs: Vec<String>,
        diagnostics: Vec<DiagnosticEvent>,
    },
    DomDump {
        html: String,
        node_count: usize,
    },
    Error {
        message: String,
    },
}

/// Writes a length-checked JSON-line IPC frame.
pub fn write_ipc_message<W: Write, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), IpcError> {
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge);
    }
    writer.write_all(&payload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Reads a length-checked JSON-line IPC frame.
pub fn read_ipc_message<R: BufRead, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, IpcError> {
    let mut line = Vec::with_capacity(512);
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if total == 0 {
                return Err(IpcError::Closed);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            total += pos;
            if total > MAX_IPC_MESSAGE_BYTES {
                return Err(IpcError::MessageTooLarge);
            }
            line.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            break;
        } else {
            total += available.len();
            if total > MAX_IPC_MESSAGE_BYTES {
                return Err(IpcError::MessageTooLarge);
            }
            line.extend_from_slice(available);
            let len = available.len();
            reader.consume(len);
        }
    }
    let msg = serde_json::from_slice(&line)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_ipc_message() {
        let msg = BrowserToRenderer::LoadDocument {
            url: "https://example.com/".to_string(),
            origin: "https://example.com".to_string(),
            html: "<h1>Hello</h1>".to_string(),
            csp: Some("default-src 'self'".to_string()),
            viewport_width: 1024.0,
            viewport_height: 768.0,
        };
        let mut buf = Vec::new();
        write_ipc_message(&mut buf, &msg).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded: BrowserToRenderer = read_ipc_message(&mut cursor).unwrap();
        match decoded {
            BrowserToRenderer::LoadDocument { url, origin, .. } => {
                assert_eq!(url, "https://example.com/");
                assert_eq!(origin, "https://example.com");
            }
            _ => panic!("unexpected variant"),
        }
    }
}
