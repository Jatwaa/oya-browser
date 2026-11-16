#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::backtrace::Backtrace;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_MEMORY_EVENTS: usize = 2000;
pub const MAX_LOG_FILE_BYTES: u64 = 5 * 1024 * 1024;
pub const DEFAULT_LOG_FILE: &str = "logs/rustchrome.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    LowLevel,
    Info,
    Warn,
    Error,
    Security,
    Crash,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowLevel => "LOWLEVEL",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Security => "SECURITY",
            Self::Crash => "CRASH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogCategory {
    Net,
    Security,
    DomCss,
    JsCompat,
    Perf,
    Ipc,
    Lifecycle,
    LowLevel,
    Crash,
}

impl LogCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Net => "NET",
            Self::Security => "SECURITY",
            Self::DomCss => "DOM/CSS",
            Self::JsCompat => "JS-COMPAT",
            Self::Perf => "PERF",
            Self::Ipc => "IPC",
            Self::Lifecycle => "LIFECYCLE",
            Self::LowLevel => "LOWLEVEL",
            Self::Crash => "CRASH",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub timestamp_ms: u64,
    pub severity: Severity,
    pub category: LogCategory,
    pub origin: String,
    pub renderer_pid: u32,
    pub message: String,
}

impl DiagnosticEvent {
    pub fn new(
        severity: Severity,
        category: LogCategory,
        origin: impl Into<String>,
        renderer_pid: u32,
        message: impl Into<String>,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            timestamp_ms,
            severity,
            category,
            origin: origin.into(),
            renderer_pid,
            message: message.into(),
        }
    }
}

/// Immediately writes and hardware-flushes (`sync_data`) a diagnostic or crash event to `logs/rustchrome.jsonl`.
/// Used by panic hooks, OS exception filters, and process exit handlers so no crash or exit is ever lost.
pub fn write_emergency_event_to_disk(event: &DiagnosticEvent) {
    let path = Path::new(DEFAULT_LOG_FILE);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path)
        && let Ok(line) = serde_json::to_string(event)
    {
        let _ = writeln!(file, "{line}");
        let _ = file.flush();
        let _ = file.sync_data();
    }
}

/// Installs global Rust panic and thread-unwind hooks that capture full stack backtraces,
/// thread identifiers, and source locations directly to `logs/rustchrome.jsonl` before termination.
pub fn install_panic_and_exit_hooks(process_role: &'static str) {
    let pid = std::process::id();
    write_emergency_event_to_disk(&DiagnosticEvent::new(
        Severity::LowLevel,
        LogCategory::Lifecycle,
        process_role,
        pid,
        format!(
            "Process started: role={process_role}, pid={pid}, arch={}, os={}, switches={:?}",
            std::env::consts::ARCH,
            std::env::consts::OS,
            // Only `--switch` names: addresses and paths given on the command line stay private.
            std::env::args()
                .skip(1)
                .filter(|a| a.starts_with("--"))
                .map(|a| a.split('=').next().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        ),
    ));

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let pid = std::process::id();
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("unnamed-thread");
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown-location".to_string());

        let payload = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_string()
        };

        let bt = Backtrace::force_capture();
        let bt_compact: String = bt
            .to_string()
            .lines()
            .take(18)
            .collect::<Vec<_>>()
            .join(" | ");

        let crash_event = DiagnosticEvent::new(
            Severity::Crash,
            LogCategory::Crash,
            process_role,
            pid,
            format!(
                "UNHANDLED PANIC in {process_role} (thread='{thread_name}', id={:?}) at {location}: {payload} || Backtrace: {bt_compact}",
                thread.id()
            ),
        );
        write_emergency_event_to_disk(&crash_event);
        default_hook(panic_info);
    }));
}

pub struct LogStore {
    events: VecDeque<DiagnosticEvent>,
    async_tx: Option<Sender<String>>,
}

impl Default for LogStore {
    fn default() -> Self {
        Self::new(Some(PathBuf::from(DEFAULT_LOG_FILE)))
    }
}

impl LogStore {
    pub fn new(log_path: Option<PathBuf>) -> Self {
        let mut events = VecDeque::with_capacity(512);
        let mut async_tx = None;

        if let Some(p) = log_path {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            // Fast tail preload: only read the last 32 KB of the log file so startup is instantaneous!
            if let Ok(mut file) = fs::File::open(&p) {
                if let Ok(len) = file.metadata().map(|m| m.len())
                    && len > 32 * 1024
                {
                    let _ = file.seek(SeekFrom::End(-(32 * 1024)));
                }
                let reader = BufReader::new(file);
                let mut recent = VecDeque::with_capacity(128);
                for line in reader.lines().map_while(Result::ok) {
                    if line.starts_with('{')
                        && let Ok(ev) = serde_json::from_str::<DiagnosticEvent>(&line)
                    {
                        if recent.len() >= 120 {
                            recent.pop_front();
                        }
                        recent.push_back(ev);
                    }
                }
                events.extend(recent);
            }

            // Spawn a non-blocking background writer thread so UI threads never block on disk/SMB flush!
            let (tx, rx) = mpsc::channel::<String>();
            let writer_path = p.clone();
            let _ = std::thread::Builder::new()
                .name("oya-async-logger".to_string())
                .spawn(move || {
                    if let Ok(meta) = fs::metadata(&writer_path)
                        && meta.len() >= MAX_LOG_FILE_BYTES
                    {
                        let mut rotated = writer_path.clone();
                        rotated.set_extension("jsonl.old");
                        let _ = fs::rename(&writer_path, rotated);
                    }
                    let mut open_file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&writer_path)
                        .ok();
                    while let Ok(line) = rx.recv() {
                        if let Some(ref mut f) = open_file {
                            let _ = writeln!(f, "{line}");
                            // Drain any queued lines before flushing once per batch
                            while let Ok(more) = rx.try_recv() {
                                let _ = writeln!(f, "{more}");
                            }
                            let _ = f.flush();
                        }
                    }
                });
            async_tx = Some(tx);
        }
        Self { events, async_tx }
    }

    pub fn record(&mut self, event: DiagnosticEvent) {
        if let Some(ref tx) = self.async_tx
            && let Ok(line) = serde_json::to_string(&event)
        {
            let _ = tx.send(line);
        }
        if self.events.len() >= MAX_MEMORY_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn record_low_level(&mut self, origin: &str, message: impl Into<String>) {
        self.record(DiagnosticEvent::new(
            Severity::LowLevel,
            LogCategory::LowLevel,
            origin,
            std::process::id(),
            message,
        ));
    }

    pub fn record_lifecycle(&mut self, origin: &str, message: impl Into<String>) {
        self.record(DiagnosticEvent::new(
            Severity::Info,
            LogCategory::Lifecycle,
            origin,
            std::process::id(),
            message,
        ));
    }

    pub fn extend(&mut self, events: impl IntoIterator<Item = DiagnosticEvent>) {
        for ev in events {
            self.record(ev);
        }
    }

    pub fn events(&self) -> &VecDeque<DiagnosticEvent> {
        &self.events
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }

    pub fn render_html_report(&self) -> String {
        let mut rows = String::new();
        for ev in self.events.iter().rev().take(200) {
            let color = match ev.severity {
                Severity::LowLevel => "#5f6368",
                Severity::Info => "#1a73e8",
                Severity::Warn => "#b06000",
                Severity::Error => "#d93025",
                Severity::Security => "#188038",
                Severity::Crash => "#9c27b0",
            };
            rows.push_str(&format!(
                "<div class=\"row\"><span style=\"color:{color};font-weight:bold\">[{}][{}]</span> <span class=\"meta\">pid={} origin={}</span> — {}</div>\n",
                ev.severity.as_str(),
                ev.category.as_str(),
                ev.renderer_pid,
                escape_html(&ev.origin),
                escape_html(&ev.message),
            ));
        }
        if rows.is_empty() {
            rows.push_str("<p>No diagnostic events recorded yet.</p>");
        }
        format!(
            r#"<!doctype html>
<html>
<head><title>RustChrome Issue &amp; Low-Level Telemetry Logs</title>
<style>
body {{ background-color: #f8f9fa; color: #202124; padding: 24px; }}
h1 {{ color: #1a73e8; font-size: 24px; margin-bottom: 10px; }}
.row {{ background-color: #ffffff; border: 1px solid #dadce0; padding: 8px; margin-bottom: 6px; font-size: 13px; }}
.meta {{ color: #5f6368; }}
</style>
</head>
<body>
  <h1>RustChrome Low-Level Diagnostic, Exit &amp; Crash Logs ({} events)</h1>
  <p><a href="rustchrome://newtab">Back to New Tab</a></p>
  {rows}
</body>
</html>"#,
            self.events.len()
        )
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_in_memory_events() {
        let mut store = LogStore::new(None);
        for i in 0..(MAX_MEMORY_EVENTS + 50) {
            store.record(DiagnosticEvent::new(
                Severity::Info,
                LogCategory::Perf,
                "https://example.com",
                1234,
                format!("event {i}"),
            ));
        }
        assert_eq!(store.events().len(), MAX_MEMORY_EVENTS);
    }
}
