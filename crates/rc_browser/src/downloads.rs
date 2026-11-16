use crate::gui::is_risky_download;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DOWNLOADS_FILE: &str = "oya_downloads.json";
const MAX_HISTORY_ENTRIES: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadState {
    AwaitingConfirmation,
    Downloading,
    Scanning,
    Ready,
    Failed(String),
    Discarded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HazardLevel {
    Pending,
    Clean,
    Questionable(String),
    Hazardous(String),
}

impl HazardLevel {
    pub fn requires_open_confirmation(&self) -> bool {
        matches!(
            self,
            HazardLevel::Questionable(_) | HazardLevel::Hazardous(_)
        )
    }

    pub fn is_hazardous(&self) -> bool {
        matches!(self, HazardLevel::Hazardous(_))
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            HazardLevel::Questionable(r) | HazardLevel::Hazardous(r) => Some(r.as_str()),
            HazardLevel::Pending | HazardLevel::Clean => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadEntry {
    pub id: u64,
    pub tab_id: u64,
    pub file_name: String,
    pub source_url: String,
    pub source_host: String,
    pub local_path: Option<PathBuf>,
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub file_size_bytes: Option<u64>,
    pub state: DownloadState,
    pub hazard: HazardLevel,
    pub sha256_hex: Option<String>,
    pub user_confirmed_download: bool,
    pub scan_summary: String,
}

impl DownloadEntry {
    pub fn is_questionable_or_hazardous(&self) -> bool {
        self.hazard.requires_open_confirmation() || is_risky_download(&self.file_name)
    }
}

#[derive(Debug, Clone)]
pub struct DownloadScanReport {
    pub hazard: HazardLevel,
    pub sha256_hex: Option<String>,
    pub file_size_bytes: Option<u64>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DownloadStore {
    pub next_id: u64,
    pub entries: Vec<DownloadEntry>,
}

impl DownloadStore {
    pub fn load() -> Self {
        if let Some(raw) = crate::integrity::load_verified(Path::new(DOWNLOADS_FILE))
            && let Ok(mut parsed) = serde_json::from_str::<DownloadStore>(&raw)
        {
            if parsed.next_id == 0 {
                parsed.next_id = parsed.entries.iter().map(|e| e.id).max().unwrap_or(0) + 1;
            }
            // Any in-flight downloads from a previous closed session cannot resume automatically.
            for entry in &mut parsed.entries {
                if matches!(
                    entry.state,
                    DownloadState::Downloading | DownloadState::Scanning | DownloadState::AwaitingConfirmation
                ) {
                    entry.state = DownloadState::Failed("Session ended before completion".to_string());
                }
            }
            return parsed;
        }
        Self {
            next_id: 1,
            entries: Vec::new(),
        }
    }

    pub fn save(&self) {
        if let Ok(serialized) = serde_json::to_string_pretty(self) {
            crate::integrity::save_sealed(Path::new(DOWNLOADS_FILE), &serialized);
        }
    }

    fn alloc_id(&mut self) -> u64 {
        if self.next_id == 0 {
            self.next_id = 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn record_blocked(
        &mut self,
        tab_id: u64,
        source_url: String,
        source_host: String,
        file_name: String,
    ) -> u64 {
        if let Some(existing) = self.entries.iter().find(|e| {
            e.source_url == source_url && e.state == DownloadState::AwaitingConfirmation
        }) {
            return existing.id;
        }
        let id = self.alloc_id();
        self.entries.insert(
            0,
            DownloadEntry {
                id,
                tab_id,
                file_name,
                source_url,
                source_host,
                local_path: None,
                started_at_ms: now_ms(),
                completed_at_ms: None,
                file_size_bytes: None,
                state: DownloadState::AwaitingConfirmation,
                hazard: HazardLevel::Questionable(
                    "Executable or script file type — confirm before downloading.".to_string(),
                ),
                sha256_hex: None,
                user_confirmed_download: false,
                scan_summary: "Awaiting user confirmation before download".to_string(),
            },
        );
        self.trim();
        self.save();
        id
    }

    pub fn record_started(
        &mut self,
        tab_id: u64,
        source_url: String,
        source_host: String,
        file_name: String,
        local_path: PathBuf,
        confirmed_risky: bool,
    ) -> u64 {
        if let Some(existing) = self.entries.iter_mut().find(|e| {
            e.source_url == source_url && e.state == DownloadState::AwaitingConfirmation
        }) {
            existing.tab_id = tab_id;
            existing.file_name = file_name;
            existing.source_host = source_host;
            existing.local_path = Some(local_path);
            existing.started_at_ms = now_ms();
            existing.state = DownloadState::Downloading;
            existing.user_confirmed_download = confirmed_risky;
            existing.scan_summary = "Downloading…".to_string();
            let id = existing.id;
            self.save();
            return id;
        }

        let id = self.alloc_id();
        self.entries.insert(
            0,
            DownloadEntry {
                id,
                tab_id,
                file_name,
                source_url,
                source_host,
                local_path: Some(local_path),
                started_at_ms: now_ms(),
                completed_at_ms: None,
                file_size_bytes: None,
                state: DownloadState::Downloading,
                hazard: HazardLevel::Pending,
                sha256_hex: None,
                user_confirmed_download: confirmed_risky,
                scan_summary: "Downloading…".to_string(),
            },
        );
        self.trim();
        self.save();
        id
    }

    pub fn mark_discarded_by_url(&mut self, source_url: &str) {
        if let Some(entry) = self.entries.iter_mut().find(|e| {
            e.source_url == source_url && e.state == DownloadState::AwaitingConfirmation
        }) {
            entry.state = DownloadState::Discarded;
            entry.scan_summary = "Discarded by user before download".to_string();
            self.save();
        }
    }

    pub fn mark_completed_for_scan(
        &mut self,
        source_url: &str,
        local_path: Option<PathBuf>,
        succeeded: bool,
    ) -> Option<(u64, PathBuf)> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.source_url == source_url && e.state == DownloadState::Downloading)
            .or_else(|| self.entries.iter().position(|e| e.source_url == source_url))?;
        let entry = &mut self.entries[idx];

        entry.completed_at_ms = Some(now_ms());
        if let Some(p) = local_path {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                entry.file_name = name.to_string();
            }
            entry.local_path = Some(p);
        }

        if !succeeded {
            entry.state = DownloadState::Failed("Download interrupted or failed".to_string());
            entry.scan_summary = "Download did not complete".to_string();
            self.save();
            return None;
        }

        if let Some(path) = entry.local_path.clone() {
            entry.state = DownloadState::Scanning;
            entry.hazard = HazardLevel::Pending;
            entry.scan_summary = "Scanning for hazards…".to_string();
            let id = entry.id;
            self.save();
            Some((id, path))
        } else {
            entry.state = DownloadState::Failed("No output file path returned".to_string());
            entry.scan_summary = "Missing local file path".to_string();
            self.save();
            None
        }
    }

    pub fn apply_scan_report(&mut self, id: u64, report: DownloadScanReport) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.state = DownloadState::Ready;
            entry.hazard = report.hazard;
            entry.sha256_hex = report.sha256_hex;
            entry.file_size_bytes = report.file_size_bytes;
            entry.scan_summary = report.summary;
            self.save();
        }
    }

    pub fn remove(&mut self, id: u64) {
        self.entries.retain(|e| e.id != id);
        self.save();
    }

    pub fn clear_finished(&mut self) {
        self.entries.retain(|e| {
            matches!(
                e.state,
                DownloadState::AwaitingConfirmation | DownloadState::Downloading | DownloadState::Scanning
            )
        });
        self.save();
    }

    pub fn by_id(&self, id: u64) -> Option<&DownloadEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    fn trim(&mut self) {
        if self.entries.len() > MAX_HISTORY_ENTRIES {
            self.entries.truncate(MAX_HISTORY_ENTRIES);
        }
    }
}

/// Performs a multi-layer hazard scan on a completed download:
/// 1. SHA-256 digest & size
/// 2. Magic-byte vs extension spoofing detection
/// 3. Double-extension & risky/archive/macro extension check
/// 4. Suspicious script payload indicator scan
/// 5. Windows Defender (`MpCmdRun.exe`) file scan when available
/// 6. Mark-of-the-Web (`Zone.Identifier`) ADS verification on Windows
pub fn scan_downloaded_file(path: &Path, source_url: &str) -> DownloadScanReport {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();

    let Ok(mut file) = fs::File::open(path) else {
        return DownloadScanReport {
            hazard: HazardLevel::Questionable("File could not be opened for hazard scanning.".into()),
            sha256_hex: None,
            file_size_bytes: None,
            summary: "Could not read file for scanning".to_string(),
        };
    };

    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(4096);
    let mut text_sample = Vec::with_capacity(256 * 1024);
    let mut buf = [0u8; 65536];
    let mut total_size: u64 = 0;

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total_size += n as u64;
                hasher.update(&buf[..n]);
                if header.len() < 4096 {
                    let take = (4096 - header.len()).min(n);
                    header.extend_from_slice(&buf[..take]);
                }
                if text_sample.len() < 256 * 1024 {
                    let take = (256 * 1024 - text_sample.len()).min(n);
                    text_sample.extend_from_slice(&buf[..take]);
                }
            }
            Err(e) => {
                return DownloadScanReport {
                    hazard: HazardLevel::Questionable(format!("Scan read error: {e}")),
                    sha256_hex: None,
                    file_size_bytes: Some(total_size),
                    summary: format!("Read error during scan: {e}"),
                };
            }
        }
    }

    let sha256_hex = format!("{:x}", hasher.finalize());
    let mut notes = Vec::new();
    let mut worst_hazard = HazardLevel::Clean;

    // 1. Double-extension spoofing (e.g. invoice.pdf.exe, photo.jpg.js)
    if has_suspicious_double_extension(&file_name) {
        worst_hazard = escalate_hazard(
            worst_hazard,
            HazardLevel::Hazardous(format!(
                "Suspicious double extension detected in \"{file_name}\" (common malware disguise)."
            )),
        );
        notes.push("Double extension detected");
    }

    // 2. Magic-byte vs extension spoofing
    if let Some(spoof_msg) = detect_extension_spoofing(&file_name, &header) {
        worst_hazard = escalate_hazard(worst_hazard, HazardLevel::Hazardous(spoof_msg.clone()));
        notes.push("Header/extension mismatch");
    }

    // 3. Windows Defender scan (when available on Windows)
    match run_windows_defender_scan(path) {
        DefenderScan::ThreatFound => {
            worst_hazard = escalate_hazard(
                worst_hazard,
                HazardLevel::Hazardous(
                    "Windows Defender detected a potential threat in this file.".to_string(),
                ),
            );
            notes.push("Defender: THREAT DETECTED");
        }
        DefenderScan::Clean => {
            notes.push("Defender: 0 threats");
        }
        DefenderScan::NotAvailable => {
            notes.push("Static heuristic scan");
        }
    }

    // 4. Risky executable/script or archive/macro extension
    if is_risky_download(&file_name) {
        worst_hazard = escalate_hazard(
            worst_hazard,
            HazardLevel::Questionable(
                "Executable or script file type can run code on your computer.".to_string(),
            ),
        );
        notes.push("Executable/script type");
    } else if is_archive_or_macro_ext(&file_name) {
        worst_hazard = escalate_hazard(
            worst_hazard,
            HazardLevel::Questionable(
                "Archive or macro-enabled document — verify contents before trusting.".to_string(),
            ),
        );
        notes.push("Archive/macro-capable type");
    }

    // 5. Suspicious script payload patterns inside text/script/HTML/SVG files
    if is_inspectable_text_or_script(&file_name, &header)
        && let Some(pattern) = detect_suspicious_script_patterns(&text_sample)
    {
        worst_hazard = escalate_hazard(
            worst_hazard,
            HazardLevel::Questionable(format!(
                "Contains suspicious script indicator ({pattern}); confirm carefully before opening."
            )),
        );
        notes.push("Suspicious script pattern");
    }

    // 6. Ensure Mark-of-the-Web (Zone.Identifier=3) on Windows for defense-in-depth
    ensure_mark_of_the_web(path, source_url);

    let summary = if notes.is_empty() {
        "No hazards found".to_string()
    } else {
        notes.join(" · ")
    };

    DownloadScanReport {
        hazard: worst_hazard,
        sha256_hex: Some(sha256_hex),
        file_size_bytes: Some(total_size),
        summary,
    }
}

fn escalate_hazard(current: HazardLevel, candidate: HazardLevel) -> HazardLevel {
    match (&current, &candidate) {
        (HazardLevel::Hazardous(_), _) => current,
        (_, HazardLevel::Hazardous(_)) => candidate,
        (HazardLevel::Questionable(_), _) => current,
        (_, HazardLevel::Questionable(_)) => candidate,
        _ => current,
    }
}

fn has_suspicious_double_extension(file_name: &str) -> bool {
    if !is_risky_download(file_name) {
        return false;
    }
    let Some((stem, _)) = file_name.rsplit_once('.') else {
        return false;
    };
    let Some((_, prev_ext)) = stem.rsplit_once('.') else {
        return false;
    };
    matches!(
        prev_ext.to_ascii_lowercase().as_str(),
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "rtf" | "jpg"
            | "jpeg" | "png" | "gif" | "webp" | "mp3" | "mp4" | "wav" | "zip"
    )
}

fn detect_extension_spoofing(file_name: &str, header: &[u8]) -> Option<String> {
    let ext = file_name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();

    let benign_non_exec = matches!(
        ext.as_str(),
        "pdf" | "txt" | "csv" | "json" | "md" | "jpg" | "jpeg" | "png" | "gif" | "webp"
            | "bmp" | "ico" | "mp3" | "mp4" | "wav" | "flac" | "mkv" | "webm" | "doc" | "xls"
            | "ppt" | "docx" | "xlsx" | "pptx"
    );
    if !benign_non_exec {
        return None;
    }

    if header.starts_with(b"MZ") {
        return Some(format!(
            "Disguised Windows executable (MZ header) masquerading as .{ext}."
        ));
    }
    if header.starts_with(b"\x7fELF") {
        return Some(format!(
            "Disguised ELF executable masquerading as .{ext}."
        ));
    }
    if header.starts_with(b"#!") {
        return Some(format!(
            "Disguised shell/script file (#!) masquerading as .{ext}."
        ));
    }
    None
}

fn is_archive_or_macro_ext(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    matches!(
        lower.rsplit_once('.').map(|(_, e)| e),
        Some("zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "cab" | "docm" | "xlsm" | "pptm")
    )
}

fn is_inspectable_text_or_script(file_name: &str, header: &[u8]) -> bool {
    let lower = file_name.to_ascii_lowercase();
    if matches!(
        lower.rsplit_once('.').map(|(_, e)| e),
        Some(
            "ps1" | "psm1" | "psd1" | "bat" | "cmd" | "vbs" | "vbe" | "js" | "jse" | "wsf"
                | "wsh" | "hta" | "html" | "htm" | "svg" | "reg" | "inf"
        )
    ) {
        return true;
    }
    let trimmed = header.iter().position(|b| !b.is_ascii_whitespace()).map_or(&[][..], |i| &header[i..]);
    trimmed.starts_with(b"<script") || trimmed.starts_with(b"<hta:")
}

fn detect_suspicious_script_patterns(sample: &[u8]) -> Option<&'static str> {
    let lower = String::from_utf8_lossy(sample).to_ascii_lowercase();
    const PATTERNS: [(&str, &str); 7] = [
        ("-encodedcommand", "PowerShell -EncodedCommand"),
        ("wscript.shell", "WScript.Shell"),
        ("shell.application", "Shell.Application"),
        ("activexobject", "ActiveXObject"),
        ("powershell -w hidden", "hidden PowerShell"),
        ("mshta ", "mshta execution"),
        ("eval(atob(", "obfuscated eval(atob)"),
    ];
    for (needle, label) in PATTERNS {
        if lower.contains(needle) {
            return Some(label);
        }
    }
    None
}

enum DefenderScan {
    Clean,
    ThreatFound,
    NotAvailable,
}

fn run_windows_defender_scan(path: &Path) -> DefenderScan {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let Some(mpcmd) = find_mpcmdrun() else {
            return DefenderScan::NotAvailable;
        };
        let output = std::process::Command::new(mpcmd)
            .arg("-Scan")
            .arg("-ScanType")
            .arg("3")
            .arg("-File")
            .arg(path)
            .arg("-DisableRemediation")
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        match output {
            Ok(out) => match out.status.code() {
                Some(0) => DefenderScan::Clean,
                Some(2) => DefenderScan::ThreatFound,
                _ => DefenderScan::NotAvailable,
            },
            Err(_) => DefenderScan::NotAvailable,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        DefenderScan::NotAvailable
    }
}

#[cfg(windows)]
fn find_mpcmdrun() -> Option<PathBuf> {
    let platform_root = Path::new(r"C:\ProgramData\Microsoft\Windows Defender\Platform");
    if let Ok(entries) = fs::read_dir(platform_root) {
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|entry| entry.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        dirs.reverse();
        for dir in dirs {
            let candidate = dir.join("MpCmdRun.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let fallback = PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe");
    fallback.is_file().then_some(fallback)
}

fn ensure_mark_of_the_web(path: &Path, source_url: &str) {
    #[cfg(windows)]
    {
        let mut ads_os = path.as_os_str().to_os_string();
        ads_os.push(":Zone.Identifier");
        let ads_path = PathBuf::from(ads_os);
        if !ads_path.exists() {
            let content = format!("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl={source_url}\r\n");
            let _ = fs::write(ads_path, content);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (path, source_url);
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn format_timestamp_ms(ms: u64) -> String {
    let total_secs = (ms / 1000) as i64;
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Converts days since 1970-01-01 to (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_disguised_executable_and_double_extension() {
        let tmp = std::env::temp_dir().join("oya_scan_test_fake.pdf");
        let _ = fs::write(&tmp, b"MZ\x90\x00\x03\x00\x00\x00disguised_pe");
        let report = scan_downloaded_file(&tmp, "https://example.com/report.pdf");
        let _ = fs::remove_file(&tmp);
        assert!(report.hazard.is_hazardous(), "{:?}", report.hazard);
        assert!(report.sha256_hex.is_some());

        assert!(has_suspicious_double_extension("invoice.pdf.exe"));
        assert!(!has_suspicious_double_extension("oya_setup.exe"));
    }

    #[test]
    fn detects_suspicious_script_patterns() {
        let tmp = std::env::temp_dir().join("oya_scan_test_script.ps1");
        let _ = fs::write(&tmp, b"powershell -EncodedCommand SGVsbG8=");
        let report = scan_downloaded_file(&tmp, "https://example.com/run.ps1");
        let _ = fs::remove_file(&tmp);
        assert!(report.hazard.requires_open_confirmation());
    }

    #[test]
    fn clean_text_file_passes_scan() {
        let tmp = std::env::temp_dir().join("oya_scan_test_clean.txt");
        let _ = fs::write(&tmp, b"Hello from Oya Browser!");
        let report = scan_downloaded_file(&tmp, "https://example.com/notes.txt");
        let _ = fs::remove_file(&tmp);
        assert_eq!(report.hazard, HazardLevel::Clean);
        assert_eq!(report.file_size_bytes, Some(23));
    }
}
