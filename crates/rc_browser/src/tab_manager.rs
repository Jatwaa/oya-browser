use crate::bookmarks::BookmarkStore;
use rc_cdp::{CdpAction, CdpRequest};
use rc_ipc::{
    BrowserToRenderer, DisplayList, RegionKind, RendererToBrowser, SubresourceKind,
    read_ipc_message, write_ipc_message,
};
use rc_log::{DiagnosticEvent, LogCategory, LogStore, Severity};
use rc_net::NetworkService;
use rc_sandbox::{SandboxedProcess, spawn_sandboxed_renderer, validate_and_extract_origin};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::process::{ChildStdin, ChildStdout};

const SETTINGS_FILE: &str = "settings.json";
pub const SETTINGS_URL: &str = "oya://settings";

pub fn is_settings_url(url: &str) -> bool {
    url == SETTINGS_URL || url == "rustchrome://settings" || url.starts_with("oya://settings/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeMode {
    #[default]
    Day,
    Night,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UiFontFamily {
    #[default]
    SystemProportional,
    MonospaceCode,
    ModernReadable,
}

impl UiFontFamily {
    pub fn all() -> &'static [UiFontFamily] {
        &[
            UiFontFamily::SystemProportional,
            UiFontFamily::MonospaceCode,
            UiFontFamily::ModernReadable,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            UiFontFamily::SystemProportional => "Segoe UI / System Proportional (Default)",
            UiFontFamily::MonospaceCode => "Consolas / Monospace Code",
            UiFontFamily::ModernReadable => "Modern High-Legibility Sans",
        }
    }
}

fn default_font_size() -> f32 {
    14.0
}

fn default_auto_lock() -> u32 {
    5
}

fn default_true() -> bool {
    true
}

fn default_zoom_pct() -> u32 {
    100
}

fn default_language() -> String {
    "en-US (English - United States)".to_string()
}

fn default_download_dir() -> String {
    "Downloads".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StartupBehavior {
    #[default]
    OpenNewTab,
    ContinueWhereLeftOff,
    OpenSpecificUrl,
}

impl StartupBehavior {
    pub fn all() -> &'static [StartupBehavior] {
        &[
            StartupBehavior::OpenNewTab,
            StartupBehavior::ContinueWhereLeftOff,
            StartupBehavior::OpenSpecificUrl,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            StartupBehavior::OpenNewTab => "Open the New Tab page (chosen Search Engine)",
            StartupBehavior::ContinueWhereLeftOff => "Continue where you left off",
            StartupBehavior::OpenSpecificUrl => "Open a specific page or set of pages",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchEngine {
    Google,
    DuckDuckGo,
    Bing,
    Brave,
    YouTube,
    Custom,
}

impl SearchEngine {
    pub fn all() -> &'static [SearchEngine] {
        &[
            SearchEngine::Google,
            SearchEngine::DuckDuckGo,
            SearchEngine::Bing,
            SearchEngine::Brave,
            SearchEngine::YouTube,
            SearchEngine::Custom,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            SearchEngine::Google => "Google (https://www.google.com)",
            SearchEngine::DuckDuckGo => "DuckDuckGo (https://duckduckgo.com)",
            SearchEngine::Bing => "Bing (https://www.bing.com)",
            SearchEngine::Brave => "Brave Search (https://search.brave.com)",
            SearchEngine::YouTube => "YouTube (https://www.youtube.com)",
            SearchEngine::Custom => "Custom Search Page",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EqualizerPreset {
    #[default]
    Flat,
    BassBoost,
    VocalClarity,
    Cinema4K,
    Electronic,
    Rock,
    TrebleCrisp,
    LoudnessNight,
    Custom,
}

impl EqualizerPreset {
    pub fn all() -> &'static [EqualizerPreset] {
        &[
            EqualizerPreset::Flat,
            EqualizerPreset::BassBoost,
            EqualizerPreset::VocalClarity,
            EqualizerPreset::Cinema4K,
            EqualizerPreset::Electronic,
            EqualizerPreset::Rock,
            EqualizerPreset::TrebleCrisp,
            EqualizerPreset::LoudnessNight,
            EqualizerPreset::Custom,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            EqualizerPreset::Flat => "Flat (Reference 0 dB)",
            EqualizerPreset::BassBoost => "Bass Boost (Deep Sub + Punch)",
            EqualizerPreset::VocalClarity => "Vocal & Dialogue Clarity",
            EqualizerPreset::Cinema4K => "4K Cinema & Soundstage",
            EqualizerPreset::Electronic => "Electronic / EDM",
            EqualizerPreset::Rock => "Rock & Live Instruments",
            EqualizerPreset::TrebleCrisp => "Crisp Highs / Air",
            EqualizerPreset::LoudnessNight => "Night Mode / Loudness Contour",
            EqualizerPreset::Custom => "Custom 10-Band Curve",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            EqualizerPreset::Flat => "Flat",
            EqualizerPreset::BassBoost => "Bass Boost",
            EqualizerPreset::VocalClarity => "Vocal",
            EqualizerPreset::Cinema4K => "4K Cinema",
            EqualizerPreset::Electronic => "EDM",
            EqualizerPreset::Rock => "Rock",
            EqualizerPreset::TrebleCrisp => "Crisp Highs",
            EqualizerPreset::LoudnessNight => "Night Mode",
            EqualizerPreset::Custom => "Custom",
        }
    }

    pub fn band_gains_db(&self) -> [f32; 10] {
        // 31Hz, 62Hz, 125Hz, 250Hz, 500Hz, 1kHz, 2kHz, 4kHz, 8kHz, 16kHz
        match self {
            EqualizerPreset::Flat | EqualizerPreset::Custom => [0.0; 10],
            EqualizerPreset::BassBoost => [7.0, 6.0, 4.5, 2.0, 0.0, 0.0, 0.5, 1.0, 1.5, 1.5],
            EqualizerPreset::VocalClarity => [-2.0, -1.5, 0.0, 2.0, 4.0, 5.0, 4.5, 2.5, 1.0, 0.0],
            EqualizerPreset::Cinema4K => [6.0, 5.0, 2.5, 0.0, -1.0, 1.5, 3.0, 4.0, 4.5, 5.0],
            EqualizerPreset::Electronic => [6.5, 5.5, 2.0, -1.5, -2.0, 0.5, 2.5, 4.5, 5.5, 6.0],
            EqualizerPreset::Rock => [5.0, 4.0, 2.5, -1.0, -1.5, 1.0, 3.5, 4.5, 4.5, 4.0],
            EqualizerPreset::TrebleCrisp => [0.0, 0.0, 0.0, 0.5, 1.0, 2.0, 4.0, 5.5, 6.5, 7.0],
            EqualizerPreset::LoudnessNight => [4.5, 3.5, 1.5, 0.0, 1.5, 2.5, 2.0, 3.0, 4.0, 4.5],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VideoUpscalerMode {
    Off,
    #[default]
    DynamicAuto,
    Crisp4KDetail,
    AnimeLineArt,
    CinemaHdr,
}

impl VideoUpscalerMode {
    pub fn all() -> &'static [VideoUpscalerMode] {
        &[
            VideoUpscalerMode::Off,
            VideoUpscalerMode::DynamicAuto,
            VideoUpscalerMode::Crisp4KDetail,
            VideoUpscalerMode::AnimeLineArt,
            VideoUpscalerMode::CinemaHdr,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            VideoUpscalerMode::Off => "Off (Native Unfiltered Video)",
            VideoUpscalerMode::DynamicAuto => {
                "Dynamic Auto Upscaler (Adapts to 480p/720p/1080p/4K Resolution)"
            }
            VideoUpscalerMode::Crisp4KDetail => "4K Ultra-Crisp Edge & Micro-Contrast Reconstruction",
            VideoUpscalerMode::AnimeLineArt => "Anime / Clean Line-Art Shader Upscale",
            VideoUpscalerMode::CinemaHdr => "Cinema HDR Vibrance & Deep Contrast Enhancer",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            VideoUpscalerMode::Off => "Off",
            VideoUpscalerMode::DynamicAuto => "Dynamic Auto (480p–4K)",
            VideoUpscalerMode::Crisp4KDetail => "4K Ultra-Crisp",
            VideoUpscalerMode::AnimeLineArt => "Anime / Line-Art",
            VideoUpscalerMode::CinemaHdr => "Cinema HDR",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            VideoUpscalerMode::Off => "off",
            VideoUpscalerMode::DynamicAuto => "auto",
            VideoUpscalerMode::Crisp4KDetail => "crisp4k",
            VideoUpscalerMode::AnimeLineArt => "anime",
            VideoUpscalerMode::CinemaHdr => "hdr",
        }
    }
}

fn default_upscaler_sharpness() -> f32 {
    55.0
}

fn default_upscaler_vibrance() -> f32 {
    25.0
}

fn default_eq_bands() -> [f32; 10] {
    [0.0; 10]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSettings {
    pub search_engine: SearchEngine,
    pub custom_home_url: String,
    pub custom_search_template: String,
    #[serde(default)]
    pub theme_mode: ThemeMode,
    #[serde(default)]
    pub font_family: UiFontFamily,
    #[serde(default = "default_font_size")]
    pub font_size_pt: f32,
    #[serde(default = "default_true")]
    pub show_bookmarks_bar: bool,
    #[serde(default = "default_true")]
    pub autofill_passwords_enabled: bool,
    #[serde(default = "default_true")]
    pub offer_to_save_passwords: bool,
    #[serde(default = "default_true")]
    pub allow_cross_device_passkeys: bool,
    #[serde(default = "default_true")]
    pub block_third_party_cookies: bool,
    #[serde(default = "default_true")]
    pub https_first_mode: bool,
    #[serde(default = "default_true")]
    pub do_not_track: bool,
    #[serde(default = "default_true")]
    pub memory_saver_enabled: bool,
    #[serde(default)]
    pub default_allow_tabs_in_background: bool,
    #[serde(default = "default_true")]
    pub show_home_button: bool,
    #[serde(default = "default_zoom_pct")]
    pub page_zoom_pct: u32,
    #[serde(default)]
    pub startup_behavior: StartupBehavior,
    #[serde(default)]
    pub startup_custom_url: String,
    #[serde(default = "default_language")]
    pub preferred_language: String,
    #[serde(default = "default_download_dir")]
    pub download_directory: String,
    #[serde(default = "default_true")]
    pub hardware_acceleration_enabled: bool,
    /// Blocks legacy code-injection points into Oya's process (applies at start-up).
    #[serde(default = "default_true")]
    pub block_code_injection: bool,
    /// Lets sites ask to show notifications (off: all requests are refused).
    #[serde(default)]
    pub allow_notifications: bool,
    /// Lock the password vault after this many idle minutes.
    #[serde(default = "default_auto_lock")]
    pub vault_auto_lock_minutes: u32,
    // 10-Band Graphic Equalizer + Dynamic Video Upscaler + 4K Smooth Playback
    #[serde(default)]
    pub eq_enabled: bool,
    #[serde(default)]
    pub eq_preset: EqualizerPreset,
    #[serde(default)]
    pub eq_preamp_db: f32,
    #[serde(default = "default_eq_bands")]
    pub eq_bands_db: [f32; 10],
    #[serde(default)]
    pub upscaler_mode: VideoUpscalerMode,
    #[serde(default = "default_upscaler_sharpness")]
    pub upscaler_sharpness: f32,
    #[serde(default = "default_upscaler_vibrance")]
    pub upscaler_vibrance: f32,
    #[serde(default = "default_true")]
    pub optimize_4k_playback: bool,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        Self {
            search_engine: SearchEngine::Google,
            custom_home_url: "https://www.google.com".to_string(),
            custom_search_template: "https://www.google.com/search?q={q}".to_string(),
            theme_mode: ThemeMode::Day,
            font_family: UiFontFamily::SystemProportional,
            font_size_pt: 14.0,
            show_bookmarks_bar: true,
            autofill_passwords_enabled: true,
            offer_to_save_passwords: true,
            allow_cross_device_passkeys: true,
            block_third_party_cookies: true,
            https_first_mode: true,
            do_not_track: true,
            memory_saver_enabled: true,
            default_allow_tabs_in_background: false,
            show_home_button: true,
            page_zoom_pct: 100,
            startup_behavior: StartupBehavior::OpenNewTab,
            startup_custom_url: "https://www.google.com".to_string(),
            preferred_language: default_language(),
            download_directory: default_download_dir(),
            hardware_acceleration_enabled: true,
            block_code_injection: true,
            allow_notifications: false,
            vault_auto_lock_minutes: default_auto_lock(),
            eq_enabled: false,
            eq_preset: EqualizerPreset::Flat,
            eq_preamp_db: 0.0,
            eq_bands_db: [0.0; 10],
            upscaler_mode: VideoUpscalerMode::DynamicAuto,
            upscaler_sharpness: 55.0,
            upscaler_vibrance: 25.0,
            optimize_4k_playback: true,
        }
    }
}

impl BrowserSettings {
    pub fn load() -> Self {
        if let Some(raw) = crate::integrity::load_verified(Path::new(SETTINGS_FILE))
            && let Ok(parsed) = serde_json::from_str::<BrowserSettings>(&raw)
        {
            return parsed;
        }
        Self::default()
    }

    /// Writes the settings with a tamper seal (see `integrity`).
    pub fn save(&self) {
        if let Ok(serialized) = serde_json::to_string_pretty(self) {
            crate::integrity::save_sealed(Path::new(SETTINGS_FILE), &serialized);
        }
    }

    /// BCP-47 language tag (e.g. `en-US`) taken from `preferred_language`, or `None` if it is not
    /// a plain tag. Only letters, digits and `-` are accepted, so it is safe to pass to WebView2.
    pub fn language_tag(&self) -> Option<String> {
        let tag = self.preferred_language.split_whitespace().next()?;
        let valid = !tag.is_empty()
            && tag.len() <= 35
            && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && tag.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        valid.then(|| tag.to_string())
    }

    pub fn blank_tab_url(&self) -> String {
        match self.search_engine {
            SearchEngine::Google => "https://www.google.com".to_string(),
            SearchEngine::DuckDuckGo => "https://duckduckgo.com".to_string(),
            SearchEngine::Bing => "https://www.bing.com".to_string(),
            SearchEngine::Brave => "https://search.brave.com".to_string(),
            SearchEngine::YouTube => "https://www.youtube.com".to_string(),
            SearchEngine::Custom => {
                let t = self.custom_home_url.trim();
                if t.is_empty() {
                    "https://www.google.com".to_string()
                } else if t.contains("://") {
                    t.to_string()
                } else {
                    format!("https://{t}")
                }
            }
        }
    }

    pub fn search_url(&self, query: &str) -> String {
        let encoded = encode_query(query.trim());
        match self.search_engine {
            SearchEngine::Google => format!("https://www.google.com/search?q={encoded}"),
            SearchEngine::DuckDuckGo => format!("https://duckduckgo.com/?q={encoded}"),
            SearchEngine::Bing => format!("https://www.bing.com/search?q={encoded}"),
            SearchEngine::Brave => format!("https://search.brave.com/search?q={encoded}"),
            SearchEngine::YouTube => {
                format!("https://www.youtube.com/results?search_query={encoded}")
            }
            SearchEngine::Custom => {
                let tpl = self.custom_search_template.trim();
                if tpl.contains("{q}") {
                    tpl.replace("{q}", &encoded)
                } else if !tpl.is_empty() {
                    format!("{tpl}{encoded}")
                } else {
                    format!("https://www.google.com/search?q={encoded}")
                }
            }
        }
    }
}

fn encode_query(q: &str) -> String {
    let mut out = String::new();
    for b in q.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct RendererProcess {
    pub pid: u32,
    pub sandboxed: bool,
    process: SandboxedProcess,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl RendererProcess {
    pub fn spawn() -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut process =
            spawn_sandboxed_renderer(&exe, &["--type=renderer"]).map_err(|e| e.to_string())?;
        let stdin_raw = process
            .child
            .stdin
            .take()
            .ok_or_else(|| "Renderer stdin missing".to_string())?;
        let stdout_raw = process
            .child
            .stdout
            .take()
            .ok_or_else(|| "Renderer stdout missing".to_string())?;

        let stdin = BufWriter::new(stdin_raw);
        let mut stdout = BufReader::new(stdout_raw);

        let ready: RendererToBrowser =
            read_ipc_message(&mut stdout).map_err(|e| format!("Renderer handshake failed: {e}"))?;
        let (pid, child_sandboxed) = match ready {
            RendererToBrowser::Ready { pid, sandboxed } => (pid, sandboxed),
            other => return Err(format!("Unexpected renderer handshake: {other:?}")),
        };

        Ok(Self {
            pid,
            // Only report "sandboxed" when BOTH the Job Object was attached by the host AND the
            // child confirmed its own process mitigation policies were applied.
            sandboxed: process.sandboxed && child_sandboxed,
            process,
            stdin,
            stdout,
        })
    }

    pub fn send_and_recv(
        &mut self,
        msg: &BrowserToRenderer,
    ) -> Result<RendererToBrowser, String> {
        write_ipc_message(&mut self.stdin, msg).map_err(|e| e.to_string())?;
        read_ipc_message(&mut self.stdout).map_err(|e| e.to_string())
    }

    pub fn send_only(&mut self, msg: &BrowserToRenderer) -> Result<(), String> {
        write_ipc_message(&mut self.stdin, msg).map_err(|e| e.to_string())
    }
}

impl Drop for RendererProcess {
    fn drop(&mut self) {
        let _ = self.send_only(&BrowserToRenderer::Shutdown);
        let _ = self.process.child.kill();
        let _ = self.process.child.wait();
    }
}

#[derive(Clone)]
pub struct TabState {
    pub id: u64,
    pub allow_in_background: bool,
    pub current_url: String,
    pub current_origin: String,
    pub active_renderer_pid: u32,
    pub active_sandboxed: bool,
    pub title: String,
    pub display_list: DisplayList,
    pub console_logs: Vec<String>,
    pub script_errors: Vec<String>,
    pub dom_node_count: usize,
    pub last_error: Option<String>,
    pub back_stack: Vec<String>,
    pub forward_stack: Vec<String>,
}

impl Default for TabState {
    fn default() -> Self {
        Self {
            id: 1,
            allow_in_background: false,
            current_url: "about:blank".to_string(),
            current_origin: "null".to_string(),
            active_renderer_pid: 0,
            active_sandboxed: false,
            title: "New Tab".to_string(),
            display_list: DisplayList::default(),
            console_logs: Vec::new(),
            script_errors: Vec::new(),
            dom_node_count: 0,
            last_error: None,
            back_stack: Vec::new(),
            forward_stack: Vec::new(),
        }
    }
}

pub enum ClickOutcome {
    None,
    Navigate(String),
    Updated,
}

pub struct BrowserController {
    net: NetworkService,
    renderers: HashMap<String, RendererProcess>,
    next_tab_id: u64,
    pub tabs: Vec<TabState>,
    pub active_tab: usize,
    pub log_store: LogStore,
    pub settings: BrowserSettings,
    pub bookmarks: BookmarkStore,
    pub live_webview_mode: bool,
    pub viewport_width: f32,
    pub viewport_height: f32,
}

impl Default for BrowserController {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserController {
    pub fn new() -> Self {
        let settings = BrowserSettings::load();
        let initial_tab = TabState {
            id: 1,
            allow_in_background: settings.default_allow_tabs_in_background,
            ..TabState::default()
        };
        Self {
            net: NetworkService::new(),
            renderers: HashMap::new(),
            next_tab_id: 2,
            tabs: vec![initial_tab],
            active_tab: 0,
            log_store: LogStore::default(),
            settings,
            bookmarks: BookmarkStore::load(),
            live_webview_mode: false,
            viewport_width: 960.0,
            viewport_height: 640.0,
        }
    }

    pub fn new_gui() -> Self {
        let mut ctrl = Self::new();
        ctrl.live_webview_mode = true;
        ctrl
    }

    pub fn tab(&self) -> &TabState {
        &self.tabs[self.active_tab]
    }

    pub fn tab_mut(&mut self) -> &mut TabState {
        &mut self.tabs[self.active_tab]
    }

    pub fn new_tab(&mut self, url: &str) {
        let id = self.next_tab_id;
        self.next_tab_id += 1;
        let tab = TabState {
            id,
            allow_in_background: self.settings.default_allow_tabs_in_background,
            ..TabState::default()
        };
        self.tabs.push(tab);
        self.active_tab = self.tabs.len() - 1;
        let target = if url.is_empty() || url == "rustchrome://newtab" || url == "oya://newtab" {
            self.settings.blank_tab_url()
        } else {
            url.to_string()
        };
        self.navigate_or_record_error(&target, false);
    }

    pub fn duplicate_tab(&mut self, index: usize) {
        if index >= self.tabs.len() {
            return;
        }
        let src_url = self.tabs[index].current_url.clone();
        let allow_bg = self.tabs[index].allow_in_background;
        self.new_tab(&src_url);
        self.tab_mut().allow_in_background = allow_bg;
    }

    pub fn close_tab(&mut self, index: usize) -> Option<u64> {
        if self.tabs.len() <= 1 || index >= self.tabs.len() {
            return None;
        }
        let removed = self.tabs.remove(index);
        if self.active_tab >= self.tabs.len() {
            self.active_tab = self.tabs.len() - 1;
        }
        self.discard_idle_renderers();
        Some(removed.id)
    }

    /// Low-resource optimization: terminates renderer processes not used by any active tab.
    pub fn discard_idle_renderers(&mut self) -> usize {
        let active_origins: HashSet<String> = self
            .tabs
            .iter()
            .map(|t| t.current_origin.clone())
            .collect();
        let before = self.renderers.len();
        self.renderers.retain(|k, _| active_origins.contains(k));
        before.saturating_sub(self.renderers.len())
    }

    pub fn navigate(&mut self, raw_url: &str, push_history: bool) -> Result<(), String> {
        let cur_for_norm = self.tab().current_url.clone();
        let normalized = normalize_url(
            raw_url,
            &cur_for_norm,
            &self.settings,
            self.live_webview_mode,
        );

        // In GUI mode, live HTTP(S) pages (including YouTube video playback & user's search engine)
        // are rendered directly by the embedded child WebView viewport without blocking the UI thread.
        if self.live_webview_mode
            && (normalized.starts_with("https://") || normalized.starts_with("http://"))
        {
            self.bookmarks.record_visit(&normalized);
            let origin_key = validate_and_extract_origin(&normalized)
                .map(|o| o.to_string())
                .unwrap_or_else(|_| "null".to_string());
            if push_history {
                let cur = self.tab().current_url.clone();
                if cur != "about:blank" && cur != normalized {
                    self.tab_mut().back_stack.push(cur);
                    self.tab_mut().forward_stack.clear();
                }
            }
            self.log_store.record(DiagnosticEvent::new(
                Severity::Info,
                LogCategory::Lifecycle,
                &origin_key,
                0,
                "Navigating WebView2 tab",
            ));
            let tab = self.tab_mut();
            tab.current_url = normalized.clone();
            tab.current_origin = origin_key;
            // Web pages are rendered by Microsoft Edge WebView2 in its own Chromium-sandboxed
            // processes, which this browser does not spawn or track. Report no Oya renderer.
            tab.active_renderer_pid = 0;
            tab.active_sandboxed = false;
            tab.last_error = None;
            if tab.title == "New Tab" || tab.title.is_empty() {
                tab.title = normalized;
            }
            return Ok(());
        }

        // Settings is drawn natively by the GUI; it needs no renderer process or network fetch.
        if is_settings_url(&normalized) {
            if push_history {
                let cur = self.tab().current_url.clone();
                if cur != "about:blank" && cur != normalized {
                    self.tab_mut().back_stack.push(cur);
                    self.tab_mut().forward_stack.clear();
                }
            }
            let tab = self.tab_mut();
            tab.current_url = SETTINGS_URL.to_string();
            tab.current_origin = SETTINGS_URL.to_string();
            tab.title = "Settings".to_string();
            tab.active_renderer_pid = 0;
            tab.active_sandboxed = false;
            tab.last_error = None;
            tab.display_list = DisplayList::default();
            return Ok(());
        }

        // Special internal page: oya://logs or rustchrome://logs rendered from live LogStore
        let (final_url, origin_key, body, csp_header, net_diags) =
            if normalized == "rustchrome://logs" || normalized == "oya://logs" {
                (
                    "oya://logs".to_string(),
                    "oya://logs".to_string(),
                    self.log_store.render_html_report(),
                    Some("script-src 'self' 'unsafe-inline'".to_string()),
                    Vec::new(),
                )
            } else {
                let doc = self.net.fetch_document(&normalized).map_err(|e| {
                    let msg = e.to_string();
                    self.log_store.record(DiagnosticEvent::new(
                        Severity::Error,
                        LogCategory::Net,
                        &normalized,
                        0,
                        &msg,
                    ));
                    msg
                })?;
                (
                    doc.final_url,
                    doc.origin.to_string(),
                    doc.body,
                    doc.csp_header,
                    doc.diagnostics,
                )
            };

        self.log_store.extend(net_diags);

        if push_history {
            let cur = self.tab().current_url.clone();
            if cur != "about:blank" && cur != final_url {
                self.tab_mut().back_stack.push(cur);
                self.tab_mut().forward_stack.clear();
            }
        }

        if !self.renderers.contains_key(&origin_key) {
            let proc = RendererProcess::spawn()?;
            self.log_store.record(DiagnosticEvent::new(
                Severity::Security,
                LogCategory::Security,
                &origin_key,
                proc.pid,
                format!(
                    "Spawned isolated renderer (pid={}, sandboxed={})",
                    proc.pid, proc.sandboxed
                ),
            ));
            self.renderers.insert(origin_key.clone(), proc);
        }

        let mut reply = {
            let renderer = self.renderers.get_mut(&origin_key).unwrap();
            match renderer.send_and_recv(&BrowserToRenderer::LoadDocument {
                url: final_url.clone(),
                origin: origin_key.clone(),
                html: body,
                csp: csp_header,
                viewport_width: self.viewport_width,
                viewport_height: self.viewport_height,
            }) {
                Ok(r) => r,
                Err(e) => {
                    self.renderers.remove(&origin_key);
                    self.log_store.record(DiagnosticEvent::new(
                        Severity::Error,
                        LogCategory::Ipc,
                        &origin_key,
                        0,
                        format!("Renderer IPC failed during LoadDocument: {e}"),
                    ));
                    return Err(e);
                }
            }
        };

        // Service any subresource fetch requests from the sandboxed renderer
        loop {
            match reply {
                RendererToBrowser::FetchSubresource { url, kind } => {
                    let is_bin = matches!(kind, SubresourceKind::Image);
                    let resp_msg = match self.net.fetch_subresource(&url, &origin_key, is_bin) {
                        Ok((body_utf8, bytes)) => BrowserToRenderer::SubresourceResponse {
                            url,
                            kind,
                            ok: true,
                            body_utf8,
                            bytes,
                            error: None,
                        },
                        Err(e) => {
                            let err_str = e.to_string();
                            self.log_store.record(DiagnosticEvent::new(
                                Severity::Warn,
                                LogCategory::Net,
                                &origin_key,
                                0,
                                format!("Subresource error ({url}): {err_str}"),
                            ));
                            BrowserToRenderer::SubresourceResponse {
                                url,
                                kind,
                                ok: false,
                                body_utf8: None,
                                bytes: Vec::new(),
                                error: Some(err_str),
                            }
                        }
                    };
                    let renderer = self.renderers.get_mut(&origin_key).unwrap();
                    reply = match renderer.send_and_recv(&resp_msg) {
                        Ok(r) => r,
                        Err(e) => {
                            self.renderers.remove(&origin_key);
                            self.log_store.record(DiagnosticEvent::new(
                                Severity::Error,
                                LogCategory::Ipc,
                                &origin_key,
                                0,
                                format!("Renderer IPC failed after SubresourceResponse: {e}"),
                            ));
                            return Err(e);
                        }
                    };
                }
                other => {
                    reply = other;
                    break;
                }
            }
        }

        let (pid, sandboxed) = {
            let r = &self.renderers[&origin_key];
            (r.pid, r.sandboxed)
        };

        let tab = self.tab_mut();
        tab.active_renderer_pid = pid;
        tab.active_sandboxed = sandboxed;
        tab.current_origin = origin_key;
        tab.last_error = None;

        match reply {
            RendererToBrowser::FrameRendered {
                title,
                url,
                display_list,
                console_logs,
                script_errors,
                diagnostics,
                dom_node_count,
            } => {
                tab.title = title;
                tab.current_url = url;
                tab.display_list = display_list;
                tab.console_logs = console_logs;
                tab.script_errors = script_errors;
                tab.dom_node_count = dom_node_count;
                self.log_store.extend(diagnostics);
                Ok(())
            }
            RendererToBrowser::Error { message } => Err(message),
            other => Err(format!("Unexpected renderer reply: {other:?}")),
        }
    }

    pub fn navigate_or_record_error(&mut self, raw_url: &str, push_history: bool) {
        if let Err(err) = self.navigate(raw_url, push_history) {
            let tab = self.tab_mut();
            tab.last_error = Some(err.clone());
            tab.script_errors.push(format!("[Browser] {err}"));
        }
    }

    pub fn go_back(&mut self) {
        let cur = self.tab().current_url.clone();
        if let Some(prev) = self.tab_mut().back_stack.pop() {
            self.tab_mut().forward_stack.push(cur);
            self.navigate_or_record_error(&prev, false);
        }
    }

    pub fn go_forward(&mut self) {
        let cur = self.tab().current_url.clone();
        if let Some(next) = self.tab_mut().forward_stack.pop() {
            self.tab_mut().back_stack.push(cur);
            self.navigate_or_record_error(&next, false);
        }
    }

    pub fn reload(&mut self) {
        let url = self.tab().current_url.clone();
        self.navigate_or_record_error(&url, false);
    }

    pub fn resize(&mut self, width: f32, height: f32) {
        if (self.viewport_width - width).abs() < 2.0 && (self.viewport_height - height).abs() < 2.0
        {
            return;
        }
        self.viewport_width = width;
        self.viewport_height = height;
        let origin = self.tab().current_origin.clone();
        if let Some(renderer) = self.renderers.get_mut(&origin)
            && let Ok(RendererToBrowser::FrameRendered { display_list, .. }) =
                renderer.send_and_recv(&BrowserToRenderer::Resize {
                    viewport_width: width,
                    viewport_height: height,
                })
        {
            self.tab_mut().display_list = display_list;
        }
    }

    pub fn click_at(&mut self, x: f32, y: f32) -> ClickOutcome {
        let regions = self.tab().display_list.hit_regions.clone();
        let cur_url = self.tab().current_url.clone();
        let origin = self.tab().current_origin.clone();

        for region in regions {
            if x >= region.x
                && x <= region.x + region.w
                && y >= region.y
                && y <= region.y + region.h
            {
                match region.kind {
                    RegionKind::Link { href } => {
                        return ClickOutcome::Navigate(resolve_href(&cur_url, &href));
                    }
                    RegionKind::Button { node_id } => {
                        if let Some(renderer) = self.renderers.get_mut(&origin)
                            && let Ok(RendererToBrowser::FrameRendered {
                                display_list,
                                console_logs,
                                script_errors,
                                diagnostics,
                                dom_node_count,
                                ..
                            }) = renderer
                                .send_and_recv(&BrowserToRenderer::TriggerButton { node_id })
                        {
                            let tab = self.tab_mut();
                            tab.display_list = display_list;
                            tab.console_logs.extend(console_logs);
                            tab.script_errors.extend(script_errors);
                            tab.dom_node_count = dom_node_count;
                            self.log_store.extend(diagnostics);
                            return ClickOutcome::Updated;
                        }
                    }
                    RegionKind::Input { .. } => return ClickOutcome::None,
                }
            }
        }
        ClickOutcome::None
    }

    pub fn is_hovering_interactive(&self, x: f32, y: f32) -> bool {
        self.tab().display_list.hit_regions.iter().any(|r| {
            x >= r.x && x <= r.x + r.w && y >= r.y && y <= r.y + r.h
        })
    }

    pub fn eval_js(&mut self, source: &str) -> Result<String, String> {
        let origin = self.tab().current_origin.clone();
        let reply = {
            let renderer = self
                .renderers
                .get_mut(&origin)
                .ok_or_else(|| "No active renderer".to_string())?;
            renderer.send_and_recv(&BrowserToRenderer::ExecuteScript {
                source: source.to_string(),
            })?
        };
        match reply {
            RendererToBrowser::ScriptResult {
                value,
                error,
                console_logs,
                diagnostics,
            } => {
                self.tab_mut().console_logs.extend(console_logs);
                self.log_store.extend(diagnostics);
                if let Some(err) = error {
                    self.tab_mut().script_errors.push(err.clone());
                    Err(err)
                } else {
                    if let Some(renderer) = self.renderers.get_mut(&origin)
                        && let Ok(RendererToBrowser::FrameRendered {
                            display_list,
                            title,
                            dom_node_count,
                            ..
                        }) = renderer.send_and_recv(&BrowserToRenderer::Resize {
                            viewport_width: self.viewport_width,
                            viewport_height: self.viewport_height,
                        })
                    {
                        let tab = self.tab_mut();
                        tab.display_list = display_list;
                        tab.title = title;
                        tab.dom_node_count = dom_node_count;
                    }
                    Ok(value)
                }
            }
            _ => Err("Unexpected reply from renderer".to_string()),
        }
    }

    pub fn dump_dom(&mut self) -> Result<(String, usize), String> {
        let origin = self.tab().current_origin.clone();
        let renderer = self
            .renderers
            .get_mut(&origin)
            .ok_or_else(|| "No active renderer".to_string())?;
        match renderer.send_and_recv(&BrowserToRenderer::DumpDom)? {
            RendererToBrowser::DomDump { html, node_count } => Ok((html, node_count)),
            _ => Err("Unexpected reply from renderer".to_string()),
        }
    }

    pub fn handle_cdp_request(&mut self, req: CdpRequest) {
        let result = match req.action {
            CdpAction::GetTargetInfo => {
                let t = self.tab();
                Ok(json!({
                    "url": t.current_url,
                    "title": t.title,
                    "origin": t.current_origin,
                    "rendererPid": t.active_renderer_pid,
                    "sandboxed": t.active_sandboxed,
                }))
            }
            CdpAction::Navigate { url } => self
                .navigate(&url, true)
                .map(|()| json!({ "frameId": "main", "url": self.tab().current_url })),
            CdpAction::Evaluate { expression } => self.eval_js(&expression).map(|val| {
                json!({
                    "result": { "type": "string", "value": val }
                })
            }),
            CdpAction::GetDom => self.dump_dom().map(|(html, node_count)| {
                json!({
                    "root": {
                        "nodeCount": node_count,
                        "outerHTML": html
                    }
                })
            }),
        };
        let _ = req.reply.send(result);
    }

    pub fn active_renderers_info(&self) -> Vec<(String, u32, bool)> {
        self.renderers
            .iter()
            .map(|(origin, proc)| (origin.clone(), proc.pid, proc.sandboxed))
            .collect()
    }
}

fn normalize_url(
    raw: &str,
    current_url: &str,
    settings: &BrowserSettings,
    live_webview_mode: bool,
) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || (live_webview_mode && (trimmed == "rustchrome://newtab" || trimmed == "oya://newtab"))
    {
        return if live_webview_mode {
            settings.blank_tab_url()
        } else {
            "rustchrome://newtab".to_string()
        };
    }
    if trimmed == "oya://newtab" {
        return "rustchrome://newtab".to_string();
    }
    if trimmed.contains("://")
        || trimmed.starts_with("about:")
        || trimmed.starts_with("data:")
        || trimmed.starts_with("javascript:")
    {
        return trimmed.to_string();
    }
    if trimmed.starts_with("watch?v=") {
        return format!("https://www.youtube.com/{trimmed}");
    }
    if (trimmed.starts_with('/') || trimmed.starts_with('?'))
        && (current_url.starts_with("https://") || current_url.starts_with("http://"))
        && let Ok(base) = url::Url::parse(current_url)
        && let Ok(joined) = base.join(trimmed)
    {
        return joined.to_string();
    }
    if trimmed.contains('.') && !trimmed.contains(' ') {
        format!("https://{trimmed}")
    } else {
        // Omnibox search query routed to the user's chosen search engine in Options
        settings.search_url(trimmed)
    }
}

fn resolve_href(base: &str, href: &str) -> String {
    if href.contains("://") || href.starts_with("about:") || href.starts_with("data:") {
        return href.to_string();
    }
    if let Ok(base_url) = url::Url::parse(base)
        && let Ok(joined) = base_url.join(href)
    {
        return joined.to_string();
    }
    href.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_tab_and_search_respect_user_options() {
        let mut settings = BrowserSettings::default();
        assert_eq!(settings.blank_tab_url(), "https://www.google.com");
        assert_eq!(
            normalize_url("rustchrome://newtab", "about:blank", &settings, true),
            "https://www.google.com"
        );
        assert_eq!(
            normalize_url("funny cat videos", "https://www.google.com", &settings, true),
            "https://www.google.com/search?q=funny+cat+videos"
        );

        settings.search_engine = SearchEngine::DuckDuckGo;
        assert_eq!(settings.blank_tab_url(), "https://duckduckgo.com");
        assert_eq!(
            normalize_url("weather today", "https://duckduckgo.com", &settings, true),
            "https://duckduckgo.com/?q=weather+today"
        );
    }
}
