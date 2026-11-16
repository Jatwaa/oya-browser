//! Security features of the browser window: user-approval gate, outside-change detection,
//! remote-debugging consent, password vault flows (run off the UI thread), download and
//! permission controls, and the related settings sections.
//!
//! This is a child module of `gui`, so it works directly with `RustChromeApp`'s fields.

use super::*;
use rc_vault::{
    DEVICE_ENTROPY, DerivedKeys, DeviceProtector, HelloOutcome, NewPinKeys, VaultError,
    pin_strength, windows_hello_prompt,
};
use std::sync::Mutex;
use std::time::SystemTime;
use zeroize::Zeroizing;

/// Binds the password vault to this Windows account and PC (DPAPI).
pub(super) struct DpapiProtector;

impl DeviceProtector for DpapiProtector {
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        rc_sandbox::dpapi_protect(data, DEVICE_ENTROPY)
    }
    fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        rc_sandbox::dpapi_unprotect(data, DEVICE_ENTROPY)
    }
}

/// What a PIN check or Windows Hello prompt running on a worker thread is for.
pub(super) enum Purpose {
    AutoLogin { origin: String, tab_id: u64 },
    SaveOffer,
    Approval,
    ChangePin { new_pin: Zeroizing<String> },
    CrossDeviceVerify { rp_id: String },
}

pub(super) enum TaskResult {
    Unlock {
        purpose: Purpose,
        result: Result<DerivedKeys, VaultError>,
    },
    NewPin {
        then_save_offer: bool,
        result: Result<NewPinKeys, VaultError>,
    },
    Hello {
        purpose: Purpose,
        outcome: HelloOutcome,
    },
    CrossDevicePasskey {
        purpose: Purpose,
        outcome: rc_sandbox::CrossDevicePasskeyOutcome,
    },
}

/// Changes that must be confirmed by the user (Windows Hello or vault PIN) before they happen.
pub(super) enum ApprovalAction {
    ApplySettings(Box<BrowserSettings>),
    AdoptOutsideSettings(String),
    AdoptOutsideBookmarks(String),
    ClearBrowsingData,
    ResetSettings,
    DeletePassword { origin: String, username: String },
    EnableRemoteDebugging(u16),
    UsePrivateProfile,
}

pub(super) struct PendingApproval {
    pub action: ApprovalAction,
    pub summary: String,
    pub pin: String,
    pub status: String,
    pub hello_unavailable: bool,
}

pub(super) struct BlockedDownload {
    pub tab_id: u64,
    pub url: String,
    pub file_name: String,
}

#[derive(Clone)]
pub(super) struct PermEntry {
    pub kind: i32,
    pub origin: String,
    pub state: i32,
}

/// Unsaved edits of protected text settings (they need approval when saved).
#[derive(Default)]
pub(super) struct StagedText {
    pub home: Option<String>,
    pub template: Option<String>,
    pub startup: Option<String>,
    pub download: Option<String>,
}

pub(super) type PermissionSink = Arc<Mutex<Option<Result<Vec<PermEntry>, String>>>>;

/// File types that can run code when opened.
const RISKY_EXTENSIONS: [&str; 38] = [
    "exe", "msi", "msix", "msixbundle", "appx", "appxbundle", "bat", "cmd", "com", "scr", "pif",
    "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "reg",
    "dll", "cpl", "jar", "iso", "img", "vhd", "vhdx", "application", "appref-ms", "msc", "chm",
    "xll", "scf", "inf",
];

pub(super) fn is_risky_download(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower
        .rsplit_once('.')
        .is_some_and(|(_, ext)| RISKY_EXTENSIONS.contains(&ext))
}

/// Human-readable list of protected settings that differ between `old` and `new`. Turning a
/// protection *on* is never listed; turning it off, or changing where searches, start-up pages
/// and downloads go, is.
pub(super) fn protected_changes(old: &BrowserSettings, new: &BrowserSettings) -> Vec<String> {
    let mut c = Vec::new();
    if old.search_engine != new.search_engine {
        c.push(format!(
            "search engine: {} → {}",
            old.search_engine.label(),
            new.search_engine.label()
        ));
    }
    if old.custom_home_url != new.custom_home_url {
        c.push(format!("custom home page → {}", new.custom_home_url));
    }
    if old.custom_search_template != new.custom_search_template {
        c.push(format!("custom search address → {}", new.custom_search_template));
    }
    if old.startup_behavior != new.startup_behavior {
        c.push(format!("on startup → {}", new.startup_behavior.label()));
    }
    if old.startup_custom_url != new.startup_custom_url {
        c.push(format!("startup page → {}", new.startup_custom_url));
    }
    if old.download_directory != new.download_directory {
        c.push(format!("download folder → {}", new.download_directory));
    }
    if old.block_third_party_cookies && !new.block_third_party_cookies {
        c.push("turn off tracker blocking".to_string());
    }
    if old.https_first_mode && !new.https_first_mode {
        c.push("allow insecure http:// connections".to_string());
    }
    if old.do_not_track && !new.do_not_track {
        c.push("stop sending Global Privacy Control".to_string());
    }
    if old.block_code_injection && !new.block_code_injection {
        c.push("allow code injection into Oya".to_string());
    }
    if !old.allow_notifications && new.allow_notifications {
        c.push("let sites ask to show notifications".to_string());
    }
    if new.vault_auto_lock_minutes > old.vault_auto_lock_minutes {
        c.push(format!(
            "keep the password vault unlocked for {} minutes",
            new.vault_auto_lock_minutes
        ));
    }
    if old.offer_to_save_passwords != new.offer_to_save_passwords
        || old.autofill_passwords_enabled != new.autofill_passwords_enabled
    {
        // Not protected: listed only so the summary is complete when other changes need approval.
    }
    c
}

fn permission_kind_label(kind: i32) -> &'static str {
    use webview2_com::Microsoft::Web::WebView2::Win32 as w;
    match kind {
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_CAMERA.0 => "Camera",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_MICROPHONE.0 => "Microphone",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_GEOLOCATION.0 => "Location",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_NOTIFICATIONS.0 => "Notifications",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_CLIPBOARD_READ.0 => "Clipboard",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_OTHER_SENSORS.0 => "Motion sensors",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_MULTIPLE_AUTOMATIC_DOWNLOADS.0 => {
            "Automatic downloads"
        }
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_FILE_READ_WRITE.0 => "Files",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_AUTOPLAY.0 => "Autoplay",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_LOCAL_FONTS.0 => "Fonts",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_WINDOW_MANAGEMENT.0 => "Window placement",
        k if k == w::COREWEBVIEW2_PERMISSION_KIND_MIDI_SYSTEM_EXCLUSIVE_MESSAGES.0 => "MIDI devices",
        _ => "Other",
    }
}

/// Asks WebView2 for every site permission that is not at its default.
fn query_permissions(webview: &WebView, sink: PermissionSink, ctx: egui::Context) -> Result<(), String> {
    use webview2_com::GetNonDefaultPermissionSettingsCompletedHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_PERMISSION_KIND, COREWEBVIEW2_PERMISSION_STATE, ICoreWebView2_13,
        ICoreWebView2Profile4,
    };
    use windows_core::{Interface, PWSTR};
    let core = webview.webview();
    let handler = GetNonDefaultPermissionSettingsCompletedHandler::create(Box::new(
        move |hr, collection| {
            let mut out = Vec::new();
            let result: Result<Vec<PermEntry>, String> = (|| {
                hr.map_err(|e| e.to_string())?;
                if let Some(coll) = collection {
                    let mut n = 0u32;
                    // SAFETY: COM accessors on a collection handed to us by WebView2.
                    unsafe {
                        coll.Count(&mut n).map_err(|e| e.to_string())?;
                        for i in 0..n {
                            let item = coll.GetValueAtIndex(i).map_err(|e| e.to_string())?;
                            let mut kind = COREWEBVIEW2_PERMISSION_KIND::default();
                            let mut state = COREWEBVIEW2_PERMISSION_STATE::default();
                            let mut origin = PWSTR::null();
                            item.PermissionKind(&mut kind).map_err(|e| e.to_string())?;
                            item.PermissionState(&mut state).map_err(|e| e.to_string())?;
                            item.PermissionOrigin(&mut origin).map_err(|e| e.to_string())?;
                            out.push(PermEntry {
                                kind: kind.0,
                                origin: webview2_com::CoTaskMemPWSTR::from(origin).to_string(),
                                state: state.0,
                            });
                        }
                    }
                }
                Ok(std::mem::take(&mut out))
            })();
            if let Ok(mut slot) = sink.lock() {
                *slot = Some(result);
            }
            ctx.request_repaint();
            Ok(())
        },
    ));
    // SAFETY: COM calls on the UI thread that owns this WebView2 instance.
    unsafe {
        let wv13: ICoreWebView2_13 = core.cast().map_err(|e| e.to_string())?;
        let profile = wv13.Profile().map_err(|e| e.to_string())?;
        let p4: ICoreWebView2Profile4 = profile.cast().map_err(|e| e.to_string())?;
        p4.GetNonDefaultPermissionSettings(&handler)
            .map_err(|e| e.to_string())
    }
}

/// Puts one site permission back to "ask".
fn reset_permission(webview: &WebView, entry: &PermEntry) -> Result<(), String> {
    use webview2_com::SetPermissionStateCompletedHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_PERMISSION_KIND, COREWEBVIEW2_PERMISSION_STATE_DEFAULT, ICoreWebView2_13,
        ICoreWebView2Profile4,
    };
    use windows_core::{HSTRING, Interface};
    let core = webview.webview();
    let origin = HSTRING::from(entry.origin.as_str());
    let handler = SetPermissionStateCompletedHandler::create(Box::new(|_hr| Ok(())));
    // SAFETY: COM calls on the UI thread that owns this WebView2 instance.
    unsafe {
        let wv13: ICoreWebView2_13 = core.cast().map_err(|e| e.to_string())?;
        let profile = wv13.Profile().map_err(|e| e.to_string())?;
        let p4: ICoreWebView2Profile4 = profile.cast().map_err(|e| e.to_string())?;
        p4.SetPermissionState(
            COREWEBVIEW2_PERMISSION_KIND(entry.kind),
            &origin,
            COREWEBVIEW2_PERMISSION_STATE_DEFAULT,
            &handler,
        )
        .map_err(|e| e.to_string())
    }
}

/// Keeps Microsoft SmartScreen (malware and phishing reputation checks) switched on.
pub(super) fn enforce_smartscreen(webview: &WebView) -> Result<(), String> {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings8;
    use windows_core::Interface;
    let core = webview.webview();
    // SAFETY: COM calls on the UI thread that owns this WebView2 instance.
    unsafe {
        let settings = core.Settings().map_err(|e| e.to_string())?;
        let s8: ICoreWebView2Settings8 = settings.cast().map_err(|e| e.to_string())?;
        s8.SetIsReputationCheckingRequired(true)
            .map_err(|e| e.to_string())
    }
}

/// Text field for a protected setting: edits stay local until "Save", which then goes through
/// the approval gate. Returns the value to save.
fn staged_field(
    ui: &mut egui::Ui,
    slot: &mut Option<String>,
    current: &str,
    hint: &str,
    width: f32,
) -> Option<String> {
    let mut text = slot.clone().unwrap_or_else(|| current.to_string());
    let resp = ui.add(
        egui::TextEdit::singleline(&mut text)
            .hint_text(hint)
            .desired_width(width.min(ui.available_width())),
    );
    if resp.changed() {
        *slot = Some(text);
    }
    let mut commit = None;
    if let Some(v) = slot.clone() {
        if v == current {
            *slot = None;
        } else {
            if ui.button("Save").clicked() {
                commit = Some(v.trim().to_string());
                *slot = None;
            }
            if ui.small_button("Cancel").clicked() {
                *slot = None;
            }
        }
    }
    commit
}

fn danger_button(text: &str, p: &Palette) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_string()).color(egui::Color32::WHITE))
        .fill(p.danger)
        .stroke(egui::Stroke::NONE)
}

fn primary_button(text: &str, p: &Palette) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_string()).color(p.on_accent))
        .fill(p.accent)
        .stroke(egui::Stroke::NONE)
}

fn warning_frame(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.surface)
        .stroke(egui::Stroke::new(1.0, p.danger))
        .inner_margin(egui::Margin::symmetric(12, 8))
}

impl RustChromeApp {
    // ------------------------------------------------------------------
    // Start-up
    // ------------------------------------------------------------------

    /// Applies the start-up security findings: vault binding, outside changes, WebView2
    /// overrides and the remote-debugging request.
    pub(super) fn init_security(&mut self, startup: crate::StartupSecurity) {
        self.vault.set_device_protector(Box::new(DpapiProtector));
        self.outside_changes = crate::integrity::take_reports();
        if let Some(blocking) = startup.webview2_overrides.iter().find(|o| o.blocking) {
            self.webview_blocked = Some(format!(
                "Oya will not load websites because {} points WebView2 at a different browser program. Remove that setting and restart Oya.",
                blocking.source
            ));
        }
        if let Some(port) = startup.debug_port {
            self.request_approval(
                ApprovalAction::EnableRemoteDebugging(port),
                format!(
                    "Oya was started with remote debugging on port {port}. Allowing it lets any program on this PC that has the connection key control the browser, read pages and run scripts."
                ),
            );
        }
        for o in &startup.webview2_overrides {
            self.controller.log_store.record(DiagnosticEvent::new(
                Severity::Security,
                LogCategory::Security,
                "startup",
                0,
                format!("WebView2 override found: {} (blocking={})", o.source, o.blocking),
            ));
        }
        self.startup = startup;
    }

    // ------------------------------------------------------------------
    // Off-thread PIN / Windows Hello work
    // ------------------------------------------------------------------

    fn start_unlock(&mut self, pin: String, purpose: Purpose, ctx: &egui::Context) {
        let pin = Zeroizing::new(pin);
        match self.vault.unlock_job(&pin) {
            Ok(job) => {
                let tx = self.task_tx.clone();
                let ctx = ctx.clone();
                self.busy = Some("Checking PIN…".to_string());
                std::thread::spawn(move || {
                    let result = job.run();
                    let _ = tx.send(TaskResult::Unlock { purpose, result });
                    ctx.request_repaint();
                });
            }
            Err(e) => self.report_purpose_error(&purpose, e.to_string()),
        }
    }

    fn start_new_pin(&mut self, new_pin: &str, then_save_offer: bool, ctx: &egui::Context) -> Result<(), String> {
        let job = self.vault.new_pin_job(new_pin).map_err(|e| e.to_string())?;
        let tx = self.task_tx.clone();
        let ctx = ctx.clone();
        self.busy = Some("Securing the vault…".to_string());
        std::thread::spawn(move || {
            let result = job.run();
            let _ = tx.send(TaskResult::NewPin {
                then_save_offer,
                result,
            });
            ctx.request_repaint();
        });
        Ok(())
    }

    fn start_hello(&mut self, purpose: Purpose, reason: String, ctx: &egui::Context) {
        let tx = self.task_tx.clone();
        let ctx = ctx.clone();
        self.busy = Some("Waiting for Windows Hello…".to_string());
        std::thread::spawn(move || {
            let outcome = windows_hello_prompt(&reason);
            let _ = tx.send(TaskResult::Hello { purpose, outcome });
            ctx.request_repaint();
        });
    }

    fn start_cross_device_passkey(
        &mut self,
        purpose: Purpose,
        rp_id: String,
        origin: String,
        parent_hwnd: isize,
        ctx: &egui::Context,
    ) {
        let tx = self.task_tx.clone();
        let ctx = ctx.clone();
        self.busy = Some("Waiting for passkey on another device…".to_string());
        std::thread::spawn(move || {
            let outcome = rc_sandbox::prompt_cross_device_passkey(
                parent_hwnd,
                &rp_id,
                &origin,
                "b3lhLWJyb3dzZXItcGFzc2tleS1jaGFsbGVuZ2U",
            );
            let _ = tx.send(TaskResult::CrossDevicePasskey { purpose, outcome });
            ctx.request_repaint();
        });
    }

    fn report_purpose_error(&mut self, purpose: &Purpose, msg: String) {
        match purpose {
            Purpose::AutoLogin { .. } => self.validation_status_msg = msg,
            Purpose::SaveOffer => self.save_offer_status_msg = msg,
            Purpose::Approval => {
                if let Some(a) = self.approval.as_mut() {
                    a.status = msg;
                }
            }
            Purpose::ChangePin { .. } => {
                self.vault_status_banner = format!("Could not change the PIN: {msg}")
            }
            Purpose::CrossDeviceVerify { .. } => {
                self.vault_status_banner = msg;
            }
        }
    }

    /// Handles finished PIN checks and Windows Hello prompts.
    pub(super) fn poll_tasks(&mut self, ctx: &egui::Context) {
        while let Ok(done) = self.task_rx.try_recv() {
            self.busy = None;
            match done {
                TaskResult::Unlock { purpose, result } => {
                    if let Err(e) = self.vault.finish_unlock(result) {
                        self.report_purpose_error(&purpose, e.to_string());
                        continue;
                    }
                    match purpose {
                        Purpose::AutoLogin { origin, tab_id } => {
                            if !self.vault.upgrade_reasons().is_empty() {
                                self.validation_status_msg = "Your password vault needs a new PIN before it can fill passwords. Open Settings → Passwords and autofill.".to_string();
                                continue;
                            }
                            match self
                                .vault
                                .verify_user_identity(BiometricModality::MasterPin, "", &origin)
                            {
                                Ok(audit) => {
                                    self.audit(&origin, audit);
                                    self.finish_auto_login(&origin, tab_id);
                                }
                                Err(e) => self.validation_status_msg = e.to_string(),
                            }
                        }
                        Purpose::SaveOffer => self.save_pending_offer(),
                        Purpose::Approval => {
                            if self.vault.pin_entered_within(Duration::from_secs(30)) {
                                self.approve_now();
                            }
                        }
                        Purpose::ChangePin { new_pin } => {
                            if let Err(e) = self.start_new_pin(&new_pin, false, ctx) {
                                self.vault_status_banner = format!("Could not change the PIN: {e}");
                            }
                        }
                        Purpose::CrossDeviceVerify { .. } => {}
                    }
                }
                TaskResult::NewPin {
                    then_save_offer,
                    result,
                } => match self.vault.commit_new_pin(result) {
                    Ok(()) => {
                        self.vault_status_banner = if self.vault.is_device_bound() {
                            "PIN set. Your passwords are re-encrypted and can only be opened by your Windows account on this PC."
                        } else {
                            "PIN set. Your passwords are re-encrypted."
                        }
                        .to_string();
                        self.audit("vault", "Vault PIN set or changed".to_string());
                        if then_save_offer {
                            self.save_pending_offer();
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if then_save_offer {
                            self.save_offer_status_msg = msg;
                        } else {
                            self.vault_status_banner = format!("Could not change the PIN: {msg}");
                        }
                    }
                },
                TaskResult::Hello { purpose, outcome } => match purpose {
                    Purpose::AutoLogin { origin, tab_id } => {
                        match self
                            .vault
                            .complete_hello_ceremony(outcome, BiometricModality::Fingerprint)
                        {
                            Ok(audit) => {
                                self.audit(&origin, audit);
                                self.finish_auto_login(&origin, tab_id);
                            }
                            Err(e) => self.validation_status_msg = e.to_string(),
                        }
                    }
                    Purpose::Approval => {
                        if outcome.is_verified() {
                            self.approve_now();
                        } else if let Some(a) = self.approval.as_mut() {
                            a.status = outcome.message().to_string();
                            a.hello_unavailable = !outcome.message().contains("canceled");
                        }
                    }
                    _ => {}
                },
                TaskResult::CrossDevicePasskey { purpose, outcome } => match purpose {
                    Purpose::AutoLogin { origin, tab_id } => match outcome {
                        rc_sandbox::CrossDevicePasskeyOutcome::Verified(assertion) => {
                            let detail = format!(
                                "Verified via cross-device passkey (cred={} bytes, sig={} bytes)",
                                assertion.credential_id.len(),
                                assertion.signature.len()
                            );
                            match self.vault.complete_cross_device_ceremony(&detail) {
                                Ok(audit) => {
                                    self.audit(&origin, audit);
                                    self.finish_auto_login(&origin, tab_id);
                                }
                                Err(e) => self.validation_status_msg = e.to_string(),
                            }
                        }
                        rc_sandbox::CrossDevicePasskeyOutcome::Cancelled => {
                            self.validation_status_msg = "Cross-device passkey prompt was cancelled.".to_string();
                        }
                        rc_sandbox::CrossDevicePasskeyOutcome::Unavailable(reason)
                        | rc_sandbox::CrossDevicePasskeyOutcome::Failed(reason) => {
                            self.validation_status_msg = reason;
                        }
                    },
                    Purpose::CrossDeviceVerify { rp_id } => match outcome {
                        rc_sandbox::CrossDevicePasskeyOutcome::Verified(assertion) => {
                            let detail = format!(
                                "Cross-device passkey verified for {rp_id} (cred={} bytes, sig={} bytes)",
                                assertion.credential_id.len(),
                                assertion.signature.len()
                            );
                            self.audit(&rp_id, detail.clone());
                            self.vault_status_banner = detail;
                        }
                        rc_sandbox::CrossDevicePasskeyOutcome::Cancelled => {
                            self.vault_status_banner = "Cross-device passkey prompt was cancelled.".to_string();
                        }
                        rc_sandbox::CrossDevicePasskeyOutcome::Unavailable(reason)
                        | rc_sandbox::CrossDevicePasskeyOutcome::Failed(reason) => {
                            self.vault_status_banner = reason;
                        }
                    },
                    _ => {}
                },
            }
        }
    }

    fn audit(&mut self, origin: &str, msg: String) {
        self.controller.log_store.record(DiagnosticEvent::new(
            Severity::Security,
            LogCategory::Security,
            origin,
            0,
            msg,
        ));
    }

    /// Locks the vault after the idle time, when Windows locks, and after sleep.
    pub(super) fn vault_tick(&mut self, ctx: &egui::Context) {
        if !self.vault.is_unlocked() {
            self.last_wall_clock = SystemTime::now();
            return;
        }
        let minutes = self.controller.settings.vault_auto_lock_minutes.clamp(1, 60) as u64;
        let mut locked = self.vault.lock_if_idle(Duration::from_secs(minutes * 60));
        // A jump in wall-clock time means the PC slept or hibernated.
        let now = SystemTime::now();
        if now
            .duration_since(self.last_wall_clock)
            .is_ok_and(|d| d > Duration::from_secs(90))
        {
            self.vault.lock();
            locked = true;
        }
        self.last_wall_clock = now;
        if self.last_lock_poll.elapsed() > Duration::from_secs(2) {
            self.last_lock_poll = Instant::now();
            if rc_sandbox::is_workstation_locked() {
                self.vault.lock();
                locked = true;
            }
        }
        if locked {
            self.audit("vault", "Password vault locked automatically".to_string());
        } else {
            // Keep ticking while unlocked even if nothing else repaints.
            ctx.request_repaint_after(Duration::from_secs(2));
        }
    }

    // ------------------------------------------------------------------
    // Sign-in with a saved password
    // ------------------------------------------------------------------

    fn live_origin_of(&self, tab_id: u64) -> Option<String> {
        self.webviews
            .get(&tab_id)
            .and_then(|twv| twv.webview.url().ok())
            .and_then(|u| validate_and_extract_origin(&u).ok())
            .map(|o| o.to_string())
    }

    /// Starts filling a saved password into the active tab after confirmation.
    pub(super) fn begin_auto_login(
        &mut self,
        origin: &str,
        modality: BiometricModality,
        parent_hwnd: isize,
        ctx: &egui::Context,
    ) {
        if !self.vault.has_credential_for_origin(origin) {
            self.active_validation_origin = None;
            return;
        }
        let tab_id = self.controller.tab().id;
        let live = self.live_origin_of(tab_id);
        if live.as_deref() != Some(origin) {
            self.validation_status_msg = format!(
                "Sign-in blocked: the open page is not {origin}. Open the site's sign-in page first."
            );
            self.audit(
                origin,
                format!(
                    "Blocked auto-login for {origin}: live page origin is {}",
                    live.as_deref().unwrap_or("unknown")
                ),
            );
            return;
        }
        if self.vault.is_unlocked() && !self.vault.upgrade_reasons().is_empty() {
            self.validation_status_msg = "Your password vault needs a new PIN before it can fill passwords. Open Settings → Passwords and autofill.".to_string();
            return;
        }
        let purpose = Purpose::AutoLogin {
            origin: origin.to_string(),
            tab_id,
        };
        match modality {
            BiometricModality::MasterPin => {
                let pin = std::mem::take(&mut self.validation_pin_input);
                self.start_unlock(pin, purpose, ctx);
            }
            BiometricModality::CrossDevicePasskey => {
                if !self.vault.is_unlocked() {
                    self.validation_status_msg =
                        "Enter your vault PIN once; after that a passkey on another device can confirm sign-ins."
                            .to_string();
                    return;
                }
                let rp_id = host_of(origin);
                self.start_cross_device_passkey(
                    purpose,
                    rp_id,
                    origin.to_string(),
                    parent_hwnd,
                    ctx,
                );
            }
            _ => {
                if !self.vault.is_unlocked() {
                    self.validation_status_msg =
                        "Enter your vault PIN once; after that Windows Hello can confirm sign-ins."
                            .to_string();
                    return;
                }
                self.start_hello(purpose, format!("sign in to {}", host_of(origin)), ctx);
            }
        }
    }

    fn finish_auto_login(&mut self, origin: &str, tab_id: u64) {
        // The page may have navigated while the user confirmed: check again.
        if self.live_origin_of(tab_id).as_deref() != Some(origin) {
            self.vault.identity_verified_for_ceremony = false;
            self.validation_status_msg = "Sign-in cancelled: the page changed.".to_string();
            return;
        }
        match self.vault.consume_verified_password_for_origin(origin) {
            Ok((username, mut password, auto_submit)) => {
                if let Some(twv) = self.webviews.get(&tab_id) {
                    let mut msg = serde_json::json!({
                        "t": "fill",
                        "origin": origin,
                        "user": username,
                        "pass": password.as_str(),
                        "auto": auto_submit,
                    });
                    post_to_page(&twv.webview, &msg);
                    if let Some(serde_json::Value::String(p)) = msg.get_mut("pass") {
                        p.zeroize();
                    }
                }
                password.zeroize();
                self.validation_status_msg.clear();
                self.active_validation_origin = None;
            }
            Err(e) => self.validation_status_msg = e.to_string(),
        }
    }

    fn save_pending_offer(&mut self) {
        if !self.vault.upgrade_reasons().is_empty() {
            self.save_offer_status_msg =
                "Your password vault needs a new PIN first (Settings → Passwords and autofill)."
                    .to_string();
            return;
        }
        let saved = match self.pending_save_offer.as_ref() {
            Some(offer) => {
                self.vault
                    .store_password(&offer.origin, &offer.username, &offer.password, true)
            }
            None => Ok(()),
        };
        match saved {
            Ok(()) => {
                if let Some(mut old) = self.pending_save_offer.take() {
                    self.audit(&old.origin.clone(), format!("Saved encrypted password for {}", old.origin));
                    old.password.zeroize();
                }
                self.save_offer_status_msg.clear();
            }
            Err(e) => self.save_offer_status_msg = e.to_string(),
        }
    }

    pub(super) fn render_save_offer_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, parent_hwnd: isize, p: &Palette) {
        let Some((offer_origin, offer_username)) = self
            .pending_save_offer
            .as_ref()
            .map(|o| (o.origin.clone(), o.username.clone()))
        else {
            return;
        };
        let needs_new_pin = !self.vault.has_master_pin();
        let needs_unlock = !needs_new_pin && !self.vault.is_unlocked();
        let mut save = false;
        let mut cancel = false;
        egui::Panel::top("oya_save_credentials_bar")
            .frame(infobar_frame(p))
            .show_separator_line(false)
            .resizable(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    paint_inline_icon(ui, Icon::Key, p.on_tonal);
                    ui.label(
                        egui::RichText::new(format!(
                            "Save password for {offer_username} on {}?",
                            host_of(&offer_origin)
                        ))
                        .color(p.on_tonal)
                        .strong(),
                    );
                    let mut pin_enter = false;
                    if needs_new_pin || needs_unlock {
                        let pin_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.save_offer_pin_input)
                                .password(true)
                                .desired_width(200.0)
                                .hint_text(if needs_new_pin {
                                    "Create vault PIN (8+ characters)"
                                } else {
                                    "Vault PIN"
                                }),
                        );
                        if pin_resp.clicked() || pin_resp.has_focus() {
                            reclaim_win32_keyboard_focus(parent_hwnd);
                        }
                        pin_enter = pin_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if needs_new_pin && !self.save_offer_pin_input.is_empty() {
                            let s = pin_strength(&self.save_offer_pin_input);
                            ui.label(egui::RichText::new(s.label).color(if s.acceptable { p.on_tonal } else { p.danger }));
                        }
                    }
                    if self.busy.is_some() {
                        ui.add(egui::Spinner::new().size(14.0));
                    } else if ui.add(primary_button("Save", p)).clicked() || pin_enter {
                        save = true;
                    }
                    if ui.button("Never mind").clicked() {
                        cancel = true;
                    }
                    if !self.save_offer_status_msg.is_empty() {
                        ui.colored_label(p.danger, &self.save_offer_status_msg);
                    }
                });
            });
        if save {
            let pin = std::mem::take(&mut self.save_offer_pin_input);
            if needs_new_pin {
                let pin = Zeroizing::new(pin);
                if let Err(e) = self.start_new_pin(&pin, true, ctx) {
                    self.save_offer_status_msg = e;
                }
            } else if needs_unlock {
                self.start_unlock(pin, Purpose::SaveOffer, ctx);
            } else {
                self.save_pending_offer();
            }
        }
        if cancel {
            if let Some(mut old) = self.pending_save_offer.take() {
                old.password.zeroize();
            }
            self.save_offer_pin_input.zeroize();
            self.save_offer_pin_input.clear();
            self.save_offer_status_msg.clear();
        }
    }

    pub(super) fn render_auto_login_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, parent_hwnd: isize, p: &Palette) {
        let Some(val_origin) = self.active_validation_origin.clone() else {
            return;
        };
        let cur_origin = self.controller.tab().current_origin.clone();
        if val_origin != cur_origin || !self.vault.has_credential_for_origin(&val_origin) {
            self.active_validation_origin = None;
            return;
        }
        let saved_user = self
            .vault
            .saved_username_for_origin(&val_origin)
            .unwrap_or_else(|| "saved account".to_string());
        let hello_ready = self.vault.is_unlocked()
            && self.vault.preferred_modality != BiometricModality::MasterPin;
        let mut action: Option<BiometricModality> = None;
        egui::Panel::top("oya_auto_login_bar")
            .frame(infobar_frame(p))
            .show_separator_line(false)
            .resizable(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    paint_inline_icon(ui, Icon::Key, p.on_tonal);
                    ui.label(
                        egui::RichText::new(format!("Sign in to {} as {saved_user}?", host_of(&val_origin)))
                            .color(p.on_tonal)
                            .strong(),
                    );
                    if self.busy.is_some() {
                        ui.add(egui::Spinner::new().size(14.0));
                        ui.label(egui::RichText::new(self.busy.clone().unwrap_or_default()).color(p.on_tonal));
                    } else {
                        if hello_ready {
                            if ui.add(primary_button("Use Windows Hello", p)).clicked() {
                                action = Some(BiometricModality::Fingerprint);
                            }
                            ui.label(egui::RichText::new("or").color(p.on_tonal));
                        }
                        if self.vault.is_unlocked()
                            && self.controller.settings.allow_cross_device_passkeys
                            && ui
                                .button("Passkey on another device")
                                .on_hover_text(
                                    "Scan a QR code with your phone or tablet, or tap a USB/NFC security key",
                                )
                                .clicked()
                        {
                            action = Some(BiometricModality::CrossDevicePasskey);
                        }
                        let pin_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.validation_pin_input)
                                .password(true)
                                .desired_width(150.0)
                                .hint_text("Vault PIN"),
                        );
                        if pin_resp.clicked() || pin_resp.has_focus() {
                            reclaim_win32_keyboard_focus(parent_hwnd);
                        }
                        let pin_enter = pin_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let sign_in = if hello_ready {
                            egui::Button::new("Sign in with PIN")
                        } else {
                            primary_button("Sign in", p)
                        };
                        if ui.add(sign_in).clicked() || pin_enter {
                            action = Some(BiometricModality::MasterPin);
                        }
                    }
                    if ui.button("Not now").clicked() {
                        self.active_validation_origin = None;
                        self.validation_pin_input.zeroize();
                        self.validation_pin_input.clear();
                        self.validation_status_msg.clear();
                    }
                    if !self.validation_status_msg.is_empty() {
                        ui.colored_label(p.danger, &self.validation_status_msg);
                    }
                });
            });
        if let Some(modality) = action {
            self.begin_auto_login(&val_origin, modality, parent_hwnd, ctx);
        }
    }

    // ------------------------------------------------------------------
    // Approval gate
    // ------------------------------------------------------------------

    pub(super) fn request_approval(&mut self, action: ApprovalAction, summary: String) {
        self.approval = Some(PendingApproval {
            action,
            summary,
            pin: String::new(),
            status: String::new(),
            hello_unavailable: false,
        });
    }

    fn approve_now(&mut self) {
        let Some(mut ap) = self.approval.take() else {
            return;
        };
        ap.pin.zeroize();
        self.audit("approval", format!("Approved: {}", ap.summary));
        match ap.action {
            ApprovalAction::ApplySettings(settings) => {
                self.controller.settings = *settings;
                self.controller.settings.save();
                self.last_style_key = None;
            }
            ApprovalAction::AdoptOutsideSettings(raw) => {
                if let Ok(parsed) = serde_json::from_str::<BrowserSettings>(&raw) {
                    self.controller.settings = parsed;
                    self.controller.settings.save();
                    self.last_style_key = None;
                }
            }
            ApprovalAction::AdoptOutsideBookmarks(raw) => {
                self.controller.bookmarks.adopt_json(&raw);
            }
            ApprovalAction::ClearBrowsingData => {
                let cleared = self
                    .webviews
                    .values()
                    .next()
                    .map(|twv| twv.webview.clear_all_browsing_data().is_ok())
                    .unwrap_or(false);
                self.settings_status = if cleared {
                    "Browsing data cleared.".to_string()
                } else {
                    "Open any website first, then clear browsing data.".to_string()
                };
            }
            ApprovalAction::ResetSettings => {
                self.controller.settings = BrowserSettings::default();
                self.controller.settings.save();
                self.last_style_key = None;
            }
            ApprovalAction::DeletePassword { origin, username } => {
                self.vault
                    .passwords
                    .retain(|e| !(e.origin == origin && e.username == username));
                self.vault.save();
            }
            ApprovalAction::EnableRemoteDebugging(port) => {
                let (tx, rx) = mpsc::channel();
                match rc_cdp::start_cdp_server(port, tx) {
                    Ok(handle) => {
                        eprintln!("DevTools listening on {}", handle.browser_ws_url());
                        self.cdp_rx = Some(rx);
                        self.cdp_handle = Some(handle);
                    }
                    Err(e) => {
                        self.settings_status = format!("Remote debugging could not start: {e}")
                    }
                }
            }
            ApprovalAction::UsePrivateProfile => {
                let _ = std::fs::remove_file("webview2_profile_location.txt");
                self.settings_status = "Restart Oya to use a private sign-in folder. You will need to sign in to websites again.".to_string();
                self.dismissed_location_warning = true;
            }
        }
    }

    pub(super) fn render_approval_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, parent_hwnd: isize, p: &Palette) {
        if self.approval.is_none() {
            return;
        }
        let has_pin = self.vault.has_master_pin();
        let busy = self.busy.clone();
        #[derive(PartialEq)]
        enum Act {
            None,
            Hello,
            Pin,
            Plain,
            Cancel,
        }
        let mut act = Act::None;
        egui::Panel::top("oya_approval_bar")
            .frame(warning_frame(p))
            .show_separator_line(false)
            .resizable(false)
            .show(ui, |ui| {
                let Some(ap) = self.approval.as_mut() else { return };
                ui.horizontal_wrapped(|ui| {
                    paint_inline_icon(ui, Icon::Lock, p.danger);
                    ui.label(egui::RichText::new("Your approval is needed").strong().color(p.text));
                });
                ui.add(egui::Label::new(egui::RichText::new(&ap.summary).color(p.text)).wrap());
                ui.horizontal_wrapped(|ui| {
                    if let Some(b) = &busy {
                        ui.add(egui::Spinner::new().size(14.0));
                        ui.label(b);
                        return;
                    }
                    if !ap.hello_unavailable && ui.add(primary_button("Confirm with Windows Hello", p)).clicked() {
                        act = Act::Hello;
                    }
                    if has_pin {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut ap.pin)
                                .password(true)
                                .hint_text("Vault PIN")
                                .desired_width(150.0),
                        );
                        if r.clicked() || r.has_focus() {
                            reclaim_win32_keyboard_focus(parent_hwnd);
                        }
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.button("Confirm with PIN").clicked() || enter {
                            act = Act::Pin;
                        }
                    } else if ap.hello_unavailable && ui.add(danger_button("Approve", p)).clicked() {
                        act = Act::Plain;
                    }
                    if ui.button("Cancel").clicked() {
                        act = Act::Cancel;
                    }
                });
                if !ap.status.is_empty() {
                    ui.colored_label(p.danger, &ap.status);
                }
                if ap.hello_unavailable && !has_pin {
                    ui.label(
                        egui::RichText::new("Tip: create a vault PIN in Settings so changes like this need more than a click.")
                            .color(p.text_weak)
                            .size(12.5),
                    );
                }
            });
        match act {
            Act::Hello => {
                let reason = "approve a change to Oya's settings".to_string();
                self.start_hello(Purpose::Approval, reason, ctx);
            }
            Act::Pin => {
                let pin = self
                    .approval
                    .as_mut()
                    .map(|a| std::mem::take(&mut a.pin))
                    .unwrap_or_default();
                self.start_unlock(pin, Purpose::Approval, ctx);
            }
            Act::Plain => self.approve_now(),
            Act::Cancel => {
                if let Some(mut a) = self.approval.take() {
                    a.pin.zeroize();
                    self.audit("approval", format!("Declined: {}", a.summary));
                }
            }
            Act::None => {}
        }
    }

    /// Called after the settings page is drawn: any protected change made on it is reverted and
    /// turned into an approval request.
    pub(super) fn guard_settings_changes(&mut self, before: BrowserSettings) {
        let changes = protected_changes(&before, &self.controller.settings);
        if changes.is_empty() {
            return;
        }
        let proposed = std::mem::replace(&mut self.controller.settings, before);
        self.controller.settings.save();
        self.request_approval(
            ApprovalAction::ApplySettings(Box::new(proposed)),
            format!("Change these settings: {}.", changes.join("; ")),
        );
    }

    // ------------------------------------------------------------------
    // Security notices
    // ------------------------------------------------------------------

    pub(super) fn render_security_bars(&mut self, ui: &mut egui::Ui, p: &Palette) {
        // Remote control active.
        if let Some(handle) = &self.cdp_handle {
            let port = handle.addr.port();
            let mut off = false;
            egui::Panel::top("oya_remote_debug_bar")
                .frame(egui::Frame::new().fill(p.danger).inner_margin(egui::Margin::symmetric(12, 6)))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "Remote control is on (port {port}). Programs with the connection key can control Oya."
                            ))
                            .color(egui::Color32::WHITE)
                            .strong(),
                        );
                        if ui.button("Turn off").clicked() {
                            off = true;
                        }
                    });
                });
            if off {
                if let Some(h) = self.cdp_handle.take() {
                    h.disable();
                }
                self.cdp_rx = None;
                self.audit("remote-debugging", "Remote debugging turned off".to_string());
            }
        }

        // WebView2 redirected: no web pages.
        if let Some(reason) = &self.webview_blocked {
            egui::Panel::top("oya_webview_blocked_bar")
                .frame(warning_frame(p))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(egui::RichText::new(reason).color(p.danger).strong()).wrap());
                });
        }

        // Settings or bookmarks changed by another program.
        if let Some(report) = self.outside_changes.first().cloned() {
            let is_settings = report
                .file
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("settings"));
            let summary = if is_settings {
                match serde_json::from_str::<BrowserSettings>(&report.external) {
                    Ok(theirs) => {
                        let c = protected_changes(&self.controller.settings, &theirs);
                        if c.is_empty() {
                            "Another program changed Oya's settings while Oya was closed.".to_string()
                        } else {
                            format!("Another program changed Oya's settings while Oya was closed: {}.", c.join("; "))
                        }
                    }
                    Err(_) => "Another program replaced Oya's settings file with something unreadable.".to_string(),
                }
            } else {
                "Another program changed your bookmarks while Oya was closed.".to_string()
            };
            let mut keep_mine = false;
            let mut review = false;
            egui::Panel::top("oya_outside_change_bar")
                .frame(warning_frame(p))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(egui::RichText::new(&summary).color(p.text).strong()).wrap());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new("Oya kept your previous version.").color(p.text_weak));
                        if ui.add(primary_button("Keep mine", p)).clicked() {
                            keep_mine = true;
                        }
                        if ui.button("Review their changes…").clicked() {
                            review = true;
                        }
                    });
                });
            if keep_mine || review {
                self.outside_changes.remove(0);
                if keep_mine {
                    // Re-seal our version so the outside copy is replaced.
                    if is_settings {
                        self.controller.settings.save();
                    } else {
                        self.controller.bookmarks.save();
                    }
                } else {
                    let action = if is_settings {
                        ApprovalAction::AdoptOutsideSettings(report.external.clone())
                    } else {
                        ApprovalAction::AdoptOutsideBookmarks(report.external.clone())
                    };
                    self.request_approval(action, format!("Use the version written by another program? {summary}"));
                }
            }
        }

        // Vault needs a new PIN.
        if self.vault.is_unlocked() && !self.vault.upgrade_reasons().is_empty() {
            let reasons = self.vault.upgrade_reasons().join("; ");
            let mut open = false;
            egui::Panel::top("oya_vault_upgrade_bar")
                .frame(warning_frame(p))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "Your password vault needs a new PIN: {reasons}. Saving and filling passwords are paused until then."
                            ))
                            .color(p.text),
                        );
                        if ui.add(primary_button("Set a new PIN", p)).clicked() {
                            open = true;
                        }
                    });
                });
            if open {
                self.open_settings(OptionsSection::AutofillAndPasswords);
            }
        }

        // Risky download waiting for a decision.
        if let Some(dl) = self.pending_downloads.first() {
            let (name, host) = (dl.file_name.clone(), host_of(&dl.url));
            let mut decision: Option<bool> = None;
            egui::Panel::top("oya_download_bar")
                .frame(warning_frame(p))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        paint_inline_icon(ui, Icon::Warning, p.danger);
                        ui.label(
                            egui::RichText::new(format!(
                                "“{name}” can run programs on your computer. Only keep it if you trust {host}."
                            ))
                            .color(p.text),
                        );
                        if ui.button("Keep").clicked() {
                            decision = Some(true);
                        }
                        if ui.add(primary_button("Discard", p)).clicked() {
                            decision = Some(false);
                        }
                    });
                });
            if let Some(keep) = decision {
                let dl = self.pending_downloads.remove(0);
                self.audit(
                    "downloads",
                    format!("{} risky download {}", if keep { "Kept" } else { "Discarded" }, dl.file_name),
                );
                if keep {
                    self.approved_downloads.borrow_mut().insert(dl.url.clone());
                    if let Some(twv) = self.webviews.get(&dl.tab_id) {
                        let _ = twv.webview.load_url(&dl.url);
                    }
                }
            }
        }

        // Ignored outside WebView2 settings (informational).
        let ignored: Vec<String> = self
            .startup
            .webview2_overrides
            .iter()
            .filter(|o| !o.blocking)
            .map(|o| o.source.clone())
            .collect();
        if !ignored.is_empty() && !self.dismissed_override_notice {
            let mut dismiss = false;
            egui::Panel::top("oya_override_notice")
                .frame(infobar_frame(p))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "Oya ignored outside settings that try to change how its web engine starts: {}.",
                                ignored.join(", ")
                            ))
                            .color(p.on_tonal),
                        );
                        if ui.button("OK").clicked() {
                            dismiss = true;
                        }
                    });
                });
            if dismiss {
                self.dismissed_override_notice = true;
            }
        }

        // Program or sign-in folders that other accounts can modify.
        let s = &self.startup;
        if !self.dismissed_location_warning
            && (!s.program_folder_writers.is_empty()
                || !s.planted_dlls.is_empty()
                || !s.profile_folder_writers.is_empty())
        {
            let mut lines = Vec::new();
            if !s.planted_dlls.is_empty() {
                lines.push(format!(
                    "Unexpected DLL files are next to Oya ({}). Oya ships none, so they may have been planted.",
                    s.planted_dlls.join(", ")
                ));
            }
            if !s.program_folder_writers.is_empty() {
                lines.push(format!(
                    "Other accounts can modify Oya's program folder ({}), so they could replace Oya with a fake copy.",
                    s.program_folder_writers.join(", ")
                ));
            }
            let shared_profile = !s.profile_folder_writers.is_empty();
            if shared_profile {
                lines.push(format!(
                    "Other accounts can modify the folder holding your website sign-ins ({}).",
                    s.profile_folder_writers.join(", ")
                ));
            }
            let mut dismiss = false;
            let mut private = false;
            egui::Panel::top("oya_location_warning")
                .frame(warning_frame(p))
                .show_separator_line(false)
                .resizable(false)
                .show(ui, |ui| {
                    for l in &lines {
                        ui.add(egui::Label::new(egui::RichText::new(l).color(p.text)).wrap());
                    }
                    ui.horizontal_wrapped(|ui| {
                        if shared_profile
                            && Path::new("webview2_profile_location.txt").exists()
                            && ui.button("Use a private sign-in folder…").clicked()
                        {
                            private = true;
                        }
                        if ui.button("Dismiss").clicked() {
                            dismiss = true;
                        }
                    });
                });
            if dismiss {
                self.dismissed_location_warning = true;
            }
            if private {
                self.request_approval(
                    ApprovalAction::UsePrivateProfile,
                    "Switch to a new sign-in folder that only your account can open? After restarting Oya you will need to sign in to websites again. The old folder is not deleted.".to_string(),
                );
            }
        }
    }

    /// Full-screen notice ("<site> is full screen — Press Esc to exit"), drawn in its own
    /// always-on-top window so it shows above the page.
    pub(super) fn render_fullscreen_notice(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some((host, since)) = self.fullscreen_notice.clone() else {
            return;
        };
        if !self.is_fullscreen || since.elapsed() > Duration::from_secs(4) {
            self.fullscreen_notice = None;
            return;
        }
        let monitor = ctx
            .input(|i| i.viewport().monitor_size)
            .unwrap_or(egui::vec2(1920.0, 1080.0));
        let size = egui::vec2(460.0, 44.0);
        let builder = egui::ViewportBuilder::default()
            .with_title("Oya full screen")
            .with_decorations(false)
            .with_resizable(false)
            .with_taskbar(false)
            .with_always_on_top()
            .with_active(false)
            .with_mouse_passthrough(true)
            .with_position(egui::pos2((monitor.x - size.x) / 2.0, 28.0))
            .with_inner_size(size);
        let text = format!("{host} is full screen — press Esc to exit");
        let p = *p;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("oya_fullscreen_notice"),
            builder,
            |ui, _| {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(32, 33, 36))
                    .inner_margin(egui::Margin::symmetric(16, 10))
                    .show(ui, |ui| {
                        ui.set_width(size.x - 32.0);
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(&text).color(egui::Color32::WHITE).size(15.0));
                        });
                    });
                let _ = p;
            },
        );
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    // ------------------------------------------------------------------
    // Settings sections with security controls
    // ------------------------------------------------------------------

    pub(super) fn section_passwords(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let ctx = ui.ctx().clone();
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            let mut changed = false;
            changed |= toggle_row(
                ui,
                p,
                &mut s.offer_to_save_passwords,
                "Offer to save passwords",
                "Asks after you sign in on an HTTPS site. Passwords are encrypted with your vault PIN and locked to this PC.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.autofill_passwords_enabled,
                "Sign in with saved passwords",
                "Fills a saved password only after you confirm with Windows Hello or your vault PIN, and only on the exact site it was saved for.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.allow_cross_device_passkeys,
                "Sign in with a passkey on another device",
                "Allows FIDO2 hybrid transport (QR code with phone/tablet or USB/NFC security key) for WebAuthn and sign-in confirmation.",
            );
            row_divider(ui, p);
            row_label(ui, p, "Lock the vault after", "It also locks when Windows locks or the PC sleeps.");
            ui.horizontal_wrapped(|ui| {
                for m in [1u32, 5, 15, 30, 60] {
                    changed |= ui
                        .selectable_value(&mut s.vault_auto_lock_minutes, m, format!("{m} min"))
                        .changed();
                }
            });
            if changed {
                s.save();
            }
            row_divider(ui, p);
            row_label(ui, p, "Confirm sign-ins with", "");
            ui.horizontal_wrapped(|ui| {
                let mut changed = false;
                changed |= ui
                    .radio_value(&mut self.vault.preferred_modality, BiometricModality::Fingerprint, "Windows Hello")
                    .changed();
                changed |= ui
                    .radio_value(&mut self.vault.preferred_modality, BiometricModality::MasterPin, "Vault PIN only")
                    .changed();
                changed |= ui
                    .radio_value(
                        &mut self.vault.preferred_modality,
                        BiometricModality::CrossDevicePasskey,
                        "Passkey on another device",
                    )
                    .changed();
                if changed {
                    self.vault.save();
                }
            });
        });
        ui.add_space(10.0);

        card(ui, p, |ui| {
            let has_pin = self.vault.has_master_pin();
            let status = if !has_pin {
                "No vault PIN yet — nothing can be saved until you create one".to_string()
            } else if self.vault.is_unlocked() {
                format!(
                    "Unlocked{}",
                    if self.vault.is_device_bound() { " · locked to this PC" } else { "" }
                )
            } else {
                format!("Locked{}", if self.vault.is_device_bound() { " · locked to this PC" } else { "" })
            };
            ui.horizontal_wrapped(|ui| {
                row_label(ui, p, "Password vault", &status);
                if self.vault.is_unlocked() && ui.button("Lock now").clicked() {
                    self.vault.lock();
                }
            });
            row_divider(ui, p);
            ui.label(egui::RichText::new(if has_pin { "Change vault PIN" } else { "Create vault PIN" }).color(p.text));
            let mut submit = false;
            ui.horizontal_wrapped(|ui| {
                if has_pin {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_current_pin)
                            .password(true)
                            .hint_text("Current PIN")
                            .desired_width(170.0),
                    );
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.vault_new_pin)
                        .password(true)
                        .hint_text("New PIN (8+ characters)")
                        .desired_width(210.0),
                );
                if self.busy.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                } else if ui.button(if has_pin { "Change PIN" } else { "Create PIN" }).clicked() {
                    submit = true;
                }
            });
            if !self.vault_new_pin.is_empty() {
                let st = pin_strength(&self.vault_new_pin);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(160.0, 6.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 3.0, p.control_hover);
                    let frac = (st.score as f32 + 1.0) / 5.0;
                    let fill = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * frac, rect.height()));
                    let col = if !st.acceptable { p.danger } else if st.score >= 3 { p.success } else { p.warn };
                    ui.painter().rect_filled(fill, 3.0, col);
                    ui.label(egui::RichText::new(st.label).color(col));
                    if !st.advice.is_empty() {
                        ui.label(egui::RichText::new(st.advice).color(p.text_weak).size(12.5));
                    }
                });
            }
            ui.label(
                egui::RichText::new(
                    "The PIN cannot be recovered. A few unrelated words with a number are easy to remember and hard to guess.",
                )
                .color(p.text_weak)
                .size(12.5),
            );
            if !self.vault_status_banner.is_empty() {
                ui.colored_label(p.accent, &self.vault_status_banner);
            }
            if submit {
                let current = std::mem::take(&mut self.vault_current_pin);
                let new_pin = Zeroizing::new(std::mem::take(&mut self.vault_new_pin));
                if has_pin {
                    self.start_unlock(current, Purpose::ChangePin { new_pin }, &ctx);
                } else if let Err(e) = self.start_new_pin(&new_pin, false, &ctx) {
                    self.vault_status_banner = format!("Could not create the PIN: {e}");
                }
            }
        });
        ui.add_space(10.0);

        let mut test_cross_device = false;
        let cross_device_enabled = self.controller.settings.allow_cross_device_passkeys;
        card(ui, p, |ui| {
            row_label(
                ui,
                p,
                &format!("Passkeys & other devices ({})", self.vault.passkeys.len()),
                "Use a passkey from your phone, tablet, or USB/NFC security key via Windows FIDO2 hybrid transport.",
            );
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        self.busy.is_none() && cross_device_enabled,
                        egui::Button::new("Verify with passkey on another device…"),
                    )
                    .clicked()
                {
                    test_cross_device = true;
                }
                if !cross_device_enabled {
                    ui.colored_label(
                        p.text_weak,
                        "Enable \"Sign in with a passkey on another device\" above to use QR/hybrid passkeys.",
                    );
                }
            });
            if !self.vault.passkeys.is_empty() {
                ui.add_space(6.0);
                for pk in &self.vault.passkeys {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&pk.rp_id).strong());
                        ui.label(egui::RichText::new(&pk.user_name).color(p.text_weak));
                        ui.label(egui::RichText::new(format_date(pk.created_at_ms)).color(p.text_weak));
                    });
                }
            }
        });
        if test_cross_device {
            let ctx = ui.ctx().clone();
            self.start_cross_device_passkey(
                Purpose::CrossDeviceVerify {
                    rp_id: "oya.browser".to_string(),
                },
                "oya.browser".to_string(),
                "https://oya.browser".to_string(),
                0,
                &ctx,
            );
        }
        ui.add_space(10.0);

        card(ui, p, |ui| {
            row_label(
                ui,
                p,
                &format!("Saved passwords ({})", self.vault.passwords.len()),
                "",
            );
            let mut trigger_origin = None;
            let mut delete: Option<(String, String)> = None;
            ui.add_space(6.0);
            let cols = [
                TableCol::new("Site", 2.6, 100.0),
                TableCol::new("Username", 2.6, 100.0),
                TableCol::new("Saved", 0.8, 80.0),
                TableCol::new("After filling", 0.8, 90.0),
            ];
            let tail = 150.0;
            let texts: Vec<[String; 4]> = self
                .vault
                .passwords
                .iter()
                .map(|e| {
                    [
                        host_of(&e.origin),
                        e.username.clone(),
                        format_date(e.created_at_ms),
                        if e.auto_submit { "Signs in".to_string() } else { "Fill only".to_string() },
                    ]
                })
                .collect();
            let content = column_content_widths(
                ui,
                &cols,
                texts.iter().map(|t| t.iter().map(|s| s.as_str()).collect()),
            );
            let widths = table_widths(ui.available_width(), &cols, tail, &content);
            table_header(ui, p, &cols, &widths, tail);
            if self.vault.passwords.is_empty() {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("No saved passwords yet.").color(p.text_weak));
            }
            for (i, entry) in self.vault.passwords.iter().enumerate() {
                let cells = [
                    (host_of(&entry.origin), p.text),
                    (entry.username.clone(), p.text_weak),
                    (format_date(entry.created_at_ms), p.text_weak),
                    (
                        if entry.auto_submit { "Signs in".to_string() } else { "Fill only".to_string() },
                        p.text_weak,
                    ),
                ];
                let resp = table_row(ui, p, egui::Id::unique(("pw_row", i)), &widths, &cells, tail, |ui| {
                    if ui.small_button("Remove…").clicked() {
                        delete = Some((entry.origin.clone(), entry.username.clone()));
                    }
                    if ui.small_button("Sign in").clicked() {
                        trigger_origin = Some(entry.origin.clone());
                    }
                });
                resp.on_hover_text(format!("{}\n{}", entry.origin, entry.username));
            }
            if let Some((origin, username)) = delete {
                let summary = format!(
                    "Permanently delete the saved password for {username} on {}? This cannot be undone.",
                    host_of(&origin)
                );
                self.request_approval(ApprovalAction::DeletePassword { origin, username }, summary);
            }
            if let Some(origin) = trigger_origin {
                self.navigate_active(&origin);
                self.validation_status_msg.clear();
                self.active_validation_origin = Some(origin);
            }

            ui.add_space(14.0);
            ui.label(egui::RichText::new("Add a password").color(p.text));
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.vault_new_origin).hint_text("https://example.com").desired_width(220.0));
                ui.add(egui::TextEdit::singleline(&mut self.vault_new_username).hint_text("Username").desired_width(160.0));
                ui.add(egui::TextEdit::singleline(&mut self.vault_new_password).password(true).hint_text("Password").desired_width(160.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.vault_new_auto_submit, "Submit the form after filling");
                if ui.button("Save password").clicked() {
                    let origin = validate_and_extract_origin(self.vault_new_origin.trim())
                        .map(|o| o.to_string())
                        .unwrap_or_default();
                    let user = self.vault_new_username.trim().to_string();
                    let mut pass = std::mem::take(&mut self.vault_new_password);
                    let auto_sub = self.vault_new_auto_submit;
                    self.vault_status_banner = if !origin.starts_with("https://") {
                        "Enter the site as an https:// address.".to_string()
                    } else if !self.vault.upgrade_reasons().is_empty() {
                        "Set a new vault PIN first.".to_string()
                    } else {
                        match self.vault.store_password(&origin, &user, &pass, auto_sub) {
                            Ok(()) => format!("Saved password for {user} on {}.", host_of(&origin)),
                            Err(e) => format!("Not saved: {e}"),
                        }
                    };
                    pass.zeroize();
                }
            });
        });
    }

    pub(super) fn section_privacy(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let ctx = ui.ctx().clone();
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            let mut changed = false;
            changed |= toggle_row(
                ui,
                p,
                &mut s.block_third_party_cookies,
                "Block third-party trackers and cookies",
                "Uses WebView2 Strict tracking prevention. A few sites may not work; turn off to use Balanced.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.https_first_mode,
                "Always use secure connections",
                "Upgrades http:// pages to https://. Local network addresses are not upgraded.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.do_not_track,
                "Ask sites not to sell or share your data",
                "Sends the Global Privacy Control signal to page scripts. Applies to tabs opened after the change.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.allow_notifications,
                "Let sites ask to show notifications",
                "Off: every notification request is refused without asking.",
            );
            if changed {
                s.save();
            }
        });
        ui.add_space(10.0);

        card(ui, p, |ui| {
            row_label(
                ui,
                p,
                "Site permissions",
                "Sites you allowed or blocked for camera, microphone, location and more. Reset puts a site back to asking.",
            );
            let state = self.permission_list.lock().ok().and_then(|g| g.clone());
            ui.horizontal_wrapped(|ui| {
                if ui.button("Show sites").clicked() {
                    if let Ok(mut g) = self.permission_list.lock() {
                        *g = None;
                    }
                    match self.webviews.values().next() {
                        Some(twv) => {
                            if let Err(e) = query_permissions(&twv.webview, Arc::clone(&self.permission_list), ctx.clone()) {
                                self.settings_status = format!("Could not read site permissions: {e}");
                            }
                        }
                        None => self.settings_status = "Open any website first, then show site permissions.".to_string(),
                    }
                }
            });
            if let Some(result) = state {
                match result {
                    Err(e) => {
                        ui.colored_label(p.danger, e);
                    }
                    Ok(list) if list.is_empty() => {
                        ui.label(egui::RichText::new("No site has a saved permission.").color(p.text_weak));
                    }
                    Ok(list) => {
                        let mut reset = None;
                        for e in &list {
                            row_divider(ui, p);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(host_of(&e.origin)).color(p.text).strong());
                                let allowed = e.state
                                    == webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_PERMISSION_STATE_ALLOW.0;
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{} · {}",
                                        permission_kind_label(e.kind),
                                        if allowed { "Allowed" } else { "Blocked" }
                                    ))
                                    .color(p.text_weak),
                                );
                                if ui.small_button("Reset").clicked() {
                                    reset = Some(e.clone());
                                }
                            });
                        }
                        if let Some(entry) = reset
                            && let Some(twv) = self.webviews.values().next()
                        {
                            let _ = reset_permission(&twv.webview, &entry);
                            let _ = query_permissions(&twv.webview, Arc::clone(&self.permission_list), ctx.clone());
                        }
                    }
                }
            }
        });
        ui.add_space(10.0);

        card(ui, p, |ui| {
            row_label(
                ui,
                p,
                "Clear browsing data",
                "Deletes cookies, cache, site storage and history for every site. Saved passwords and bookmarks are kept.",
            );
            if ui.button("Clear browsing data…").clicked() {
                self.request_approval(
                    ApprovalAction::ClearBrowsingData,
                    "Delete cookies, cache, site storage and history for every site? You will be signed out of websites.".to_string(),
                );
            }
            if !self.settings_status.is_empty() {
                ui.colored_label(p.accent, &self.settings_status);
            }
        });
        ui.add_space(10.0);

        card(ui, p, |ui| {
            row_label(ui, p, "Protection status", "");
            let h = self.startup.hardening;
            let rows = [
                ("Web pages run in WebView2's Chromium sandbox", true),
                ("Microsoft SmartScreen checks downloads and sites", true),
                ("Settings and bookmarks are sealed against outside changes", true),
                ("Password vault locked to this PC", self.vault.is_device_bound()),
                ("System DLLs only (blocks DLL planting at run time)", h.dll_search_restricted),
                ("Code-injection points blocked", h.extension_points_disabled),
                ("No program code loaded from network or untrusted files", h.image_load_restricted),
                ("Remote control off", self.cdp_handle.is_none()),
            ];
            for (label, ok) in rows {
                ui.horizontal(|ui| {
                    paint_inline_icon(ui, if ok { Icon::Check } else { Icon::Warning }, if ok { p.success } else { p.danger });
                    ui.label(egui::RichText::new(label).color(p.text));
                });
            }
        });
    }

    pub(super) fn section_search_engine(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            row_label(ui, p, "Search engine used in the address bar and for new tabs", "Changing it needs your approval.");
            let mut choice = s.search_engine;
            for &engine in SearchEngine::all() {
                ui.radio_value(&mut choice, engine, engine.label());
            }
            s.search_engine = choice;
            if s.search_engine == SearchEngine::Custom {
                row_divider(ui, p);
                ui.horizontal_wrapped(|ui| {
                    ui.label("Home page");
                    if let Some(v) = staged_field(ui, &mut self.staged.home, &s.custom_home_url, "https://", 320.0) {
                        s.custom_home_url = v;
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label("Search address ({q} = query)");
                    if let Some(v) = staged_field(ui, &mut self.staged.template, &s.custom_search_template, "https://…{q}", 320.0) {
                        s.custom_search_template = v;
                    }
                });
            }
        });
    }

    pub(super) fn section_on_startup(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            for &beh in StartupBehavior::all() {
                ui.radio_value(&mut s.startup_behavior, beh, beh.label());
            }
            if s.startup_behavior == StartupBehavior::OpenSpecificUrl {
                ui.horizontal_wrapped(|ui| {
                    if let Some(v) = staged_field(ui, &mut self.staged.startup, &s.startup_custom_url, "https://", 360.0) {
                        s.startup_custom_url = v;
                    }
                });
            }
        });
    }

    pub(super) fn section_downloads(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            row_label(ui, p, "Download location", "Applies to tabs opened after the change. Changing it needs your approval.");
            ui.horizontal_wrapped(|ui| {
                if let Some(v) = staged_field(ui, &mut self.staged.download, &s.download_directory, "C:\\Users\\you\\Downloads", 420.0) {
                    s.download_directory = v;
                }
            });
            let dir = PathBuf::from(s.download_directory.trim());
            if !s.download_directory.trim().is_empty() && !(dir.is_absolute() && dir.is_dir()) {
                ui.colored_label(p.danger, "This folder does not exist; files will go to the Windows default Downloads folder.");
            }
            row_divider(ui, p);
            row_label(
                ui,
                p,
                "Risky file types",
                "Programs, scripts, shortcuts and disk images (.exe, .msi, .ps1, .bat, .js, .lnk, .iso …) wait for you to choose Keep before they download.",
            );
        });
    }

    pub(super) fn section_reset(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            row_label(
                ui,
                p,
                "Restore settings to their original defaults",
                "Resets search engine, appearance, privacy, media and startup settings. Bookmarks and saved passwords are kept.",
            );
            if ui.button("Reset settings…").clicked() {
                self.request_approval(
                    ApprovalAction::ResetSettings,
                    "Reset all Oya settings to their defaults?".to_string(),
                );
            }
        });
    }
}
