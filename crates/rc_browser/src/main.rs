#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bookmarks;
mod gui;
mod integrity;
mod tab_manager;

use gui::RustChromeApp;
use rc_cdp::start_cdp_server;
use rc_log::{
    DiagnosticEvent, LogCategory, Severity, install_panic_and_exit_hooks,
    write_emergency_event_to_disk,
};
use rc_sandbox::install_os_exception_filter;
use std::sync::mpsc;
use tab_manager::BrowserController;

/// File in the data folder naming an existing WebView2 profile folder from an older build.
const PROFILE_POINTER: &str = "webview2_profile_location.txt";

/// The WebView2 user-data folder to use: an older build's profile if one was adopted (so the
/// user stays signed in to websites), otherwise `WebView2` inside the data folder.
pub fn webview2_profile_dir() -> std::path::PathBuf {
    if let Ok(saved) = std::fs::read_to_string(PROFILE_POINTER) {
        let dir = std::path::PathBuf::from(saved.trim());
        if dir.is_absolute() && dir.is_dir() {
            return dir;
        }
    }
    // Must be absolute: WebView2 resolves a relative folder against the program's own folder,
    // not the working directory, which put sign-in data next to the executable.
    std::env::current_dir()
        .map(|d| d.join("WebView2"))
        .unwrap_or_else(|_| std::path::PathBuf::from("WebView2"))
}

/// Switches the working directory to `%LOCALAPPDATA%\OyaBrowser`. Renderer child processes
/// inherit it.
///
/// The first time, data written by older builds is picked up from the folder the browser was
/// started from or the folder holding the executable (older builds kept everything next to
/// whichever of these was current): settings, bookmarks and the old vault file are copied, and
/// an existing WebView2 profile is used where it is. Copying a profile would sign the user out
/// of sites such as Google, whose sessions are bound to the original profile. Nothing is deleted
/// from the old location.
fn enter_app_data_dir() {
    let Some(base) = std::env::var_os("LOCALAPPDATA").filter(|b| !b.is_empty()) else {
        return;
    };
    let target = std::path::PathBuf::from(base).join("OyaBrowser");
    if std::fs::create_dir_all(target.join("logs")).is_err() {
        return;
    }

    let mut sources = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        sources.push(cwd);
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()))
        && !sources.contains(&exe_dir)
    {
        sources.push(exe_dir);
    }
    sources.retain(|s| *s != target);

    // Prefer the source with the most recently modified bookmarks/settings.
    let modified = |dir: &std::path::Path| {
        ["bookmarks.json", "settings.json"]
            .iter()
            .filter_map(|f| std::fs::metadata(dir.join(f)).and_then(|m| m.modified()).ok())
            .max()
    };
    sources.sort_by_key(|s| std::cmp::Reverse(modified(s)));

    let new_profile = target.join("WebView2");
    let pointer = target.join(PROFILE_POINTER);
    for old in &sources {
        for name in ["settings.json", "bookmarks.json", "logs/rustchrome_vault.json"] {
            let (from, to) = (old.join(name), target.join(name));
            if from.is_file() && !to.exists() {
                let _ = std::fs::copy(&from, &to);
            }
        }
        let old_profile = old.join("logs").join("webview_profile");
        if old_profile.is_dir()
            && old_profile.is_absolute()
            && !new_profile.exists()
            && !pointer.exists()
        {
            let _ = std::fs::write(&pointer, old_profile.to_string_lossy().as_bytes());
        }
    }
    let _ = std::env::set_current_dir(&target);
}

/// Findings from the start-up checks, shown to the user by the GUI.
pub struct StartupSecurity {
    pub hardening: rc_sandbox::HostHardening,
    /// WebView2 overrides that were found (environment variables are removed before WebView2
    /// starts; blocking policies stop web pages from loading).
    pub webview2_overrides: Vec<rc_sandbox::WebView2Override>,
    /// DLL files sitting next to the program (Oya ships none).
    pub planted_dlls: Vec<String>,
    /// Other accounts that can modify Oya's program folder.
    pub program_folder_writers: Vec<String>,
    /// Other accounts that can modify the folder holding website sign-ins.
    pub profile_folder_writers: Vec<String>,
    /// `--remote-debugging-port` given on the command line; needs approval before starting.
    pub debug_port: Option<u16>,
}

fn startup_security_checks() -> StartupSecurity {
    let settings = tab_manager::BrowserSettings::load();
    let hardening = rc_sandbox::harden_host_process(settings.block_code_injection);
    let exe = std::env::current_exe().ok();
    let exe_name = exe
        .as_ref()
        .and_then(|e| e.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "oya_browser.exe".to_string());
    let webview2_overrides = rc_sandbox::webview2_overrides(&exe_name);
    for var in rc_sandbox::host_hardening::WEBVIEW2_ENV_VARS {
        if std::env::var_os(var).is_some() {
            // SAFETY: called on the main thread at start-up, before any other thread exists or
            // reads the environment.
            unsafe { std::env::remove_var(var) };
        }
    }
    let program_folder_writers = exe
        .as_ref()
        .and_then(|e| e.parent())
        .and_then(|d| rc_sandbox::writable_by_others(d).ok())
        .unwrap_or_default();
    let profile_dir = webview2_profile_dir();
    let profile_dir = std::fs::canonicalize(&profile_dir).unwrap_or(profile_dir);
    let profile_folder_writers = if profile_dir.exists() {
        rc_sandbox::writable_by_others(&profile_dir).unwrap_or_default()
    } else {
        Vec::new()
    };
    StartupSecurity {
        hardening,
        webview2_overrides,
        planted_dlls: rc_sandbox::unexpected_dlls_beside_exe(),
        program_folder_writers,
        profile_folder_writers,
        debug_port: None,
    }
}

fn main() {
    install_os_exception_filter();
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--type=renderer") {
        // Renderers handle untrusted content: always load DLLs from System32 only and block
        // injection points.
        let _ = rc_sandbox::harden_host_process(true);
        install_panic_and_exit_hooks("renderer");
        // Report "sandboxed" only if the mitigation policies actually apply in this process.
        rc_renderer::run_renderer_stdio(false);
        write_emergency_event_to_disk(&DiagnosticEvent::new(
            Severity::LowLevel,
            LogCategory::Lifecycle,
            "renderer",
            std::process::id(),
            "Renderer child process exited cleanly",
        ));
        return;
    }

    // Keep all browser data (settings, bookmarks, logs, WebView2 profile) in one per-user folder
    // instead of whatever directory the browser happened to be started from.
    enter_app_data_dir();
    install_panic_and_exit_hooks("browser");
    let startup = startup_security_checks();

    let mut headless = false;
    let mut dump_dom = false;
    let mut cdp_port: Option<u16> = None;
    let mut initial_url = "rustchrome://newtab".to_string();

    for arg in args.iter().skip(1) {
        if arg == "--headless" {
            headless = true;
        } else if arg == "--dump-dom" {
            dump_dom = true;
            headless = true;
        } else if let Some(port_str) = arg.strip_prefix("--remote-debugging-port=") {
            cdp_port = port_str.parse::<u16>().ok();
        } else if !arg.starts_with("--") {
            initial_url = arg.clone();
        }
    }

    // Headless automation starts the DevTools server at once (the caller asked for it). The GUI
    // asks the user first; see `StartupSecurity::debug_port`.
    let cdp_rx = if let (true, Some(port)) = (headless, cdp_port) {
        let (tx, rx) = mpsc::channel();
        match start_cdp_server(port, tx) {
            Ok(handle) => {
                eprintln!("DevTools listening on {}", handle.browser_ws_url());
                Some(rx)
            }
            Err(err) => {
                eprintln!("Failed to start CDP server on port {port}: {err}");
                None
            }
        }
    } else {
        None
    };

    if headless {
        let mut controller = BrowserController::new();
        if let Err(err) = controller.navigate(&initial_url, false) {
            eprintln!("Navigation failed: {err}");
            std::process::exit(1);
        }

        if dump_dom {
            match controller.dump_dom() {
                Ok((html, count)) => {
                    let tab = controller.tab();
                    println!(
                        "<!-- RustChrome DOM Dump | nodes={count} | pid={} | sandboxed={} -->",
                        tab.active_renderer_pid, tab.active_sandboxed
                    );
                    println!("{html}");
                    for log in &tab.console_logs {
                        eprintln!("[console] {log}");
                    }
                    for err in &tab.script_errors {
                        eprintln!("[script-error] {err}");
                    }
                }
                Err(err) => {
                    eprintln!("DOM dump failed: {err}");
                    std::process::exit(1);
                }
            }
            return;
        }

        if let Some(rx) = cdp_rx {
            while let Ok(req) = rx.recv() {
                controller.handle_cdp_request(req);
            }
        }
        return;
    }

    let mut viewport_builder = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1120.0, 740.0])
        .with_title("Oya Browser");

    if let Some(icon_data) = gui::load_oya_window_icon() {
        viewport_builder = viewport_builder.with_icon(std::sync::Arc::new(icon_data));
    }

    let native_options = eframe::NativeOptions {
        viewport: viewport_builder,
        ..Default::default()
    };

    if let Err(err) = eframe::run_native(
        "Oya Browser",
        native_options,
        Box::new(move |_cc| {
            Ok(Box::new(RustChromeApp::new(
                &initial_url,
                StartupSecurity {
                    debug_port: cdp_port,
                    ..startup
                },
            )))
        }),
    ) {
        write_emergency_event_to_disk(&DiagnosticEvent::new(
            Severity::Crash,
            LogCategory::Crash,
            "browser",
            std::process::id(),
            format!("eframe::run_native failed: {err}"),
        ));
        eprintln!("Failed to launch Oya Browser GUI: {err}");
        std::process::exit(1);
    }

    write_emergency_event_to_disk(&DiagnosticEvent::new(
        Severity::LowLevel,
        LogCategory::Lifecycle,
        "browser",
        std::process::id(),
        "Browser UI event loop exited normally",
    ));
}
