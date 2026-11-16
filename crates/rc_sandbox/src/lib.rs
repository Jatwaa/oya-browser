pub mod host_hardening;
pub mod os_sandbox;
pub mod policy;

pub use os_sandbox::{
    CrossDevicePasskeyAssertion, CrossDevicePasskeyOutcome, RENDERER_MEMORY_LIMIT_BYTES,
    SandboxedProcess, apply_renderer_mitigations, get_win32_client_physical_size,
    install_os_exception_filter, open_file_with_shell, prompt_cross_device_passkey,
    reclaim_win32_keyboard_focus, reveal_file_in_explorer, set_win32_fullscreen,
    set_window_dark_mode, spawn_sandboxed_renderer,
};
pub use policy::{CspPolicy, OriginKey, SecurityError, validate_and_extract_origin};
pub use host_hardening::{
    WEBVIEW2_ENV_VARS,
    HostHardening, WebView2Override, dpapi_protect, dpapi_unprotect, harden_host_process,
    is_workstation_locked, unexpected_dlls_beside_exe, webview2_overrides, writable_by_others,
};
