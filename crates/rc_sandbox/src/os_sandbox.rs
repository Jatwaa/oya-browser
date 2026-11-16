use std::io;
use std::process::{Child, Command, Stdio};

/// Hard memory limit per renderer process (1 GiB) to support large SPA ASTs while preventing runaway OOM.
pub const RENDERER_MEMORY_LIMIT_BYTES: usize = 1024 * 1024 * 1024;

pub struct SandboxedProcess {
    pub child: Child,
    pub sandboxed: bool,
    #[cfg(windows)]
    _job_handle: Option<WindowsJobHandle>,
}

#[cfg(windows)]
struct WindowsJobHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsJobHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

/// Spawns a child renderer process with cleared environment and OS-level resource/process isolation.
pub fn spawn_sandboxed_renderer(exe_path: &std::path::Path, extra_args: &[&str]) -> io::Result<SandboxedProcess> {
    let mut cmd = Command::new(exe_path);
    cmd.args(extra_args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    // Preserve SystemRoot on Windows so basic OS DLLs resolve cleanly,
    // and suppress any console window for child renderer processes.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
        if let Ok(sys_root) = std::env::var("SystemRoot") {
            cmd.env("SystemRoot", sys_root);
        }
    }

    let child = cmd.spawn()?;

    // The Job Object is attached right after spawn. The child only runs its own trusted start-up
    // code until then: it blocks on stdin, and no untrusted page content is sent to it until this
    // function has returned with the job in place.
    #[cfg(windows)]
    {
        let job = attach_windows_job_sandbox(&child);
        let sandboxed = job.is_some();
        Ok(SandboxedProcess {
            child,
            sandboxed,
            _job_handle: job,
        })
    }

    #[cfg(not(windows))]
    {
        Ok(SandboxedProcess {
            child,
            sandboxed: true,
        })
    }
}

/// Applies in-process OS hardening mitigations inside the child renderer process.
/// Returns `true` if OS mitigations were successfully enforced.
pub fn apply_renderer_mitigations() -> bool {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use windows_sys::Win32::System::Threading::{
            ProcessDynamicCodePolicy, ProcessStrictHandleCheckPolicy, SetProcessMitigationPolicy,
        };

        #[repr(C)]
        struct MitigationFlags(u32);

        unsafe {
            // RaiseExceptionOnInvalidHandleReference | HandleExceptionsPermanentlyEnabled
            let strict = MitigationFlags(0x3);
            let ok_strict = SetProcessMitigationPolicy(
                ProcessStrictHandleCheckPolicy,
                (&raw const strict).cast(),
                size_of::<MitigationFlags>(),
            );

            // Pure-Rust Boa interpreter needs zero RWX/dynamic code pages!
            let dyn_code = MitigationFlags(0x1);
            let ok_dyn = SetProcessMitigationPolicy(
                ProcessDynamicCodePolicy,
                (&raw const dyn_code).cast(),
                size_of::<MitigationFlags>(),
            );

            // Both policies must be in force for the renderer to count as hardened.
            ok_strict != 0 && ok_dyn != 0
        }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(windows)]
fn attach_windows_job_sandbox(child: &Child) -> Option<WindowsJobHandle> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS,
        JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    };

    unsafe {
        let job: HANDLE = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return None;
        }

        let mut ext_limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        ext_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        ext_limits.BasicLimitInformation.ActiveProcessLimit = 1;
        ext_limits.ProcessMemoryLimit = RENDERER_MEMORY_LIMIT_BYTES;

        let ok_limits = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const ext_limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        let mut ui_limits: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
        ui_limits.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS;

        let _ = SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            (&raw const ui_limits).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        );

        let proc_handle = child.as_raw_handle() as HANDLE;
        let ok_assign = AssignProcessToJobObject(job, proc_handle);
        if ok_limits == 0 || ok_assign == 0 {
            CloseHandle(job);
            return None;
        }

        Some(WindowsJobHandle(job))
    }
}

#[cfg(windows)]
#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: *mut core::ffi::c_void,
    number_parameters: u32,
    exception_information: [usize; 15],
}

#[cfg(windows)]
#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut core::ffi::c_void,
}

#[cfg(windows)]
unsafe extern "system" fn unhandled_seh_filter(info: *const ExceptionPointers) -> i32 {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let (code, addr) = unsafe {
        if !info.is_null() && !(*info).exception_record.is_null() {
            let rec = &*(*info).exception_record;
            (rec.exception_code, rec.exception_address as usize)
        } else {
            (0, 0)
        }
    };

    let code_name = match code {
        0xC0000005 => "EXCEPTION_ACCESS_VIOLATION",
        0xC00000FD => "EXCEPTION_STACK_OVERFLOW",
        0xC000001D => "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xC0000094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xC0000409 => "STATUS_STACK_BUFFER_OVERRUN",
        0xE06D7363 => "CPP_EH_EXCEPTION",
        _ => "WIN32_SEH_EXCEPTION",
    };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let pid = std::process::id();

    let _ = std::fs::create_dir_all("logs");
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/rustchrome.jsonl")
    {
        let _ = writeln!(
            file,
            r#"{{"timestamp_ms":{ts},"severity":"Crash","category":"Crash","origin":"os-seh","renderer_pid":{pid},"message":"FATAL OS EXCEPTION: {code_name} (code=0x{code:08X}) at address=0x{addr:016X}"}}"#
        );
        let _ = file.flush();
        let _ = file.sync_data();
    }
    1 // EXCEPTION_EXECUTE_HANDLER
}

/// Installs a low-level OS unhandled exception filter (Windows SEH) so native GPU/WebView2/FFI
/// faults are written and flushed to `logs/rustchrome.jsonl` before the process terminates.
pub fn install_os_exception_filter() {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetUnhandledExceptionFilter(
                lpTopLevelExceptionFilter: Option<
                    unsafe extern "system" fn(*const ExceptionPointers) -> i32,
                >,
            ) -> *mut core::ffi::c_void;
        }
        unsafe {
            let _ = SetUnhandledExceptionFilter(Some(unhandled_seh_filter));
        }
    }
}

/// Reclaims Win32 keyboard focus from any child HWND (such as an embedded WebView2 control)
/// back to the parent `eframe`/`winit` window so `egui::TextEdit` fields (like the URL bar)
/// immediately receive keyboard input when clicked.
pub fn reclaim_win32_keyboard_focus(parent_hwnd: isize) {
    #[cfg(windows)]
    {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetFocus() -> *mut core::ffi::c_void;
            fn SetFocus(hWnd: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        }
        if parent_hwnd != 0 {
            unsafe {
                let target = parent_hwnd as *mut core::ffi::c_void;
                if GetFocus() != target {
                    let _ = SetFocus(target);
                }
            }
        }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Win32Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[cfg(windows)]
#[repr(C)]
struct MonitorInfo {
    cb_size: u32,
    rc_monitor: Win32Rect,
    rc_work: Win32Rect,
    dw_flags: u32,
}

#[cfg(windows)]
struct SavedWindowBounds {
    style: isize,
    ex_style: isize,
    rect: Win32Rect,
    /// The window was maximized before full screen; it is maximized again on exit.
    was_maximized: bool,
}

#[cfg(windows)]
static SAVED_WINDOW_STATE: std::sync::Mutex<Option<SavedWindowBounds>> =
    std::sync::Mutex::new(None);

/// Queries the exact physical pixel dimensions `(width, height)` of the parent window's client area.
pub fn get_win32_client_physical_size(parent_hwnd: isize) -> Option<(u32, u32)> {
    #[cfg(windows)]
    {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetClientRect(hWnd: *mut core::ffi::c_void, lpRect: *mut Win32Rect) -> i32;
        }
        if parent_hwnd == 0 {
            return None;
        }
        let mut rc = Win32Rect::default();
        let ok = unsafe { GetClientRect(parent_hwnd as *mut core::ffi::c_void, &raw mut rc) };
        if ok != 0 {
            let w = (rc.right - rc.left).max(100) as u32;
            let h = (rc.bottom - rc.top).max(100) as u32;
            return Some((w, h));
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = parent_hwnd;
        None
    }
}

/// Transitions the Win32 top-level window into true borderless monitor-spanning fullscreen
/// (`rcMonitor` covering 100% of the physical screen including over the taskbar) or restores
/// its previous windowed style and bounds.
pub fn set_win32_fullscreen(parent_hwnd: isize, fullscreen: bool) -> Option<(u32, u32)> {
    #[cfg(windows)]
    {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetWindowLongPtrW(hWnd: *mut core::ffi::c_void, nIndex: i32) -> isize;
            fn SetWindowLongPtrW(
                hWnd: *mut core::ffi::c_void,
                nIndex: i32,
                dwNewLong: isize,
            ) -> isize;
            fn GetWindowRect(hWnd: *mut core::ffi::c_void, lpRect: *mut Win32Rect) -> i32;
            fn MonitorFromWindow(
                hWnd: *mut core::ffi::c_void,
                dwFlags: u32,
            ) -> *mut core::ffi::c_void;
            fn GetMonitorInfoW(
                hMonitor: *mut core::ffi::c_void,
                lpmi: *mut MonitorInfo,
            ) -> i32;
            fn SetWindowPos(
                hWnd: *mut core::ffi::c_void,
                hWndInsertAfter: *mut core::ffi::c_void,
                X: i32,
                Y: i32,
                cx: i32,
                cy: i32,
                uFlags: u32,
            ) -> i32;
            fn IsZoomed(hWnd: *mut core::ffi::c_void) -> i32;
            fn ShowWindow(hWnd: *mut core::ffi::c_void, nCmdShow: i32) -> i32;
        }

        if parent_hwnd == 0 {
            return None;
        }
        let hwnd = parent_hwnd as *mut core::ffi::c_void;
        const SW_MAXIMIZE: i32 = 3;
        const SW_RESTORE: i32 = 9;
        const WS_MAXIMIZE: isize = 0x0100_0000;
        const GWL_STYLE: i32 = -16;
        const GWL_EXSTYLE: i32 = -20;
        const WS_OVERLAPPEDWINDOW: isize = 0x00CF0000;
        const WS_POPUP: isize = 0x80000000u32 as isize;
        const WS_VISIBLE: isize = 0x10000000;
        const WS_EX_WINDOWEDGE: isize = 0x00000100;
        const WS_EX_CLIENTEDGE: isize = 0x00000200;
        const MONITOR_DEFAULTTONEAREST: u32 = 2;
        const SWP_NOOWNERZORDER: u32 = 0x0200;
        const SWP_FRAMECHANGED: u32 = 0x0020;
        const SWP_SHOWWINDOW: u32 = 0x0040;

        unsafe {
            if fullscreen {
                // A maximized window keeps a maximized client area (smaller than the monitor)
                // even after its frame is removed, which left a strip of window frame below the
                // page. Restore it to normal size first, as Chromium does.
                let was_maximized = IsZoomed(hwnd) != 0;
                if was_maximized {
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                }
                let cur_style = GetWindowLongPtrW(hwnd, GWL_STYLE);
                let cur_ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
                let mut cur_rect = Win32Rect::default();
                let _ = GetWindowRect(hwnd, &raw mut cur_rect);

                if let Ok(mut guard) = SAVED_WINDOW_STATE.lock()
                    && guard.is_none()
                {
                    *guard = Some(SavedWindowBounds {
                        style: cur_style & !WS_MAXIMIZE,
                        ex_style: cur_ex,
                        rect: cur_rect,
                        was_maximized,
                    });
                }

                let hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
                let mut mi = MonitorInfo {
                    cb_size: std::mem::size_of::<MonitorInfo>() as u32,
                    rc_monitor: Win32Rect::default(),
                    rc_work: Win32Rect::default(),
                    dw_flags: 0,
                };
                if !hmon.is_null() && GetMonitorInfoW(hmon, &raw mut mi) != 0 {
                    let new_style =
                        (cur_style & !WS_OVERLAPPEDWINDOW & !WS_MAXIMIZE) | WS_POPUP | WS_VISIBLE;
                    let new_ex = cur_ex & !(WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE);
                    let _ = SetWindowLongPtrW(hwnd, GWL_STYLE, new_style);
                    let _ = SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_ex);

                    let mw = (mi.rc_monitor.right - mi.rc_monitor.left).max(100);
                    let mh = (mi.rc_monitor.bottom - mi.rc_monitor.top).max(100);
                    let _ = SetWindowPos(
                        hwnd,
                        std::ptr::null_mut(),
                        mi.rc_monitor.left,
                        mi.rc_monitor.top,
                        mw,
                        mh,
                        SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW,
                    );
                    return Some((mw as u32, mh as u32));
                }
            } else if let Ok(mut guard) = SAVED_WINDOW_STATE.lock()
                && let Some(saved) = guard.take()
            {
                let _ = SetWindowLongPtrW(hwnd, GWL_STYLE, saved.style | WS_VISIBLE);
                let _ = SetWindowLongPtrW(hwnd, GWL_EXSTYLE, saved.ex_style);
                let w = (saved.rect.right - saved.rect.left).max(400);
                let h = (saved.rect.bottom - saved.rect.top).max(300);
                let _ = SetWindowPos(
                    hwnd,
                    std::ptr::null_mut(),
                    saved.rect.left,
                    saved.rect.top,
                    w,
                    h,
                    SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW,
                );
                if saved.was_maximized {
                    let _ = ShowWindow(hwnd, SW_MAXIMIZE);
                }
                return Some((w as u32, h as u32));
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = (parent_hwnd, fullscreen);
        None
    }
}

/// Cryptographic assertion returned by an external passkey authenticator (phone, tablet, or security key)
/// via Windows Cross-Device WebAuthn (`webauthn.dll`).
#[derive(Debug, Clone)]
pub struct CrossDevicePasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub client_data_json: String,
}

/// Outcome of prompting the user to sign in using a passkey on another device.
#[derive(Debug, Clone)]
pub enum CrossDevicePasskeyOutcome {
    Verified(CrossDevicePasskeyAssertion),
    Cancelled,
    Unavailable(String),
    Failed(String),
}

/// Invokes Windows' native Cross-Device Passkey / FIDO2 Hybrid Transport ceremony (`webauthn.dll`)
/// so the user can sign in using a passkey stored on another device (iPhone, iPad, Android phone via
/// QR code + Bluetooth, or a USB/NFC security key).
///
/// This is a blocking modal call and should be run on a worker thread.
pub fn prompt_cross_device_passkey(
    parent_hwnd: isize,
    rp_id: &str,
    origin: &str,
    challenge_b64url: &str,
) -> CrossDevicePasskeyOutcome {
    #[cfg(windows)]
    {
        use core::ffi::c_void;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        #[repr(C)]
        struct WebAuthnClientData {
            dw_version: u32,
            cb_client_data_json: u32,
            pb_client_data_json: *const u8,
            pwsz_hash_alg_id: *const u16,
        }

        #[repr(C)]
        struct WebAuthnCredentials {
            c_credentials: u32,
            p_credentials: *const c_void,
        }

        #[repr(C)]
        struct WebAuthnExtensions {
            c_extensions: u32,
            p_extensions: *const c_void,
        }

        #[repr(C)]
        struct WebAuthnGetAssertionOptions {
            dw_version: u32,
            dw_timeout_milliseconds: u32,
            credential_list: WebAuthnCredentials,
            extensions: WebAuthnExtensions,
            dw_authenticator_attachment: u32,
            dw_user_verification_requirement: u32,
            dw_flags: u32,
        }

        #[repr(C)]
        struct WebAuthnCredential {
            dw_version: u32,
            cb_id: u32,
            pb_id: *const u8,
            pwsz_credential_type: *const u16,
        }

        #[repr(C)]
        struct WebAuthnAssertion {
            dw_version: u32,
            cb_authenticator_data: u32,
            pb_authenticator_data: *const u8,
            cb_signature: u32,
            pb_signature: *const u8,
            credential: WebAuthnCredential,
            cb_user_id: u32,
            pb_user_id: *const u8,
        }

        type FnGetAssertion = unsafe extern "system" fn(
            hwnd: *mut c_void,
            pwsz_rp_id: *const u16,
            p_client_data: *const WebAuthnClientData,
            p_options: *const WebAuthnGetAssertionOptions,
            pp_assertion: *mut *mut WebAuthnAssertion,
        ) -> i32;
        type FnFreeAssertion = unsafe extern "system" fn(p_assertion: *mut WebAuthnAssertion);

        unsafe extern "system" {
            fn GetForegroundWindow() -> *mut c_void;
        }

        fn to_wide_null(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        let clean_rp = rp_id.trim();
        if clean_rp.is_empty() {
            return CrossDevicePasskeyOutcome::Failed("Missing relying party ID".to_string());
        }

        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
            challenge_b64url.replace('"', ""),
            origin.replace('"', "")
        );

        unsafe {
            let dll_name = to_wide_null("webauthn.dll");
            let hmod = LoadLibraryW(dll_name.as_ptr());
            if hmod.is_null() {
                return CrossDevicePasskeyOutcome::Unavailable(
                    "Windows WebAuthn service (webauthn.dll) is not available on this OS version."
                        .to_string(),
                );
            }

            let get_proc =
                GetProcAddress(hmod, c"WebAuthnAuthenticatorGetAssertion".as_ptr().cast());
            let free_proc = GetProcAddress(hmod, c"WebAuthnFreeAssertion".as_ptr().cast());
            let (Some(get_fn_raw), Some(free_fn_raw)) = (get_proc, free_proc) else {
                FreeLibrary(hmod);
                return CrossDevicePasskeyOutcome::Unavailable(
                    "Windows WebAuthn API entrypoints were not found.".to_string(),
                );
            };

            let get_assertion: FnGetAssertion = std::mem::transmute(get_fn_raw);
            let free_assertion: FnFreeAssertion = std::mem::transmute(free_fn_raw);

            let hwnd = if parent_hwnd != 0 {
                parent_hwnd as *mut c_void
            } else {
                GetForegroundWindow()
            };
            let rp_w = to_wide_null(clean_rp);
            let alg_w = to_wide_null("SHA-256");

            let client_bytes = client_data_json.as_bytes();
            let client_data = WebAuthnClientData {
                dw_version: 1,
                cb_client_data_json: client_bytes.len() as u32,
                pb_client_data_json: client_bytes.as_ptr(),
                pwsz_hash_alg_id: alg_w.as_ptr(),
            };

            // dwAuthenticatorAttachment = 2 (WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM)
            // Prompts for QR-code phone/tablet passkey or external FIDO2 security key.
            let options = WebAuthnGetAssertionOptions {
                dw_version: 1,
                dw_timeout_milliseconds: 120_000,
                credential_list: WebAuthnCredentials {
                    c_credentials: 0,
                    p_credentials: std::ptr::null(),
                },
                extensions: WebAuthnExtensions {
                    c_extensions: 0,
                    p_extensions: std::ptr::null(),
                },
                dw_authenticator_attachment: 2,
                dw_user_verification_requirement: 2,
                dw_flags: 0,
            };

            let mut assertion_ptr: *mut WebAuthnAssertion = std::ptr::null_mut();
            let hr = get_assertion(
                hwnd,
                rp_w.as_ptr(),
                &raw const client_data,
                &raw const options,
                &raw mut assertion_ptr,
            );

            let outcome = if hr == 0 && !assertion_ptr.is_null() {
                let a = &*assertion_ptr;
                let cred_id = if !a.credential.pb_id.is_null() && a.credential.cb_id > 0 {
                    std::slice::from_raw_parts(a.credential.pb_id, a.credential.cb_id as usize)
                        .to_vec()
                } else {
                    Vec::new()
                };
                let auth_data =
                    if !a.pb_authenticator_data.is_null() && a.cb_authenticator_data > 0 {
                        std::slice::from_raw_parts(
                            a.pb_authenticator_data,
                            a.cb_authenticator_data as usize,
                        )
                        .to_vec()
                    } else {
                        Vec::new()
                    };
                let signature = if !a.pb_signature.is_null() && a.cb_signature > 0 {
                    std::slice::from_raw_parts(a.pb_signature, a.cb_signature as usize).to_vec()
                } else {
                    Vec::new()
                };
                let user_handle = if !a.pb_user_id.is_null() && a.cb_user_id > 0 {
                    std::slice::from_raw_parts(a.pb_user_id, a.cb_user_id as usize).to_vec()
                } else {
                    Vec::new()
                };
                free_assertion(assertion_ptr);
                CrossDevicePasskeyOutcome::Verified(CrossDevicePasskeyAssertion {
                    credential_id: cred_id,
                    authenticator_data: auth_data,
                    signature,
                    user_handle,
                    client_data_json,
                })
            } else {
                let code = hr as u32;
                // NTE_USER_CANCELLED (0x80090036) or HRESULT_FROM_WIN32(ERROR_CANCELLED) (0x800704C7)
                if code == 0x8009_0036 || code == 0x8007_04C7 {
                    CrossDevicePasskeyOutcome::Cancelled
                } else if code == 0x8009_0027 || code == 0x8007_0032 {
                    CrossDevicePasskeyOutcome::Unavailable(format!(
                        "Cross-device passkey transport is unavailable on this system (0x{code:08X})."
                    ))
                } else {
                    CrossDevicePasskeyOutcome::Failed(format!(
                        "Cross-device passkey verification did not complete (0x{code:08X})."
                    ))
                }
            };

            FreeLibrary(hmod);
            outcome
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (parent_hwnd, rp_id, origin, challenge_b64url);
        CrossDevicePasskeyOutcome::Unavailable(
            "Cross-device passkeys are only supported on Windows.".to_string(),
        )
    }
}

/// Applies Windows DWM dark or light mode to the native window caption/title bar.
pub fn set_window_dark_mode(hwnd: isize, dark: bool) {
    #[cfg(windows)]
    {
        if hwnd == 0 {
            return;
        }
        use core::ffi::c_void;
        use windows_sys::Win32::Foundation::{FreeLibrary, HWND};
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SetWindowPos, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOOWNERZORDER,
            SWP_NOSIZE, SWP_NOZORDER,
        };

        type DwmSetWindowAttributeFn =
            unsafe extern "system" fn(hwnd: HWND, dw_attribute: u32, pv_attribute: *const c_void, cb_attribute: u32) -> i32;

        let dll: Vec<u16> = "dwmapi.dll\0".encode_utf16().collect();
        // SAFETY: dynamically loading system dwmapi.dll and calling DwmSetWindowAttribute on a valid HWND.
        unsafe {
            let hmod = LoadLibraryW(dll.as_ptr());
            if hmod.is_null() {
                return;
            }
            if let Some(proc) = GetProcAddress(hmod, c"DwmSetWindowAttribute".as_ptr().cast()) {
                let dwm_set: DwmSetWindowAttributeFn = core::mem::transmute(proc);
                let val: i32 = if dark { 1 } else { 0 };
                // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 11 / 10 20H1+), fallback 19 (older Win10).
                let hr = dwm_set(
                    hwnd as HWND,
                    20,
                    (&val as *const i32).cast(),
                    core::mem::size_of::<i32>() as u32,
                );
                if hr < 0 {
                    let _ = dwm_set(
                        hwnd as HWND,
                        19,
                        (&val as *const i32).cast(),
                        core::mem::size_of::<i32>() as u32,
                    );
                }
                let _ = SetWindowPos(
                    hwnd as HWND,
                    core::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE
                        | SWP_NOSIZE
                        | SWP_NOZORDER
                        | SWP_NOOWNERZORDER
                        | SWP_NOACTIVATE
                        | SWP_FRAMECHANGED,
                );
            }
            FreeLibrary(hmod);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (hwnd, dark);
    }
}

