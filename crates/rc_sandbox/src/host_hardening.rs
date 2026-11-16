//! Protections and integrity checks for the Oya browser process itself (Windows).
//!
//! Everything here acts only on Oya's own process, files and settings: nothing changes system
//! configuration or other programs.

/// What [`harden_host_process`] managed to switch on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostHardening {
    /// DLLs loaded at run time come only from System32 (not the program folder or the
    /// working directory).
    pub dll_search_restricted: bool,
    /// Legacy injection points (AppInit DLLs, global window hooks, Winsock LSPs) are blocked.
    pub extension_points_disabled: bool,
    /// Images from network shares or low-integrity files cannot be loaded; System32 is preferred.
    pub image_load_restricted: bool,
}

/// Applies Windows process-mitigation policies to the browser process.
///
/// `block_injection` controls the extension-point policy, which also stops a few legacy input
/// method editors and assistive tools that rely on global hooks.
pub fn harden_host_process(block_injection: bool) -> HostHardening {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use windows_sys::Win32::System::LibraryLoader::{
            LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
        };
        use windows_sys::Win32::System::Threading::{
            ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
        };
        let mut out = HostHardening::default();
        // SAFETY: plain Win32 calls with correctly sized, initialised policy structures.
        unsafe {
            out.dll_search_restricted = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0;
            if block_injection {
                let flags: u32 = 0x1; // DisableExtensionPoints
                out.extension_points_disabled = SetProcessMitigationPolicy(
                    ProcessExtensionPointDisablePolicy,
                    (&raw const flags).cast(),
                    size_of::<u32>(),
                ) != 0;
            }
            // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
            let flags: u32 = 0x1 | 0x2 | 0x4;
            out.image_load_restricted = SetProcessMitigationPolicy(
                ProcessImageLoadPolicy,
                (&raw const flags).cast(),
                size_of::<u32>(),
            ) != 0;
        }
        out
    }
    #[cfg(not(windows))]
    {
        let _ = block_injection;
        HostHardening::default()
    }
}

/// `*.dll` files in the program's own folder. Oya ships none, so any found there were placed by
/// someone else (a classic DLL-planting trick).
pub fn unexpected_dlls_beside_exe() -> Vec<String> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_ascii_lowercase().ends_with(".dll"))
        .collect();
    found.sort();
    found
}

/// Encrypts `data` so that only the current Windows user on this PC can decrypt it (DPAPI).
pub fn dpapi_protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        dpapi(data, entropy, true)
    }
    #[cfg(not(windows))]
    {
        let _ = (data, entropy);
        Err("DPAPI is only available on Windows".to_string())
    }
}

/// Reverses [`dpapi_protect`]. Fails for another user or another PC.
pub fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        dpapi(data, entropy, false)
    }
    #[cfg(not(windows))]
    {
        let _ = (data, entropy);
        Err("DPAPI is only available on Windows".to_string())
    }
}

#[cfg(windows)]
fn dpapi(data: &[u8], entropy: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let extra = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: input/entropy blobs point at live slices; DPAPI allocates `output` with
    // LocalAlloc, which is copied out and released with LocalFree.
    unsafe {
        let ok = if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return Err(format!(
                "Windows data protection failed ({})",
                std::io::Error::last_os_error()
            ));
        }
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        // Wipe before freeing: unprotected output may be key material.
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
        Ok(bytes)
    }
}

/// True while the Windows session is locked (lock screen or secure desktop showing).
pub fn is_workstation_locked() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::StationsAndDesktops::{
            CloseDesktop, DESKTOP_SWITCHDESKTOP, OpenInputDesktop, SwitchDesktop,
        };
        // SAFETY: the desktop handle is checked and closed. SwitchDesktop to the current input
        // desktop is a no-op that fails only when the session is locked.
        unsafe {
            let desk = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
            if desk.is_null() {
                return true;
            }
            let switched = SwitchDesktop(desk) != 0;
            CloseDesktop(desk);
            !switched
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// An outside setting that would change which WebView2 runtime Oya uses or how it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebView2Override {
    pub source: String,
    /// True when the override can load a different (possibly malicious) browser runtime, so Oya
    /// must not start WebView2 while it is present.
    pub blocking: bool,
}

/// Environment variables that WebView2 reads at start-up.
pub const WEBVIEW2_ENV_VARS: [&str; 6] = [
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
];

/// Finds WebView2 overrides: environment variables (which the caller should remove from its own
/// process before WebView2 starts) and Group Policy / registry settings that apply to `exe_name`.
pub fn webview2_overrides(exe_name: &str) -> Vec<WebView2Override> {
    let mut found: Vec<WebView2Override> = WEBVIEW2_ENV_VARS
        .iter()
        .filter(|v| std::env::var_os(v).is_some())
        .map(|v| WebView2Override {
            source: format!("environment variable {v}"),
            blocking: false,
        })
        .collect();
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        for (root, root_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            for (policy, blocking) in [
                ("BrowserExecutableFolder", true),
                ("ReleaseChannelPreference", false),
                ("ReleaseChannels", false),
                ("ChannelSearchKind", false),
            ] {
                let key = format!("Software\\Policies\\Microsoft\\Edge\\WebView2\\{policy}");
                for name in registry_value_names(root, &key) {
                    if name == "*" || name.eq_ignore_ascii_case(exe_name) {
                        found.push(WebView2Override {
                            source: format!("policy {root_name}\\{key} ({name})"),
                            blocking,
                        });
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    let _ = exe_name;
    found
}

#[cfg(windows)]
fn registry_value_names(
    root: windows_sys::Win32::System::Registry::HKEY,
    path: &str,
) -> Vec<String> {
    use windows_sys::Win32::System::Registry::{
        HKEY, KEY_READ, RegCloseKey, RegEnumValueW, RegOpenKeyExW,
    };
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key: HKEY = std::ptr::null_mut();
    let mut names = Vec::new();
    // SAFETY: the key handle is opened read-only, used with sized buffers and closed.
    unsafe {
        if RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return names;
        }
        for index in 0..256u32 {
            let mut buf = [0u16; 512];
            let mut len = buf.len() as u32;
            let rc = RegEnumValueW(
                key,
                index,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if rc != 0 {
                break;
            }
            names.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
        RegCloseKey(key);
    }
    names
}

/// Accounts other than the current user, SYSTEM, Administrators and TrustedInstaller that can
/// modify `path`. An empty list means only you (and the system) can change it.
pub fn writable_by_others(path: &std::path::Path) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        acl::writers_other_than_me(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(Vec::new())
    }
}

#[cfg(windows)]
mod acl {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
        GetAclInformation, GetTokenInformation, LookupAccountSidW, PSID, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const INHERIT_ONLY_ACE: u8 = 0x08;
    const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA / ADD_FILE
        | 0x0000_0004 // FILE_APPEND_DATA / ADD_SUBDIRECTORY
        | 0x0001_0000 // DELETE
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000; // GENERIC_WRITE
    const TRUSTED: [&str; 4] = [
        "S-1-5-18",     // SYSTEM
        "S-1-5-32-544", // Administrators
        "S-1-3-0",      // CREATOR OWNER (means: whoever creates the item, i.e. you)
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
    ];

    unsafe fn sid_string(sid: PSID) -> Option<String> {
        let mut out: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 || out.is_null() {
            return None;
        }
        let mut len = 0;
        while unsafe { *out.add(len) } != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
        unsafe { LocalFree(out.cast()) };
        Some(s)
    }

    unsafe fn account_name(sid: PSID) -> Option<String> {
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let (mut nl, mut dl, mut use_) = (256u32, 256u32, 0i32);
        let ok = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut nl,
                domain.as_mut_ptr(),
                &mut dl,
                &mut use_,
            )
        };
        if ok == 0 {
            return None;
        }
        let n = String::from_utf16_lossy(&name[..nl as usize]);
        let d = String::from_utf16_lossy(&domain[..dl as usize]);
        Some(if d.is_empty() { n } else { format!("{d}\\{n}") })
    }

    fn current_user_sid() -> Option<String> {
        // SAFETY: token handle checked and closed; buffer sized by the first call.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            let mut buf = vec![0u8; needed as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), needed, &mut needed);
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            sid_string(user.User.Sid)
        }
    }

    pub fn writers_other_than_me(path: &std::path::Path) -> Result<Vec<String>, String> {
        let me = current_user_sid().ok_or("could not read the current user")?;
        let wide: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut others = Vec::new();
        // SAFETY: the security descriptor is allocated by Windows and freed with LocalFree; ACEs
        // are read through GetAce within the reported count.
        unsafe {
            let rc = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != 0 {
                return Err(format!("could not read permissions (error {rc})"));
            }
            if dacl.is_null() {
                LocalFree(sd);
                return Ok(vec!["Everyone (no access list at all)".to_string()]);
            }
            let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
            if GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) != 0
            {
                for i in 0..info.AceCount {
                    let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                    if GetAce(dacl, i, &mut ace) == 0 || ace.is_null() {
                        continue;
                    }
                    let bytes = ace as *const u8;
                    let (ace_type, flags) = (*bytes, *bytes.add(1));
                    if ace_type != ACCESS_ALLOWED_ACE_TYPE || flags & INHERIT_ONLY_ACE != 0 {
                        continue;
                    }
                    let mask = std::ptr::read_unaligned(bytes.add(4) as *const u32);
                    if mask & WRITE_RIGHTS == 0 {
                        continue;
                    }
                    let sid = bytes.add(8) as PSID;
                    let Some(s) = sid_string(sid) else { continue };
                    // S-1-15-*: app-container sandbox identities (WebView2 grants its own
                    // sandboxed processes access); not other people's accounts.
                    if s == me || TRUSTED.contains(&s.as_str()) || s.starts_with("S-1-15-") {
                        continue;
                    }
                    // Accounts Windows cannot name (deleted, or from another PC) are shown by
                    // the last part of their ID only.
                    let label = account_name(sid).unwrap_or_else(|| {
                        let rid = s.rsplit('-').next().unwrap_or("?");
                        format!("an unknown account (…-{rid})")
                    });
                    if !others.contains(&label) {
                        others.push(label);
                    }
                }
            }
            LocalFree(sd);
        }
        Ok(others)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_and_entropy_binding() {
        let secret = b"oya-device-secret";
        let blob = dpapi_protect(secret, b"oya").unwrap();
        assert_ne!(blob.as_slice(), secret.as_slice());
        assert_eq!(dpapi_unprotect(&blob, b"oya").unwrap(), secret);
        assert!(dpapi_unprotect(&blob, b"other").is_err());
    }

    #[test]
    fn acl_check_runs_on_temp_dir() {
        let dir = std::env::temp_dir();
        assert!(writable_by_others(&dir).is_ok());
    }
}
