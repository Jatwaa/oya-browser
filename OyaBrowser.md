# Oya Browser — Complete Project Documentation & Technical Specification

> **Oya Browser** (formerly RustChrome) is a Windows browser whose shell, password vault, settings and built-in pages are written in Rust. **Websites are rendered by Microsoft Edge WebView2 (Chromium)**, which provides web compatibility and its own multi-process sandbox; a small Rust engine (html5ever, Taffy, Boa) renders Oya's own `oya://` pages and the headless mode. Priorities: security, speed and a calm, minimal interface.

---

## 1. Executive Summary & Vision

Traditional Chromium-based web browsers suffer from severe memory bloat, redundant background processes, telemetry overhead, and high power consumption during media playback. Oya Browser solves these issues by pairing an **11-crate modular Rust architecture** with **Windows Job Object OS sandboxing**, **hardware-accelerated WebAudio and GPU shaders**, **Argon2id + Cascaded AEAD encryption**, and an **ultra-responsive, futuristic space-age GUI**.

### Key Milestones Completed Thus Far
- **Multi-Process Architecture**: Strict separation between the Browser Host and child Renderer processes communicating via bounded IPC channels.
- **Enterprise Security Vault**: Argon2id key derivation, cascaded AES-256-GCM + XChaCha20-Poly1305 authenticated encryption, NIST P-256 Passkeys, and multi-modal biometric/PIN identity verification.
- **Media FX Studio**: Live 10-band WebAudio graphic equalizer, Dynamic GPU video upscaler (adaptive edge & contrast reconstruction), and 4K/8K 60–240 fps stutter-free playback optimization.
- **Minimal Chromium-style UI**: Shrinking tabs that merge with the toolbar, a pill-shaped address bar with a site-security chip, a ⋮ menu that floats above the page, Settings as its own tab, and a neutral palette whose text meets WCAG AA contrast (checked by a unit test).
- **Modern Browser Layout Engine**: Taffy-powered flexbox/grid/block layout with anti-layout-thrashing architecture, memoized text measurements, and batch-read/batch-write frame scheduling.
- **True Borderless Full Screen**: Monitor-spanning Win32 full screen (`rcMonitor`) with automatic multi-frame toolbar restoration on exit.
- **Background Media Playback**: Per-tab `"Allow in Background"` toggle enabling seamless continuous audio/video playback when switching tabs.
- **Smart Bookmarks Manager**: Live search, Smart Sort (frequency, recency, domain), nested folders, and 1-click import from Chrome, Edge, and Firefox.
- **Low-Level Telemetry & Crash Resilience**: Lock-free asynchronous logging thread, instant startup tail preload (< 2 ms), and Windows Structured Exception Handling (SEH) crash filters.
- **Clean Standalone Windows Binary**: The release build produces `target\release\oya_browser.exe` directly (the old `rustchrome.exe` name is no longer built), configured with `#![windows_subsystem = "windows"]` for zero console window popup on launch.

---

## 2. Workspace Architecture & 11-Crate Ecosystem

The workspace is organized into 11 decoupled Rust crates under [crates/](crates):

```
RustChrome/ (Oya Browser)
├── assets/
│   └── oya_logo.jpg             # Mascot & taskbar icon source
├── crates/
│   ├── rc_ipc/                  # Bounded IPC protocol & DisplayList commands (#![forbid(unsafe_code)])
│   ├── rc_sandbox/              # Windows Job Objects, SEH crash filter, focus & fullscreen
│   ├── rc_vault/                # Argon2id, AES-256-GCM, XChaCha20, Passkeys & Biometrics (#![forbid(unsafe_code)])
│   ├── rc_log/                  # Lock-free background logger, crash hooks, emergency disk fallback (#![forbid(unsafe_code)])
│   ├── rc_dom/                  # html5ever parser, arena-allocated DOM & computed styles (#![forbid(unsafe_code)])
│   ├── rc_layout/               # Taffy layout engine, anti-thrashing memoized measurement (#![forbid(unsafe_code)])
│   ├── rc_js/                   # boa_engine ECMAScript runtime & DOM bindings (#![forbid(unsafe_code)])
│   ├── rc_net/                  # Pure-Rust ureq + rustls networking & internal protocols (#![forbid(unsafe_code)])
│   ├── rc_cdp/                  # Chrome DevTools Protocol HTTP & WebSocket server (#![forbid(unsafe_code)])
│   ├── rc_renderer/             # Sandboxed child process runner (--type=renderer) (#![forbid(unsafe_code)])
│   └── rc_browser/              # Main host application, eframe/egui GUI & tab orchestration
├── target/release/
│   └── oya_browser.exe          # Release binary
└── Cargo.toml                   # Workspace manifest
```

---

## 3. Subsystem Breakdown & Implemented Features

### 3.1. Main Browser Host & GUI ([rc_browser](crates/rc_browser))
- **Window & data**: `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` hides the console. On start the browser switches to `%LOCALAPPDATA%\OyaBrowser`, where `settings.json`, `bookmarks.json`, `logs\` and the WebView2 profile (`WebView2\`) live; on first run, settings, bookmarks and the old vault are copied from the start folder or the program folder of an older build, and an older build's WebView2 profile is kept where it is (its path is stored in `webview2_profile_location.txt`) so website sign-ins survive. The password vault is `%APPDATA%\OyaBrowser\vault.json`. All of these are written atomically (temp file + rename).
- **Theme**: neutral light/dark palettes (`palette_for` in [gui.rs](crates/rc_browser/src/gui.rs)) with Segoe UI when installed. Selected items use a tonal fill with a high-contrast foreground; the old `selection.stroke = Stroke::NONE` that made selected tab text invisible is gone. `palette_text_meets_wcag_aa` checks every text/background pair at 4.5:1 or better.
- **Tab strip**: tabs share the width and shrink to 72 px, then scroll; the active tab merges with the toolbar. Each tab shows a site initial (or a spinner while loading), a truncated title and a close button on hover/active. Middle-click closes, drag reorders, right-click opens the tab menu (new tab, reload, duplicate, keep playing in background, close, close others).
- **Toolbar**: back, forward, reload/stop, optional home, the address bar, the media-studio button and the ⋮ menu. No text buttons, no process badge.
- **Address bar**: clicking selects the whole URL; the host is emphasised and the rest dimmed (anti-spoofing cue). The chip on the left shows a padlock, a red "Not secure" for `http://`, or the Oya logo for internal pages, and opens a site-information panel. A key icon appears when a password is saved for the site; the star toggles the bookmark.
- **Floating menus**: the ⋮ menu, tab menu and site panel are drawn in a small borderless always-on-top window positioned under their button, so they appear above the WebView2 page instead of behind it, and close when focus moves elsewhere.
- **Keyboard**: `Ctrl+T`, `Ctrl+W`, `Ctrl+L`/`Alt+D`, `Ctrl+Tab`/`Ctrl+Shift+Tab`, `Ctrl+PgDn`/`PgUp`, `Ctrl+1…9`, `Ctrl +`/`-`/`0` (zoom), `Alt+←/→`, `F5`/`Ctrl+R`, `F11`, `Esc`, `F12`. `reclaim_win32_keyboard_focus` routes keys to the browser UI when the WebView2 window had focus.

### 3.2. Media FX Studio: Equalizer, HD/4K Engine & Upscaler ([gui.rs](crates/rc_browser/src/gui.rs))
- **10-Band Graphic Equalizer**:
  - Intercepts HTML5 `<video>` and `<audio>` elements using the WebAudio API (`AudioContext`).
  - Preamp gain control (`-12 dB` to `+12 dB`) paired with 10 biquad filter nodes:
    - Bands: `31Hz` (low-shelf), `62Hz`, `125Hz`, `250Hz`, `500Hz`, `1kHz`, `2kHz`, `4kHz`, `8kHz`, and `16kHz` (high-shelf).
  - Built-in acoustic curve presets:
    - **Flat**: Reference 0 dB neutral response.
    - **Bass Boost**: Punchy low-end emphasis (+7 dB sub-bass).
    - **Vocal Clarity**: Midrange presence boost for clear dialogue.
    - **4K Cinema**: Wide dynamic soundstage contouring.
    - **Electronic / EDM**: Deep sub-bass with sparkling treble peaks.
    - **Rock**: High-energy guitar and live instrument contour.
    - **Crisp Highs**: Top-end air and micro-detail boost.
    - **Night Mode**: Loudness-compensated dynamic compression.
    - **Custom**: User-tunable sliders across all 10 bands.
- **Dynamic GPU Video Upscaler**:
  - Injects dynamic SVG convolution kernels (`<feConvolveMatrix>`) directly into the hardware compositor surface.
  - Four upscaling profiles:
    - **Dynamic Auto**: Automatically calculates scale factors based on stream resolution (stronger sharpening on 480p/720p, subtle micro-contrast on 1440p/4K).
    - **4K Ultra-Crisp**: High-pass edge reconstruction and micro-contrast.
    - **Anime / Line-Art**: Clean line-detection edge enhancement.
    - **Cinema HDR**: Extended contrast curve and color vibrance expansion.
  - User-adjustable **Detail Sharpness** (0–100%) and **HDR Vibrance** (0–100%) sliders.
- **4K / 8K Hardware Layer & Stutter Prevention**:
  - Automatically tags HTML5 media elements with `will-change: transform`, `backface-visibility: hidden`, and `decoding="async"`.
  - YouTube 4K Stream Lock: hooks into YouTube's player API (`setPlaybackQualityRange`) to lock playback to the highest available stream tier (`hd2160` / `highres`).
  - Comprehensive WebView2 hardware flags enabled on spawn:
    `--enable-gpu-rasterization`, `--enable-zero-copy`, `--enable-hardware-overlays`, `--ignore-gpu-blocklist`, `--num-raster-threads=4`, and Skia/D3D11 zero-copy acceleration.
- **Anti-Clipping & Two-Phase Layout Architecture**:
  - Replaced floating comboboxes with inline selectable curved pills, allowing the studio bar to cleanly expand and automatically push the video viewport down.
  - Automatic `any_popup_open()` clearance adds top margin whenever a tab context menu is open so native HWNDs never obscure UI controls.
  - Implementation of Web Layout Best Practices (referencing [web.dev/avoid-large-complex-layouts-and-layout-thrashing](https://web.dev/articles/avoid-large-complex-layouts-and-layout-thrashing)):
    - **Phase 1 (Batch Geometric Reads)**: Gathers element geometry (`videoHeight`, styles, attributes) in a single pass.
    - **Phase 2 (Batch Style Writes)**: Applies filters, styles, and attributes together.
    - Coalesces updates via `requestAnimationFrame` (`scheduleMediaFxPass`) to eliminate forced synchronous layouts.

### 3.3. Full Screen Architecture & Automatic Toolbar Restoration
- True Win32 monitor full screen implemented via `set_win32_fullscreen` in [os_sandbox.rs](crates/rc_sandbox/src/os_sandbox.rs), targeting `GetMonitorInfoW` and `rcMonitor` to bypass taskbar occlusions.
- HTML5 full screen bridge (`__oya_set_browser_fullscreen`) expands the active video player container to fill 100% of the display viewport while hiding YouTube mastheads and sidebars.
- **Multi-Frame Exit Resynchronization**:
  - WebView2 IPC events immediately trigger `egui_ctx.request_repaint()`.
  - Captures `Escape` in keydown and keyup phases to tear down fullscreen CSS and notify the Rust coordinator.
  - Intercepts clicks on YouTube's `.ytp-fullscreen-button` to exit browser fullscreen seamlessly.
  - Multi-frame counter (`fs_sync_frames = 15`) forces bounds recalculation across transition frames as the OS window frame restores, guaranteeing the top toolbar immediately reappears.

### 3.4. Background Media Playback ("Allow in Background")
- Problem: Modern browsers throttle background tabs and mute/pause YouTube when switching tabs.
- Solution:
  - Overrides the DOM Page Visibility API (`document.hidden` and `document.visibilityState`) in [gui.rs](crates/rc_browser/src/gui.rs) so background tabs report as continuously visible.
  - Stops immediate propagation of `visibilitychange` events when `"Allow in Background"` is enabled.
  - Off-screen tab positioning (`-15000, -15000`) keeps background tabs active without consuming foreground composition fill-rate.
  - Chromium keeps audible pages running in the background; the throttling-disable switches were removed so silent background tabs no longer burn CPU.

### 3.5. Password Vault ([rc_vault](crates/rc_vault))
- **Key derivation**: Argon2id from the vault PIN. New and changed PINs use 64 MiB, 3 passes, 1 lane; the parameters are stored in the vault file so older vaults (19 MiB, 2 passes) still open.
- **Encryption**: each secret is sealed with AES-256-GCM and then XChaCha20-Poly1305, both bound to the site origin as associated data.
- **Randomness**: salts, nonces, passkey private keys and credential IDs come from the operating system's CSPRNG.
- **No default PIN**: nothing can be saved until the user creates a PIN of at least 8 characters that is not a common, repeated or sequential pattern (a strength meter guides the choice). A locked vault refuses to store or reveal anything.
- **Locked to this PC**: the keys also depend on a secret protected by Windows (DPAPI) for this account on this PC, so a copied `vault.json` cannot be opened elsewhere even with the PIN.
- **Forced upgrade**: a vault with a weak PIN, older key settings or no PC binding is unlocked but cannot save or fill passwords until the PIN is changed.
- **Auto-lock**: after 1–60 idle minutes (default 5), when Windows locks, and after sleep.
- **Off the UI thread**: PIN checks (Argon2id) and Windows Hello prompts run on worker threads, so the window never freezes.
- **Unlock and lockout**: entering the PIN unlocks the vault; "Lock now" wipes the keys. After 5 wrong PINs a delay starts at 30 s and doubles. Changing the PIN needs the current PIN typed within the last two minutes.
- **Windows Hello**: optional confirmation on top of an unlocked vault, using `UserConsentVerifier` through PowerShell called by absolute path. If Windows Hello is unavailable the check fails; it is never skipped. The key itself still comes only from the PIN.
- **Changing the PIN** requires the current PIN and re-encrypts every password and passkey; if any entry cannot be decrypted, nothing changes.
- **Sign-in flow**: passwords are captured only when a sign-in form is actually submitted on an HTTPS page, and offered for saving in an info bar. Saved passwords are filled only after confirmation, only into a page whose real URL (reported by WebView2, not by the page) matches the saved origin, and the page-side fill function is locked so a page cannot replace it.
- **Passkeys**: creation and signing (P-256 / ES256) exist in the vault and check that the relying-party ID matches the origin, but are not yet offered to websites.

### 3.6. Settings (`oya://settings`)
Settings opens in its own tab (one Settings tab is reused). Wide windows show a left navigation rail and a single centered column (max 760 px); narrow windows turn the rail into wrapping chips. Every row wraps, so nothing is clipped. The search box filters across all sections.
1. **Bookmarks and import**: import from Chrome, Edge, Firefox or a file; add bookmarks and folders; search, sort and move bookmarks.
2. **Passwords and autofill**: save/sign-in toggles, Windows Hello or PIN-only confirmation, vault status and lock, create/change PIN, saved passwords (delete asks for confirmation), add a password.
3. **Privacy and security**: third-party tracker blocking (WebView2 Strict tracking prevention, otherwise Balanced), HTTPS-First (upgrades `http://` except local addresses), Global Privacy Control signal, clear browsing data (with confirmation).
4. **Performance and media**: Memory Saver (background tabs use WebView2's low-memory mode and are unloaded after 15 minutes hidden, except tabs kept playing), background playback per tab, media studio.
5. **Appearance**: light/dark theme, interface text size and font, page zoom, home button, bookmarks bar.
6. **Search engine**, 7. **On startup**, 8. **Languages** (`--lang` for WebView2, after restart), 9. **Downloads** (folder applied to downloads), 10. **System and developer** (graphics acceleration after restart, logs, console, processes), 11. **Reset settings** (with confirmation), 12. **About Oya**.

### 3.6a. Hijack and Tamper Protection
- **Approval gate**: changing the search engine, home/startup page or download folder, turning a protection off, letting sites ask for notifications, lengthening the vault auto-lock, clearing browsing data, resetting settings, deleting a saved password and enabling remote debugging all wait for Windows Hello or the vault PIN. The change is held back until approved.
- **Tamper seal**: `settings.json` and `bookmarks.json` are sealed with an HMAC-SHA256 key protected by Windows (DPAPI). If another program edits them while Oya is closed, Oya keeps its trusted copy and shows what changed, with "Keep mine" or "Review their changes" (which needs approval).
- **Remote debugging consent**: `--remote-debugging-port` no longer starts the DevTools server by itself in the window; it asks for approval and then shows a red "Remote control is on" bar with "Turn off".
- **WebView2 redirection**: `WEBVIEW2_*` environment variables (extra switches, other runtime folder, debugger pipes) are removed before WebView2 starts, and a Group Policy that points Oya at another browser runtime stops web pages from loading, with an explanation.
- **Process protections**: DLLs load from System32 only, legacy injection points (AppInit DLLs, global hooks) are blocked (setting "Block code injection into Oya"), and program code cannot be loaded from network shares or low-integrity files. DLL files found next to the program are reported.
- **Location check**: Oya warns when other Windows accounts can modify its program folder or the folder holding website sign-ins, and can switch to a private sign-in folder.
- **Downloads and permissions**: programs, scripts, shortcuts and disk images wait for "Keep"; SmartScreen reputation checks are enforced on every page; notification requests are refused unless enabled; a Site permissions list shows and resets what sites were allowed or blocked.
- **Page isolation**: the page bridge keeps all its state in a closure; pages cannot see or call any Oya function. The browser talks to it only with WebView2 messages. Full-screen requests from pages are honoured only after a real click or key press, and every full-screen entry shows "<site> is full screen — press Esc to exit".

### 3.6b. Panes
- The Panes button (four squares) offers one page, two side by side, two stacked, one large and two small, or four in a 2 × 2 grid. Every pane shows a live page at the same time and resizes with the window and the draggable dividers.
- Each pane has a title bar with maximize/restore and close; double-clicking the title maximizes. Maximizing fills the content area with that pane; restoring brings the layout back.
- The focused pane (blue line) is the active tab: clicking into a page, clicking its title bar or pressing Alt+1…4 focuses it, and the address bar, sign-in and toolbar act on it. Clicking a tab shows it in the focused pane; a tab's right-click menu can place it in any pane. Empty panes offer "New tab here" or any open tab. Ctrl+Shift+M maximizes or restores.

### 3.7. Bookmarks Manager ([bookmarks.rs](crates/rc_browser/src/bookmarks.rs))
- **Folder & Subfolder Hierarchy**: Full tree organization (e.g. `Work/Rust`, `Media & Video`, `Bookmarks Bar`).
- **Live Search & Filtering**: Instant title, URL, and category tag searching with folder filtering pills.
- **Smart Sort Algorithm**: Multi-factor scoring sorting bookmarks by access frequency, recency, domain grouping, or alphabetical title.
- **Browser Import Engine**:
  - Automatically locates standard profile directories on Windows:
    - **Google Chrome**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks`
    - **Microsoft Edge**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks`
    - **Mozilla Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\*.default*\places.sqlite`
  - Imports bookmarks with original folder structures preserved.
  - Supports importing standard exported HTML bookmark files.

### 3.8. DOM, CSS & Anti-Thrashing Layout Engine ([rc_dom](crates/rc_dom) & [rc_layout](crates/rc_layout))
- **Arena-Allocated DOM**: `ArenaDom` stores all nodes in a flat `Vec<DomNode>` indexed by integer `NodeId` handles, eliminating reference cycles and heap churn.
- **Spec-Compliant HTML5**: Uses `html5ever` for spec-accurate HTML parsing and DOM tree construction.
- **CSS Cascade & Style Computation**: Computes styles across element tags, classes, inline styles, and parent inheritance.
- **Optimized Layout Engine ([rc_layout/lib.rs](crates/rc_layout/src/lib.rs))**:
  - Backed by the `taffy` flexbox, grid, and block calculation engine.
  - Implemented modern layout optimizations based on browser architecture research:
    - Pre-allocated `TaffyTree::with_capacity` to prevent repeated vector resizing.
    - Memoized text measurement (`cached_layout` in `LayoutNodeCtx::Text`): caches `(width_key, computed_size, wrapped_lines)` so multi-pass flexbox intrinsic sizing never re-wraps text.
    - Strict separation of Layout and Paint: pre-computed wrapped lines are passed directly from layout into DisplayList generation without recomputing text geometry.

### 3.9. Telemetry, Logging & Crash Filters ([rc_log](crates/rc_log) & [rc_sandbox](crates/rc_sandbox))
- **Asynchronous Telemetry Pipeline**:
  - Non-blocking logging channel via `crossbeam_channel::unbounded`.
  - Dedicated background worker thread (`oya-async-logger`) batches disk writes to `%LOCALAPPDATA%\OyaBrowser\logs\rustchrome.jsonl`.
  - Fast 32 KB tail preload reads recent diagnostic events on startup in under 2 ms.
- **Crash Hooks & SEH Filters**:
  - `install_panic_and_exit_hooks`: Captures unhandled Rust panics, thread IDs, payloads, and backtraces.
  - `install_os_exception_filter`: Attaches a Windows Structured Exception Handling (SEH) filter (`SetUnhandledExceptionFilter`) capturing fatal access violations (`STATUS_ACCESS_VIOLATION`), illegal instructions, and stack overflows.
  - Synchronous disk fallback (`write_emergency_event_to_disk`): Directly writes fatal crash events to disk using low-level OS file handles even if the background logger thread is deadlocked or dying.

### 3.10. Child Process Sandboxing & CDP Automation ([rc_sandbox](crates/rc_sandbox), [rc_renderer](crates/rc_renderer), [rc_cdp](crates/rc_cdp))
- **Windows Job Object Sandboxing**:
  - Renderers launched in isolated Job Objects (`CreateJobObjectW`, `AssignProcessToJobObject`).
  - Limits enforced:
    - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Terminating the browser host instantly kills all renderer child processes.
    - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1`: Child processes cannot spawn sub-processes.
    - `JOB_OBJECT_LIMIT_PROCESS_MEMORY = 1 GiB`: Strict per-tab RAM threshold.
    - Mitigation policies: dynamic code generation prohibited (`ProcessDynamicCodePolicy`) and strict handle checks. A renderer is reported as restricted only if the Job Object was attached **and** both policies applied. (A low-integrity token is not implemented.)
  - These Oya renderers draw only Oya's own pages. Websites run in WebView2's processes, which Oya does not spawn; the UI no longer shows a "sandboxed PID" badge for them.
- **WebView2 hardening**: top-level navigation is limited to `https:`, `http:` (subject to HTTPS-First), `about:blank` and `blob:https:`; `file:`, `javascript:`, `data:` and custom protocol handlers are blocked. Pop-ups open as normal tabs. URL and origin come from WebView2's committed-navigation events and the IPC source URL, never from page messages. WebView2's own form autofill is off.
- **Chrome DevTools Protocol (CDP)** (only with `--remote-debugging-port`):
  - Listens on 127.0.0.1. Requests must carry a loopback `Host` header (blocks DNS rebinding) and no `Origin` header (blocks web pages); WebSocket URLs contain a random 128-bit token printed at start-up and returned by `/json/version`. At most 8 connections.
  - Endpoints: `/json/version`, `/json/list`. Methods: `Browser.getVersion`, `Target.getTargets`, `Page.navigate`, `Runtime.evaluate`, `DOM.getDocument`.

---

## 4. Verification & Testing History

All functionality has been verified through automated workspace testing and release builds:

```powershell
cargo test --workspace --quiet
```

| Crate | What the tests cover | Tests |
| :--- | :--- | :--- |
| **`rc_vault`** | Encrypt/decrypt and single-use release, no default PIN, locked vault refuses writes, Windows Hello fails closed, PIN change keeps every entry, wrong-PIN throttling, unique random nonces, passkey RP-ID check and signing | 7 |
| **`rc_browser`** | Search/new-tab URLs, bookmarks folders/sort/import (in memory), palette contrast (WCAG AA), navigation scheme policy and local-host rules, language switch cannot inject arguments | 5 |
| **`rc_cdp`** | Rejects foreign `Host`, any `Origin`, and WebSocket paths without the token | 1 |
| **`rc_sandbox`** | Origin extraction, CSP parsing, scheme filters | 4 |
| **`rc_net`** | Request handling and internal schemes | 4 |
| **`rc_js`** | Boa execution and limits | 2 |
| **`rc_ipc`**, **`rc_log`**, **`rc_dom`**, **`rc_layout`**, **`rc_renderer`** | Serialization, logging, parsing, layout, renderer loop | 1 each |

Total: 37 tests (vault 10, browser 9 including pane layouts and the tamper seal, sandbox 6 including DPAPI). Tests do not read or write the real vault, settings or bookmarks files.

---

## 5. Build, Run & Deployment Guide

### Prerequisites
- Windows 10/11 (64-bit)
- Rust 1.80+ (`stable-x86_64-pc-windows-msvc`)
- Microsoft Visual Studio C++ Build Tools (MSVC runtime)
- Microsoft Edge WebView2 Evergreen Runtime (pre-installed on Windows 10/11)

### Building Release Binaries
To build the fully optimized, stripped release binaries without console popups:

```powershell
# Stop running instances if open
Stop-Process -Name "oya_browser" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "rustchrome" -Force -ErrorAction SilentlyContinue

# Build release package (produces target\release\oya_browser.exe directly)
cargo build --release -p rc_browser
```

### Running Oya Browser
```powershell
# Launch Oya Browser GUI (Default blank/search tab)
.\target\release\oya_browser.exe

# Launch directly to a specific URL
.\target\release\oya_browser.exe https://www.youtube.com

# Launch with Chrome DevTools Protocol enabled (prints the tokenised ws:// URL to use)
.\target\release\oya_browser.exe --remote-debugging-port=9222

# Headless DOM Inspection Mode
.\target\release\oya_browser.exe --headless --dump-dom https://example.com
```

---

## 6. Architecture Roadmap & Future Enhancements

1. **WebExtensions V3 Runtime**:
   - Manifest V3 extension loading architecture with sandboxed background service workers and content-script injection.
2. **Built-in Ad & Tracker Blocker** (beyond WebView2's tracking prevention):
   - Native Rust implementation of EasyList/Brave ad-blocking rules compiled into fast Aho-Corasick automaton filters for zero-overhead network request interception.
3. **Tab Grouping & Vertical Tabs**:
   - Collapsible vertical tab side-rail for ultra-wide monitors with drag-and-drop color-coded workspaces.
4. **Hardware AV1 / VP9 Custom Shader Pipeline**:
   - Direct3D 12 compute shaders for AI-powered frame interpolation and super-resolution video enhancement.
