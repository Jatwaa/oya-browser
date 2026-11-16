# Changelog

## v1.1.0 — first public release

### Security
- Page identity comes from WebView2, not from page messages; saved passwords fill only on the exact site they belong to.
- Password vault: OS random numbers, Argon2id (64 MiB, 3 passes), no default PIN, 8+ character PINs with a strength meter, keys bound to the Windows account (DPAPI), auto-lock on idle, Windows lock and sleep, and forced upgrade of weak or legacy vaults.
- Approval gate: protected settings, clearing data, resetting, deleting passwords and remote debugging need Windows Hello or the vault PIN.
- Settings and bookmarks are sealed against outside edits.
- HTTPS-First, strict tracker blocking, Global Privacy Control, SmartScreen enforced, risky-download confirmation, notification requests refused by default, site-permission review.
- Process hardening: no legacy injection points, System32-only DLL loading, no remote or low-integrity images; planted DLLs and shared program folders are reported.
- DevTools Protocol server: loopback only, Host/Origin checks, secret token, connection cap.
- Full screen only after a real user gesture, with an Esc notice; no page-visible browser hooks; no browsing history in logs.

### Interface
- New Chrome-style tab strip, address bar with security chip, floating ⋮ menu, and Settings as a searchable tab.
- Panes: up to four live pages side by side with resizable dividers and maximize/restore.
- Bookmarks and passwords shown as tables; bookmark descriptions with hover tooltips.
- Media studio with a centred 10-band equalizer and video enhancement.
- Light and dark themes meeting WCAG AA contrast; Segoe UI where available.

### Fixes
- Unreadable selected tabs; Options running off screen; white strip in full screen from a maximized window.
- Data now lives in `%LOCALAPPDATA%\OyaBrowser` and `%APPDATA%\OyaBrowser` instead of the start folder.
