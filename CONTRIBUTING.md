# Contributing to Oya Browser

Thanks for helping! Oya aims to be **secure, fast and light at the same time**, so every change
is weighed against all three.

## Getting started

1. Install [Rust](https://rustup.rs) (stable) and the Visual Studio C++ Build Tools with the
   Windows SDK. Oya currently targets Windows 10/11 x64.
2. Clone the repository and run:
   ```powershell
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo run -p rc_browser
   ```

## Pull requests

- Keep each pull request focused on one change and describe what it fixes and how you tested it.
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` must pass;
  CI runs both on every pull request.
- Add or update tests for behaviour changes, especially anything in `rc_vault`, `rc_sandbox`,
  `rc_cdp` or the security code in `rc_browser`.
- New `unsafe` code belongs only where the Windows API requires it, with a `// SAFETY:` comment.
- Never weaken a protection silently. Changes to security defaults, the approval gate or the
  vault format need a clear explanation in the pull request.
- Do not commit personal data: settings, bookmarks, vault files, logs or WebView2 profiles
  (they are listed in `.gitignore`).

## Reporting bugs and ideas

Open an issue with steps to reproduce, the Oya version (Settings → About Oya) and your Windows
version. For security problems, follow [SECURITY.md](SECURITY.md) instead.

## License

By contributing, you agree that your contributions are dual-licensed under the MIT and
Apache-2.0 licenses, as described in the [README](README.md#license).
