# Security policy

Security is Oya Browser's first priority, so reports are very welcome.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private reporting instead: open the repository's **Security** tab and choose
**Report a vulnerability**. Include:

- what an attacker can do, and what they need (a malicious web page, a local program, …);
- the steps or a minimal page that reproduces it;
- the Oya version (Settings → About Oya) and your Windows version.

You should get a reply within a week. Once a fix is released, the report is credited in the
release notes unless you ask otherwise.

## Supported versions

Only the latest release receives security fixes. Please update before reporting.

## Scope

In scope: Oya's own code — the browser shell, password vault, settings and approval system,
the page bridge, the DevTools Protocol server, the built-in renderer and the release packaging.

Out of scope (please report these upstream):

- bugs in Chromium or Microsoft Edge WebView2 itself → Microsoft Security Response Center;
- attacks that require malware already running as the same Windows user with full access,
  unless Oya makes them meaningfully easier.

## Release integrity

Every release lists SHA-256 checksums in `SHA256SUMS.txt`, and the binaries are built by GitHub
Actions from the tagged source. Releases are not yet code-signed.
