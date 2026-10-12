# Security Policy & Self-Defense Architecture 🔒

At **SamuLibre**, we recognize a critical paradox in the cybersecurity industry: **antivirus and security tools running with elevated privileges (SYSTEM / Administrator) frequently become the primary zero-day attack vector for adversaries.**

Memory corruption bugs in file format parsers, DLL hijacking in unverified directories, and NTFS junction/symlink traversals in quarantine engines have historically plagued proprietary antivirus suites.

SamuLibre was engineered from the ground up to eliminate this attack surface.

---

## 🛡️ Anti-Attack Vector Architecture (Garantía de Auto-Defensa)

### 1. 100% Memory-Safe Rust Core
- SamuLibre is implemented entirely in **pure Rust**, eliminating entire classes of critical vulnerabilities including Buffer Overflows, Use-After-Free, Double Free, Null Pointer Dereferencing, and Type Confusion.
- Background threads operate with strong thread safety primitives (`Arc<Mutex<...>>`), avoiding race conditions.

### 2. Anti-Symlink & Anti-Junction Traversal (Anti-LPE)
- **Problem:** Malicious unprivileged users often create NTFS directory junctions or symbolic links pointing to sensitive OS directories (`C:\Windows\System32\`), tricking elevated antivirus software into deleting or overwriting critical system files during quarantine.
- **SamuLibre Defense:** Both `samulibre-watcher` and `QuarantineVault` strictly inspect `fs::symlink_metadata()` before opening, moving, or deleting any file. Any attempt to pass a symbolic link or junction point is rejected and flagged immediately.

### 3. Bounded Stream Scanning (Anti-Zip Bomb & DoS Mitigation)
- Parsing of archives and executables enforces a strict `MAX_SCAN_BUFFER` cap (512 KB headers) and an overall bounded streaming limit of 50 MB with per-file timeouts.
- Files exhibiting malicious recursive expansion or anomalous compression ratios are dropped safely without consuming host memory or stalling scan pipelines.

### 4. Webview DOM Sanitization & Anti-XSS
- All file names, detection identifiers, process names, and hashes rendered in the desktop GUI are sanitized through strict HTML character escaping (`escapeHtml()`) before interpolation.
- The Webview environment operates in a sandboxed local origin, preventing remote code execution or DOM-based script injection attacks.

### 5. Verified Zero-Telemetry
- SamuLibre contains no analytics trackers, no advertising SDKs, and no telemetry pings.
- All intelligence evaluation (YARA-X rules, heuristic entropy analysis, canaries, and CVE mitigation) runs **100% locally on your machine**.

---

## 📋 Supported Versions

| Version | Status | Security Updates |
| :--- | :---: | :---: |
| **0.1.x / 0.2.x** | :white_check_mark: Supported | Active |
| `< 0.1.0` | :x: End of Life | None |

---

## 🚨 Reporting a Vulnerability & Responsible Disclosure

If you discover a security vulnerability within SamuLibre:

1. **Do not open a public issue.**
2. Report the vulnerability privately via [GitHub Private Vulnerability Reporting](https://github.com/saghet/SamuLibre/security/advisories/new) or by contacting the core security team at `dev@samulibre.org`.
3. Provide a clear description, reproduction steps, and proof-of-concept (PoC) if applicable.

We acknowledge receipt of all vulnerability reports within **24 hours** and adhere to a 90-day responsible disclosure window. Researchers who submit verified vulnerabilities will be credited in our **Hall of Fame**.
