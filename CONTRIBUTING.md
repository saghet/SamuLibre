# Contributing to SamuLibre 🛡️

Thank you for your interest in making **SamuLibre** the premier open-source cybersecurity and EDR suite!

## How You Can Contribute

1. **Adding New Virtual Patch Rules (CVE Mitigations)**:
   - Propose rules for unpatched vulnerabilities in Windows services, RPC, or kernel drivers in `crates/samulibre-patcher`.
2. **Improving YARA-X Heuristics & Malware Signatures**:
   - Add new malicious pattern rules or signatures in `crates/samulibre-scanner/src/lib.rs`.
3. **Enhancing Platform Support**:
   - Help port Linux/macOS equivalents for Endpoint Shield and packet inspection.
4. **UI & Translation**:
   - Add new languages to `data/ui/index.html`.

## Development Guidelines

- **Format Code**: Run `cargo fmt` before submitting PRs.
- **Run Tests**: Ensure all tests pass with `cargo test --workspace`.
- **Zero Telemetry Rule**: Under no circumstances should SamuLibre send telemetry, user identifiers, or private data to external servers without explicit consent.

## Submitting a Pull Request

1. Fork the repository.
2. Create your feature branch (`git checkout -b feat/new-cve-rule`).
3. Commit your changes (`git commit -m 'feat: add virtual patch for CVE-2026-XXXX'`).
4. Push to the branch (`git push origin feat/new-cve-rule`).
5. Open a Pull Request on GitHub.
