# License Compliance

## Licencias del Proyecto y Dependencias
- **SamuLibre**: `GPL-3.0-or-later` (`Cargo.toml`, `LICENSE`).
- **Portmaster (Referencia Arquitectónica)**: `GPL-3.0`. No se copió código fuente de Portmaster ni el controlador `portmaster-windows-kext`; el motor `samulibre-netdefense` fue implementado íntegramente en Rust sobre APIs públicas de Windows (`Fwpm*`, `iphlpapi`).
- **Crates de Terceros**: `windows` (MIT OR Apache-2.0), `tokio` (MIT), `rustls` (Apache-2.0 OR ISC OR MIT), `webpki-roots` (MPL-2.0), `ureq` (MIT OR Apache-2.0), `serde` (MIT OR Apache-2.0), `sysinfo` (MIT), `sha2` (MIT OR Apache-2.0). Todas compatibles con `GPL-3.0-or-later`.
- **Feeds de Threat Intelligence**: abuse.ch URLhaus/ThreatFox (`CC0 1.0 Universal`), Spamhaus DROP (`Spamhaus Free Usage Terms`).
