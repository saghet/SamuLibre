# Threat Intelligence

## Fuentes Soportadas
`ThreatIntelManager` (`crates/samulibre-netdefense/src/threat_intel.rs`) soporta:
- **abuse.ch URLhaus** (Hostfile, licencia `CC0 1.0 Universal`)
- **abuse.ch ThreatFox** (JSON IOCs, licencia `CC0 1.0 Universal`)
- **Spamhaus DROP / EDROP** (CIDR, `Spamhaus Free Usage Terms`)
- **OpenPhish Community** (URL txt, deshabilitado por defecto)
- **STIX 2.1 JSON Bundles** (`ingest_stix_bundle`)

## Política Anti-Falsos Positivos y Rollback
- Cada indicador registra procedencia, fecha de actualización, expiración automática (`expires_at`), hash SHA-256 de integridad y nivel de confianza (`0-100`).
- El bloqueo automático requiere `confidence >= 80` (`AUTO_BLOCK_CONFIDENCE_THRESHOLD`) o correlación con detección del Antivirus, evitando bloquear IPs legítimas de CDN/Cloud por una sola mención débil.
- Cada actualización genera respaldo en `threat_intel.bak.json` permitiendo `rollback()` inmediato.
