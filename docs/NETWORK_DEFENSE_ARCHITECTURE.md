# SamuLibre Network Defense Architecture

## Visión General
`samulibre-netdefense` es el subsistema nativo en Rust que implementa **SamuLibre Network Defense Engine** sobre Windows Filtering Platform (WFP) en modo usuario, `iphlpapi.dll`, un resolver local DNS-over-HTTPS / DNS-over-TLS y correlación directa con el motor antivirus de SamuLibre.

## Componentes Principales
- **WfpController** (`crates/samulibre-netdefense/src/wfp.rs`): Gestiona sesión dinámica en Base Filtering Engine (`FwpmEngineOpen0`), proveedor propio (`SAMULIBRE_WFP_PROVIDER_GUID`) y subcapa aislada (`SAMULIBRE_WFP_SUBLAYER_GUID`) sin alterar ni desactivar Windows Defender Firewall.
- **SocketMonitor** (`crates/samulibre-netdefense/src/socket_monitor.rs`): Enumeración de sockets TCP/UDP (IPv4 e IPv6) mediante `GetExtendedTcpTable` y `GetExtendedUdpTable`, con caché de hash SHA-256 por ejecutable.
- **SecureDnsProxy** (`crates/samulibre-netdefense/src/dns_proxy.rs`): Servidor DNS local (`127.0.0.1:53`) con parseo RFC 1035, DoH (RFC 8484), DoT (RFC 7858), protección contra DNS Rebinding y bypass de sufijos corporativos/VPN.
- **TorSecureModeManager** (`crates/samulibre-netdefense/src/tor_protection.rs`): Aislamiento WFP por AppID para Tor Browser, verificación SOCKS5 y Kill Switch Fail-Closed.
- **ThreatIntelManager** (`crates/samulibre-netdefense/src/threat_intel.rs`): Ingesta de feeds (URLhaus, ThreatFox, Spamhaus DROP, STIX 2.1) con umbral de confianza y rollback.
- **AV Correlation** (`crates/samulibre-netdefense/src/av_correlation.rs`): Bloqueo automático de red ante detecciones del antivirus delegando la cuarentena de archivos al AV.
- **Persistencia 24/7** (`crates/samulibre-watcher/src/service.rs`): El servicio Windows SCM `SamuLibreWatcher` restaura políticas WFP, ejecuta el proxy DNS y supervisa el Kill Switch de Tor independientemente de la GUI.
