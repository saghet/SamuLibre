# Security Tests Report (`samulibre-netdefense`)

## Pruebas Automatizadas Ejecutadas (`crates/samulibre-netdefense/tests/netdefense_lab.rs`)
- `test_socket_monitor_and_benchmark`: Enumeración real de sockets TCP/UDP IPv4/IPv6 vía `iphlpapi.dll` (`GetExtendedTcpTable` / `GetExtendedUdpTable`).
- `test_app_policy_sha256_tamper_reevaluation`: Verificación de política por ruta completa + SHA-256; alteración del binario en disco fuerza estado `ModifiedNeedsReeval`.
- `test_dns_wire_parser_block_and_corporate_bypass`: Parseo RFC 1035, bloqueo `NXDOMAIN` de dominios C2 y detección de DNS Rebinding (`127.0.0.1`, `192.168.x.x`).
- `test_threat_intel_stix_hostfile_and_rollback`: Ingesta de hostfile URLhaus, bundle STIX 2.1 y restauración vía `rollback()`.
- `test_tor_secure_mode_kill_switch_and_torrc`: Parseo de `torrc` (`SocksPort`, `ControlPort`, `UseBridges`) y activación de Kill Switch Fail-Closed cuando el proxy SOCKS5 Tor no responde.
- `test_av_correlation_and_rule_expiration`: Correlación de alerta AV con creación de regla WFP permanente sin eliminar el archivo (delegado al AV) y poda de reglas temporales expiradas.

## Pruebas Pendientes de Entorno Elevado / VM
Las pruebas de inserción real de filtros en el kernel BFE (`FwpmEngineOpen0` + `FwpmFilterAdd0`), enlace en `127.0.0.1:53` y captura de tráfico en vivo contra `check.torproject.org` / `dnsleaktest.com` / `browserleaks.com` requieren ejecución con privilegios de Administrador / Servicio `LocalSystem` en Windows.
