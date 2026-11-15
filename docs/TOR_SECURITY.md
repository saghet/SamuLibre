# Tor Secure Mode — Seguridad y Limitaciones

## Funcionamiento
`TorSecureModeManager` (`crates/samulibre-netdefense/src/tor_protection.rs`) integra el firewall WFP con la detección de Tor Browser (`firefox.exe` en ruta Tor Browser), el proceso `tor.exe`, pluggable transports (`obfs4proxy`, `snowflake-client`, `lyrebird`) y la lectura de `torrc` (`SocksPort`, `ControlPort`, `UseBridges`).

## Política Fail-Closed y Kill Switch
1. Al activar Tor Secure Mode, `WfpController::apply_tor_app_isolation()` inserta filtros de peso `15` permitiendo únicamente `127.0.0.1:socks_port` (y `control_port`) para las aplicaciones protegidas.
2. Filtros de peso `10` bloquean todo el resto de tráfico saliente IPv4 e IPv6 (TCP/UDP/ICMP/DNS puerto 53) de esas aplicaciones.
3. Si el daemon `tor.exe` cae o el puerto SOCKS5 deja de responder al saludo `0x05 0x01 0x00`, los filtros de bloqueo **permanecen activos** (`TorProtectionHealth::TorDownKillSwitchActive`) evitando cualquier fuga hacia clearnet.
4. No se bloquea UDP globalmente en todo el sistema; las restricciones se aplican por `AppID` a las aplicaciones protegidas.

## Limitaciones Técnicas (Sin Anonimato Absoluto)
Tor Secure Mode previene fugas de red directas en Windows a nivel WFP, pero **no** garantiza anonimato absoluto frente a correlación de tráfico global, fingerprinting del navegador, exploits en capa de aplicación o filtración voluntaria de datos por el usuario.
