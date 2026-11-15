# DNS Protection (DoH / DoT / Anti-Rebinding)

## Capacidades Implementadas
`SecureDnsProxy` (`crates/samulibre-netdefense/src/dns_proxy.rs`):
- **DNS-over-HTTPS (RFC 8484)** mediante `POST application/dns-message` (Quad9, Cloudflare, Mullvad o personalizado).
- **DNS-over-TLS (RFC 7858)** sobre TLS (`rustls` + `webpki-roots`) en el puerto `853`.
- **Filtrado de Amenazas**: Bloquea dominios de malware, C2, phishing y rastreadores devolviendo `NXDOMAIN` (RCODE=3).
- **Protección contra DNS Rebinding**: Inspecciona registros `A` y `AAAA` devueltos por el upstream; si un dominio público resuelve a rangos privados/loopback/link-local (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`), bloquea la respuesta.
- **Compatibilidad Corporativa y VPN**: Respeta sufijos internos configurables (`.local`, `.lan`, `.internal`, `.corp`, `.home.arpa`) y nombres sin punto para no romper resolución interna ni VPN corporativas.
