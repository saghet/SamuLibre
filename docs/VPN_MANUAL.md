# SamuLibre Enterprise VPN Suite - Operation & Administration Manual

## 1. Overview & Architecture

The SamuLibre VPN Engine (`samulibre-vpn`) provides encrypted network transport for Windows and Android endpoints. It is engineered with high-throughput WireGuard protocol primitives, supplemented by OpenVPN and Tor SOCKS5 fallback capabilities.

### Key Capabilities
- **WireGuard Core**: UDP tunnel utilizing ChaCha20-Poly1305 authenticated encryption and Curve25519 key exchange.
- **Hardware-Accelerated Throughput**: Minimal CPU overhead with sub-millisecond encryption latency.
- **WFP-Based Kill Switch**: Intercepts outbound packets at the Windows Filtering Platform layer to prevent packets leaking outside the tunnel adapter.
- **IPv6 Leak Defense**: Enforces drop policies on native IPv6 interfaces via `netsh advfirewall` rules when connected to an IPv4-only VPN tunnel.
- **DNS Leak Prevention**: Enforces DNS-over-HTTPS (DoH) via secure resolvers (Cloudflare `1.1.1.1` and Quad9 `9.9.9.9`), overriding ISP-provided DNS servers.
- **Emergency Recovery Mechanism (`emergency_recover_vpn`)**: Recovers connectivity if abnormal system shutdown occurs while the Kill Switch was armed.

---

## 2. Server Fleet & Geolocation

SamuLibre connects to hardened privacy jurisdictions:
- **Switzerland (CH)**: Zúrich (`185.156.73.4`, Port 51820) - Default Recommended Node. High throughput and strict Swiss privacy protection.
- **Iceland (IS)**: Reykjavík (`193.107.86.12`, Port 51820) - Freedom of speech Haven.
- **Sweden (SE)**: Estocolmo (`185.213.154.8`, Port 51820) - Low latency Nordic transit.
- **Germany (DE)**: Fráncfort (`194.36.191.10`, Port 51820) - 1 Gbps Central European backbone.
- **Netherlands (NL)**: Ámsterdam (`195.206.105.15`, Port 51820) - Tier-1 peering exchange.

---

## 3. Operational Procedures

### Establishing a Secure Connection
1. In the **VPN Suite** cockpit, select your desired server from the grid (e.g. *Suiza*).
2. Click the central **Conectar** button.
3. The engine initiates handshake negotiation with the endpoint.
4. Upon confirmation:
   - Status transitions to **CONECTADO Y CIFRADO**.
   - Public IP changes to the gateway exit node.
   - Live throughput counters (KB/s) and connection timer begin updating.

### Running Tunnel & Leak Diagnostics
Click **🩺 Diagnóstico** in the VPN panel to execute an end-to-end network verification:
- **DNS Leak Test**: Verifies that standard UDP 53 queries are intercepted and routed through the secure resolver.
- **IPv6 Leak Test**: Checks if any native IPv6 address is advertised to external peers.
- **Kill Switch Verification**: Validates that WFP filter rules are active and blocking non-tunneled traffic.
- **Gateway Latency**: Measures round-trip time (RTT) to the VPN exit node.

---

## 4. Emergency Recovery Procedures

In the rare event of an OS crash or power failure while the Kill Switch is active, Windows may boot with internet access blocked.

### Remediation via GUI
Navigate to the **VPN Suite** tab and click **⚡ Restaurar Red Ahora** in the *Mecanismo Failsafe* banner.

### Remediation via Command Line (Administrator PowerShell)
```powershell
# 1. Reset all firewall profiles to default policy
netsh advfirewall reset

# 2. Remove SamuLibre specific block rules
netsh advfirewall firewall delete rule name="SamuLibre_VPN_KillSwitch_BlockAll"
netsh advfirewall firewall delete rule name="SamuLibre_IPv6_Leak_Block"

# 3. Flush DNS resolver caches
ipconfig /flushdns

# 4. Re-enable network adapters
Get-NetAdapter | Restart-NetAdapter
```
