# SamuLibre Security Center - Enterprise Architecture Specification

## 1. Executive Summary & Vision

SamuLibre Security Center evolves SamuLibre from an isolated antivirus program into an integrated, corporate-grade Endpoint Protection Platform (EPP) and Endpoint Detection & Response (EDR) hybrid. 

Rather than isolated modules that merely share a window, SamuLibre Security Center functions as a cohesive cybersecurity ecosystem where:
- The **Antivirus Core & Real-Time Watcher** continuously scan processes, file operations, and execution vectors.
- The **Enterprise VPN Engine** guarantees encrypted transport via WireGuard with active DNS and IPv6 leak prevention, WFP-based Kill Switch, and failsafe network recovery.
- The **Virtual Patching Engine** applies surgical, compensatory mitigations to active CVE attack vectors in vulnerable Windows components (Print Spooler, Netlogon, MSDT, RPC) without disrupting legitimate software.
- The **Windows Patch Intelligence Service** inventories system architecture, queries CBS (Component Based Servicing) packages and WUA (Windows Update Agent) history, synchronizes with the official Microsoft Security Response Center (MSRC) and CISA Known Exploited Vulnerabilities (KEV) catalogs, and coordinates bidirectional correlation between CVEs, pending KBs, and virtual patch rules.

```
+----------------------------------------------------------------------------------------------------+
|                                    SAMULIBRE SECURITY CENTER                                       |
|                                (Consola Unificada WebView2 / Rust)                                 |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+────────────────────────────────────────────────────────────────────────────────────────────────────+
|                                        INTER-PROCESS BUS                                           |
|                            (Tao EventLoopProxy / Asynchronous IPC)                                 |
+────────────────────────────────────────────────────────────────────────────────────────────────────+
        │                                 │                               │                       │
        ▼                                 ▼                               ▼                       ▼
+────────────────+               +─────────────────+             +────────────────+      +────────────────+
| Antivirus Core |               |    VPN Suite    |             |  Virtual Patch |      | Windows Update |
|  & Watcher     |               | (WireGuard/WFP) |             |    Centinela   |      |  Intelligence  |
+────────────────+               +─────────────────+             +────────────────+      +────────────────+
        │                                 │                               │                       │
        ▼                                 ▼                               ▼                       ▼
┌────────────────┐               ┌─────────────────┐             ┌────────────────┐      ┌────────────────┐
| File Monitor   |               | Tunnel & Crypt  |             | CVE Rules      |      | CBS Packages   |
| YARA & Heurist |               | Kill Switch WFP |             | Pre-validation |      | WUA History    |
| Crypto Vault   |               | Netsh IPv6 Blk  |             | Incident Logs  |      | MSRC Catalog   |
| SSEM Syslog    |               | Failsafe Reset  |             | Native vs Comp |      | Non-forced Rb  |
└────────────────┘               └─────────────────┘             └────────────────┘      └────────────────┘
```

---

## 2. Component Directory & Responsibilities

| Component | Responsible Subsystem | Technical Mechanism | Operating System Boundary |
|---|---|---|---|
| **Security Center Dashboard** | `crates/samulibre-gui` + `data/ui/index.html` | Real-time circular health index (0-100%), 5 real engine telemetry cards, alert dispatcher | WebView2 / User Space |
| **Antivirus Core & Real-Time** | `crates/samulibre-core`, `samulibre-watcher`, `samulibre-shield` | File system monitor, Shannon entropy, PE parsing, behavioral rules, YARA signatures, EcoQoS scheduling | Kernel mini-filter / Win32 API |
| **Enterprise VPN Engine** | `crates/samulibre-vpn` | WireGuard UDP tunnel, ChaCha20-Poly1305, WFP (Windows Filtering Platform) Kill Switch, Netsh IPv6 filter, DoH resolver | Network NDIS / WFP Filter |
| **Virtual Patching Engine** | `crates/samulibre-patcher` | Registry mitigation policies, protocol disabling, RPC ACL enforcement, dynamic compatibility pre-validation | Windows Registry & SCM |
| **Windows Servicing & Updates** | `crates/samulibre-patcher/src/windows_kb_service.rs` | Direct CBS registry querying (`HKLM\...\Component Based Servicing\Packages`), WUA COM API (`IUpdateSearcher`), pending reboot evaluation (`RebootPending`, `PendingFileRenameOperations`) | Windows Servicing Stack (CBS/WUA) |
| **Vulnerability Correlator** | `crates/samulibre-patcher/src/correlation.rs` | Bidirectional correlation graph: `CVE ↔ Affected Component ↔ Corrective KB ↔ Installation Status ↔ Compensatory Patch` | Offline JSON & Threat Intelligence |
| **Controlled Patch Installer** | `crates/samulibre-patcher/src/patch_installer.rs` | WUA COM Installer API with explicit administrator consent, isolated thread, zero unprompted reboots | TrustedInstaller / WUA |

---

## 3. Single Source of Truth & Metric Integrity

A core tenet of SamuLibre Security Center is **the complete absence of simulated or hardcoded fake metrics**.
Every badge, score, table row, and indicator directly reflects verified state queried from the underlying operating system and Rust engines:
- **Global Health Score**: Calculated dynamically by `crates/samulibre-patcher/src/alerts.rs` based on deductions for active CISA KEV vulnerabilities, pending critical KBs, pending reboot requirements, unprotected VPN state, and disabled shields.
- **Antivirus Status**: Queried from `AntivirusCore::get_protection_health()` checking the Windows Service status, file monitor latency, event queue bounding, and signature timestamp.
- **VPN Telemetry**: Queried from `VpnManager::get_state()` collecting live throughput counters (`download_speed_bps`, `upload_speed_bps`), connection duration (`duration_seconds`), and active tunnel IP.
- **Virtual Patching Status**: Differentiates between `ActiveCompensatory` (rule enabled because official fix is missing) and `NativePatchInstalled` (verified installed in CBS or WUA).

---

## 4. Fault Tolerance, Emergency Failsafes & Coexistence

1. **VPN Kill Switch Failsafe (`emergency_recover_vpn`)**:
   - If an unexpected system crash or power outage leaves WFP or firewall rules in place, network connectivity is blocked.
   - SamuLibre includes a fail-safe recovery mechanism executing `netsh advfirewall reset`, flushing DNS resolution caches (`ipconfig /flushdns`), removing restrictive outbound blocks, and restoring default interface routing.
2. **Virtual Patch Pre-Validation**:
   - Before activating any compensatory rule, the engine executes a pre-validation check against the operating system build, product name, and running services. If the target service is not present or the OS build already incorporates the fix natively, the rule is not applied, avoiding false disruptions.
3. **Controlled Windows Update Servicing**:
   - Automated rebooting of production servers or workstations is strictly prohibited.
   - If a cumulative update requires a reboot, SamuLibre flags `reboot_pending = true`, identifies the exact servicing trigger (`CBS\RebootPending`, `WindowsUpdate\Auto Update\RebootRequired`, or `PendingFileRenameOperations`), and presents non-disruptive notifications.
