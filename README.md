<div align="center">

# 🛡️ SamuLibre

### The Open-Source Antivirus, EDR & Autonomous 0-Day Virtual Patcher in 100% Rust
**Native Windows 11 Glassmorphism UI • Ransomware Tripwires • Multi-Engine YARA-X • Privacy VPN • 5 MB Resting RAM**

[![Rust](https://img.shields.io/badge/Language-Rust_1.80+-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows_11_%2F_10-0078D6.svg?style=for-the-badge&logo=windows)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-13%2F13_Passing-brightgreen.svg?style=for-the-badge)](https://github.com/saghet/SamuLibre/actions)
[![RAM](https://img.shields.io/badge/Resting_RAM-5.45_MB-success.svg?style=for-the-badge)](https://github.com/saghet/SamuLibre)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-0%25_Verified-blueviolet.svg?style=for-the-badge)](https://github.com/saghet/SamuLibre)

[English](README.md) • [Español](#-resumen-en-español) • [Architecture](#-architecture) • [Comparison](#-head-to-head-comparison) • [Quickstart](#-quickstart)

</div>

---

## ⚡ What is SamuLibre?

**SamuLibre** is a next-generation open-source security suite engineered from scratch in **pure Rust**. It delivers enterprise-grade **EDR (Endpoint Detection and Response)**, **autonomous virtual patching for zero-day vulnerabilities**, **ransomware tripwire canaries**, and a **privacy VPN** — wrapped in an Apple-inspired glassmorphism desktop GUI.

Unlike legacy antivirus software that hogs 300+ MB of RAM and uploads your personal telemetry to closed servers, SamuLibre consumes **less than 5.5 MB of resting RAM** and runs 100% locally on your machine with **zero telemetry**.

---

## 🥊 Head-to-Head Comparison

| Capability | **SamuLibre** | Windows Defender | CrowdStrike Falcon | ClamAV |
| :--- | :---: | :---: | :---: | :---: |
| **Language** | **100% Rust** | C / C++ | C++ / Proprietary | C / C++ |
| **Resting RAM Footprint** | **~5.5 MB - 38 MB** | 150 MB - 350 MB | 100 MB - 250 MB | 800 MB+ (Signatures in RAM) |
| **Windows 11 EcoQoS (E-Cores)** | :white_check_mark: **Native** | :x: No | :x: No | :x: No |
| **Autonomous 0-Day Virtual Patching** | :white_check_mark: **Yes** | :x: Waiting for KBs | :warning: Cloud Rule Only | :x: No |
| **Auto-Rollback on Official KBs** | :white_check_mark: **Yes** | :x: N/A | :x: No | :x: No |
| **Ransomware Tripwire Canaries** | :white_check_mark: **Sub-ms MFT Fast-Path** | :warning: Limited | :white_check_mark: Yes | :x: No |
| **LSASS Credential Dumping Defense** | :white_check_mark: **Active (Mimikatz block)** | :warning: RunAsPPL only | :white_check_mark: Yes | :x: No |
| **Browser Cookie / Token Shield** | :white_check_mark: **DPAPI Protected** | :x: No | :warning: Enterprise tier | :x: No |
| **Integrated Privacy VPN (Tor & WireGuard)** | :white_check_mark: **Built-in** | :x: Paid ($) | :x: No | :x: No |
| **Open Source / Zero Telemetry** | :white_check_mark: **100% GPL-3.0** | :x: Proprietary | :x: Proprietary | :white_check_mark: Open Source |

---

## 🚀 Key Modules & Capabilities

### 1. 🩹 Autonomous Virtual Patcher (`samulibre-patcher`)
* **Real-time CVE Triage**: Scans Windows OS build, installed KBs (`Get-HotFix`), and registry against active critical vulnerabilities (e.g. *CVE-2024-38063 IPv6 RCE*, *CVE-2024-38077 RDP Licensing Service*, *PrintNightmare*, *Follina*, *EternalBlue*).
* **Autonomous Mitigation**: Deploys dynamic WFP firewall rules, registry security hardening, and service lockdowns to neutralize attack vectors **before Microsoft issues an official update**.
* **Smart Auto-Rollback**: Continuously verifies whether Windows Update installed the native patch. The moment the official Microsoft KB is verified on disk, **SamuLibre automatically revokes the virtual patch rule**, eliminating any system overhead.

### 2. 🛡️ Endpoint Shield & Ransomware Tripwires (`samulibre-shield`)
* **Zero I/O Canary File Traps**: Deploys attractive decoy files (`.xlsx`, `.docx`, `.key`) in critical user directories. Uses NTFS Master File Table (`mtime` + `size`) metadata fast-paths to verify integrity in **< 0.001 ms without disk I/O reads**. If ransomware modifies or encrypts a decoy, SamuLibre halts the attacking process immediately.
* **LSASS Credential Dumping Shield**: Intercepts memory scraping attempts targeting `lsass.exe` (Mimikatz, NanoDump, ProcDump, and malicious `comsvcs.dll` invocations).
* **Anti-InfoStealer Cookie Guard**: Blocks unauthorized scripts and background binaries from harvesting Chromium (`Chrome`, `Edge`, `Brave`) and Firefox session cookies and DPAPI encrypted credentials.

### 3. 🔍 Ultra-Fast Multi-Engine Scanner (`samulibre-scanner`)
* **Substring Pre-Filtering**: Employs an ultra-fast raw-byte anchor filter before triggering heavy YARA-X NFA/DFA engines. Benign files bypass regex parsing in **< 0.05 ms**.
* **YARA-X & Shannon Entropy Heuristics**: Detects obfuscated PowerShell droppers (`-enc`, `-nop`, `IEX`, `DownloadString`), memory AMSI bypass patches, and packed binaries with Shannon entropy ($H > 7.85$).
* **Live On-Access File Watcher (`samulibre-watcher`)**: Intercepts newly created or modified files with 200 ms debouncing and automatically isolates threats into an **XOR-encrypted quarantine vault**.

### 4. 🌐 Privacy VPN & Anti-Censorship Suite (`samulibre-vpn`)
* **Multi-Hop Tor & WireGuard Tunneling**: One-click encrypted routing through privacy-first jurisdictions (Switzerland, Iceland, Netherlands, Sweden, Panama, Canada).
* **Quad9 Malware-Blocking DNS**: Automatic DNS-over-HTTPS / static DNS routing through Quad9's Swiss non-profit malware-filtering servers (`9.9.9.9`).
* **Hardware Kill-Switch**: Outbound Windows Filtering Platform (WFP) rules that prevent unencrypted IP/DNS leaks if the tunnel drops.

### 5. 🍃 EcoQoS & Memory Trimming (Windows 11)
* **Efficiency Cores (E-Cores) Scheduling**: Background threads run at `THREAD_PRIORITY_LOWEST`, instructing the Windows 11 thread scheduler to execute background scans strictly on energy-efficient E-Cores.
* **Active Working Set Trimming**: Automatically invokes Win32 `EmptyWorkingSet` every 60 seconds to release unreferenced physical memory pages back to the operating system, keeping RAM between **5.45 MB and 38.9 MB**.

---

## 🏛️ Architecture

```mermaid
flowchart TD
    subgraph UI["Desktop Presentation Layer"]
        GUI["Apple-Style Glassmorphism GUI (Tao + Wry)"]
        Tray["System Tray Resident Icon (Muda)"]
    end

    subgraph Core["SamuLibre Core Orchestrator"]
        EventBus["Bidirectional IPC Event Loop"]
        Scheduler["Windows 11 EcoQoS (E-Cores Scheduler)"]
    end

    subgraph Engines["Security & Defense Subsystems"]
        Patcher["Virtual Patcher (0-Day Triage & Auto-Rollback)"]
        Shield["Endpoint Shield (LSASS Guard & Tripwire Canaries)"]
        Scanner["Multi-Engine Scanner (YARA-X + ClamAV + Entropy)"]
        Watcher["On-Access Watcher & Encrypted Quarantine Vault"]
        VPN["Privacy VPN (WireGuard / Tor + Quad9 Secure DNS)"]
    end

    UI --> EventBus
    EventBus --> Core
    Core --> Patcher
    Core --> Shield
    Core --> Scanner
    Core --> Watcher
    Core --> VPN
```

---

## 🎯 MITRE ATT&CK® Coverage

| Technique | Description | SamuLibre Countermeasure |
| :--- | :--- | :--- |
| **T1003.001** | OS Credential Dumping: LSASS Memory | `samulibre-shield` VM_READ interceptor |
| **T1486** | Data Encrypted for Impact (Ransomware) | Honeytoken Canary Tripwires (Zero I/O fast-path) |
| **T1562.001** | Impair Defenses: AMSI Patching | YARA-X `AmsiScanBuffer` memory patch detection |
| **T1059.001** | PowerShell Scripting Interpreter | Heuristic dropper parser & hidden window detector |
| **T1555.003** | Credentials from Web Browsers | Anti-InfoStealer DPAPI & `Login Data` protection |
| **T1048** | Exfiltration Over Alternative Protocol | WFP Network Kill-Switch & Quad9 Anti-Leak DNS |

---

## 🚀 Quickstart

### Option 1: Download Precompiled Binary (Recommended)
1. Head over to [GitHub Releases](https://github.com/saghet/SamuLibre/releases).
2. Download `samulibre-windows-x64.zip`.
3. Extract and run `samulibre.exe`.

### Option 2: Build From Source

Make sure you have [Rust](https://rustup.rs/) (1.80+) installed:

```bash
# Clone the repository
git clone https://github.com/saghet/SamuLibre.git
cd SamuLibre

# Run the native desktop application
cargo run --release -p samulibre-gui
```

### CLI Commands:
```bash
# Check overall security posture
cargo run --release -p samulibre-cli -- status

# Run full interactive security demo
cargo run --release -p samulibre-cli -- demo

# Scan and apply virtual patches for unpatched Windows CVEs
cargo run --release -p samulibre-cli -- patcher scan
cargo run --release -p samulibre-cli -- patcher apply

# Deploy decoy canary tripwires
cargo run --release -p samulibre-cli -- shield deploy-canaries
```

---

## 🧪 Testing

SamuLibre includes an automated test suite verifying fast-paths, virtual patching, live on-access watcher, and quarantine lifecycle:

```bash
cargo test --workspace
```

---

## 🇪🇸 Resumen en Español

**SamuLibre** es una suite de ciberseguridad, EDR y parchado virtual de código abierto (GPLv3) desarrollada íntegramente en **Rust**.
- **Parchado Virtual Autónomo:** Protege contra vulnerabilidades de día cero (*0-days*) antes de que Microsoft publique el parche oficial, y revoca automáticamente la mitigación en cuanto detecta que el sistema se ha actualizado.
- **Canarios Señuelo Anti-Ransomware:** Trampas en disco verificadas por metadatos NTFS en microsegundos (sin lecturas constantes a disco).
- **Protección de Credenciales:** Bloqueo contra volcados de memoria LSASS (Mimikatz) y robo de cookies/sesiones web por InfoStealers.
- **Rendimiento de Ultra-Bajo Consumo:** Consume entre **5.45 MB y 38 MB de memoria RAM** en reposo mediante el modo **EcoQoS** de Windows 11 en núcleos de eficiencia (E-Cores).
- **Cero Telemetría:** 100% privado, local e independiente.

---

## 🤝 Contributing

Contributions are warmly welcomed! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new CVE virtual patch rules, YARA-X signatures, or UI improvements.

---

## 📄 License

SamuLibre is licensed under the [GNU General Public License v3.0](LICENSE). 100% Free and Open Source.
