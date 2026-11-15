# SamuLibre Virtual Patching Engine - Architecture & Rule Manual

## 1. Concept & Purpose

A **Virtual Patch** is a surgical, compensatory security control implemented to prevent the exploitation of a known vulnerability (CVE) without modifying the original vulnerable binary or waiting for the operating system restart required by an official update.

SamuLibre Virtual Patching Engine (`samulibre-patcher`) protects endpoints during the **patch gap** (the critical window between vulnerability disclosure and official patch deployment).

```
   Vulnerability Disclosed (Zero-Day / N-Day)
                    │
                    ▼
   [ SamuLibre Virtual Patch Activated ] ───▶ Vector Blocked Instantly (0 Reboots)
                    │
   [ Patch Gap: Days to Weeks ]
                    │
                    ▼
   Official Microsoft KB Released & Installed
                    │
                    ▼
   [ SamuLibre Centinela Verifies CBS Package ]
                    │
                    ▼
   [ Virtual Patch Transitions to NativePatchInstalled ]
```

---

## 2. Rule Architecture & Schema

Each virtual patch rule in SamuLibre contains structured metadata and strict validation parameters:

```rust
pub struct VirtualPatchRule {
    pub id: String,                  // Unique identifier (e.g. VP-WIN-2022-30190)
    pub cve: String,                 // Associated CVE ID (e.g. CVE-2022-30190)
    pub title: String,               // Human-readable title
    pub description: String,         // Exploit vector description
    pub severity: Severity,          // Critical, High, Medium, Low
    pub target_component: String,    // ms-msdt, spoolsv.exe, lsass.exe, etc.
    pub required_kb: Vec<String>,    // Corrective Microsoft KBs (e.g. KB5014699)
    pub strategy: MitigationStrategy,// Technical enforcement strategy
    pub status: PatchStatus,         // Active, Unmitigated, NativePatched, Incompatible
}
```

### Supported Technical Mitigation Strategies
1. **RegistryPolicy**: Configures specific hardening registry keys (e.g. `RpcAuthnLevel` on Netlogon, `DisableWebWarnings`, `NoInteractiveServices`).
2. **ProtocolFilter**: Disables legacy or vulnerable protocol handlers (e.g. unregistering URL protocol handler for `ms-msdt`).
3. **AclHardening**: Tightens security descriptors on sensitive directories and named pipes (e.g. Print Spooler driver directories).
4. **BehavioralBlock**: Real-time process supervision blocking suspicious parent-child process relationships (e.g. `WINWORD.EXE` launching `msdt.exe` or `powershell.exe`).

---

## 3. Active Rule Catalog

| Rule ID | CVE ID | Vulnerability Title | Target Component | Mitigating Microsoft KB | Severity |
|---|---|---|---|---|---|
| `VP-WIN-2022-30190` | `CVE-2022-30190` | Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution ("Follina") | `ms-msdt` URI Handler | `KB5014699` | **Critical (CVSS 9.8)** |
| `VP-WIN-2021-34527` | `CVE-2021-34527` | Windows Print Spooler Remote Code Execution ("PrintNightmare") | `spoolsv.exe` Driver Installs | `KB5004945` | **Critical (CVSS 9.0)** |
| `VP-WIN-2020-1472` | `CVE-2020-1472` | Netlogon Elevation of Privilege ("Zerologon") | `lsass.exe` Netlogon Channel | `KB4571694` | **Critical (CVSS 10.0)** |
| `VP-WIN-2023-36884` | `CVE-2023-36884` | Windows Search & Office Remote Code Execution | Search & Office OLE Integration | `KB5028166` | **High (CVSS 8.8)** |
| `VP-WIN-2024-38063` | `CVE-2024-38063` | Windows TCP/IP Remote Code Execution Vulnerability | `tcpip.sys` IPv6 Processing | `KB5041585` | **Critical (CVSS 9.8)** |

---

## 4. Pre-Validation & Incident Audit Logging

### Pre-Validation Protocol
Before any rule is activated:
1. SamuLibre checks the host OS edition and build via `WindowsSystemInventory`.
2. SamuLibre checks whether the target component or service is active on the host. If a service (e.g. `Spooler`) is disabled, the rule reports `NotRequired`.
3. If CBS or WUA confirms that the corrective KB is already installed, the engine flags `NativePatchInstalled` and leaves compensatory registry hooks inactive to avoid cluttering system state.

### Incident Logging
Any attempt by malware or exploit scripts to trigger a mitigated vector is intercepted and recorded in `data/incidents/virtual_patch_incidents.json` with timestamp, source process ID, targeted CVE, and blocked action.
