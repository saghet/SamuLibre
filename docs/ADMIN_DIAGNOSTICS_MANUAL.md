# SamuLibre Security Center - Administrator Diagnostics & Troubleshooting Manual

## 1. Overview & Health Management

The SamuLibre Security Center incorporates built-in automated diagnostic routines for every critical subsystem. Administrators can diagnose endpoint state, troubleshoot connectivity issues, inspect virtual patch enforcement, and verify Windows Servicing status.

---

## 2. Real-Time Antivirus & Watcher Diagnostics

### Automatic Diagnostics Battery
From the **Antivirus** console (or via IPC `run_realtime_autodiagnostic`), SamuLibre executes an 8-test validation suite:
1. **Windows Service Check**: Verifies that the SamuLibre background service is running or user-space daemon is operational.
2. **File Monitor Integrity**: Validates `ReadDirectoryChangesW` handle status and latency.
3. **Queue Bounding**: Ensures the event ring buffer has bounded capacity and does not drop file access events.
4. **Scan Engine Latency**: Measures SHA-256 and YARA evaluation speed against benchmark files.
5. **EICAR Standard Test**: Simulates safe synthetic detection to guarantee alert generation.
6. **XOR Quarantine Isolation**: Validates read-only file isolation into `data/quarantine`.
7. **IPC Latency**: Verifies responsive asynchronous bridge between Tao and WebView2.
8. **EcoQoS Mode**: Confirms that background scanner threads execute with efficiency QoS.

---

## 3. VPN Network Diagnostics & Failsafe Recovery

### Network Verification Checklist
1. **Kill Switch Verification**: Run `run_vpn_diagnostics` to ensure that WFP filter rules drop all non-WireGuard outbound traffic.
2. **DNS Leak Prevention**: Verifies that queries to UDP port 53 are dropped or routed to DoH.
3. **IPv6 Leak Defense**: Verifies that native IPv6 traffic is disabled or filtered on all network adapters.

### Troubleshooting Network Lockout
If connectivity is lost after an abrupt reboot:
- Click **Restaurar Red Ahora** in the VPN Suite tab.
- Or execute:
  ```powershell
  netsh advfirewall reset
  ipconfig /flushdns
  ```

---

## 4. Virtual Patching & Windows Servicing Diagnostics

### Checking Virtual Patch Status
Run Centinela audit via GUI or verify `data/kbs/kb_intelligence_cache.json`.
- If a rule shows **COMPENSATORIO ACTIVO**, the vulnerability is unpatched by Microsoft KB on this machine, and SamuLibre is applying compensatory controls.
- If a rule shows **NATIVO INSTALADO**, the corrective KB has been verified in CBS packages, and compensatory registry hooks are deactivated.

### Checking Windows Servicing Status
Inspect `wuHostSummary` and `wuRebootBanner` in the **Windows Updates** tab:
- If a reboot is pending, the exact registry key is identified (`CBS`, `WUA`, or `PendingFileRenameOperations`).
- To force an update check, click **Sincronizar WUA / CBS**.
