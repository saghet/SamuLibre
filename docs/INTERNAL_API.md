# SamuLibre Security Center - Internal API & IPC Reference

## 1. Asynchronous IPC Protocol

Communication between the WebView2 user interface and the Rust core is handled through serialized JSON IPC messages via `Tao EventLoopProxy`.

### IPC Request Structure
```json
{
  "action": "<action_name>",
  "payload": "<optional_json_or_string>"
}
```

---

## 2. Security Center Actions & Callbacks

### Security Center Overview
- **Action**: `get_security_center_overview`
- **Rust Handler**: Computes global health score, aggregates alerts from all engines, and counts unmitigated vulnerabilities.
- **Frontend Callback**: `window.onSecurityCenterOverview(overview)`
- **Payload Schema**:
  ```json
  {
    "health_score": 92,
    "verdict": "Excelente",
    "alerts": [
      {
        "id": "alert-001",
        "title": "Actualización de Seguridad Crítica Pendiente",
        "description": "KB5044284 corrige CVE-2024-43573 explotado activamente.",
        "priority": "Critical",
        "subsystem": "Windows Updates",
        "action_target": "windows-updates",
        "cve": "CVE-2024-43573"
      }
    ]
  }
  ```

---

## 3. VPN Actions & Callbacks

| Action | Payload | Description | Callback |
|---|---|---|---|
| `get_vpn_state` | `null` | Retrieves current VPN state and country list | `window.onVpnStateUpdated(state, countries)` |
| `connect_vpn` | `{"country_code": "CH", "protocol": "WireGuard"}` | Initiates WireGuard tunnel handshake | `window.onVpnStateUpdated(state, countries)` |
| `disconnect_vpn` | `null` | Closes VPN tunnel and disarms Kill Switch | `window.onVpnStateUpdated(state, countries)` |
| `reconnect_vpn` | `null` | Tears down and re-establishes VPN tunnel | `window.onVpnStateUpdated(state, countries)` |
| `toggle_vpn_kill_switch` | `true/false` | Arms or disarms WFP-based Kill Switch | `window.onVpnStateUpdated(state, countries)` |
| `toggle_vpn_ipv6_protection` | `true/false` | Enables/disables netsh IPv6 drop rules | `window.onVpnStateUpdated(state, countries)` |
| `run_vpn_diagnostics` | `null` | Executes DNS, IPv6, and latency tests | `window.onVpnDiagnostics(result)` |
| `emergency_recover_vpn` | `null` | Resets WFP and netsh firewall rules | `window.onVpnStateUpdated(state, countries)` |
| `get_vpn_history` | `null` | Fetches historical connection log | `window.onVpnHistoryLoaded(history)` |

---

## 4. Virtual Patching & Windows Servicing Actions & Callbacks

| Action | Payload | Description | Callback |
|---|---|---|---|
| `get_virtual_patch_rules` | `null` | Fetches active virtual patch rule catalog | `window.onPatchRulesUpdated(rules, os, sentinel, kb)` |
| `toggle_virtual_patch` | `{"cve": "CVE-2022-30190", "enable": true}` | Enables/disables compensatory mitigation | `window.onPatchRulesUpdated(...)` |
| `get_virtual_patch_incidents` | `null` | Retrieves incident log | `window.onVirtualPatchIncidentsLoaded(incidents)` |
| `get_windows_patch_summary` | `null` | Queries CBS, WUA, and MSRC catalog | `window.onWindowsPatchSummary(summary)` |
| `get_cve_correlations` | `null` | Calculates bidirectional correlation matrix | `window.onCveCorrelations(correlations)` |
| `install_pending_kb` | `{"kb_number": "KB5044284", "require_consent": true}` | Downloads & installs KB via WUA API | `window.onKbInstallCompleted(resultMsg)` |
| `toggle_patch_sentinel` | `true/false` | Triggers Centinela compatibility audit | `window.onPatchRulesUpdated(...)` |
