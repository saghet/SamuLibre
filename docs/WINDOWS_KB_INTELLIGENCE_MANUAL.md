# SamuLibre Windows Patch Intelligence Service - Administration Manual

## 1. Overview & Architecture

The **SamuLibre Windows Patch Intelligence Service** provides continuous inventory, discovery, intelligence, and safe installation of Microsoft Windows updates.

Unlike generic monitoring utilities that merely execute `wmic qfe get` (which fails to enumerate modern Servicing Stack and Cumulative updates), SamuLibre interfaces directly with the native Windows Servicing architecture:
1. **Component Based Servicing (CBS)**: Directly parses `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages` to inventory installed servicing packages, cumulative updates, and hotfixes.
2. **Windows Update Agent (WUA)**: Interfaces via COM with `Microsoft.Update.Session` to query `QueryHistory` and perform asynchronous search via `IUpdateSearcher` (`IsInstalled=0 and Type='Software'`).
3. **MSRC & CISA KEV Intelligence**: Enriches update records with CVSS scores, exploitability indicators, and supersedence chains.
4. **Controlled Installation Engine**: Executes downloads and installations with explicit administrator consent, avoiding unprompted disruptions or forced reboots.

---

## 2. Host System Inventory

On initialization and on-demand refresh, SamuLibre queries `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`:
- `ProductName` (e.g. `Windows 11 Pro`)
- `DisplayVersion` (e.g. `23H2` or `24H2`)
- `CurrentBuildNumber` & `UBR` (Update Build Revision, e.g. `22631.4460`)
- `BuildLabEx` (Detailed kernel compilation stamp)
- `Architecture` (`x86_64` / `ARM64`)
- Critical running services (`Spooler`, `LanmanServer`, `TermService`, `W3SVC`)

---

## 3. Pending Reboot Detection (Without Forced Restarts)

SamuLibre monitors four authoritative Windows servicing registry locations:
1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
2. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
3. `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
4. `HKLM\SOFTWARE\Microsoft\Updates\UpdateExeVolatile`

### Enterprise Policy Guarantee
> **Strict Non-Disruptive Servicing Policy**: SamuLibre will **never** automatically force a reboot of the operating system. When a reboot is required, the UI clearly displays an informational banner detailing the servicing reason, allowing system administrators to schedule maintenance windows appropriately.

---

## 4. Controlled Installation Workflow

1. Navigate to **Windows Updates** in the lateral menu.
2. View the **Actualizaciones Pendientes** table.
3. Review the KB number, CVSS severity, and whether the update addresses an actively exploited CVE (flagged with **🔥 CISA KEV**).
4. Click **Instalar...** on the target package.
5. In the confirmation dialog:
   - Review package details.
   - Check the mandatory administrator consent box (*"Autorizo formalmente la descarga e instalación..."*).
   - Click **Descargar e Instalar**.
6. The engine downloads the payload via Windows Update Agent, applies the installation package in a non-blocking thread, and reports completion without forcing a system restart.
