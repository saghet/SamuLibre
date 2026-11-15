# Windows Filtering Platform (WFP) Implementation

## Arquitectura en Modo Usuario
`WfpController` (`crates/samulibre-netdefense/src/wfp.rs`) opera directamente contra el servicio **Base Filtering Engine (BFE)** de Windows mediante `fwpuclnt.dll` (`windows::Win32::NetworkManagement::WindowsFilteringPlatform`).

## Capas Utilizadas
- `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `FWPM_LAYER_ALE_AUTH_CONNECT_V6`: Autorización de conexiones salientes por `FWPM_CONDITION_ALE_APP_ID` (`FwpmGetAppIdFromFileName0`), protocolo (`FWPM_CONDITION_IP_PROTOCOL`), IP remota (`FWPM_CONDITION_IP_REMOTE_ADDRESS`) y puertos (`FWPM_CONDITION_IP_REMOTE_PORT` / `LOCAL_PORT`).
- `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` / `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`: Autorización de conexiones entrantes.

## Coexistencia con Windows Defender Firewall
SamuLibre registra un proveedor (`SAMULIBRE_WFP_PROVIDER_GUID`) y una subcapa (`SAMULIBRE_WFP_SUBLAYER_GUID`, peso `0x7FFF`) propios. No modifica, sobrescribe ni desactiva las reglas o subcapas de Windows Defender Firewall.

## Requisitos de Privilegios
Abrir el motor BFE (`FwpmEngineOpen0`) requiere privilegios de Administrador o ejecución como servicio Windows (`LocalSystem`). Cuando la GUI se ejecuta sin elevación, `WfpController::initialize()` reporta explícitamente `elevated: false` sin simular estado activo.
