# Portmaster Integration Analysis & Architectural Decision

## Evaluación de Alternativas
1. **Alternativa A — Portmaster como motor externo administrado**: Requiere empaquetar el runtime Go de Portmaster y su controlador `pm_kernel64.sys`, comunicarse por API HTTP/WebSocket local (`127.0.0.1:817`), duplicar consumo de RAM (~100-250 MB adicionales) y depender de binarios/firmas de terceros para el driver.
2. **Alternativa B — Fork de Portmaster**: Modificar `portmaster-windows-kext` invalida la firma criptográfica WHCP de Safing. En Windows 10/11 retail un driver `.sys` modificado no puede cargarse sin firma EV + Microsoft Partner Center Attestation (o `TESTSIGNING ON`, prohibido en equipos finales).
3. **Alternativa C (Seleccionada) — Motor propio en Rust (`samulibre-netdefense`)**: Adopta los conceptos arquitectónicos de Portmaster (subcapa WFP dedicada, políticas por ruta + hash, DNS cifrado local, monitor en tiempo real, feeds de inteligencia y Tor Fail-Closed) implementados íntegramente en Rust sobre APIs nativas WFP en modo usuario (`Fwpm*`) e `iphlpapi.dll`.

## Ventajas Técnicas y Legales
- Cero controladores de kernel sin firmar y cero riesgo de BSOD.
- Homogeneidad de licencia (`GPL-3.0-or-later`) sin mezclar código propietario ni dependencias Go externas.
- Correlación en memoria con `samulibre-watcher` y `samulibre-shield`.
