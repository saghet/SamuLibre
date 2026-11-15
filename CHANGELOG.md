# Registro de Cambios (Changelog)

Todas las modificaciones notables realizadas en este proyecto están documentadas en este archivo.
El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y se adhiere a [Semantic Versioning](https://semver.org/lang/es/).

---

## [2.0.20] - 2026-11-15

### Agregado
- **Crate `samulibre-intel` (Threat Intelligence & Signature Ecosystem):**
  - Base de datos central normalizada (`samulibre_intel.db`) con historial de cambios, deduplicación por `content_hash`, control de licencias SBOM y manifiesto firmado (`manifest.json`).
  - Integración de **YARA Forge** (*Core* en producción, *Extended* en observación, *Full* en laboratorio) y repositorios verificados (*Neo23x0 Signature-Base*, *Yara-Rules*, *ReversingLabs*, *Ditekshen*, *ATR*).
  - **Motor Anti-Falsos Positivos (`AntiFalsePositiveEngine`) y `YaraPromotionGate`:** Clasificación por 3 entornos (*Laboratorio → Observación → Producción*), verificación Authenticode y pruebas de regresión.
  - **Caché Binaria YARA (`SAMUYAR2` `compiled_yara.bin`):** Carga rápida de reglas YARA-X compiladas con validación sintáctica y detección de reglas genéricas o corruptas.
  - **Adaptador Sigma / MITRE ATT&CK (`BehaviorRuleAdapter`)** y **SamuLibre Driver Security Intelligence (`DriverSecurityIntel`)** con base *LOLDrivers* para detección de riesgos BYOVD.
  - **Conectores Threat Intel Live:** *Abuse.ch MalwareBazaar* (POST API v1), *ThreatFox* (POST API v1, ventana 7 días), *URLhaus* (API v1), *Feodo Tracker*, *YARAify*, *AlienVault OTX* (paginación hasta 150 pulses) y *ClamAV* local.
- **Gestión Segura de API Keys y Auto-Sync Diaria:**
  - Panel **🔑 API Keys** en el encabezado del Explorador de Base de Firmas Activas con botones **💾 Guardar Llaves**, **💾 Guardar y Probar** y **⚡ Probar Feeds**, respaldado en `data/secure/intel_keys.json` (excluido de Git y logs).
  - Hilo de actualización automática diaria cada 24 horas para feeds API y repositorios incrementales de hashes (`Neo23x0/signature-base`, `LOLDrivers`).
- **Crate `samulibre-netdefense` y Expansión de UI:**
  - Tarjeta ampliada **IOCs de Red (C2 / Dom / URL)** con desglose en vivo y filtros dedicados para **Red (C2/Dom/URL)**, **Dominios**, **URLs** e **IPs C2**.

### Corregido
- Endpoints retirados (`410 Gone`) de Abuse.ch migrados a APIs v1 autenticadas con header `Auth-Key`.
- Tolerancia a BOM UTF-8 al leer `data/secure/intel_keys.json`.
- Unificación de **🔄 Sincronizar Ahora** para ejecutar también los conectores Threat Intel y refrescar desde SQLite.
- Corrección de falsos positivos en tiempo real sobre scripts temporales de PowerShell (`__PSScriptPolicyTest_*.ps1`) y endurecimiento de cuarentena.

---

## [2.2.0] - 2026-11-07

### Agregado
- **SamuLibre Security Center Unificado:** Consola ejecutiva integral de ciberseguridad para endpoints con panel de control de 9 secciones, índice de salud global circular (0-100%) y telemetría en tiempo real sin métricas simuladas.
- **Integración de Suite VPN Corporativa:** Interfaz y telemetría en vivo del motor `samulibre-vpn` (WireGuard / OpenVPN / Tor), temporizador de conexión, contadores de velocidad y tráfico, selector de servidores seguros (Suiza, Islandia, Suecia, Alemania), protección contra fugas DNS e IPv6 (`netsh advfirewall`), Kill Switch WFP y mecanismo failsafe de restauración de red (`emergency_recover_vpn`).
- **SamuLibre Virtual Patching Engine Fortalecido:** Gestión y auditoría de mitigaciones compensatorias quirúrgicas para vulnerabilidades críticas de Windows (Follina CVE-2022-30190, PrintNightmare CVE-2021-34527, Zerologon CVE-2020-1472, CVE-2023-36884, CVE-2024-38063), diferenciación estricta entre mitigación compensatoria y parche nativo instalado, validación de compatibilidad previa y registro de incidentes de explotación.
- **Windows Patch Intelligence Service:** Descubrimiento e inventario nativo del sistema operativo (edición, versión, compilación, UBR, arquitectura), consulta autoritativa de paquetes de servicio CBS (`Component Based Servicing`) y WUA (`Windows Update Agent`), correlación con catálogos oficiales de MSRC y CISA KEV (Known Exploited Vulnerabilities), y detección de reinicios pendientes (`RebootPending`, `PendingFileRenameOperations`) sin forzar reinicios no autorizados.
- **Motor de Correlación Bidireccional CVE ↔ KB ↔ Virtual Patching:** Grafo relacional interactivo con filtrado por explotación activa en la naturaleza (CISA KEV), severidad CVSS > 9.0, estado de KB y reglas compensatorias activas.
- **Instalador Controlado de Actualizaciones Oficiales:** Instalación de KBs vía WUA API con requerimiento de consentimiento explícito del administrador y garantía estricta de no interrupción de tareas ni reinicio forzado.

---

## [2.1.13] - 2026-11-07

### Agregado
- **Subsistema de Servicio Windows 24/7 (SCM):** Integración completa del despachador de servicios de Windows con el crate `windows-service` v0.8.1 para arranque persistente pre-login y ejecución protegida como `NT AUTHORITY\SYSTEM`.
- **Instalación y Elevación UAC en Un Clic:** Botón contextual `[🛡 Instalar Servicio Windows (UAC)]` y badge interactivo en la tarjeta diagnóstica de la interfaz gráfica para desplegar y registrar el servicio sin salir de la GUI.
- **Health Manager de Protección:** Subsistema de auditoría continua en tiempo real que verifica con evidencia criptográfica y de sistema operativo los 9 componentes esenciales de protección de endpoint.
- **Batería de Autodiagnóstico en Tiempo Real:** 8 pruebas automatizadas bajo demanda que evalúan la latencia del monitor, la cola priorizada, la desinfección EICAR, la bóveda XOR y el despachador IPC.
- **Canal IPC Bidireccional Asíncrono:** Comunicación continua a través de `Tao EventLoopProxy` y WebView2 con refresco cada 5 segundos de métricas de telemetría y salud de subsistemas.

### Corregido
- **Resolución de Bloqueo "PENDIENTE" en GUI:** Corregida discrepancia entre el binario de ejecución en `target\release` y el frontend `index.html`. Sincronización de todas las acciones IPC (`get_protection_health`, `run_realtime_autodiagnostic`, `start_realtime_service`).
- **Control de Instancia Única y Fugas de Conexión:** Corrección del enlace en puerto local `49721` y señal `SHOW` para traer ventanas existentes al frente sin bloquear reinicios.
- **Manejo Seguro de Exclusiones:** Validación de rutas normalizadas y hashes fijados para prevenir bypass de análisis en carpetas vigiladas.
- **Tolerancia a Fallos en Inicio:** Detección y saneamiento automático de proxies de red huérfanos al iniciar la aplicación.

### Rendimiento
- **Memoria en Reposo Optimizada:** Consumo promedio del proceso GUI y motor en reposo por debajo de **42 MB de RAM**.
- **Caché Fast-Path en Memoria:** Verificación instantánea de hashes de archivos benignos con latencia inferior a **0.05 ms** por acceso.

---

## [2.1.0] - 2026-10-24

### Agregado
- Motor heurístico avanzado con cálculo de entropía Shannon para detección de empaquetadores polimórficos (*UPX, Themida, VMProtect*).
- Despliegue de archivos trampa canario anti-ransomware con monitoreo diferencial de escrituras.
- Bóveda de cuarentena cifrada con algoritmo XOR reversible y preservación de metadatos de procedencia.

---

## [2.0.0] - 2026-10-15

### Agregado
- Rediseño visual completo con estética glassmorphism moderna e intuitiva.
- Migración integral de la arquitectura a Rust workspace modular (11 crates independientes).
- Módulo de parchado virtual autónomo para mitigación de CVEs de Windows 11 sin necesidad de reinicio.
