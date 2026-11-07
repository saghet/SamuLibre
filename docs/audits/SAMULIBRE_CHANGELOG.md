# SAMULIBRE: REGISTRO DE CAMBIOS Y MODERNIZACIÓN (CHANGELOG)
## Historial Técnico de Modificaciones, Correcciones de Seguridad y Nuevas Características

---

### Versión 2.1.13 - Hardening & Engineering Modernization (Noviembre 2026)

#### 1. Motor de Actualización de Firmas (Fase 2)
- **Añadido:** Módulo `samulibre_scanner::updater` con arquitectura modular completa: `UpdateManager`, `SourceManager`, `IntegrityValidator`, `YaraRulesManager`, `ThreatIntelligenceManager`, `ClamAvIntegration`, `RollbackManager` y `AtomicInstaller`.
- **Añadido:** Cliente HTTP nativo `ureq` (2.12.1 con backend TLS `rustls`) para descargas seguras sin dependencias externas de OpenSSL en Windows.
- **Añadido:** Descarga, validación SHA-256 y compilación automática de reglas comunitarias YARA oficiales (`MALW_Eicar.yar` y familias de malware).
- **Añadido:** Descarga y normalización de indicadores de compromiso de la lista de bloqueo C2 de Abuse.ch Feodo Tracker.
- **Añadido:** Despliegue atómico de base de firmas (`.tmp` $\rightarrow$ `.db`) con copia de seguridad `.bak` y reversión automática (rollback) ante fallos de sintaxis o corrupción.
- **Añadido:** Registro de auditoría persistente de actualizaciones en `data/signatures/update_history.json`.
- **Añadido:** Subcomando de consola `samulibre-cli update` con retroalimentación paso a paso en tiempo real.
- **Corregido:** Eliminación del código simulado anterior en la GUI que generaba métricas ficticias de firmas sin realizar peticiones de red.

#### 2. Protección en Tiempo Real y Bóveda de Cuarentena (Fase 3)
- **Corregido:** Fallo silencioso de aislamiento en `QuarantineVault::isolate_file`. Se implementó reintento con retroceso escalonado (`[50, 150, 300, 600]` ms) y limpieza forzada de permisos `ReadOnly`.
- **Añadido:** Neutralización in-situ de emergencia: si un archivo infectado está bloqueado por otro proceso y no puede eliminarse inmediatamente, se trunca y se sobrescribe con `[SAMULIBRE_QUARANTINED_NEUTRALIZED]`.
- **Añadido:** Manejo de intercepción por minifiltros de kernel (código de error del sistema operativo 225 / `ERROR_VIRUS_INFECTED`), evitando excepciones al procesar amenazas bloqueadas por Defender.
- **Añadido:** Escritura atómica ofuscada en cuarentena mediante inversión XOR (`0xAA`) para anular cabeceras ejecutables PE.
- **Corregido:** Gestión de violaciones de compartición (`ERROR_SHARING_VIOLATION` / OS error 32) mediante backoff escalonado en `inspect_on_access_with_retry` (`[100, 250, 500, 1000]` ms).
- **Añadido:** Conexión del flujo de eventos de `samulibre-watcher` con `PredictiveRansomwareMonitor`, analizando la entropía de Shannon de los primeros 32 KB para detectar ráfagas de cifrado masivo.
- **Añadido:** Suite de pruebas automatizadas en tiempo real con la muestra estándar EICAR (`test_realtime_eicar_detection`).

#### 3. Detección y Blindaje de Sandboxing (Fase 4)
- **Seguridad Crítica:** Eliminación de la ejecución directa y desprotegida de binarios PE hostiles en el host (`Command::new` en `MicroSandbox`).
- **Añadido:** Análisis estático seguro, desensamblado de cadenas y mapeo a tácticas de MITRE ATT&CK:
  - `T1055`: Inyección de procesos (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
  - `T1105`: Descarga de herramientas remotas (`URLDownloadToFile`, `InternetOpen`).
  - `T1059`: Intérpretes de scripts ocultos (`powershell -enc`, `wscript.shell`).
  - `T1486`: Destrucción de copias de seguridad de volumen y cifrado (`vssadmin delete shadows`).

#### 4. Falsos Positivos y Exclusiones Criptográficas (Fase 5)
- **Añadido:** Estructura `PinnedExclusion` en `samulibre-types` con anclaje de hash SHA-256 opcional/obligatorio.
- **Añadido:** `ExclusionManager` integrado en `MultiEngineScanner`, verificando si un archivo excluido coincide con su hash SHA-256 original antes de omitir la alerta.
- **Añadido:** Revocación automática de exclusión: si un archivo en la lista de confianza es modificado o reemplazado por malware, la exclusión queda anulada y se analiza normalmente.
- **Añadido:** Clasificación de veredictos en 5 niveles (`ThreatVerdict`): `ConfirmedMalware`, `LikelyMalware`, `Inconclusive`, `LikelyFalsePositive`, `ConfirmedFalsePositive`.
- **Conectado:** La opción de "Excluir" en la GUI ahora calcula el SHA-256 del archivo y lo ancla en `data/exclusions.json`.

#### 5. Autoprotección y Endurecimiento (Fase 6)
- **Añadido:** Verificación de integridad por línea base criptográfica SHA-256 en `AntiTamperShield`.
- **Añadido:** Bloqueo de escritura y protección de archivos del antivirus mediante permisos de solo lectura en Windows.
- **Corregido:** Bug de truncamiento de hash SHA-256 en archivos mayores a 16 MB (`samulibre-scanner/src/lib.rs`), garantizando el cálculo íntegro de huella digital sobre el 100% del archivo.

#### 6. Calidad y Verificación
- **Pruebas:** 60 pruebas unitarias y de integración pasando exitosamente en todo el workspace (`cargo test --workspace`).
- **Compilación:** Cero advertencias (`0 warnings`) y cero errores en todos los crates.
