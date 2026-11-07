# REGISTRO DE REPARACIONES Y REFACTORIZACIÓN DEL MOTOR DE TIEMPO REAL

**Proyecto:** SamuLibre Antivirus & Endpoint Detection  
**Módulo:** RealTime Watcher & Diagnostic Engine  
**Versión:** 2.1.14  
**Equipo Responsable:** Senior C++/Rust Developer, Principal Software Architect, Windows Systems Engineer  

---

## 1. RESUMEN DE COMPONENTES INTERVENIDOS

| Módulo / Crate | Fichero Modificado | Naturaleza del Cambio / Reparación |
| :--- | :--- | :--- |
| **`samulibre-types`** | `src/lib.rs` | Agregada enumeración de 6 estados `RealtimeProtectionStatus` (`Active`, `Initializing`, `Partial`, `Disabled`, `Error`, `Unverified`), estructura de telemetría atómica `RealtimeTelemetry` y estructuras para diagnósticos `RealtimeDiagnosticReport` y `RealtimeDiagnosticTestResult`. |
| **`samulibre-watcher`** | `src/service.rs` | Implementado controlador completo de servicio Windows y proceso demonio en segundo plano (`is_service_or_daemon_running`, `record_service_pid`, `remove_service_pid`, `install_windows_service`, `uninstall_windows_service`, `start_service`, `stop_service`). |
| **`samulibre-watcher`** | `src/lib.rs` | Rediseño integral: cola acotada prioritaria `RealtimeEventQueue`, generador de `correlation_id` (UUID v4) y prefijo `[TRACE: {id}]`, gestión de bloqueos de archivo con reintento exponencial (`Sharing Violations`), fast-path en caché limpia (<0.05ms), sincronización atómica a `data/realtime_telemetry.json` y batería de autodiagnóstico de 8 pruebas reales sobre disco. |
| **`samulibre-core`** | `src/lib.rs` | Agregados métodos delegadores `get_realtime_telemetry()` y `run_realtime_autodiagnostic()`, integrando el estado del watcher con la API principal del antivirus. |
| **`samulibre-cli`** | `src/main.rs` | Incorporado subcomando `service` (`install`, `uninstall`, `start`, `stop`, `status`, `run`, `autodiagnostic`) y enriquecido `samulibre watcher status` para leer telemetría en vivo. |
| **`samulibre-gui`** | `src/main.rs` | Agregados eventos `CustomUserEvent::RealtimeTelemetryLoaded` y `CustomUserEvent::RealtimeDiagnosticReportLoaded`, handlers IPC para `"get_realtime_telemetry"`, `"run_realtime_autodiagnostic"`, `"start_realtime_service"`, `"stop_realtime_service"` y sondeo de fondo en el bucle principal. |
| **`data/ui`** | `index.html` | Corregido texto engañoso en `showScanProgressUI()`, reconstruido por completo `tab-tiempo-real` con indicadores de los 6 estados operacionales, 4 tarjetas KPI de telemetría viva, sección de Diagnóstico con matriz de 9 subsistemas, tabla de trazas de pruebas y botón de ejecución de autodiagnóstico. |

---

## 2. DETALLE TÉCNICO DE LAS CORRECCIONES APLICADAS

### 2.1 Desacoplamiento del Ciclo de Vida: Demonio / Servicio Windows
- **Problema previo:** Si el usuario minimizaba o cerraba la ventana gráfica, los hilos de `notify` se cancelaban, interrumpiendo la monitorización del sistema de archivos.
- **Solución implementada:** Se creó el comando CLI `samulibre service run`, el cual puede registrarse con `sc create SamuLibreService` o invocarse como un proceso demonio sin interfaz (`--daemon`). El demonio mantiene activa la protección en segundo plano y escribe su estado en `data/realtime_telemetry.json`. Cuando la GUI arranca, detecta automáticamente el servicio y se enlaza a su telemetría viva.

### 2.2 Cola Asíncrona Priorizada con Límite Estricto (Bounded Priority Queue)
- **Problema previo:** Los eventos de archivo se transmitían mediante canales unbounded, lo que exponía al sistema a ataques de denegación de servicio por saturación de memoria.
- **Solución implementada:** Se construyó la clase `RealtimeEventQueue` con una capacidad acotada a 10,000 eventos. Dispone de dos niveles de prioridad:
  - `EventPriority::High`: Eventos originados en carpetas de descarga (`Downloads`) o temporales (`Temp`). Se posicionan al frente de la cola mediante `push_front` para garantizar que ejecutables o scripts recién descargados se inspeccionen primero.
  - `EventPriority::Normal`: Modificaciones y lecturas rutinarias en otros directorios vigilados.

### 2.3 Manejo de Sharing Violations (Reintento con Backoff Exponencial)
- **Problema previo:** Al comenzar a descargar o copiar un archivo de gran tamaño, el sistema operativo o navegador mantiene el descriptor abierto con bloqueo exclusivo. La apertura inmediata por el antivirus devolvía `ERROR_SHARING_VIOLATION` (código 32 de Win32), provocando que el archivo no fuera analizado.
- **Solución implementada:** En `inspect_on_access_with_correlation`, si se produce un error de tipo `std::io::ErrorKind::PermissionDenied`, el worker aplica hasta 3 reintentos con retrasos escalonados (20ms, 40ms y 80ms), permitiendo que el proceso de escritura libere el descriptor antes de proceder con el cálculo del hash SHA-256.

### 2.4 Trazabilidad de Extremo a Extremo con Correlation IDs
- **Problema previo:** Resultaba imposible correlacionar un evento de modificación en disco con su entrada correspondiente en la cola, su hash, su regla YARA y su eventual traslado a cuarentena.
- **Solución implementada:** A cada evento se le adjudica un `correlation_id` (UUID versión 4). Todos los mensajes de log de depuración y auditoría incorporan el prefijo `[TRACE: {correlation_id}]`, y cada registro en el historial de amenazas preserva el ID de correlación para auditorías forenses posteriores.

### 2.5 Eliminación de la Falsa Telemetría en la Interfaz de Usuario
- **Problema previo:** `showScanProgressUI()` asignaba estáticamente "Analizando sistema en tiempo real..." durante escaneos bajo demanda, y la pestaña mostraba permanentemente un botón "ACTIVADO" falso.
- **Solución implementada:** 
  - `showScanProgressUI()` ahora muestra claramente: `"Escaneando archivos del sistema (Análisis Bajo Demanda)..."`.
  - La pestaña de tiempo real ahora refleja el estado real del motor mediante la enumeración de 6 niveles (`PROTECCIÓN ACTIVA`, `INICIALIZANDO`, `PROTECCIÓN PARCIAL`, `PROTECCIÓN DESACTIVADA`, `ERROR DE PROTECCIÓN`, `NO VERIFICADO`), consumiendo los datos transmitidos mediante IPC por el backend.
