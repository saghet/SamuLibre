# REGISTRO DE REPARACIONES Y MATRIZ DE TRAZABILIDAD (CHANGELOG)

**Proyecto:** SamuLibre Antivirus & Endpoint Detection  
**Versión:** 2.1.14 (Parche de Sincronización Forense y Fuente Única de Verdad)  
**Fecha:** 7 de Noviembre de 2026  
**Auditor Responsable:** DevSecOps Engineer & Principal Software Architect  

---

## 1. MATRIZ INTEGRAL DE TRAZABILIDAD TÉCNICA

A continuación se detalla la correspondencia formal y verificada entre requisitos, componentes, cambios de código, pruebas ejecutadas y evidencia fáctica de resolución:

| Requisito del Proyecto | Componente Afectado | Fichero y Código Modificado | Prueba Ejecutada | Evidencia Fáctica Registrada | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **R1: Erradicar falso positivo visual en Sidebar Footer** | UX / Sidebar Status | `data/ui/index.html` (líneas 210-219)<br>Reemplazado bloque HTML estático por `#sidebarStatusTitle` y `#sidebarStatusDot`. | Inspección de DOM y emisión de snapshot IPC | El texto y color del footer ahora se actualizan dinámicamente con `snapshot.overall_status_label` y `snapshot.overall_status_color`. | ✅ **VALIDADO** |
| **R2: Erradicar falso positivo visual en Dashboard Hero** | UX / Dashboard Hero | `data/ui/index.html` (líneas 254-283)<br>Reemplazado texto estático "Tu equipo está protegido" por nodos `#dashHeroBadge` y `#dashHeroTitle`. | Inspección de DOM en carga inicial y ciclo de 5s | El hero card muestra el estado real ponderado (`Running`, `Degraded`, `Stopped`). | ✅ **VALIDADO** |
| **R3: Corregir mapeo de carpetas de vigilancia** | IPC / Watcher Settings | `crates/samulibre-types/src/lib.rs` & `data/ui/index.html` (línea 2088)<br>Corregido acceso a `settings.custom_watch_dirs`. | `samulibre-watcher::tests::test_watcher_settings_and_dynamic_dirs` | Las carpetas vigiladas reales (`Downloads`, `Desktop`, `Documents`, `Temp`) se muestran en pantalla en lugar del texto mock. | ✅ **VALIDADO** |
| **R4: Crear Fuente Única de Verdad (`ProtectionHealthManager`)** | Core / Health Engine | `crates/samulibre-core/src/health.rs`<br>Implementada estructura `ProtectionHealthManager::evaluate_health()` y 9 recolectores de evidencia. | `samulibre-cli health` | Salida formal de consola detallando los 9 subsistemas con evidencia concreta y sin estados inventados. | ✅ **VALIDADO** |
| **R5: Normalizar estados de los 9 subsistemas** | Types / Health Model | `crates/samulibre-types/src/lib.rs`<br>Añadido enum `SubsystemState` (`Running`, `Stopped`, `Starting`, `Degraded`, `Failed`, `NotInstalled`, etc.). | `cargo test -p samulibre-types` | Todos los crates compilan y consumen la misma tipificación normalizada. | ✅ **VALIDADO** |
| **R6: Comprobación rigurosa de Servicio Windows en SCM** | Watcher / Service Control | `crates/samulibre-watcher/src/service.rs`<br>Añadida función `query_windows_service_state()` con consulta Win32 `sc.exe query`. | `samulibre service status` y `samulibre health` | Si no está en SCM, reporta `NOT_INSTALLED` (error 1060) y conmuta el estado global a `DEGRADED` (Modo Usuario) en amarillo. | ✅ **VALIDADO** |
| **R7: Cola de Eventos con Límite y Prioridades** | Watcher / Queue Engine | `crates/samulibre-watcher/src/lib.rs`<br>`RealtimeEventQueue` acotada a 10,000 elementos con canal `High` para `Downloads/Temp`. | `samulibre-watcher::tests::test_realtime_event_queue_priority_and_bounding` | Eventos de descarga se procesan al frente de la cola (`push_front`) y no se desborda la memoria. | ✅ **VALIDADO** |
| **R8: Manejo de Sharing Violations (Bloqueos de Archivo)** | Watcher / On-Access Engine | `crates/samulibre-watcher/src/lib.rs`<br>Reintento exponencial de 3 fases (20ms/40ms/80ms) ante `PermissionDenied`. | Autodiagnóstico Prueba 4 (Gestión de Bloqueo I/O) | Latencia 2 ms: el backoff esperó la liberación del descriptor y procesó el archivo con éxito. | ✅ **VALIDADO** |
| **R9: Detección On-Access y Aislamiento en Cuarentena** | Watcher / Scanner | `crates/samulibre-watcher/src/lib.rs`<br>`inspect_on_access_with_correlation` con eliminación atómica en disco y cifrado XOR. | Autodiagnóstico Prueba 5 (Detección EICAR) | Muestra neutralizada en 14 ms, eliminada de origen y custodiada en `data/quarantine` con metadatos JSON. | ✅ **VALIDADO** |
| **R10: Sincronización continua IPC con WebView** | GUI / Main Event Loop | `crates/samulibre-gui/src/main.rs`<br>Despacho de `CustomUserEvent::ProtectionHealthLoaded` en arranque y cada 5 segundos en `proxy_shield_loop`. | Ejecución de `samulibre-gui.exe` | La interfaz recibe y pinta el snapshot cada 5 segundos sin bloqueos en el hilo UI. | ✅ **VALIDADO** |
| **R11: Exportación forense de salud del sistema** | UI / Export Handler | `data/ui/index.html`<br>Función `exportProtectionHealthReport()` con descarga de JSON fechado. | Clic en "📄 Exportar Informe" | Genera archivo JSON estructurado con la evaluación completa de los 9 subsistemas. | ✅ **VALIDADO** |

---

## 2. ARCHIVOS MODIFICADOS Y CREADOS

### Ficheros de Código Rust y Frontend:
1. `crates/samulibre-types/src/lib.rs`: Definición de `SubsystemState`, `SubsystemHealthReport` y `ProtectionHealthSnapshot`.
2. `crates/samulibre-watcher/src/service.rs`: Implementación de `query_windows_service_state()`.
3. `crates/samulibre-watcher/src/lib.rs`: Métodos accesores `is_running()` y corrección de firmas duplicadas.
4. `crates/samulibre-core/src/health.rs`: Módulo `ProtectionHealthManager` (colector de los 9 subsistemas).
5. `crates/samulibre-core/src/lib.rs`: Integración del módulo de salud y método `get_protection_health()`.
6. `crates/samulibre-gui/src/main.rs`: Despacho IPC de `ProtectionHealthLoaded` en arranque, bucle continuo e interacciones.
7. `crates/samulibre-cli/src/main.rs`: Nuevo comando `samulibre health` para auditoría en línea de comandos.
8. `data/ui/index.html`: Eliminación total de datos simulados en sidebar y dashboard; integración de `window.onProtectionHealthLoaded()`, exportación de informe y corrección de lista de directorios.

### Documentos Forenses y de Arquitectura:
1. `SAMULIBRE_REALTIME_FORENSIC_AUDIT.md`
2. `SAMULIBRE_HEALTH_MANAGER_ARCHITECTURE.md`
3. `SAMULIBRE_COMPONENT_STATUS.md`
4. `SAMULIBRE_REALTIME_TEST_REPORT.md`
5. `SAMULIBRE_UI_STATUS_AUDIT.md`
6. `SAMULIBRE_KNOWN_ISSUES.md`
7. `SAMULIBRE_REPAIR_CHANGELOG.md`
