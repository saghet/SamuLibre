# AUDITORÍA FORENSE DEL MÓDULO REAL-TIME GUARD (SAMULIBRE)

**Fecha:** 7 de Noviembre de 2026  
**Proyecto:** SamuLibre Antivirus & Endpoint Detection (Windows 10/11)  
**Clasificación:** Auditoría Forense de Estado, Sincronización y Subsistemas  
**Equipo Responsable:** Principal Software Architect, Senior Windows Developer, IPC Engineer, Software Forensics Engineer, Application Security Auditor.

---

## 1. INVESTIGACIÓN DE LAS CONTRADICCIONES ENCONTRADAS

En la auditoría inicial de la interfaz de usuario se identificó el siguiente escenario contradictorio:

- **RealTime Guard:** `NO VERIFICADO`
- **Servicio Windows 24/7:** `DETENIDO`
- **Uptime:** `0 segundos`
- **Cola de eventos:** `0 pendientes, 0 procesados, 0 descartados`
- **Inspección On-Access:** `0 archivos, 0 amenazas`
- **Diagnóstico de subsistemas:** `PENDIENTE` en todos los componentes
- **Directorios protegidos:** `Descargas del Usuario: VIGILANDO`
- **Barra inferior / Sidebar footer:** `PROTECCIÓN ACTIVA` / `MOTOR Y WATCHER EN LÍNEA` (con luz verde pulsante)

A continuación se detalla la investigación técnica forense de cada anomalía:

### Causa Raíz 1: Hardcoded HTML en el Pie del Sidebar y Dashboard
- **Fichero:** `data/ui/index.html` (líneas 211-219 previas)
- **Evidencia Forense:**
  ```html
  <!-- Sidebar Footer Status PREVIO (Falso Positivo Visual) -->
  <div class="p-4 border-t border-slate-800/60 bg-slate-950/40">
    <div class="flex items-center gap-2.5">
      <div class="w-2.5 h-2.5 rounded-full bg-emerald-500 status-ring-pulse"></div>
      <div>
        <p class="text-xs font-bold text-slate-200">Protección Activa</p>
        <p class="text-[10px] text-slate-400">Motor y Watcher en línea</p>
      </div>
    </div>
  </div>
  ```
  Este fragmento carecía de identificadores `id`, no estaba enlazado a ningún evento IPC y presentaba permanentemente un punto verde y el texto "Protección Activa / Motor y Watcher en línea", sin importar si el backend estaba detenido, cerrado o si el servicio no existía.
- **Acción Correctiva:** Se reemplazó por nodos dinámicos (`sidebarStatusDot`, `sidebarStatusTitle`, `sidebarStatusSubtitle`) gobernados exclusivamente por el `ProtectionHealthManager`.

### Causa Raíz 2: Discrepancia de Nombres en `WatcherSettings`
- **Fichero:** `crates/samulibre-types/src/lib.rs` vs `data/ui/index.html`
- **Evidencia Forense:**
  La estructura en Rust definía:
  ```rust
  pub struct WatcherSettings {
      pub enabled: bool,
      pub custom_watch_dirs: Vec<String>,
      ...
  }
  ```
  Sin embargo, el manejador JavaScript en `index.html` comprobaba:
  ```javascript
  if (!settings || !settings.monitored_paths || settings.monitored_paths.length === 0)
  ```
  Al ser `settings.monitored_paths` un valor `undefined`, la condición fallaba silenciosamente y nunca se actualizaba la lista de carpetas vigiladas, manteniendo el HTML estático inicial que mostraba "Descargas del Usuario: Vigilando".
- **Acción Correctiva:** Se corrigió el mapeo a `settings.custom_watch_dirs` y se sincronizó con `snapshot.active_watch_dirs` provisto por el gestor de salud.

### Causa Raíz 3: Confusión entre Servicio Windows (SCM) y Demonio de Espacio de Usuario
- **Evidencia Forense:**
  `service::is_service_or_daemon_running()` comprobaba si existía un servicio registrado en Windows Service Control Manager (`sc.exe query SamuLibreWatcher`).
  Al ejecutarse SamuLibre como aplicación de escritorio ordinaria sin haber instalado previamente el servicio en el sistema operativo mediante privilegios de Administrador (`samulibre service install`), el SCM devolvía el código de error `1060: ERROR_SERVICE_DOES_NOT_EXIST`.
  Por ello, la tarjeta indicaba honestamente: `Servicio Windows 24/7: DETENIDO`.
  Sin embargo, el usuario observaba a la vez la leyenda "Protección Activa" en el footer hardcodeado, generando la aparente contradicción.
- **Acción Correctiva:** Se normalizó el estado. Si el proceso opera en modo escritorio sin servicio SCM, el estado se cataloga explícitamente como `SubsystemState::Degraded` ("PROTECCIÓN PARCIAL (MODO USUARIO / GUI)") en color amarillo, aclarando que no persiste tras cerrar la ventana.

---

## 2. RESPUESTAS FORENSES A LAS DIEZ PREGUNTAS CLAVE DE AUDITORÍA

### 1. ¿Dónde se inicia el servicio?
- **Servicio Windows SCM (24/7):** Se instala mediante `samulibre service install` (`sc.exe create SamuLibreWatcher ...`) y se arranca mediante `samulibre service start` o `sc.exe start SamuLibreWatcher`.
- **Demonio en espacio de usuario:** Se inicia como subproceso mediante `samulibre service run` o a través del hilo de inicialización `c.initialize()` dentro de `crates/samulibre-gui/src/main.rs`.

### 2. ¿Quién comprueba su estado?
- El módulo `samulibre_watcher::service::query_windows_service_state()` ejecuta una consulta Win32 a `sc.exe query SamuLibreWatcher` y verifica la existencia del archivo de bloqueo de proceso `data/samulibre_service.pid`.

### 3. ¿Quién inicia el Watcher?
- `SamuLibreCore::initialize()` en `crates/samulibre-core/src/lib.rs` (línea 93) adquiere el bloqueo de `self.watcher` y llama a `w.start_background_watcher(...)`.

### 4. ¿Quién recibe los eventos?
- La biblioteca `notify::RecommendedWatcher` (apoyada en la API nativa de Windows `ReadDirectoryChangesW` con Completion Ports) captura los eventos de E/S del sistema de archivos y los deposita en la cola concurrente `RealtimeEventQueue`.

### 5. ¿Quién envía los archivos al motor?
- El hilo trabajador (*worker thread*) de `samulibre-watcher` consume de `RealtimeEventQueue`, extrae la ruta del archivo, asigna un `correlation_id` (UUID v4) y despacha la llamada `sub_watcher.inspect_on_access_with_correlation(&event.path, 3, correlation_id)`.

### 6. ¿Quién actualiza las estadísticas?
- Las estadísticas se actualizan mediante contadores atómicos `AtomicUsize` en `RealTimeWatcher`: `files_inspected`, `threats_intercepted`, `events_enqueued_total`, `events_processed_total` y `events_dropped_total`.
- Estas métricas son leídas por `ProtectionHealthManager` y `get_telemetry()`.

### 7. ¿Quién determina el estado general?
- **Antes de la refactorización:** Cada pantalla e indicador calculaba su propio estado de manera fragmentada o mantenía valores estáticos hardcodeados en HTML.
- **Actualmente:** El módulo centralizado `ProtectionHealthManager::evaluate_health()` en `crates/samulibre-core/src/health.rs` evalúa los 9 subsistemas de forma ponderada y determina el estado unificado (`ProtectionHealthSnapshot`).

### 8. ¿Quién comunica el estado a la interfaz?
- El bucle de eventos de la GUI (`proxy_shield_loop`) y el hilo de inicialización (`proxy_init`) en `crates/samulibre-gui/src/main.rs` envían `CustomUserEvent::ProtectionHealthLoaded` cada 5 segundos al WebView mediante `window.onProtectionHealthLoaded(snapshot)`.

### 9. ¿Qué ocurre cuando un componente falla?
- Si un componente crítico falla (por ejemplo, base de firmas inaccesible o fallo en bóveda de cuarentena), el estado global transiciona automáticamente a `SubsystemState::Failed` (ROJO, `ERROR CRÍTICO EN MOTOR`).
- Si falla el servicio Windows SCM pero el monitor local sigue vivo, transiciona a `SubsystemState::Degraded` (AMARILLO, `MODO USUARIO`).

### 10. ¿Qué ocurre cuando la aplicación se cierra?
- Si el usuario cierra la interfaz gráfica:
  - Si el Servicio Windows 24/7 (`samulibre service run`) está instalado y activo en el SCM, la protección en disco continúa ejecutándose de manera ininterrumpida.
  - Si solo operaba en modo escritorio, los hilos locales finalizan, pero el estado en disco (`data/realtime_telemetry.json`) registra la detención y el próximo arranque no mostrará falsos positivos de protección activa.
