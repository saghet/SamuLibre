# SAMULIBRE: ARQUITECTURA DE PROTECCIÓN EN TIEMPO REAL
## Especificación Técnica, Blindaje Anti-Lock, Bóveda Cifrada y Detección Predictiva de Ransomware

---

### 1. Resumen Ejecutivo y Diagnóstico Forense de la Fase 3

Durante la auditoría forense integral de SamuLibre, se identificaron cuatro limitaciones críticas en el subsistema de tiempo real (`samulibre-watcher`):

1. **Fallo Silencioso de Aislamiento:** En `QuarantineVault::isolate_file`, la eliminación del archivo original utilizaba `let _ = fs::remove_file(source_path);`. Cuando un navegador, dropper o proceso retenía un descriptor abierto o el archivo poseía el atributo de solo lectura (Windows), la eliminación fallaba en silencio, dejando el payload malicioso intacto en el disco.
2. **Violaciones de Compartición (Sharing Violations - OS Error 32):** Al descargarse archivos ejecutables o escribirse en disco por procesos en segundo plano, el escáner recibía `ERROR_SHARING_VIOLATION` (acceso denegado) y el evento se descartaba prematuramente.
3. **Desconexión del Monitor Predictivo:** El módulo `PredictiveRansomwareMonitor` (`crates/samulibre-shield/src/ransomware_predictive.rs`) existía como código aislado sin conexión a los eventos del vigilante del sistema de archivos.
4. **Intercepción por Filtros de Minifiltros/Kernel (OS Error 225):** Cuando un archivo contenía firmas críticas de malware o EICAR y el sistema operativo disparaba `ERROR_VIRUS_INFECTED` (código 225), el proceso de cuarentena fallaba al intentar releer los bytes desde el espacio de usuario.

---

### 2. Arquitectura de Protección en Tiempo Real Implementada

```
+----------------------------------------------------------------------------------+
|                    SAMULIBRE REAL-TIME PROTECTION SUBSYSTEM                      |
+----------------------------------------------------------------------------------+
                                        │
           FileSystem Event Loop (Notify 6.1 / ReadDirectoryChangesW)
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
         [1. Predictive Ransomware Pipeline]  [2. Fast-Path File Triage]
         • Muestreo de hasta 32 KB            • Filtro de extensiones críticas
         • Cálculo Entropía Shannon           • Debouncing temporal (150 ms)
         • Ventana móvil: 3 seg / 10 eventos  • Clean File Cache (<0.05 ms)
         • Umbral de alta entropía H >= 7.3             │
                        │                               ▼
                        ▼                     [3. Backoff Sharing Retry]
           { ThreatAlert: Ransomware }        • 4 reintentos: 100, 250, 500, 1000ms
                                              • Manejo de ERROR_SHARING_VIOLATION
                                                        │
                                                        ▼
                                              [4. MultiEngine Scanner]
                                              • Hash-Pinned Exclusions
                                              • ClamAV/ThreatFox Exact Hashes
                                              • YARA-X Reglas Heurísticas
                                              • Detección OS Error 225
                                                        │
                        ┌───────────────────────────────┴───────────────────────────────┐
                        ▼                                                               ▼
                 [File Clean]                                                 [Threat Intercepted]
         • Inserción en Clean Cache                                                     │
         • Límite acotado: 10.000 entradas                                              ▼
                                                                             [5. QuarantineVault]
                                                                             • Anti-Symlink / Anti-LPE
                                                                             • Reintento lectura segura
                                                                             • Manejo OS Error 225
                                                                             • Ofuscación reversible XOR
                                                                             • Escritura atómica (.tmp)
                                                                             • Desbloqueo ReadOnly
                                                                             • Eliminación con backoff
                                                                             • Neutralización in-situ
                                                                             • Metadatos JSON atómicos
```

---

### 3. Componentes y Mecanismos de Blindaje

#### 3.1. Bóveda de Cuarentena Segura (`QuarantineVault`)
- **Blindaje Anti-LPE / Anti-Symlink:** Valida `fs::symlink_metadata` antes de cualquier operación. Si el archivo es un enlace simbólico o NTFS junction, la operación se cancela para evitar ataques de redirección de privilegios.
- **Tolerancia a Filtros de Kernel (OS Error 225):** Si el kernel de Windows o un minifiltro bloquea la lectura directa con `ERROR_VIRUS_INFECTED`, el aislamiento registra una entrada de cuarentena de control (`[BLOCKED_BY_KERNEL_MINIFILTER_OS_ERROR_225]`), garantizando la eliminación del archivo del directorio original sin generar pánico.
- **Escritura Atómica Cifrada:** Los bytes se ofuscan mediante XOR reversible (clave `0xAA` para neutralizar cabeceras `MZ`/PE y evitar ejecuciones accidentales) y se escriben primero en `<id>.quarantine.tmp` antes de renombrarse atómicamente a `<id>.quarantine`.
- **Desbloqueo de Atributos de Solo Lectura:** Si el archivo en disco posee permisos de solo lectura (`perms.readonly()`), se eliminan explícitamente antes de llamar a `fs::remove_file`.
- **Eliminación con Retroceso Escalonado:** Se ejecutan hasta 4 intentos de eliminación con intervalos escalonados (`[50, 150, 300, 600]` ms).
- **Neutralización In-Situ Fallback:** Si un proceso externo retiene un handle de solo lectura bloqueando la desvinculación, el vault intenta abrir el archivo en modo `write + truncate` y sobrescribirlo con `[SAMULIBRE_QUARANTINED_NEUTRALIZED]`, destruyendo el código ejecutable de la amenaza.

#### 3.2. Gestión de Bloqueos I/O y Descargas (`inspect_on_access_with_retry`)
- Cuando un navegador o gestor de descargas descarga un archivo, retiene un bloqueo exclusivo mientras escribe.
- `RealTimeWatcher` implementa un ciclo de 4 reintentos (`[100, 250, 500, 1000]` ms) para permitir que el proceso de descarga termine de vaciar los buffers antes de catalogar el archivo como inaccesible.

#### 3.3. Pipeline de Detección Predictiva de Ransomware
- Conectado directamente en `RealTimeWatcher::start_background_watcher`.
- Para cada evento de creación o modificación de archivos:
  - Se leen hasta 32 KB del archivo.
  - Se calcula la entropía de Shannon ($H$).
  - Se alimenta a `PredictiveRansomwareMonitor::record_event`.
  - Si un proceso supera 10 escrituras/renombres en 3 segundos con entropía media $\ge 7.3$, se emite una alerta crítica de `ThreatCategory::RansomwareActivity` recomendando la suspensión inmediata del proceso atacante.

---

### 4. Pruebas Automatizadas y Verificación

| Prueba Unitaria | Componente | Resultado | Validación |
|---|---|---|---|
| `test_quarantine_vault_lifecycle` | Bóveda | **PASS (0.01s)** | Aislamiento, ofuscación XOR, metadatos JSON y purga permanente. |
| `test_quarantine_readonly_file_removal` | Permisos | **PASS (0.01s)** | Archivo con atributo ReadOnly desbloqueado y eliminado correctamente. |
| `test_realtime_eicar_detection` | TIEMPO REAL | **PASS (0.13s)** | Muestra EICAR interceptada, eliminada del disco y resguardada en bóveda. |
| `test_ransomware_predictive_integration` | Heurística | **PASS (0.01s)** | Ráfaga de 12 eventos con $H = 7.92$ activa alerta predictiva de ransomware. |
| `test_clean_cache_memory_bounding` | Rendimiento | **PASS (0.02s)** | Inserción de 10.500 entradas acotada estrictamente a $\le 10.000$. |
| `test_watcher_settings_and_dynamic_dirs` | Configuración | **PASS (0.01s)** | Adición, remoción dinámica y persistencia en `watcher_config.json`. |
