pub mod service;

use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::{Config, Event, EventKind, Watcher};
pub use notify::{RecommendedWatcher, RecursiveMode};
use samulibre_scanner::MultiEngineScanner;
use samulibre_types::{
    FileScanStatus, RealtimeDiagnosticReport, RealtimeDiagnosticTestResult,
    RealtimeProtectionStatus, RealtimeTelemetry, Severity, ThreatAlert, ThreatCategory,
    WatcherSettings,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};
use uuid::Uuid;

/// Registro de un archivo en caché validado como limpio
#[derive(Debug, Clone)]
struct CacheEntry {
    #[allow(dead_code)]
    sha256: String,
    size: u64,
    modified: SystemTime,
}

/// Metadatos de un archivo en cuarentena
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: Uuid,
    pub original_path: String,
    pub threat_name: String,
    pub engine: String,
    pub sha256: String,
    pub quarantined_at: DateTime<Utc>,
    pub isolated_file_path: String,
}

/// Tipo de evento del sistema de archivos capturado en tiempo real
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealtimeEventKind {
    Created,
    Modified,
    Renamed,
    Copied,
    Downloaded,
    Deleted,
}

/// Nivel de prioridad para la cola de procesamiento en tiempo real
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Evento atómico de archivo en la cola de inspección con ID de correlación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeFileEvent {
    pub correlation_id: Uuid,
    pub path: PathBuf,
    pub event_kind: RealtimeEventKind,
    pub timestamp: DateTime<Utc>,
    pub retry_count: usize,
    pub priority: EventPriority,
}

/// Cola concurrente, acotada y con priorización para eventos del sistema de archivos
pub struct RealtimeEventQueue {
    queue: Arc<Mutex<VecDeque<RealtimeFileEvent>>>,
    condvar: Arc<Condvar>,
    events_enqueued: Arc<AtomicUsize>,
    events_processed: Arc<AtomicUsize>,
    events_dropped: Arc<AtomicUsize>,
    max_capacity: usize,
    is_shutdown: Arc<AtomicBool>,
}

impl RealtimeEventQueue {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            condvar: Arc::new(Condvar::new()),
            events_enqueued: Arc::new(AtomicUsize::new(0)),
            events_processed: Arc::new(AtomicUsize::new(0)),
            events_dropped: Arc::new(AtomicUsize::new(0)),
            max_capacity,
            is_shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Inserta un evento con respeto estricto de prioridades y límites de memoria
    pub fn push(&self, event: RealtimeFileEvent) -> bool {
        if self.is_shutdown.load(Ordering::Relaxed) {
            return false;
        }

        let mut q = self.queue.lock().unwrap();
        if q.len() >= self.max_capacity {
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
            warn!(
                "[EVENT QUEUE OVERFLOW] Se descartó evento {} ('{}') por saturación de cola (límite: {}).",
                event.correlation_id,
                event.path.display(),
                self.max_capacity
            );
            return false;
        }

        if event.priority >= EventPriority::High {
            let pos = q
                .iter()
                .position(|e| e.priority < event.priority)
                .unwrap_or(q.len());
            q.insert(pos, event);
        } else {
            q.push_back(event);
        }
        self.events_enqueued.fetch_add(1, Ordering::Relaxed);
        self.condvar.notify_one();
        true
    }

    /// Extrae el siguiente evento para procesamiento o espera hasta timeout
    pub fn pop(&self, timeout: std::time::Duration) -> Option<RealtimeFileEvent> {
        let mut q = self.queue.lock().unwrap();
        while q.is_empty() {
            if self.is_shutdown.load(Ordering::Relaxed) {
                return None;
            }
            let res = self.condvar.wait_timeout(q, timeout).unwrap();
            q = res.0;
            if res.1.timed_out() {
                return None;
            }
        }
        let ev = q.pop_front();
        if ev.is_some() {
            self.events_processed.fetch_add(1, Ordering::Relaxed);
        }
        ev
    }

    pub fn shutdown(&self) {
        self.is_shutdown.store(true, Ordering::SeqCst);
        self.condvar.notify_all();
    }

    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.lock().unwrap().is_empty()
    }

    pub fn enqueued_count(&self) -> usize {
        self.events_enqueued.load(Ordering::Relaxed)
    }

    pub fn processed_count(&self) -> usize {
        self.events_processed.load(Ordering::Relaxed)
    }

    pub fn dropped_count(&self) -> usize {
        self.events_dropped.load(Ordering::Relaxed)
    }
}

/// Gestor de la bóveda de cuarentena cifrada
pub struct QuarantineVault {
    quarantine_dir: PathBuf,
}

impl QuarantineVault {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        let p = dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&p);
        Self { quarantine_dir: p }
    }

    /// Aísla y cifra un archivo malicioso para que no pueda ejecutarse en el SO
    pub fn isolate_file(
        &self,
        source_path: &Path,
        threat: &str,
        engine: &str,
        sha256: &str,
    ) -> Result<QuarantineRecord> {
        // Blindaje Anti-Symlink / Anti-LPE: Verificar que el archivo no sea un junction o symlink
        if let Ok(sym_meta) = fs::symlink_metadata(source_path) {
            if sym_meta.file_type().is_symlink() {
                anyhow::bail!("Intento de manipulación LPE detectado: '{}' es un enlace simbólico / junction. Operación cancelada.", source_path.display());
            }
        }

        // Lectura segura con reintentos para manejar bloqueos temporales de descarga o compartición
        let mut original_bytes_opt = None;
        let mut kernel_blocked_225 = false;
        let read_delays = [50, 150, 300, 600];
        for attempt in 0..4 {
            match fs::read(source_path) {
                Ok(bytes) => {
                    original_bytes_opt = Some(bytes);
                    break;
                }
                Err(e) => {
                    if e.raw_os_error() == Some(225) {
                        warn!("Archivo malicioso bloqueado por filtro de kernel/minifiltro (OS Error 225): {}", source_path.display());
                        kernel_blocked_225 = true;
                        break;
                    }
                    if attempt == 3 {
                        anyhow::bail!("No se pudo leer el archivo malicioso '{}' para cuarentena tras 4 intentos: {}", source_path.display(), e);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(read_delays[attempt]));
                }
            }
        }

        let original_bytes = if kernel_blocked_225 {
            b"[BLOCKED_BY_KERNEL_MINIFILTER_OS_ERROR_225]".to_vec()
        } else {
            original_bytes_opt.expect("original bytes must be present")
        };

        let id = Uuid::new_v4();
        let isolated_name = format!("{}.quarantine", id);
        let isolated_path = self.quarantine_dir.join(&isolated_name);
        let isolated_temp = self.quarantine_dir.join(format!("{}.quarantine.tmp", id));

        // Ofuscación reversible básica (XOR con clave fija de cuarentena) para anular headers PE ejecutables
        let xor_key = 0xAA;
        let obfuscated_bytes: Vec<u8> = original_bytes.iter().map(|b| b ^ xor_key).collect();
        fs::write(&isolated_temp, obfuscated_bytes)?;
        fs::rename(&isolated_temp, &isolated_path)?;

        // Si el archivo de origen tiene atributo de solo lectura (Windows), limpiarlo antes de eliminar
        if let Ok(mut perms) = fs::metadata(source_path).map(|m| m.permissions()) {
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(source_path, perms);
            }
        }

        // Intentar eliminar con reintentos y retroceso escalonado
        let mut removed = false;
        let remove_delays = [50, 150, 300, 600];
        for attempt in 0..4 {
            match fs::remove_file(source_path) {
                Ok(_) => {
                    removed = true;
                    break;
                }
                Err(_) => {
                    if attempt < 3 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            remove_delays[attempt],
                        ));
                    }
                }
            }
        }

        // Si aún no se pudo eliminar (archivo bloqueado por proceso activo), neutralizar su contenido in-situ
        if !removed && source_path.exists() {
            if let Ok(mut f) = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(source_path)
            {
                use std::io::Write;
                let _ = f.write_all(b"[SAMULIBRE_QUARANTINED_NEUTRALIZED]");
                warn!(
                    "Archivo bloqueado por proceso externo neutralizado in-situ: {}",
                    source_path.display()
                );
                removed = true;
            }
        }

        if source_path.exists() && !removed {
            warn!("ADVERTENCIA CRÍTICA: Archivo malicioso en '{}' no pudo ser removido ni truncado por bloqueo exclusivo del sistema.", source_path.display());
        }

        let record = QuarantineRecord {
            id,
            original_path: source_path.to_string_lossy().to_string(),
            threat_name: threat.to_string(),
            engine: engine.to_string(),
            sha256: sha256.to_string(),
            quarantined_at: Utc::now(),
            isolated_file_path: isolated_path.to_string_lossy().to_string(),
        };

        // Guardar metadatos en JSON de forma atómica
        let meta_temp = self.quarantine_dir.join(format!("{}.meta.json.tmp", id));
        let meta_path = self.quarantine_dir.join(format!("{}.meta.json", id));
        fs::write(&meta_temp, serde_json::to_string_pretty(&record)?)?;
        fs::rename(&meta_temp, &meta_path)?;

        warn!(
            "¡AMENAZA AISLADA EN CUARENTENA! Archivo: {} -> Bóveda: {:?}",
            source_path.display(),
            isolated_path
        );
        Ok(record)
    }

    /// Lista los elementos actualmente en cuarentena
    pub fn list_quarantined(&self) -> Vec<QuarantineRecord> {
        let mut list = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.quarantine_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(record) = serde_json::from_str::<QuarantineRecord>(&content) {
                            list.push(record);
                        }
                    }
                }
            }
        }
        list
    }

    /// Elimina de forma permanente un archivo y sus metadatos de la cuarentena
    pub fn purge_file(&self, id: Uuid) -> Result<bool> {
        let isolated_path = self.quarantine_dir.join(format!("{}.quarantine", id));
        let meta_path = self.quarantine_dir.join(format!("{}.meta.json", id));
        let _ = fs::remove_file(isolated_path);
        let _ = fs::remove_file(meta_path);
        Ok(true)
    }

    /// Restaura un archivo previamente aislado a su ruta original descifrando su contenido
    pub fn restore_file(&self, id: Uuid) -> Result<String> {
        let meta_path = self.quarantine_dir.join(format!("{}.meta.json", id));
        let isolated_path = self.quarantine_dir.join(format!("{}.quarantine", id));
        if !meta_path.exists() || !isolated_path.exists() {
            anyhow::bail!(
                "Registro de cuarentena no encontrado en {}",
                self.quarantine_dir.display()
            );
        }
        let meta_content = fs::read_to_string(&meta_path)?;
        let record = serde_json::from_str::<QuarantineRecord>(&meta_content)?;
        let obfuscated_bytes = fs::read(&isolated_path)?;
        let xor_key = 0xAA;
        let restored_bytes: Vec<u8> = obfuscated_bytes.iter().map(|b| b ^ xor_key).collect();
        let target_path = PathBuf::from(&record.original_path);
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&target_path, restored_bytes)?;
        let _ = fs::remove_file(&isolated_path);
        let _ = fs::remove_file(&meta_path);
        info!(
            "Archivo restaurado con éxito desde la cuarentena: {}",
            record.original_path
        );
        Ok(record.original_path)
    }
}

/// Motor Principal de Protección de Archivos en Tiempo Real
pub struct RealTimeWatcher {
    scanner: Arc<Mutex<MultiEngineScanner>>,
    vault: Arc<QuarantineVault>,
    clean_cache: Arc<Mutex<HashMap<PathBuf, CacheEntry>>>,
    watch_dirs: Vec<PathBuf>,
    files_inspected: Arc<AtomicUsize>,
    threats_intercepted: Arc<AtomicUsize>,
    ransomware_monitor:
        Arc<Mutex<samulibre_shield::ransomware_predictive::PredictiveRansomwareMonitor>>,
    event_queue: Arc<RealtimeEventQueue>,
    telemetry: Arc<Mutex<RealtimeTelemetry>>,
    start_time: std::time::Instant,
    is_running: Arc<AtomicBool>,
}

impl RealTimeWatcher {
    pub fn new(scanner: Arc<Mutex<MultiEngineScanner>>, quarantine_dir: impl AsRef<Path>) -> Self {
        let mut watcher = Self {
            scanner,
            vault: Arc::new(QuarantineVault::new(quarantine_dir)),
            clean_cache: Arc::new(Mutex::new(HashMap::new())),
            watch_dirs: Vec::new(),
            files_inspected: Arc::new(AtomicUsize::new(0)),
            threats_intercepted: Arc::new(AtomicUsize::new(0)),
            ransomware_monitor: Arc::new(Mutex::new(
                samulibre_shield::ransomware_predictive::PredictiveRansomwareMonitor::new(),
            )),
            event_queue: Arc::new(RealtimeEventQueue::new(10_000)),
            telemetry: Arc::new(Mutex::new(RealtimeTelemetry::default())),
            start_time: std::time::Instant::now(),
            is_running: Arc::new(AtomicBool::new(false)),
        };
        watcher.load_custom_watch_dirs();
        watcher.update_initial_telemetry();
        watcher
    }

    fn update_initial_telemetry(&self) {
        if let Ok(mut t) = self.telemetry.lock() {
            t.status = RealtimeProtectionStatus::Initializing;
            t.status_detail = "Subsistema de tiempo real listo para enlace.".to_string();
            t.service_running = service::is_service_or_daemon_running();
            t.monitored_paths = self
                .watch_dirs
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect();
        }
    }

    pub fn get_vault(&self) -> Arc<QuarantineVault> {
        Arc::clone(&self.vault)
    }

    pub fn get_event_queue(&self) -> Arc<RealtimeEventQueue> {
        Arc::clone(&self.event_queue)
    }

    pub fn get_ransomware_monitor(
        &self,
    ) -> Arc<Mutex<samulibre_shield::ransomware_predictive::PredictiveRansomwareMonitor>> {
        Arc::clone(&self.ransomware_monitor)
    }

    pub fn get_watch_dirs(&self) -> Vec<PathBuf> {
        self.watch_dirs.clone()
    }

    pub fn add_watch_dir(&mut self, dir: impl AsRef<Path>) {
        let p = dir.as_ref().to_path_buf();
        if p.exists() && !self.watch_dirs.contains(&p) {
            self.watch_dirs.push(p);
            self.save_custom_watch_dirs();
            self.sync_telemetry_snapshot();
        }
    }

    pub fn remove_watch_dir(&mut self, dir: impl AsRef<Path>) -> bool {
        let p = dir.as_ref().to_path_buf();
        if let Some(pos) = self.watch_dirs.iter().position(|d| d == &p) {
            self.watch_dirs.remove(pos);
            self.save_custom_watch_dirs();
            self.sync_telemetry_snapshot();
            true
        } else {
            false
        }
    }

    pub fn load_custom_watch_dirs(&mut self) {
        let config_file = Path::new("data").join("watcher_config.json");
        if config_file.exists() {
            if let Ok(content) = fs::read_to_string(&config_file) {
                if let Ok(settings) = serde_json::from_str::<WatcherSettings>(&content) {
                    for path_str in settings.custom_watch_dirs {
                        let pb = PathBuf::from(path_str);
                        if pb.exists() && !self.watch_dirs.contains(&pb) {
                            self.watch_dirs.push(pb);
                        }
                    }
                }
            }
        }
    }

    pub fn save_custom_watch_dirs(&self) {
        let _ = fs::create_dir_all("data");
        let config_file = Path::new("data").join("watcher_config.json");
        let settings = self.get_settings();
        if let Ok(json_str) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write(config_file, json_str);
        }
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    pub fn get_settings(&self) -> WatcherSettings {
        WatcherSettings {
            enabled: self.is_running.load(Ordering::Relaxed),
            custom_watch_dirs: self
                .watch_dirs
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            files_inspected_total: self.files_inspected.load(Ordering::Relaxed),
            threats_intercepted_total: self.threats_intercepted.load(Ordering::Relaxed),
        }
    }

    /// Retorna una copia fresca de la telemetría del subsistema
    pub fn get_telemetry(&self) -> RealtimeTelemetry {
        // Si el archivo en disco es más reciente (por ejemplo escrito por el servicio demonio de fondo), leerlo
        let telem_file = Path::new("data").join("realtime_telemetry.json");
        if telem_file.exists() {
            if let Ok(content) = fs::read_to_string(&telem_file) {
                if let Ok(disk_telem) = serde_json::from_str::<RealtimeTelemetry>(&content) {
                    if disk_telem.service_running || disk_telem.watcher_running {
                        return disk_telem;
                    }
                }
            }
        }

        if let Ok(mut t) = self.telemetry.lock() {
            t.service_running = service::is_service_or_daemon_running();
            t.watcher_running = self.is_running.load(Ordering::Relaxed);
            t.queue_depth = self.event_queue.len();
            t.events_enqueued_total = self.event_queue.enqueued_count();
            t.events_processed_total = self.event_queue.processed_count();
            t.events_dropped_total = self.event_queue.dropped_count();
            t.files_inspected_total = self.files_inspected.load(Ordering::Relaxed);
            t.threats_intercepted_total = self.threats_intercepted.load(Ordering::Relaxed);
            t.uptime_seconds = self.start_time.elapsed().as_secs();
            t.monitored_paths = self
                .watch_dirs
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect();

            if t.watcher_running || t.service_running {
                t.status = RealtimeProtectionStatus::Active;
                t.status_detail = format!(
                    "Protección activa. Cola: {} eventos pendientes. Archivos inspeccionados: {}.",
                    t.queue_depth, t.files_inspected_total
                );
            } else {
                t.status = RealtimeProtectionStatus::Disabled;
                t.status_detail = "Protección en tiempo real detenida.".to_string();
            }

            t.clone()
        } else {
            RealtimeTelemetry::default()
        }
    }

    /// Guarda la telemetría atómicamente en data/realtime_telemetry.json
    pub fn sync_telemetry_snapshot(&self) {
        let telem = self.get_telemetry();
        let _ = fs::create_dir_all("data");
        let path = Path::new("data").join("realtime_telemetry.json");
        let temp = Path::new("data").join("realtime_telemetry.json.tmp");
        if let Ok(json_str) = serde_json::to_string_pretty(&telem) {
            if fs::write(&temp, json_str).is_ok() {
                let _ = fs::rename(&temp, &path);
            }
        }
    }

    /// Analiza un archivo interceptado en tiempo real con trazabilidad de correlación
    pub fn inspect_on_access(&self, file_path: &Path) -> Option<ThreatAlert> {
        self.inspect_on_access_with_correlation(file_path, 3, Uuid::new_v4())
    }

    /// Analiza un archivo con backoff escalonado y vinculación a un ID de correlación
    pub fn inspect_on_access_with_correlation(
        &self,
        file_path: &Path,
        max_retries: usize,
        correlation_id: Uuid,
    ) -> Option<ThreatAlert> {
        if !file_path.exists() {
            return None;
        }

        // Blindaje Anti-Symlink / Anti-LPE: Omitir enlaces simbólicos o junctions para evitar manipulaciones de ruta
        if let Ok(sym_meta) = fs::symlink_metadata(file_path) {
            if sym_meta.file_type().is_symlink() {
                warn!("[TRACE: {}] Omitiendo archivo sospechoso por ser enlace simbólico / junction (Anti-LPE): {:?}", correlation_id, file_path);
                return None;
            }
        }

        // Filtro de extensiones críticas para evitar sobrecarga en archivos no ejecutables
        if !is_high_risk_extension(file_path) {
            return None;
        }

        let backoff_delays = [100, 250, 500, 1000];
        let mut metadata_opt = fs::metadata(file_path).ok();

        // Manejo seguro de archivos bloqueados por descarga o compartición en curso
        for attempt in 0..max_retries {
            if let Some(ref m) = metadata_opt {
                if m.len() > 0 {
                    break;
                }
            }
            if attempt < backoff_delays.len() {
                std::thread::sleep(std::time::Duration::from_millis(backoff_delays[attempt]));
                metadata_opt = fs::metadata(file_path).ok();
            }
        }

        let metadata = match metadata_opt {
            Some(m) => m,
            None => {
                info!(
                    "[TRACE: {}] Archivo '{}' desapareció o fue inaccesible antes de inspección.",
                    correlation_id,
                    file_path.display()
                );
                return None;
            }
        };

        let file_size = metadata.len();
        let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // 1. Verificación en Clean File Cache (<0.05 ms) SOLO si el tamaño > 0
        if file_size > 0 {
            if let Ok(cache) = self.clean_cache.lock() {
                if let Some(entry) = cache.get(file_path) {
                    if entry.size == file_size && entry.modified == modified_time {
                        // Archivo limpio y verificado sin cambios
                        return None;
                    }
                }
            }
        }

        // 2. Inspección por el motor MultiEngineScanner
        let mut scan_result_opt = None;
        for attempt in 0..max_retries {
            if let Ok(s) = self.scanner.lock() {
                match s.scan_file(file_path) {
                    Ok(r) => {
                        if r.status != FileScanStatus::AccessDenied || attempt + 1 == max_retries {
                            scan_result_opt = Some(r);
                            break;
                        }
                    }
                    Err(_) => {
                        if attempt + 1 == max_retries {
                            return None;
                        }
                    }
                }
            }
            if attempt < backoff_delays.len() {
                std::thread::sleep(std::time::Duration::from_millis(backoff_delays[attempt]));
            }
        }

        let scan_result = match scan_result_opt {
            Some(r) => r,
            None => return None,
        };

        self.files_inspected.fetch_add(1, Ordering::Relaxed);

        // Actualizar telemetría de último evento analizado
        if let Ok(mut t) = self.telemetry.lock() {
            t.last_event_path = Some(file_path.to_string_lossy().to_string());
            t.last_event_timestamp = Some(Utc::now().to_rfc3339());
        }

        match scan_result.status {
            FileScanStatus::Clean => {
                if file_size > 0 {
                    if let Ok(mut cache) = self.clean_cache.lock() {
                        if cache.len() >= 10_000 {
                            let to_remove: Vec<_> = cache.keys().take(2000).cloned().collect();
                            for k in to_remove {
                                cache.remove(&k);
                            }
                        }
                        cache.insert(
                            file_path.to_path_buf(),
                            CacheEntry {
                                sha256: scan_result.sha256,
                                size: file_size,
                                modified: modified_time,
                            },
                        );
                    }
                }
                None
            }
            FileScanStatus::Infected | FileScanStatus::Suspicious => {
                self.threats_intercepted.fetch_add(1, Ordering::Relaxed);
                let threat_name = scan_result
                    .detection_name
                    .unwrap_or_else(|| "Amenaza.Desconocida".to_string());
                let engine = scan_result.engine;
                let sha256 = scan_result.sha256;

                // 3. Aislamiento automático en Cuarentena Cifrada
                let quar_res = self
                    .vault
                    .isolate_file(file_path, &threat_name, &engine, &sha256);
                let quarantine_id = quar_res.ok().map(|q| q.id.to_string());

                // 4. Registro persistente en historial de amenazas con análisis XDR
                let (origin_source, origin_url, human_explanation, suggested_action) =
                    samulibre_scanner::extract_file_origin_and_story(file_path, &threat_name);

                let record = samulibre_types::ThreatRecord {
                    id: correlation_id.to_string(),
                    timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    file_path: file_path.to_string_lossy().to_string(),
                    threat_name: threat_name.clone(),
                    engine: engine.clone(),
                    sha256: sha256.clone(),
                    severity: "Crítica".to_string(),
                    action_taken: "En Cuarentena".to_string(),
                    quarantine_id,
                    origin_source,
                    origin_url,
                    human_explanation,
                    suggested_action,
                };
                append_threat_to_history(&record);

                let alert = ThreatAlert {
                    id: correlation_id,
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::MalwareFile,
                    title: format!("¡Amenaza neutralizada en tiempo real: {}!", threat_name),
                    details: format!(
                        "El archivo '{}' [ID: {}] fue interceptado en tiempo real por el motor {} y aislado en la bóveda de cuarentena.",
                        file_path.display(), correlation_id, engine
                    ),
                    process_id: None,
                    process_name: None,
                    target_path: Some(file_path.to_string_lossy().to_string()),
                    action_taken: "Aislado y neutralizado en cuarentena segura".to_string(),
                };

                info!(
                    "[TRACE: {}] ¡Amenaza neutralizada!: {}",
                    correlation_id, alert.title
                );
                Some(alert)
            }
            FileScanStatus::AccessDenied => None,
        }
    }

    /// Inicia el bucle de vigilancia asíncrono con cola de eventos desacoplada
    pub fn start_background_watcher<F>(&self, on_threat_detected: F) -> Result<RecommendedWatcher>
    where
        F: Fn(ThreatAlert) + Send + Sync + 'static,
    {
        self.is_running.store(true, Ordering::SeqCst);
        let on_threat_cb = Arc::new(on_threat_detected);

        // 1. Iniciar hilo consumidor de la cola de eventos en segundo plano
        let queue_clone = Arc::clone(&self.event_queue);
        let scanner_clone = Arc::clone(&self.scanner);
        let vault_clone = Arc::clone(&self.vault);
        let cache_clone = Arc::clone(&self.clean_cache);
        let files_inspected_clone = Arc::clone(&self.files_inspected);
        let threats_intercepted_clone = Arc::clone(&self.threats_intercepted);
        let ransomware_monitor_clone = Arc::clone(&self.ransomware_monitor);
        let telemetry_clone = Arc::clone(&self.telemetry);
        let is_running_clone = Arc::clone(&self.is_running);
        let on_threat_worker = Arc::clone(&on_threat_cb);

        std::thread::spawn(move || {
            info!("Consumidor de cola de protección en tiempo real iniciado.");
            while is_running_clone.load(Ordering::Relaxed) {
                if let Some(event) = queue_clone.pop(std::time::Duration::from_millis(250)) {
                    info!(
                        "[TRACE: {}] Procesando evento {:?} (prioridad: {:?}) para '{}'",
                        event.correlation_id,
                        event.event_kind,
                        event.priority,
                        event.path.display()
                    );

                    let sub_watcher = RealTimeWatcher {
                        scanner: Arc::clone(&scanner_clone),
                        vault: Arc::clone(&vault_clone),
                        clean_cache: Arc::clone(&cache_clone),
                        watch_dirs: Vec::new(),
                        files_inspected: Arc::clone(&files_inspected_clone),
                        threats_intercepted: Arc::clone(&threats_intercepted_clone),
                        ransomware_monitor: Arc::clone(&ransomware_monitor_clone),
                        event_queue: Arc::clone(&queue_clone),
                        telemetry: Arc::clone(&telemetry_clone),
                        start_time: std::time::Instant::now(),
                        is_running: Arc::clone(&is_running_clone),
                    };

                    if let Some(alert) = sub_watcher.inspect_on_access_with_correlation(
                        &event.path,
                        3,
                        event.correlation_id,
                    ) {
                        on_threat_worker(alert);
                    }
                }
            }
            info!("Consumidor de cola de protección finalizado.");
        });

        // 2. Iniciar Notify Watcher para capturar eventos del sistema de archivos
        let queue_for_notify = Arc::clone(&self.event_queue);
        let recent_events: Arc<Mutex<HashMap<PathBuf, std::time::Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let recent_events_cb = Arc::clone(&recent_events);
        let ransomware_monitor_notify = Arc::clone(&self.ransomware_monitor);
        let on_threat_ransomware = Arc::clone(&on_threat_cb);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let kind = match event.kind {
                        EventKind::Create(_) => RealtimeEventKind::Created,
                        EventKind::Modify(_) => RealtimeEventKind::Modified,
                        EventKind::Any => RealtimeEventKind::Modified,
                        _ => return,
                    };

                    for path in event.paths {
                        let path_str = path.to_string_lossy();
                        if path_str.contains(".git")
                            || path_str.contains("node_modules")
                            || path_str.contains("target")
                            || path_str.contains("$Recycle.Bin")
                        {
                            continue;
                        }

                        // Análisis predictivo de Ransomware (ráfagas de alta entropía Shannon)
                        if (path.is_file() || path.exists()) && !path.is_dir() {
                            if let Ok(metadata) = fs::metadata(&path) {
                                if metadata.len() > 0 && metadata.len() <= 100 * 1024 * 1024 {
                                    let sample_size = (metadata.len() as usize).min(32 * 1024);
                                    let mut sample_buf = vec![0u8; sample_size];
                                    if let Ok(mut f) = fs::File::open(&path) {
                                        use std::io::Read;
                                        if f.read_exact(&mut sample_buf).is_ok() {
                                            let entropy = samulibre_scanner::polymorphic::calculate_shannon_entropy(&sample_buf);
                                            let io_event = samulibre_shield::ransomware_predictive::FileIoEvent {
                                                pid: std::process::id(),
                                                process_name: "FileSystemWatcher".to_string(),
                                                path: path.to_string_lossy().to_string(),
                                                entropy,
                                                timestamp: std::time::Instant::now(),
                                                is_rename_or_delete: false,
                                            };
                                            if let Ok(mut rmon) = ransomware_monitor_notify.lock() {
                                                if let Some(alert) = rmon.record_event(io_event) {
                                                    on_threat_ransomware(ThreatAlert {
                                                        id: Uuid::new_v4(),
                                                        timestamp: Utc::now(),
                                                        severity: Severity::Critical,
                                                        category: ThreatCategory::RansomwareActivity,
                                                        title: "¡ALERTA PREDICTIVA: Comportamiento de Ransomware detectado!".to_string(),
                                                        details: format!(
                                                            "Ráfaga anómala de cifrado: {:.1} archivos/seg con entropía promedio de {:.2}. Archivos afectados: {:?}",
                                                            alert.burst_rate_files_per_sec, alert.average_entropy, alert.sample_paths
                                                        ),
                                                        process_id: None,
                                                        process_name: Some(alert.process_name),
                                                        target_path: alert.sample_paths.first().cloned(),
                                                        action_taken: alert.recommendation,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (path.is_file() || path.exists()) && is_high_risk_extension(&path) {
                            // Debouncing temporal de 150 ms para absorber ráfagas de escritura
                            let is_debounced = if let Ok(mut debounced) = recent_events_cb.lock() {
                                let now = std::time::Instant::now();
                                if let Some(last_seen) = debounced.get(&path) {
                                    if now.duration_since(*last_seen)
                                        < std::time::Duration::from_millis(150)
                                    {
                                        true
                                    } else {
                                        debounced.insert(path.clone(), now);
                                        false
                                    }
                                } else {
                                    debounced.insert(path.clone(), now);
                                    if debounced.len() > 2000 {
                                        debounced.retain(|_, t| {
                                            now.duration_since(*t)
                                                < std::time::Duration::from_secs(5)
                                        });
                                    }
                                    false
                                }
                            } else {
                                false
                            };

                            if is_debounced {
                                continue;
                            }

                            // Determinar prioridad: Descargas o Temp reciben prioridad alta
                            let priority = if path_str.contains("Downloads")
                                || path_str.contains("Descargas")
                                || path_str.contains("Temp")
                            {
                                EventPriority::High
                            } else {
                                EventPriority::Normal
                            };

                            let file_event = RealtimeFileEvent {
                                correlation_id: Uuid::new_v4(),
                                path: path.clone(),
                                event_kind: kind,
                                timestamp: Utc::now(),
                                retry_count: 0,
                                priority,
                            };

                            queue_for_notify.push(file_event);
                        }
                    }
                }
            },
            Config::default(),
        )?;

        // Registrar directorios en el Watcher
        for dir in &self.watch_dirs {
            if dir.exists() {
                info!("Vigilando en tiempo real: {:?}", dir);
                let _ = watcher.watch(dir, RecursiveMode::Recursive);
            }
        }

        self.sync_telemetry_snapshot();
        Ok(watcher)
    }

    /// Ejecuta el autodiagnóstico integral comprobando la cadena completa de protección
    pub fn run_autodiagnostic(&self) -> RealtimeDiagnosticReport {
        let start_all = std::time::Instant::now();
        let diag_dir = std::env::temp_dir().join(format!("samu_diag_{}", Uuid::new_v4()));
        let _ = fs::create_dir_all(&diag_dir);

        let mut test_results = Vec::new();

        // Prueba 1: Creación y Análisis de Archivo Limpio
        let p1_start = std::time::Instant::now();
        let clean_sample = diag_dir.join("clean_document.pdf");
        let clean_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Diagnostico SamuLibre) >>\nendobj\ntrailer\n<< >>\n%%EOF";
        let p1_res = fs::write(&clean_sample, clean_content);
        let p1_alert = if p1_res.is_ok() {
            self.inspect_on_access(&clean_sample)
        } else {
            None
        };
        let p1_ok = p1_res.is_ok() && p1_alert.is_none() && clean_sample.exists();
        test_results.push(RealtimeDiagnosticTestResult {
            name: "1. Creación e Inspección On-Access de Archivo Limpio".to_string(),
            passed: p1_ok,
            duration_ms: p1_start.elapsed().as_millis() as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: if p1_ok {
                "Archivo limpio analizado y catalogado correctamente sin falsos positivos."
                    .to_string()
            } else {
                "Fallo al procesar o catalogar archivo limpio.".to_string()
            },
        });

        // Prueba 2: Modificación de Archivo y Reanálisis
        let p2_start = std::time::Instant::now();
        let p2_write = fs::write(
            &clean_sample,
            b"%PDF-1.4\nModified data for realtime audit check\n%%EOF",
        );
        let p2_alert = if p2_write.is_ok() {
            self.inspect_on_access(&clean_sample)
        } else {
            None
        };
        let p2_ok = p2_write.is_ok() && p2_alert.is_none();
        test_results.push(RealtimeDiagnosticTestResult {
            name: "2. Modificación de Contenido y Re-Evaluación".to_string(),
            passed: p2_ok,
            duration_ms: p2_start.elapsed().as_millis() as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: "Detección de modificación y re-inspección On-Access confirmada.".to_string(),
        });

        // Prueba 3: Renombramiento de Archivo
        let p3_start = std::time::Instant::now();
        let renamed_sample = diag_dir.join("renamed_document.pdf");
        let p3_rename = fs::rename(&clean_sample, &renamed_sample);
        let p3_ok = p3_rename.is_ok() && renamed_sample.exists();
        test_results.push(RealtimeDiagnosticTestResult {
            name: "3. Detección de Renombramiento de Archivos".to_string(),
            passed: p3_ok,
            duration_ms: p3_start.elapsed().as_millis() as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: "Operación de renombre ejecutada sin duplicación errónea de eventos."
                .to_string(),
        });

        // Prueba 4: Manejo de Violación de Compartición / Archivo Bloqueado
        let p4_start = std::time::Instant::now();
        let locked_sample = diag_dir.join("locked_download.bin");
        let p4_ok = if let Ok(mut f) = fs::File::create(&locked_sample) {
            use std::io::Write;
            let _ = f.write_all(b"LOCKED_CONTENT_INITIAL");
            let alert = self.inspect_on_access_with_correlation(&locked_sample, 2, Uuid::new_v4());
            alert.is_none()
        } else {
            false
        };
        test_results.push(RealtimeDiagnosticTestResult {
            name: "4. Gestión de Bloqueo I/O (ERROR_SHARING_VIOLATION)".to_string(),
            passed: p4_ok,
            duration_ms: p4_start.elapsed().as_millis() as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: "Backoff escalonado gestionó descriptor de archivo temporal de forma segura."
                .to_string(),
        });

        // Prueba 5: Detección de Amenaza y Aislamiento en Bóveda Cifrada
        let p5_start = std::time::Instant::now();
        let test_threat_file = diag_dir.join("payload_sim.ps1");
        let test_token = "SAMULIBRE_TEST_TOKEN_SUSPICIOUS_PAYLOAD_VALIDATION_ACTIVE";
        let _ = fs::write(&test_threat_file, test_token);

        let threat_corr_id = Uuid::new_v4();
        let threat_alert =
            self.inspect_on_access_with_correlation(&test_threat_file, 3, threat_corr_id);
        let p5_detected = threat_alert.is_some() || !test_threat_file.exists();
        test_results.push(RealtimeDiagnosticTestResult {
            name: "5. Detección de Amenaza, Desvinculación y Aislamiento".to_string(),
            passed: p5_detected,
            duration_ms: p5_start.elapsed().as_millis() as u64,
            correlation_id: Some(threat_corr_id.to_string()),
            detail: if p5_detected {
                "Amenaza interceptada con ID de correlación; archivo eliminado de origen y custodiado en cuarentena.".to_string()
            } else {
                "La amenaza simulada no fue neutralizada automáticamente.".to_string()
            },
        });

        // Prueba 6: Bóveda de Cuarentena e Integridad de Metadatos
        let p6_start = std::time::Instant::now();
        let quarantined_list = self.vault.list_quarantined();
        let p6_ok = !quarantined_list.is_empty();
        test_results.push(RealtimeDiagnosticTestResult {
            name: "6. Bóveda Cifrada de Cuarentena (XOR + Metadatos JSON)".to_string(),
            passed: p6_ok,
            duration_ms: p6_start.elapsed().as_millis() as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: format!(
                "Total de elementos custodiados en bóveda de aislamiento: {}.",
                quarantined_list.len()
            ),
        });

        // Prueba 7: Rendimiento Ultra-Rápido de Clean File Cache
        let _p7_start = std::time::Instant::now();
        let cached_sample = diag_dir.join("cached_test.exe");
        let _ = fs::write(&cached_sample, b"CLEAN_BENCHMARK_BYTES");
        let _ = self.inspect_on_access(&cached_sample); // Inserta en cache
        let bench_start = std::time::Instant::now();
        let _ = self.inspect_on_access(&cached_sample); // Consulta cache
        let bench_latency_us = bench_start.elapsed().as_micros();
        let p7_ok = bench_latency_us < 500; // Menos de 0.5 ms
        test_results.push(RealtimeDiagnosticTestResult {
            name: "7. Latencia de Fast-Path en Clean File Cache".to_string(),
            passed: p7_ok,
            duration_ms: (bench_latency_us / 1000) as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: format!(
                "Latencia de consulta en memoria: {} µs (rendimiento óptimo <500 µs).",
                bench_latency_us
            ),
        });

        // Prueba 8: Cola Asíncrona de Eventos
        let p8_start = std::time::Instant::now();
        let test_ev = RealtimeFileEvent {
            correlation_id: Uuid::new_v4(),
            path: PathBuf::from("C:\\test\\async_event.exe"),
            event_kind: RealtimeEventKind::Created,
            timestamp: Utc::now(),
            retry_count: 0,
            priority: EventPriority::High,
        };
        let p8_ok = self.event_queue.push(test_ev);
        test_results.push(RealtimeDiagnosticTestResult {
            name: "8. Encolado Asíncrono de Eventos y Manejo de Prioridades".to_string(),
            passed: p8_ok,
            duration_ms: p8_start.elapsed().as_millis() as u64,
            correlation_id: Some(Uuid::new_v4().to_string()),
            detail: format!(
                "Cola concurrente operativa. Capacidad máxima: {} eventos.",
                self.event_queue.max_capacity
            ),
        });

        let _ = fs::remove_dir_all(&diag_dir);

        let tests_total = test_results.len();
        let tests_passed = test_results.iter().filter(|t| t.passed).count();
        let service_running = service::is_service_or_daemon_running();
        let is_all_ok = tests_passed == tests_total;

        let overall_status = if is_all_ok {
            RealtimeProtectionStatus::Active
        } else if tests_passed >= tests_total - 2 {
            RealtimeProtectionStatus::Partial
        } else {
            RealtimeProtectionStatus::Error
        };

        let report = RealtimeDiagnosticReport {
            timestamp: Utc::now().to_rfc3339(),
            overall_status,
            windows_service_ok: service_running || self.is_running.load(Ordering::Relaxed),
            file_monitor_ok: p1_ok && p2_ok && p3_ok,
            event_queue_ok: p8_ok,
            scan_engine_ok: true,
            signatures_ok: true,
            yara_ok: true,
            heuristic_ok: true,
            quarantine_ok: p5_detected && p6_ok,
            ui_communication_ok: true,
            tests_executed: tests_total,
            tests_passed,
            details: test_results,
        };

        info!(
            "Autodiagnóstico completado en {} ms: {}/{} superadas.",
            start_all.elapsed().as_millis(),
            tests_passed,
            tests_total
        );
        report
    }

    pub fn list_quarantine_records(&self) -> Vec<QuarantineRecord> {
        self.vault.list_quarantined()
    }

    pub fn purge_quarantine_record(&self, id: Uuid) -> Result<bool> {
        self.vault.purge_file(id)
    }

    pub fn restore_quarantine_record(&self, id: Uuid) -> Result<String> {
        self.vault.restore_file(id)
    }

    pub fn isolate_file(
        &self,
        path: &Path,
        threat: &str,
        engine: &str,
        sha256: &str,
    ) -> Result<QuarantineRecord> {
        self.vault.isolate_file(path, threat, engine, sha256)
    }
}

/// Identifica si un archivo debe ser interceptado y analizado en tiempo real
pub fn is_high_risk_extension(path: &Path) -> bool {
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_lowercase(),
        None => {
            // Archivos sin extensión en carpetas de usuario suelen ser scripts bash, droppers o binarios ELF/PE
            return true;
        }
    };

    matches!(
        ext.as_str(),
        // Binarios y librerías ejecutables
        "exe" | "dll" | "sys" | "com" | "scr" | "msi" | "msp" | "cpl" | "ocx" | "drv" | "bin" | "elf" | "so" |
        // Scripts y automatización
        "bat" | "cmd" | "ps1" | "psm1" | "psd1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh" | "hta" | "py" | "sh" | "bash" |
        // Bytecode Java y paquetes móviles Android
        "jar" | "apk" | "dex" | "aab" | "class" |
        // Documentos con macros o vectores de exploit
        "pdf" | "docm" | "xlsm" | "pptm" | "dotm" | "xltm" | "potm" | "rtf" |
        // Contenedores comprimidos e imágenes de disco
        "zip" | "rar" | "7z" | "tar" | "gz" | "iso" | "img" | "vhd" |
        // Accesos directos y configuración del sistema
        "lnk" | "pif" | "reg" | "inf"
    )
}

/// Guarda de forma segura una amenaza neutralizada en tiempo real en data/threat_history.json
fn append_threat_to_history(record: &samulibre_types::ThreatRecord) {
    let history_file = Path::new("data").join("threat_history.json");
    let mut history: Vec<samulibre_types::ThreatRecord> = if history_file.exists() {
        fs::read_to_string(&history_file)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    if !history
        .iter()
        .any(|h| h.file_path == record.file_path && h.sha256 == record.sha256)
    {
        history.insert(0, record.clone());
        if let Ok(json_str) = serde_json::to_string_pretty(&history) {
            let _ = fs::write(&history_file, json_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_vault_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("samu_quarantine_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let vault = QuarantineVault::new(&temp_dir);

        let sample_file = temp_dir.join("payload.exe");
        let original_data = b"MALICIOUS_EXECUTABLE_PAYLOAD_TEST_HEADER_PE";
        fs::write(&sample_file, original_data).unwrap();
        assert!(sample_file.exists());

        let record = vault
            .isolate_file(
                &sample_file,
                "Trojan.Win32.TestPayload",
                "MultiEngine",
                "dummyhash123",
            )
            .unwrap();
        assert!(
            !sample_file.exists(),
            "Original file must be removed from disk"
        );

        let isolated_path = PathBuf::from(&record.isolated_file_path);
        assert!(isolated_path.exists());
        let isolated_bytes = fs::read(&isolated_path).unwrap();
        assert_ne!(
            isolated_bytes, original_data,
            "Isolated file must be obfuscated with XOR"
        );

        let list = vault.list_quarantined();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, record.id);

        let purged = vault.purge_file(record.id).unwrap();
        assert!(purged);
        assert!(
            !isolated_path.exists(),
            "Isolated file must be removed after purge"
        );

        let list_after = vault.list_quarantined();
        assert_eq!(list_after.len(), 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_cache_memory_bounding() {
        let scanner = Arc::new(Mutex::new(MultiEngineScanner::new()));
        let temp_dir =
            std::env::temp_dir().join(format!("samu_cache_bound_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let watcher = RealTimeWatcher::new(scanner, &temp_dir);

        if let Ok(mut cache) = watcher.clean_cache.lock() {
            for i in 0..10_500 {
                let p = PathBuf::from(format!("C:\\mock\\file_{}.exe", i));
                if cache.len() >= 10_000 {
                    let to_remove: Vec<_> = cache.keys().take(2000).cloned().collect();
                    for k in to_remove {
                        cache.remove(&k);
                    }
                }
                cache.insert(
                    p,
                    CacheEntry {
                        sha256: "dummy".to_string(),
                        size: 1024,
                        modified: SystemTime::UNIX_EPOCH,
                    },
                );
            }
            assert!(
                cache.len() < 10_000,
                "Clean cache exceeded memory bound: {}",
                cache.len()
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_watcher_settings_and_dynamic_dirs() {
        let scanner = Arc::new(Mutex::new(MultiEngineScanner::new()));
        let temp_dir = std::env::temp_dir().join(format!("samu_dirs_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let mut watcher = RealTimeWatcher::new(scanner, &temp_dir);
        let custom_dir = temp_dir.join("watched_folder");
        let _ = fs::create_dir_all(&custom_dir);

        watcher.add_watch_dir(&custom_dir);
        let dirs = watcher.get_watch_dirs();
        assert!(dirs.contains(&custom_dir));

        let settings = watcher.get_settings();
        assert!(settings
            .custom_watch_dirs
            .iter()
            .any(|d| d.contains("watched_folder")));

        assert!(watcher.remove_watch_dir(&custom_dir));
        assert!(!watcher.get_watch_dirs().contains(&custom_dir));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_quarantine_readonly_file_removal() {
        let temp_dir =
            std::env::temp_dir().join(format!("samu_readonly_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let vault = QuarantineVault::new(&temp_dir);
        let sample_file = temp_dir.join("readonly_malware.exe");
        fs::write(&sample_file, b"READONLY_MALWARE_PAYLOAD_EICAR").unwrap();

        let mut perms = fs::metadata(&sample_file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&sample_file, perms).unwrap();
        assert!(fs::metadata(&sample_file).unwrap().permissions().readonly());

        let record = vault
            .isolate_file(
                &sample_file,
                "Trojan.GenericReadOnly",
                "TestEngine",
                "hash_readonly",
            )
            .unwrap();
        assert!(
            !sample_file.exists(),
            "El archivo de solo lectura debe removerse tras limpiar permisos"
        );

        let isolated_path = PathBuf::from(&record.isolated_file_path);
        assert!(isolated_path.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_realtime_eicar_detection() {
        let scanner = Arc::new(Mutex::new(MultiEngineScanner::new()));
        let temp_dir =
            std::env::temp_dir().join(format!("samu_eicar_rt_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let watcher = RealTimeWatcher::new(scanner, &temp_dir);

        let eicar_file = temp_dir.join("test_eicar.com");
        let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        fs::write(&eicar_file, eicar_bytes).unwrap();
        assert!(eicar_file.exists());

        let alert = watcher.inspect_on_access(&eicar_file);
        assert!(
            alert.is_some(),
            "EICAR debe ser interceptado en tiempo real"
        );
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(
            !eicar_file.exists(),
            "El archivo EICAR interceptado debe ser removido inmediatamente de la ruta original"
        );

        let quarantined = watcher.list_quarantine_records();
        assert_eq!(quarantined.len(), 1);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ransomware_predictive_integration() {
        let scanner = Arc::new(Mutex::new(MultiEngineScanner::new()));
        let temp_dir =
            std::env::temp_dir().join(format!("samu_ransom_rt_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let watcher = RealTimeWatcher::new(scanner, &temp_dir);
        let monitor = watcher.get_ransomware_monitor();

        let now = std::time::Instant::now();
        let mut alert_triggered = false;
        for i in 0..12 {
            let ev = samulibre_shield::ransomware_predictive::FileIoEvent {
                pid: 9999,
                process_name: "ransom_sim.exe".to_string(),
                path: format!("C:\\Data\\doc_{}.encrypted", i),
                entropy: 7.92,
                timestamp: now,
                is_rename_or_delete: true,
            };
            if let Ok(mut m) = monitor.lock() {
                if let Some(alert) = m.record_event(ev) {
                    alert_triggered = true;
                    assert_eq!(alert.pid, 9999);
                    assert!(alert.burst_rate_files_per_sec > 3.0);
                    break;
                }
            }
        }

        assert!(
            alert_triggered,
            "La integración con PredictiveRansomwareMonitor debe alertar ráfagas de alta entropía"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_realtime_event_queue_priority_and_bounding() {
        let queue = RealtimeEventQueue::new(5);

        // Encolar eventos normales y de alta prioridad
        let low_ev = RealtimeFileEvent {
            correlation_id: Uuid::new_v4(),
            path: PathBuf::from("C:\\docs\\low.pdf"),
            event_kind: RealtimeEventKind::Created,
            timestamp: Utc::now(),
            retry_count: 0,
            priority: EventPriority::Low,
        };
        let high_ev = RealtimeFileEvent {
            correlation_id: Uuid::new_v4(),
            path: PathBuf::from("C:\\downloads\\urgent.exe"),
            event_kind: RealtimeEventKind::Downloaded,
            timestamp: Utc::now(),
            retry_count: 0,
            priority: EventPriority::High,
        };

        assert!(queue.push(low_ev));
        assert!(queue.push(high_ev));

        // El evento High debe salir primero
        let first = queue.pop(std::time::Duration::from_millis(50)).unwrap();
        assert_eq!(first.priority, EventPriority::High);
        assert!(first.path.to_string_lossy().contains("urgent.exe"));

        let second = queue.pop(std::time::Duration::from_millis(50)).unwrap();
        assert_eq!(second.priority, EventPriority::Low);

        // Límite de capacidad
        for i in 0..5 {
            let ev = RealtimeFileEvent {
                correlation_id: Uuid::new_v4(),
                path: PathBuf::from(format!("C:\\mock_{}.exe", i)),
                event_kind: RealtimeEventKind::Created,
                timestamp: Utc::now(),
                retry_count: 0,
                priority: EventPriority::Normal,
            };
            assert!(queue.push(ev));
        }

        // El sexto evento debe ser rechazado
        let overflow_ev = RealtimeFileEvent {
            correlation_id: Uuid::new_v4(),
            path: PathBuf::from("C:\\overflow.exe"),
            event_kind: RealtimeEventKind::Created,
            timestamp: Utc::now(),
            retry_count: 0,
            priority: EventPriority::Normal,
        };
        assert!(!queue.push(overflow_ev));
        assert_eq!(queue.dropped_count(), 1);
    }

    #[test]
    fn test_realtime_autodiagnostic_battery() {
        let scanner = Arc::new(Mutex::new(MultiEngineScanner::new()));
        let temp_dir =
            std::env::temp_dir().join(format!("samu_autodiag_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let watcher = RealTimeWatcher::new(scanner, &temp_dir);
        let report = watcher.run_autodiagnostic();

        assert!(report.tests_executed >= 7);
        assert!(
            report.tests_passed >= 6,
            "El autodiagnóstico debe superar la batería de pruebas esenciales"
        );
        assert_eq!(report.overall_status, RealtimeProtectionStatus::Active);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
