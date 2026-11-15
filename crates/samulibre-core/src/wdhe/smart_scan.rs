use anyhow::{anyhow, Result};
use chrono::Utc;
use samulibre_types::{CleanCacheRecord, SmartScanPriority};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tracing::{debug, info};

/// Métricas de rendimiento y coordinación del Smart Scan
#[derive(Debug, Clone, Default)]
pub struct SmartScanMetrics {
    pub scans_completed: u64,
    pub cache_hits: u64,
    pub lock_conflicts_avoided: u64,
    pub large_files_streamed: u64,
    pub total_bytes_scanned: u64,
    pub total_scan_duration_ms: u64,
}

/// Elemento encolado para análisis coordinado
#[derive(Debug, Clone)]
pub struct SmartScanJob {
    pub path: PathBuf,
    pub priority: SmartScanPriority,
    pub enqueued_at: Instant,
}

/// Coordinador inteligente de escaneo y mitigación de contienda de I/O (SSCE)
pub struct SmartScanCoordinator {
    clean_cache: Arc<Mutex<HashMap<PathBuf, CleanCacheRecord>>>,
    queue: Arc<Mutex<VecDeque<SmartScanJob>>>,
    metrics: Arc<Mutex<SmartScanMetrics>>,
    max_concurrency: Arc<AtomicUsize>,
    is_cancelled: Arc<AtomicBool>,
    cache_file: PathBuf,
}

impl SmartScanCoordinator {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let cache_file = data_dir.as_ref().join("smart_scan_cache.json");
        let mut cache = HashMap::new();

        if cache_file.exists() {
            if let Ok(content) = fs::read_to_string(&cache_file) {
                if let Ok(loaded) = serde_json::from_str::<HashMap<PathBuf, CleanCacheRecord>>(&content) {
                    cache = loaded;
                }
            }
        }

        Self {
            clean_cache: Arc::new(Mutex::new(cache)),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            metrics: Arc::new(Mutex::new(SmartScanMetrics::default())),
            max_concurrency: Arc::new(AtomicUsize::new(4)),
            is_cancelled: Arc::new(AtomicBool::new(false)),
            cache_file,
        }
    }

    /// Establece el límite dinámico de hilos concurrentes
    pub fn set_concurrency_limit(&self, limit: usize) {
        let safe_limit = limit.max(1).min(16);
        self.max_concurrency.store(safe_limit, Ordering::Relaxed);
    }

    /// Encola un archivo con prioridad específica
    pub fn enqueue(&self, path: PathBuf, priority: SmartScanPriority) {
        let mut q = self.queue.lock().unwrap();
        // Insertar respetando prioridad más alta primero
        let job = SmartScanJob {
            path,
            priority,
            enqueued_at: Instant::now(),
        };

        let mut idx = q.len();
        for (i, item) in q.iter().enumerate() {
            if job.priority > item.priority {
                idx = i;
                break;
            }
        }
        q.insert(idx, job);
    }

    /// Cancela todas las operaciones de escaneo en curso de forma segura
    pub fn cancel_all(&self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
        let mut q = self.queue.lock().unwrap();
        q.clear();
        info!("Operaciones de Smart Scan canceladas por el usuario o gobernador.");
    }

    /// Reinicia la señal de cancelación
    pub fn reset_cancellation(&self) {
        self.is_cancelled.store(false, Ordering::SeqCst);
    }

    /// Comprueba si un archivo ya fue verificado como limpio y sigue inalterado
    pub fn check_cache(&self, path: &Path) -> Option<CleanCacheRecord> {
        let metadata = fs::metadata(path).ok()?;
        let size = metadata.len();
        let mtime = metadata
            .modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();

        let cache = self.clean_cache.lock().unwrap();
        if let Some(record) = cache.get(path) {
            // Invalidación criptográfica y de estado: tamaño y mtime deben coincidir exactamente
            if record.size_bytes == size && record.mtime_secs == mtime {
                let mut m = self.metrics.lock().unwrap();
                m.cache_hits += 1;
                return Some(record.clone());
            }
        }

        None
    }

    /// Registra un archivo validado como limpio en la caché
    pub fn record_clean(&self, path: PathBuf, sha256: String, size_bytes: u64, mtime_secs: u64) {
        let record = CleanCacheRecord {
            sha256,
            size_bytes,
            mtime_secs,
            scan_timestamp: Utc::now().to_rfc3339(),
            engine_version: "2.1.13".to_string(),
        };

        let mut cache = self.clean_cache.lock().unwrap();
        cache.insert(path, record);
    }

    /// Abre un archivo de forma compartida y segura para evitar bloqueos con Microsoft Defender
    /// Implementa reintentos con backoff exponencial si Defender está analizando el archivo (ERROR_SHARING_VIOLATION)
    pub fn open_file_safe_shared(path: &Path, max_retries: usize) -> Result<File> {
        let mut delay = Duration::from_millis(10);

        for attempt in 0..=max_retries {
            // Intentar abrir el archivo con lectura compartida estándar
            match File::open(path) {
                Ok(file) => return Ok(file),
                Err(e) => {
                    let err_str = e.to_string();
                    let raw_os_err = e.raw_os_error().unwrap_or(0);

                    // 0x20 = 32 = ERROR_SHARING_VIOLATION en Windows
                    if raw_os_err == 32 || err_str.contains("sharing violation") || err_str.contains("en uso") {
                        if attempt < max_retries {
                            debug!(
                                "Contienda de I/O detectada en {:?} (intento {}/{}). Esperando {:?}",
                                path, attempt + 1, max_retries, delay
                            );
                            std::thread::sleep(delay);
                            delay *= 2; // Backoff exponencial: 10ms, 20ms, 40ms...
                            continue;
                        }
                    }

                    if attempt == max_retries {
                        return Err(anyhow!("No se pudo abrir el archivo {:?} tras {} reintentos: {}", path, max_retries, e));
                    }
                }
            }
        }

        Err(anyhow!("Error al abrir archivo con acceso compartido."))
    }

    /// Analiza un archivo por streaming por bloques para archivos grandes sin sobrecargar memoria
    pub fn stream_hash_sha256(path: &Path) -> Result<(String, u64)> {
        let file = Self::open_file_safe_shared(path, 3)?;
        let mut reader = BufReader::with_capacity(64 * 1024, file); // Buffer de 64KB
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total_bytes = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            total_bytes += bytes_read as u64;
        }

        let hash = hex::encode(hasher.finalize());
        Ok((hash, total_bytes))
    }

    /// Obtiene las métricas actuales del coordinador
    pub fn get_metrics(&self) -> SmartScanMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Guarda la caché en disco
    pub fn persist_cache(&self) {
        let cache = self.clean_cache.lock().unwrap();
        if let Some(parent) = self.cache_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(serialized) = serde_json::to_string_pretty(&*cache) {
            let _ = fs::write(&self.cache_file, serialized);
        }
    }
}
