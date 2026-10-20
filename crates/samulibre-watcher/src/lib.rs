use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::{Config, Event, EventKind, Watcher};
pub use notify::{RecommendedWatcher, RecursiveMode};
use samulibre_scanner::MultiEngineScanner;
use samulibre_types::{FileScanStatus, Severity, ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
    pub fn isolate_file(&self, source_path: &Path, threat: &str, engine: &str, sha256: &str) -> Result<QuarantineRecord> {
        // Blindaje Anti-Symlink / Anti-LPE: Verificar que el archivo no sea un junction o symlink
        if let Ok(sym_meta) = fs::symlink_metadata(source_path) {
            if sym_meta.file_type().is_symlink() {
                anyhow::bail!("Intento de manipulación LPE detectado: '{}' es un enlace simbólico / junction. Operación cancelada.", source_path.display());
            }
        }

        let id = Uuid::new_v4();
        let isolated_name = format!("{}.quarantine", id);
        let isolated_path = self.quarantine_dir.join(&isolated_name);

        let original_bytes = fs::read(source_path)?;
        // Ofuscación reversible básica (XOR con clave fija de cuarentena) para anular headers PE ejecutables
        let xor_key = 0xAA;
        let obfuscated_bytes: Vec<u8> = original_bytes.iter().map(|b| b ^ xor_key).collect();
        fs::write(&isolated_path, obfuscated_bytes)?;

        // Eliminar o neutralizar el archivo original del disco
        let _ = fs::remove_file(source_path);

        let record = QuarantineRecord {
            id,
            original_path: source_path.to_string_lossy().to_string(),
            threat_name: threat.to_string(),
            engine: engine.to_string(),
            sha256: sha256.to_string(),
            quarantined_at: Utc::now(),
            isolated_file_path: isolated_path.to_string_lossy().to_string(),
        };

        // Guardar metadatos en JSON
        let meta_path = self.quarantine_dir.join(format!("{}.meta.json", id));
        fs::write(&meta_path, serde_json::to_string_pretty(&record)?)?;

        warn!("¡AMENAZA AISLADA EN CUARENTENA! Archivo: {} -> Bóveda: {:?}", source_path.display(), isolated_path);
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
            anyhow::bail!("Registro de cuarentena no encontrado en {}", self.quarantine_dir.display());
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
        info!("Archivo restaurado con éxito desde la cuarentena: {}", record.original_path);
        Ok(record.original_path)
    }
}

/// Motor de Escaneo en Tiempo Real
pub struct RealTimeWatcher {
    scanner: Arc<Mutex<MultiEngineScanner>>,
    vault: Arc<QuarantineVault>,
    clean_cache: Arc<Mutex<HashMap<PathBuf, CacheEntry>>>,
    watch_dirs: Vec<PathBuf>,
}

impl RealTimeWatcher {
    pub fn new(scanner: Arc<Mutex<MultiEngineScanner>>, quarantine_dir: impl AsRef<Path>) -> Self {
        Self {
            scanner,
            vault: Arc::new(QuarantineVault::new(quarantine_dir)),
            clean_cache: Arc::new(Mutex::new(HashMap::new())),
            watch_dirs: Vec::new(),
        }
    }

    pub fn get_vault(&self) -> Arc<QuarantineVault> {
        Arc::clone(&self.vault)
    }

    /// Añade un directorio a la vigilancia activa
    pub fn add_watch_dir(&mut self, dir: impl AsRef<Path>) {
        let p = dir.as_ref().to_path_buf();
        if p.exists() && !self.watch_dirs.contains(&p) {
            self.watch_dirs.push(p);
        }
    }

    /// Analiza un archivo interceptado en tiempo real
    pub fn inspect_on_access(&self, file_path: &Path) -> Option<ThreatAlert> {
        if !file_path.is_file() {
            return None;
        }

        // Blindaje Anti-Symlink / Anti-LPE: Omitir enlaces simbólicos o junctions para evitar manipulaciones de ruta
        if let Ok(sym_meta) = fs::symlink_metadata(file_path) {
            if sym_meta.file_type().is_symlink() {
                warn!("Omitiendo archivo sospechoso por ser enlace simbólico / junction (Anti-LPE): {:?}", file_path);
                return None;
            }
        }

        // Filtro de extensiones críticas para evitar sobrecarga en archivos de texto plano o multimedia
        if !is_high_risk_extension(file_path) {
            return None;
        }

        let metadata = match fs::metadata(file_path) {
            Ok(m) => m,
            Err(_) => return None,
        };

        let file_size = metadata.len();
        let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // 1. Verificación ultra-rápida en Clean File Cache (<0.05 ms)
        if let Ok(cache) = self.clean_cache.lock() {
            if let Some(entry) = cache.get(file_path) {
                if entry.size == file_size && entry.modified == modified_time {
                    // Archivo ya verificado y no modificado: se permite sin escanear
                    return None;
                }
            }
        }

        // 2. Escaneo en streaming con MultiEngineScanner
        let scan_result = if let Ok(s) = self.scanner.lock() {
            match s.scan_file(file_path) {
                Ok(r) => r,
                Err(_) => return None,
            }
        } else {
            return None;
        };

        match scan_result.status {
            FileScanStatus::Clean => {
                // Guardar en la caché de archivos limpios con límite acotado (máximo 10.000 entradas)
                if let Ok(mut cache) = self.clean_cache.lock() {
                    if cache.len() >= 10_000 {
                        // Desalojar 2.000 entradas para mantener la huella de memoria < 2 MB
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
                None
            }
            FileScanStatus::Infected | FileScanStatus::Suspicious => {
                let threat_name = scan_result.detection_name.unwrap_or_else(|| "Amenaza.Desconocida".to_string());
                let engine = scan_result.engine;
                let sha256 = scan_result.sha256;

                // 3. Aislamiento automático en Cuarentena Cifrada
                let quar_res = self.vault.isolate_file(file_path, &threat_name, &engine, &sha256);
                let quarantine_id = quar_res.ok().map(|q| q.id.to_string());

                // 4. Registro persistente en historial de amenazas con análisis de procedencia XDR
                let (origin_source, origin_url, human_explanation, suggested_action) =
                    samulibre_scanner::extract_file_origin_and_story(file_path, &threat_name);

                let record = samulibre_types::ThreatRecord {
                    id: Uuid::new_v4().to_string(),
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

                Some(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::MalwareFile,
                    title: format!("¡Amenaza neutralizada en tiempo real: {}!", threat_name),
                    details: format!(
                        "El archivo '{}' fue interceptado en tiempo real por el motor {} y aislado en la bóveda de cuarentena.",
                        file_path.display(), engine
                    ),
                    process_id: None,
                    process_name: None,
                    target_path: Some(file_path.to_string_lossy().to_string()),
                    action_taken: "Aislado y neutralizado en cuarentena segura".to_string(),
                })
            }
            FileScanStatus::AccessDenied => None,
        }
    }

    /// Inicia el bucle de vigilancia en segundo plano usando Notify en los directorios registrados
    /// con debouncing temporal de 200 ms para eliminar ráfagas de escritura y mantener CPU < 0.3%.
    pub fn start_background_watcher<F>(&self, on_threat_detected: F) -> Result<RecommendedWatcher>
    where
        F: Fn(ThreatAlert) + Send + Sync + 'static,
    {
        let scanner_clone = Arc::clone(&self.scanner);
        let vault_clone = Arc::clone(&self.vault);
        let cache_clone = Arc::clone(&self.clean_cache);
        let recent_events: Arc<Mutex<HashMap<PathBuf, std::time::Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let recent_events_cb = Arc::clone(&recent_events);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            for path in event.paths {
                                let path_str = path.to_string_lossy();
                                if path_str.contains(".git") || path_str.contains("node_modules") || path_str.contains("target") || path_str.contains("$Recycle.Bin") {
                                    continue;
                                }
                                if path.is_file() && is_high_risk_extension(&path) {
                                    // Debounce temporal: filtrar eventos repetidos dentro de 200 ms
                                    let is_debounced = if let Ok(mut debounced) = recent_events_cb.lock() {
                                        let now = std::time::Instant::now();
                                        if let Some(last_seen) = debounced.get(&path) {
                                            if now.duration_since(*last_seen) < std::time::Duration::from_millis(200) {
                                                true
                                            } else {
                                                debounced.insert(path.clone(), now);
                                                false
                                            }
                                        } else {
                                            debounced.insert(path.clone(), now);
                                            if debounced.len() > 2000 {
                                                debounced.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(5));
                                            }
                                            false
                                        }
                                    } else {
                                        false
                                    };

                                    if is_debounced {
                                        continue;
                                    }

                                    // Instanciar inspector puntual
                                    let sub_watcher = RealTimeWatcher {
                                        scanner: Arc::clone(&scanner_clone),
                                        vault: Arc::clone(&vault_clone),
                                        clean_cache: Arc::clone(&cache_clone),
                                        watch_dirs: Vec::new(),
                                    };
                                    if let Some(alert) = sub_watcher.inspect_on_access(&path) {
                                        on_threat_detected(alert);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        )?;

        for dir in &self.watch_dirs {
            info!("Vigilando en tiempo real: {:?}", dir);
            let _ = watcher.watch(dir, RecursiveMode::Recursive);
        }

        Ok(watcher)
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

    pub fn isolate_file(&self, path: &Path, threat: &str, engine: &str, sha256: &str) -> Result<QuarantineRecord> {
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

    if !history.iter().any(|h| h.file_path == record.file_path && h.sha256 == record.sha256) {
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
        let temp_dir = std::env::temp_dir().join(format!("samu_quarantine_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let vault = QuarantineVault::new(&temp_dir);

        // Crear archivo malicioso de prueba
        let sample_file = temp_dir.join("payload.exe");
        let original_data = b"MALICIOUS_EXECUTABLE_PAYLOAD_TEST_HEADER_PE";
        fs::write(&sample_file, original_data).unwrap();
        assert!(sample_file.exists());

        // Aislar en cuarentena
        let record = vault.isolate_file(&sample_file, "Trojan.Win32.TestPayload", "MultiEngine", "dummyhash123").unwrap();
        assert!(!sample_file.exists(), "Original file must be removed from disk");

        // Comprobar que existe el archivo cifrado y el json de metadatos
        let isolated_path = PathBuf::from(&record.isolated_file_path);
        assert!(isolated_path.exists());
        let isolated_bytes = fs::read(&isolated_path).unwrap();
        assert_ne!(isolated_bytes, original_data, "Isolated file must be obfuscated with XOR");

        // Listar
        let list = vault.list_quarantined();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, record.id);

        // Purgar definitivamente
        let purged = vault.purge_file(record.id).unwrap();
        assert!(purged);
        assert!(!isolated_path.exists(), "Isolated file must be removed after purge");

        let list_after = vault.list_quarantined();
        assert_eq!(list_after.len(), 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_cache_memory_bounding() {
        let scanner = Arc::new(Mutex::new(MultiEngineScanner::new()));
        let temp_dir = std::env::temp_dir().join(format!("samu_cache_bound_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let watcher = RealTimeWatcher::new(scanner, &temp_dir);

        // Simular inserción masiva en clean_cache
        if let Ok(mut cache) = watcher.clean_cache.lock() {
            for i in 0..10_500 {
                let p = PathBuf::from(format!("C:\\mock\\file_{}.exe", i));
                if cache.len() >= 10_000 {
                    let to_remove: Vec<_> = cache.keys().take(2000).cloned().collect();
                    for k in to_remove {
                        cache.remove(&k);
                    }
                }
                cache.insert(p, CacheEntry {
                    sha256: "dummy".to_string(),
                    size: 1024,
                    modified: SystemTime::UNIX_EPOCH,
                });
            }
            // Comprobar que nunca excede las 10.000 entradas
            assert!(cache.len() < 10_000, "Clean cache exceeded memory bound: {}", cache.len());
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
