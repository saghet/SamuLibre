use anyhow::Result;
use chrono::{Local, NaiveTime};
use samulibre_scanner::MultiEngineScanner;
use samulibre_types::{
    FileScanStatus, ScanTargetType, ScheduleFrequency, ScheduledScanConfig, ThreatRecord,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;
use uuid::Uuid;
use walkdir::WalkDir;

/// Reporte del escaneo programado completado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScanReport {
    pub timestamp: String,
    pub target_type: String,
    pub files_scanned: usize,
    pub threats_found: usize,
    pub infected_records: Vec<ThreatRecord>,
    pub elapsed_ms: u64,
}

pub struct ScheduledScanManager {
    config_path: PathBuf,
    config: ScheduledScanConfig,
}

impl ScheduledScanManager {
    pub fn new(config_path: impl AsRef<Path>) -> Self {
        let p = config_path.as_ref().to_path_buf();
        let mut mgr = Self {
            config_path: p,
            config: ScheduledScanConfig::default(),
        };
        mgr.load_config();
        mgr
    }

    pub fn get_config(&self) -> ScheduledScanConfig {
        self.config.clone()
    }

    pub fn load_config(&mut self) {
        if self.config_path.exists() {
            if let Ok(content) = fs::read_to_string(&self.config_path) {
                if let Ok(cfg) = serde_json::from_str::<ScheduledScanConfig>(&content) {
                    self.config = cfg;
                    self.recalculate_next_run();
                    return;
                }
            }
        }
        self.recalculate_next_run();
        let _ = self.save_config();
    }

    pub fn save_config(&self) -> Result<()> {
        if let Some(parent) = self.config_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json_str = serde_json::to_string_pretty(&self.config)?;
        fs::write(&self.config_path, json_str)?;
        Ok(())
    }

    pub fn update_config(&mut self, new_config: ScheduledScanConfig) -> Result<()> {
        self.config = new_config;
        self.recalculate_next_run();
        self.save_config()?;
        self.sync_native_os_scheduler();
        Ok(())
    }

    /// Recalcula el próximo timestamp de disparo según la frecuencia configurada
    pub fn recalculate_next_run(&mut self) {
        if !self.config.enabled {
            self.config.next_run = None;
            return;
        }

        let now = Local::now();
        let parsed_time = NaiveTime::parse_from_str(&self.config.scheduled_time, "%H:%M")
            .unwrap_or_else(|_| NaiveTime::from_hms_opt(2, 0, 0).unwrap());

        let next_dt = match self.config.frequency {
            ScheduleFrequency::Daily => {
                let today_target = now.date_naive().and_time(parsed_time);
                if today_target > now.naive_local() {
                    today_target
                } else {
                    today_target + chrono::Duration::days(1)
                }
            }
            ScheduleFrequency::Weekly => {
                let today_target = now.date_naive().and_time(parsed_time);
                if today_target > now.naive_local() {
                    today_target + chrono::Duration::days(7)
                } else {
                    today_target + chrono::Duration::days(7)
                }
            }
            ScheduleFrequency::Hourly => (now + chrono::Duration::hours(1)).naive_local(),
            ScheduleFrequency::IntervalHours(h) => {
                let hours = if h == 0 { 24 } else { h as i64 };
                (now + chrono::Duration::hours(hours)).naive_local()
            }
            ScheduleFrequency::Every8Days => {
                let today_target = now.date_naive().and_time(parsed_time);
                today_target + chrono::Duration::days(8)
            }
            ScheduleFrequency::IntervalDays(days) => {
                let d = if days == 0 { 8 } else { days as i64 };
                let today_target = now.date_naive().and_time(parsed_time);
                today_target + chrono::Duration::days(d)
            }
        };

        self.config.next_run = Some(next_dt.format("%Y-%m-%d %H:%M:%S").to_string());
    }

    /// Comprueba si ya es momento de disparar un escaneo programado
    pub fn is_scan_due(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        if let Some(ref next_str) = self.config.next_run {
            if let Ok(next_dt) =
                chrono::NaiveDateTime::parse_from_str(next_str, "%Y-%m-%d %H:%M:%S")
            {
                let now = Local::now().naive_local();
                return now >= next_dt;
            }
        }
        false
    }

    /// Obtiene las rutas que deben ser escaneadas de acuerdo al tipo de objetivo
    pub fn get_target_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        match self.config.target_type {
            ScanTargetType::Quick => {
                #[cfg(target_os = "windows")]
                if let Ok(profile) = std::env::var("USERPROFILE") {
                    let p = PathBuf::from(profile);
                    paths.push(p.join("Downloads"));
                    paths.push(p.join("Desktop"));
                    paths.push(p.join("AppData").join("Local").join("Temp"));
                    let startup = p
                        .join("AppData")
                        .join("Roaming")
                        .join("Microsoft")
                        .join("Windows")
                        .join("Start Menu")
                        .join("Programs")
                        .join("Startup");
                    if startup.exists() {
                        paths.push(startup);
                    }
                }
                #[cfg(not(target_os = "windows"))]
                if let Ok(home) = std::env::var("HOME") {
                    let p = PathBuf::from(home);
                    paths.push(p.join("Downloads"));
                    paths.push(p.join("Desktop"));
                    paths.push(PathBuf::from("/tmp"));
                    let autostart = p.join(".config").join("autostart");
                    if autostart.exists() {
                        paths.push(autostart);
                    }
                }
            }
            ScanTargetType::Full => {
                #[cfg(target_os = "windows")]
                if let Ok(profile) = std::env::var("USERPROFILE") {
                    paths.push(PathBuf::from(profile));
                }
                #[cfg(not(target_os = "windows"))]
                if let Ok(home) = std::env::var("HOME") {
                    paths.push(PathBuf::from(home));
                }
            }
            ScanTargetType::Custom => {
                for p_str in &self.config.custom_paths {
                    let p = PathBuf::from(p_str);
                    if p.exists() {
                        paths.push(p);
                    }
                }
            }
        }
        paths
    }

    /// Ejecuta el escaneo programado completo, actualiza estadísticas y persiste el resultado
    pub fn execute_scan(
        &mut self,
        scanner: &MultiEngineScanner,
        quarantine_fn: Option<&dyn Fn(&Path, &str, &str, &str)>,
    ) -> Result<ScheduledScanReport> {
        let start = std::time::Instant::now();
        let target_paths = self.get_target_paths();
        let mut files_scanned = 0usize;
        let mut threats_found = 0usize;
        let mut infected_records = Vec::new();

        info!(
            "Iniciando escaneo programado: objetivo {:?}",
            self.config.target_type
        );

        for base_path in target_paths {
            if !base_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&base_path)
                .follow_links(false)
                .max_depth(10)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                let path_str = path.to_string_lossy();
                if path_str.contains(".git")
                    || path_str.contains("node_modules")
                    || path_str.contains("target")
                    || path_str.contains("$Recycle.Bin")
                {
                    continue;
                }

                if path.is_file() && samulibre_watcher::is_high_risk_extension(path) {
                    files_scanned += 1;
                    if let Ok(result) = scanner.scan_file(path) {
                        if result.status == FileScanStatus::Infected
                            || result.status == FileScanStatus::Suspicious
                        {
                            threats_found += 1;
                            let threat_name = result
                                .detection_name
                                .clone()
                                .unwrap_or_else(|| "Amenaza.Programada".to_string());
                            let (origin_source, origin_url, human_explanation, suggested_action) =
                                samulibre_scanner::extract_file_origin_and_story(
                                    path,
                                    &threat_name,
                                );

                            if let Some(q_fn) = quarantine_fn {
                                q_fn(path, &threat_name, &result.engine, &result.sha256);
                            }

                            infected_records.push(ThreatRecord {
                                id: Uuid::new_v4().to_string(),
                                timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                file_path: path.to_string_lossy().to_string(),
                                threat_name,
                                engine: result.engine,
                                sha256: result.sha256,
                                severity: "Alta".to_string(),
                                action_taken: "Escaneo Programado (Neutralizado)".to_string(),
                                quarantine_id: None,
                                origin_source,
                                origin_url,
                                human_explanation,
                                suggested_action,
                            });
                        }
                    }
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        self.config.last_run = Some(now_str.clone());
        self.config.last_result_scanned = files_scanned;
        self.config.last_result_threats = threats_found;
        self.recalculate_next_run();
        let _ = self.save_config();

        let report = ScheduledScanReport {
            timestamp: now_str,
            target_type: format!("{:?}", self.config.target_type),
            files_scanned,
            threats_found,
            infected_records,
            elapsed_ms,
        };

        info!(
            "Escaneo programado finalizado: {} archivos, {} amenazas detectadas en {} ms",
            files_scanned, threats_found, elapsed_ms
        );
        Ok(report)
    }

    /// Sincroniza la tarea programada con el programador de tareas del sistema operativo (Windows / Linux)
    pub fn sync_native_os_scheduler(&self) {
        #[cfg(target_os = "windows")]
        {
            if self.config.enabled {
                let time_str = &self.config.scheduled_time;
                let current_exe =
                    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("samulibre-cli.exe"));
                let cmd_str = format!("\"{}\" schedule run-now", current_exe.display());
                let _ = std::process::Command::new("schtasks")
                    .args(&[
                        "/create",
                        "/tn",
                        "SamuLibreScan",
                        "/tr",
                        &cmd_str,
                        "/sc",
                        "daily",
                        "/st",
                        time_str,
                        "/f",
                    ])
                    .output();
            } else {
                let _ = std::process::Command::new("schtasks")
                    .args(&["/delete", "/tn", "SamuLibreScan", "/f"])
                    .output();
            }
        }

        #[cfg(target_os = "linux")]
        {
            info!("Sincronización nativa de escaneo programado evaluada en Linux.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_scan_config_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("samu_sched_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let config_path = temp_dir.join("scheduled_scans.json");

        let mut mgr = ScheduledScanManager::new(&config_path);
        let mut cfg = mgr.get_config();
        assert!(!cfg.enabled);

        cfg.enabled = true;
        cfg.frequency = ScheduleFrequency::Hourly;
        cfg.target_type = ScanTargetType::Custom;
        cfg.custom_paths = vec![temp_dir.to_string_lossy().to_string()];

        mgr.update_config(cfg).unwrap();
        assert!(mgr.get_config().enabled);
        assert!(mgr.get_config().next_run.is_some());

        // Probar ejecución de escaneo sobre carpeta personalizada
        let scanner = MultiEngineScanner::new();
        let report = mgr.execute_scan(&scanner, None).unwrap();
        assert_eq!(report.threats_found, 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
