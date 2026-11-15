use crate::db::IntelDatabase;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::Instant;

/// Hallazgo de seguridad sobre un driver kernel real del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledDriverFinding {
    pub driver_name: String,
    pub file_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub is_vulnerable_byovd: bool,
    pub loldrivers_match: Option<String>,
    pub source_url: Option<String>,
    pub risk_level: String,
    pub recommendation: String,
}

/// Reporte de auditoría de SamuLibre Driver Security Intelligence
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriverAuditReport {
    pub scanned_drivers_count: usize,
    pub loldrivers_db_hashes: usize,
    pub vulnerable_findings: Vec<InstalledDriverFinding>,
    pub duration_ms: u64,
}

pub struct DriverSecurityIntel;

impl DriverSecurityIntel {
    /// Audita el inventario real de drivers de Windows (`C:\Windows\System32\drivers`) contra LOLDrivers
    pub fn audit_windows_drivers(db: &IntelDatabase) -> Result<DriverAuditReport> {
        Self::audit_directory(db, Path::new(r"C:\Windows\System32\drivers"))
    }

    /// Audita los archivos `.sys` de un directorio contra la base LOLDrivers sin eliminar ni bloquear drivers críticos
    pub fn audit_directory(db: &IntelDatabase, drivers_dir: &Path) -> Result<DriverAuditReport> {
        let t0 = Instant::now();
        let loldrivers_map = db.load_loldrivers_sha256_map()?;
        let mut report = DriverAuditReport {
            loldrivers_db_hashes: loldrivers_map.len(),
            ..Default::default()
        };

        if !drivers_dir.exists() {
            report.duration_ms = t0.elapsed().as_millis() as u64;
            return Ok(report);
        }

        if let Ok(entries) = fs::read_dir(drivers_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let is_sys = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|e| e.eq_ignore_ascii_case("sys"))
                    .unwrap_or(false);
                if !is_sys || !path.is_file() {
                    continue;
                }

                let Ok(meta) = fs::metadata(&path) else {
                    continue;
                };
                if meta.len() > 32 * 1024 * 1024 {
                    continue;
                }

                let Ok(sha256) = Self::stream_sha256(&path) else {
                    continue;
                };
                report.scanned_drivers_count += 1;

                if let Some((threat_name, source_url)) = loldrivers_map.get(&sha256) {
                    let driver_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    report.vulnerable_findings.push(InstalledDriverFinding {
                        driver_name,
                        file_path: path.to_string_lossy().to_string(),
                        sha256,
                        size_bytes: meta.len(),
                        is_vulnerable_byovd: true,
                        loldrivers_match: Some(threat_name.clone()),
                        source_url: Some(source_url.clone()),
                        risk_level: "ALTO (BYOVD / Driver Vulnerable)".to_string(),
                        recommendation: "Driver coincidente con LOLDrivers. Verificar versión firmada actualizada del fabricante y Microsoft Vulnerable Driver Blocklist; no eliminar automáticamente si es crítico de arranque.".to_string(),
                    });
                }
            }
        }

        report.duration_ms = t0.elapsed().as_millis() as u64;
        Ok(report)
    }

    fn stream_sha256(path: &Path) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}
