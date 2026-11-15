use anyhow::{anyhow, Result};
#[cfg(test)]
use chrono::Utc;
use samulibre_types::{Severity, SsemConfig, SsemEvent, SsemExportFormat, SsemTransportProtocol, ThreatAlert};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

/// Métricas de telemetría y rendimiento de SSEM
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsemMetrics {
    pub events_received_total: u64,
    pub events_written_local: u64,
    pub events_sent_remote: u64,
    pub events_buffered_offline: u64,
    pub buffer_flushed_total: u64,
    pub delivery_failures_total: u64,
}

/// SamuLibre Security Event Manager (SSEM)
/// Orquestador corporativo de telemetría de seguridad, exportación forense e integración SIEM/SOC
pub struct SsemEngine {
    config: Arc<Mutex<SsemConfig>>,
    metrics: Arc<Mutex<SsemMetrics>>,
    _memory_queue: Arc<Mutex<VecDeque<SsemEvent>>>,
    base_dir: PathBuf,
    events_log_file: PathBuf,
    events_csv_file: PathBuf,
    offline_buffer_file: PathBuf,
}

impl SsemEngine {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let base_dir = data_dir.as_ref().join("ssem");
        let _ = fs::create_dir_all(&base_dir);

        let events_log_file = base_dir.join("events.jsonl");
        let events_csv_file = base_dir.join("events.csv");
        let offline_buffer_file = base_dir.join("offline_buffer.jsonl");

        let mut config = SsemConfig::default();
        config.endpoint_id = Self::detect_endpoint_identity();

        Self {
            config: Arc::new(Mutex::new(config)),
            metrics: Arc::new(Mutex::new(SsemMetrics::default())),
            _memory_queue: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            base_dir,
            events_log_file,
            events_csv_file,
            offline_buffer_file,
        }
    }

    /// Detecta el identificador único del endpoint (Hostname / Identidad de máquina)
    fn detect_endpoint_identity() -> String {
        #[cfg(target_os = "windows")]
        if let Ok(comp_name) = std::env::var("COMPUTERNAME") {
            return format!("WIN-{}", comp_name);
        }

        #[cfg(not(target_os = "windows"))]
        if let Ok(host) = std::env::var("HOSTNAME") {
            return format!("NIX-{}", host);
        }

        format!("SAMU-ENDPOINT-{}", Uuid::new_v4().to_string().split('-').next().unwrap_or("0000"))
    }

    /// Anomiza rutas de usuario para cumplir con GDPR / Privacidad corporativa
    pub fn anonymize_path(raw_path: &str) -> String {
        let re_win = regex::Regex::new(r"(?i)C:\\Users\\[^\\]+\\").unwrap();
        let sanitized = re_win.replace_all(raw_path, r"C:\Users\[ANONYMIZED]\");
        let re_nix = regex::Regex::new(r"/home/[^/]+/").unwrap();
        re_nix.replace_all(&sanitized, "/home/[ANONYMIZED]/").to_string()
    }

    /// Convierte una alerta interna ThreatAlert en un evento estructurado SsemEvent
    pub fn alert_to_ssem_event(&self, alert: &ThreatAlert, version: &str) -> SsemEvent {
        let cfg = self.get_config();
        let hostname = sysinfo::System::host_name().unwrap_or_else(|| "localhost".to_string());

        let file_path = alert.target_path.as_ref().map(|p| {
            if cfg.anonymize_user_paths {
                Self::anonymize_path(p)
            } else {
                p.clone()
            }
        });

        let mitre_id = match alert.category {
            samulibre_types::ThreatCategory::LsassMemoryAccess => Some("T1003.001".to_string()),
            samulibre_types::ThreatCategory::RansomwareCanaryTrip | samulibre_types::ThreatCategory::RansomwareActivity => Some("T1486".to_string()),
            samulibre_types::ThreatCategory::SuspiciousScript => Some("T1059.001".to_string()),
            samulibre_types::ThreatCategory::BrowserCredentialTheft => Some("T1555.003".to_string()),
            _ => None,
        };

        SsemEvent {
            event_id: alert.id,
            timestamp_utc: alert.timestamp.to_rfc3339(),
            endpoint_id: cfg.endpoint_id.clone(),
            hostname,
            samulibre_version: version.to_string(),
            engine_status: "Active".to_string(),
            severity: alert.severity.clone(),
            detection_category: format!("{:?}", alert.category),
            detection_name: alert.title.clone(),
            file_path,
            file_sha256: None,
            process_id: alert.process_id,
            process_name: alert.process_name.clone(),
            action_taken: alert.action_taken.clone(),
            outcome: "Success".to_string(),
            mitre_attack_id: mitre_id,
        }
    }

    /// Registra y despacha un evento de seguridad
    pub fn record_event(&self, event: SsemEvent) -> Result<()> {
        let cfg = self.get_config();
        if !cfg.enabled {
            return Ok(());
        }

        // 1. Filtrado por severidad
        if !Self::severity_allowed(&event.severity, &cfg.min_severity) {
            return Ok(());
        }

        if let Ok(mut m) = self.metrics.lock() {
            m.events_received_total += 1;
        }

        // 2. Escritura en registro local (JSONL y CSV) con rotación
        self.rotate_logs_if_needed(cfg.log_rotation_max_mb)?;
        self.append_to_local_logs(&event)?;

        // 3. Envío remoto si hay servidor SIEM configurado
        if cfg.remote_server.is_some() && cfg.transport != SsemTransportProtocol::LocalFileOnly {
            let config_clone = Arc::clone(&self.config);
            let metrics_clone = Arc::clone(&self.metrics);
            let offline_file = self.offline_buffer_file.clone();
            let event_clone = event.clone();

            // Despacho asíncrono para JAMÁS bloquear la protección del endpoint
            std::thread::spawn(move || {
                let cfg_inner = config_clone.lock().unwrap().clone();
                if let Err(e) = Self::send_remote_packet(&cfg_inner, &event_clone) {
                    warn!("[SSEM] Servidor SIEM no alcanzable: {}. Guardando en búfer offline.", e);
                    if let Ok(mut m) = metrics_clone.lock() {
                        m.delivery_failures_total += 1;
                        m.events_buffered_offline += 1;
                    }
                    let _ = Self::append_to_offline_buffer(&offline_file, &event_clone);
                } else if let Ok(mut m) = metrics_clone.lock() {
                    m.events_sent_remote += 1;
                }
            });
        }

        Ok(())
    }

    /// Determina si una severidad cumple con el umbral mínimo configurado
    fn severity_allowed(event_sev: &Severity, min_sev: &Severity) -> bool {
        let rank = |s: &Severity| match s {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
        rank(event_sev) >= rank(min_sev)
    }

    /// Formatea un evento a JSON estándar para Wazuh / Splunk / Sentinel
    pub fn format_json(event: &SsemEvent) -> Result<String> {
        serde_json::to_string(event).map_err(|e| anyhow!("Error al serializar JSON de SSEM: {}", e))
    }

    /// Formatea un evento a Syslog estándar RFC 5424 con Structured Data
    pub fn format_syslog_rfc5424(event: &SsemEvent) -> String {
        // Facility: 16 (local0)
        // Severities RFC 5424: Critical=2, High=3, Medium=4, Low=6
        let pri = match event.severity {
            Severity::Critical => 16 * 8 + 2, // 130
            Severity::High => 16 * 8 + 3,     // 131
            Severity::Medium => 16 * 8 + 4,   // 132
            Severity::Low => 16 * 8 + 6,      // 134
        };

        let proc_id = event.process_id.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
        let mitre = event.mitre_attack_id.clone().unwrap_or_else(|| "-".to_string());
        let fpath = event.file_path.clone().unwrap_or_else(|| "-".to_string());
        let fhash = event.file_sha256.clone().unwrap_or_else(|| "-".to_string());

        format!(
            "<{}>1 {} {} SamuLibre {} ThreatAlert [samu@5424 event_id=\"{}\" severity=\"{:?}\" category=\"{}\" mitre=\"{}\" path=\"{}\" hash=\"{}\"] {} - {}",
            pri,
            event.timestamp_utc,
            event.hostname,
            proc_id,
            event.event_id,
            event.severity,
            event.detection_category,
            mitre,
            fpath,
            fhash,
            event.detection_name,
            event.action_taken
        )
    }

    /// Retorna la cabecera CSV para exportación forense
    pub fn csv_header() -> &'static str {
        "event_id,timestamp_utc,endpoint_id,hostname,samulibre_version,severity,category,name,process_id,process_name,file_path,file_sha256,action_taken,mitre_attack_id\n"
    }

    /// Formatea una fila CSV con escape seguro RFC 4180
    pub fn format_csv_row(event: &SsemEvent) -> String {
        let escape = |s: &str| {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };

        format!(
            "{},{},{},{},{},{:?},{},{},{},{},{},{},{},{}\n",
            event.event_id,
            event.timestamp_utc,
            escape(&event.endpoint_id),
            escape(&event.hostname),
            escape(&event.samulibre_version),
            event.severity,
            escape(&event.detection_category),
            escape(&event.detection_name),
            event.process_id.map(|p| p.to_string()).unwrap_or_default(),
            escape(&event.process_name.clone().unwrap_or_default()),
            escape(&event.file_path.clone().unwrap_or_default()),
            escape(&event.file_sha256.clone().unwrap_or_default()),
            escape(&event.action_taken),
            escape(&event.mitre_attack_id.clone().unwrap_or_default()),
        )
    }

    /// Escribe el evento en los registros locales persistentes (JSONL y CSV)
    fn append_to_local_logs(&self, event: &SsemEvent) -> Result<()> {
        // 1. JSONL
        let json_line = format!("{}\n", Self::format_json(event)?);
        let mut f_json = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_log_file)?;
        f_json.write_all(json_line.as_bytes())?;

        // 2. CSV
        let write_header = !self.events_csv_file.exists();
        let mut f_csv = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_csv_file)?;
        if write_header {
            f_csv.write_all(Self::csv_header().as_bytes())?;
        }
        let row = Self::format_csv_row(event);
        f_csv.write_all(row.as_bytes())?;

        if let Ok(mut m) = self.metrics.lock() {
            m.events_written_local += 1;
        }

        Ok(())
    }

    /// Guarda el evento en el búfer offline en disco
    fn append_to_offline_buffer(path: &Path, event: &SsemEvent) -> Result<()> {
        let json_str = format!("{}\n", Self::format_json(event)?);
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(json_str.as_bytes())?;
        Ok(())
    }

    /// Envía un paquete al servidor remoto (Syslog RFC 5424 o JSON sobre TCP)
    fn send_remote_packet(config: &SsemConfig, event: &SsemEvent) -> Result<()> {
        let server = match &config.remote_server {
            Some(s) => s,
            None => return Ok(()),
        };

        let target_addr = format!("{}:{}", server, config.remote_port);
        let stream = TcpStream::connect_timeout(
            &target_addr.parse()?,
            Duration::from_millis(2000),
        )?;

        let mut stream = stream;
        stream.set_write_timeout(Some(Duration::from_millis(2000)))?;

        let payload = match config.format {
            SsemExportFormat::Json => format!("{}\n", Self::format_json(event)?),
            SsemExportFormat::SyslogRfc5424 => format!("{}\n", Self::format_syslog_rfc5424(event)),
            SsemExportFormat::Csv => Self::format_csv_row(event),
        };

        stream.write_all(payload.as_bytes())?;
        stream.flush()?;
        Ok(())
    }

    /// Reintenta vaciar el búfer offline hacia el SIEM cuando vuelve la conectividad
    pub fn flush_offline_buffer(&self) -> Result<usize> {
        let cfg = self.get_config();
        if cfg.remote_server.is_none() || !self.offline_buffer_file.exists() {
            return Ok(0);
        }

        let f = File::open(&self.offline_buffer_file)?;
        let reader = BufReader::new(f);
        let mut unhandled_events = Vec::new();
        let mut sent_count = 0;

        for line in reader.lines() {
            let l = line?;
            if l.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<SsemEvent>(&l) {
                if Self::send_remote_packet(&cfg, &event).is_ok() {
                    sent_count += 1;
                } else {
                    unhandled_events.push(event);
                }
            }
        }

        // Reescribir los eventos que todavía no pudieron enviarse
        if unhandled_events.is_empty() {
            let _ = fs::remove_file(&self.offline_buffer_file);
        } else {
            let mut new_f = File::create(&self.offline_buffer_file)?;
            for ev in unhandled_events {
                let _ = writeln!(new_f, "{}", Self::format_json(&ev)?);
            }
        }

        if let Ok(mut m) = self.metrics.lock() {
            m.buffer_flushed_total += sent_count as u64;
            m.events_sent_remote += sent_count as u64;
        }

        info!("[SSEM] Búfer offline vaciado: {} eventos transmitidos exitosamente.", sent_count);
        Ok(sent_count)
    }

    /// Rota los archivos de registro si superan el tamaño máximo fijado
    fn rotate_logs_if_needed(&self, max_mb: u64) -> Result<()> {
        let max_bytes = max_mb * 1024 * 1024;
        if self.events_log_file.exists() {
            if let Ok(meta) = fs::metadata(&self.events_log_file) {
                if meta.len() >= max_bytes {
                    let rotated = self.base_dir.join(format!(
                        "events.{}.jsonl",
                        chrono::Local::now().format("%Y%m%d_%H%M%S")
                    ));
                    let _ = fs::rename(&self.events_log_file, rotated);
                }
            }
        }
        Ok(())
    }

    /// Exporta todos los eventos históricos a un archivo CSV consolidado
    pub fn export_to_csv(&self, output_path: &Path) -> Result<usize> {
        if !self.events_log_file.exists() {
            let mut f = File::create(output_path)?;
            f.write_all(Self::csv_header().as_bytes())?;
            return Ok(0);
        }

        let f_in = File::open(&self.events_log_file)?;
        let reader = BufReader::new(f_in);
        let mut f_out = File::create(output_path)?;
        f_out.write_all(Self::csv_header().as_bytes())?;

        let mut count = 0;
        for line in reader.lines() {
            let l = line?;
            if let Ok(event) = serde_json::from_str::<SsemEvent>(&l) {
                f_out.write_all(Self::format_csv_row(&event).as_bytes())?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Exporta todos los eventos históricos a un archivo JSON estructurado (Splunk/Wazuh format)
    pub fn export_to_json(&self, output_path: &Path) -> Result<usize> {
        if !self.events_log_file.exists() {
            fs::write(output_path, "[]")?;
            return Ok(0);
        }

        let f_in = File::open(&self.events_log_file)?;
        let reader = BufReader::new(f_in);
        let mut events = Vec::new();

        for line in reader.lines() {
            let l = line?;
            if let Ok(event) = serde_json::from_str::<SsemEvent>(&l) {
                events.push(event);
            }
        }

        let json_pretty = serde_json::to_string_pretty(&events)?;
        fs::write(output_path, json_pretty)?;
        Ok(events.len())
    }

    pub fn get_config(&self) -> SsemConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, new_cfg: SsemConfig) {
        if let Ok(mut c) = self.config.lock() {
            *c = new_cfg;
        }
    }

    pub fn get_metrics(&self) -> SsemMetrics {
        self.metrics.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_event(sev: Severity, name: &str) -> SsemEvent {
        SsemEvent {
            event_id: Uuid::new_v4(),
            timestamp_utc: Utc::now().to_rfc3339(),
            endpoint_id: "TEST-ENDPOINT-01".to_string(),
            hostname: "SEC-WORKSTATION".to_string(),
            samulibre_version: "2.1.14".to_string(),
            engine_status: "Active".to_string(),
            severity: sev,
            detection_category: "MalwareFile".to_string(),
            detection_name: name.to_string(),
            file_path: Some("C:\\Users\\victim\\Downloads\\trojan.exe".to_string()),
            file_sha256: Some("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string()),
            process_id: Some(4040),
            process_name: Some("powershell.exe".to_string()),
            action_taken: "Aislado en Bóveda XOR".to_string(),
            outcome: "Success".to_string(),
            mitre_attack_id: Some("T1059.001".to_string()),
        }
    }

    #[test]
    fn test_ssem_rfc5424_syslog_formatting() {
        let ev = create_dummy_event(Severity::Critical, "Ransomware.Win32.Conti");
        let syslog_msg = SsemEngine::format_syslog_rfc5424(&ev);

        // Debe iniciar con <PRI>1
        assert!(syslog_msg.starts_with("<130>1"));
        assert!(syslog_msg.contains("SamuLibre"));
        assert!(syslog_msg.contains("ThreatAlert"));
        assert!(syslog_msg.contains("[samu@5424"));
        assert!(syslog_msg.contains("severity=\"Critical\""));
        assert!(syslog_msg.contains("mitre=\"T1059.001\""));
        assert!(syslog_msg.contains("Ransomware.Win32.Conti"));
    }

    #[test]
    fn test_ssem_json_formatting_wazuh_splunk_compatible() {
        let ev = create_dummy_event(Severity::High, "Trojan.Win32.DarkComet");
        let json_str = SsemEngine::format_json(&ev).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["endpoint_id"], "TEST-ENDPOINT-01");
        assert_eq!(parsed["detection_name"], "Trojan.Win32.DarkComet");
        assert_eq!(parsed["mitre_attack_id"], "T1059.001");
        assert_eq!(parsed["process_id"], 4040);
    }

    #[test]
    fn test_ssem_csv_export_and_escaping() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ssem_csv_{}", Uuid::new_v4()));
        let ssem = SsemEngine::new(&temp_dir);

        let ev = create_dummy_event(Severity::Medium, "Heuristic.Suspicious,Dropper \"Payload\"");
        ssem.record_event(ev).unwrap();

        let out_csv = temp_dir.join("export.csv");
        let exported_count = ssem.export_to_csv(&out_csv).unwrap();
        assert_eq!(exported_count, 1);

        let content = fs::read_to_string(&out_csv).unwrap();
        assert!(content.starts_with("event_id,timestamp_utc"));
        assert!(content.contains("\"Heuristic.Suspicious,Dropper \"\"Payload\"\"\""));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ssem_path_anonymization_privacy_guard() {
        let raw_win = r"C:\Users\saghe\Documents\SecretFinances.xlsx";
        let anonymized_win = SsemEngine::anonymize_path(raw_win);
        assert_eq!(anonymized_win, r"C:\Users\[ANONYMIZED]\Documents\SecretFinances.xlsx");

        let raw_nix = "/home/john_doe/confidential/keys.pem";
        let anonymized_nix = SsemEngine::anonymize_path(raw_nix);
        assert_eq!(anonymized_nix, "/home/[ANONYMIZED]/confidential/keys.pem");
    }

    #[test]
    fn test_ssem_offline_buffering_when_remote_server_unreachable() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ssem_buffer_{}", Uuid::new_v4()));
        let ssem = SsemEngine::new(&temp_dir);

        // Configurar un servidor remoto inalcanzable (IP reservada de prueba)
        let mut cfg = ssem.get_config();
        cfg.remote_server = Some("192.0.2.1".to_string()); // TEST-NET-1 (RFC 5737 inalcanzable)
        cfg.remote_port = 514;
        cfg.transport = SsemTransportProtocol::Tcp;
        ssem.set_config(cfg);

        let ev = create_dummy_event(Severity::Critical, "Offline.Buffer.Test");
        // Debe retornar Ok(()) sin bloquear jamás la llamada principal
        assert!(ssem.record_event(ev).is_ok());

        // Esperar brevemente a que el hilo asíncrono detecte timeout y bufferice
        std::thread::sleep(Duration::from_millis(2200));

        let metrics = ssem.get_metrics();
        assert!(metrics.events_written_local >= 1);
        assert!(metrics.delivery_failures_total >= 1);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
