use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Evento de actividad de disco registrado para análisis predictivo
#[derive(Debug, Clone)]
pub struct FileIoEvent {
    pub pid: u32,
    pub process_name: String,
    pub path: String,
    pub entropy: f64,
    pub timestamp: Instant,
    pub is_rename_or_delete: bool,
}

/// Alerta temprana emitida por el motor predictivo de ransomware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictiveRansomwareAlert {
    pub pid: u32,
    pub process_name: String,
    pub burst_rate_files_per_sec: f64,
    pub average_entropy: f64,
    pub sample_paths: Vec<String>,
    pub recommendation: String,
}

/// Monitor de ráfagas de I/O y picos de entropía para frenar ransomware antes de cifrado masivo
pub struct PredictiveRansomwareMonitor {
    window_duration: Duration,
    burst_threshold_count: usize,
    entropy_threshold: f64,
    recent_events: HashMap<u32, Vec<FileIoEvent>>,
}

impl PredictiveRansomwareMonitor {
    pub fn new() -> Self {
        Self {
            window_duration: Duration::from_secs(3),
            burst_threshold_count: 10, // Más de 10 archivos modificados en 3 seg
            entropy_threshold: 7.3,    // Entropía característica de cifrado AES/ChaCha
            recent_events: HashMap::new(),
        }
    }

    /// Registra un evento de escritura o renombre en el sistema de archivos
    pub fn record_event(&mut self, event: FileIoEvent) -> Option<PredictiveRansomwareAlert> {
        let now = Instant::now();
        let pid = event.pid;
        let proc_name = event.process_name.clone();

        let events = self.recent_events.entry(pid).or_default();
        // Limpiar eventos fuera de la ventana
        events.retain(|e| now.duration_since(e.timestamp) <= self.window_duration);
        events.push(event);

        if events.len() >= self.burst_threshold_count {
            let total_entropy: f64 = events.iter().map(|e| e.entropy).sum();
            let avg_entropy = total_entropy / events.len() as f64;

            if avg_entropy >= self.entropy_threshold {
                let burst_rate = events.len() as f64 / self.window_duration.as_secs_f64();
                let sample_paths: Vec<String> = events
                    .iter()
                    .take(5)
                    .map(|e| e.path.clone())
                    .collect();

                return Some(PredictiveRansomwareAlert {
                    pid,
                    process_name: proc_name,
                    burst_rate_files_per_sec: burst_rate,
                    average_entropy: avg_entropy,
                    sample_paths,
                    recommendation: "Suspender inmediatamente el proceso antes de que afecte más directorios de usuario.".to_string(),
                });
            }
        }

        None
    }

    /// Limpia el historial para procesos ya terminados
    pub fn clear_pid(&mut self, pid: u32) {
        self.recent_events.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predictive_ransomware_trigger() {
        let mut monitor = PredictiveRansomwareMonitor::new();
        let now = Instant::now();

        let mut alert_triggered = false;
        for i in 0..12 {
            let ev = FileIoEvent {
                pid: 1337,
                process_name: "crypt_test.exe".to_string(),
                path: format!("C:\\Users\\Victim\\Documents\\file_{}.docx.locked", i),
                entropy: 7.85,
                timestamp: now,
                is_rename_or_delete: true,
            };
            if let Some(alert) = monitor.record_event(ev) {
                alert_triggered = true;
                assert_eq!(alert.pid, 1337);
                assert!(alert.average_entropy > 7.3);
                break;
            }
        }

        assert!(alert_triggered, "El monitor debe activar alerta predictiva ante ráfaga de alta entropía");
    }

    #[test]
    fn test_predictive_clean_activity_no_trigger() {
        let mut monitor = PredictiveRansomwareMonitor::new();
        let now = Instant::now();

        let mut alert_triggered = false;
        for i in 0..12 {
            let ev = FileIoEvent {
                pid: 2000,
                process_name: "word.exe".to_string(),
                path: format!("C:\\Users\\Victim\\Documents\\notes_{}.txt", i),
                entropy: 4.2, // Texto plano, baja entropía
                timestamp: now,
                is_rename_or_delete: false,
            };
            if monitor.record_event(ev).is_some() {
                alert_triggered = true;
                break;
            }
        }

        assert!(!alert_triggered, "Archivos normales de texto plano con baja entropía no deben disparar alerta");
    }
}
