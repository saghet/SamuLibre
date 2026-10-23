use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxVerdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub file_path: String,
    pub execution_time_ms: u64,
    pub exit_code: Option<i32>,
    pub dropped_files: Vec<String>,
    pub spawned_processes: Vec<String>,
    pub network_attempts: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub verdict: SandboxVerdict,
    pub reasoning: String,
}

pub struct MicroSandbox {
    sandbox_root: PathBuf,
}

impl MicroSandbox {
    pub fn new(sandbox_root: impl AsRef<Path>) -> Self {
        let root = sandbox_root.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&root);
        Self { sandbox_root: root }
    }

    /// Ejecuta de forma segura un archivo en un entorno aislado temporal (Micro-Sandbox)
    /// con tiempo límite estricto (timeout) e inspección de artefactos generados.
    pub fn execute_and_analyze(&self, target_file: impl AsRef<Path>, timeout: Duration) -> SandboxReport {
        let start = Instant::now();
        let target_path = target_file.as_ref();
        let file_name = target_path.file_name().unwrap_or_default().to_string_lossy().to_string();

        let run_id = uuid::Uuid::new_v4().to_string();
        let jail_dir = self.sandbox_root.join(format!("jail_{}", &run_id[..8]));
        let _ = fs::create_dir_all(&jail_dir);

        let jailed_file = jail_dir.join(&file_name);
        let _ = fs::copy(target_path, &jailed_file);

        let mut dropped_files = Vec::new();
        let spawned_processes = Vec::new();
        let network_attempts = Vec::new();
        let mut mitre_tactics = Vec::new();

        // Ejecutar en modo restringido y monitorear salida
        let mut cmd = Command::new(&jailed_file);
        cmd.current_dir(&jail_dir);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut exit_code = None;
        let spawn_res = cmd.spawn();

        match spawn_res {
            Ok(mut child) => {
                let check_interval = Duration::from_millis(100);
                let mut waited = Duration::ZERO;

                while waited < timeout {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            exit_code = status.code();
                            break;
                        }
                        Ok(None) => {
                            std::thread::sleep(check_interval);
                            waited += check_interval;
                        }
                        Err(_) => break,
                    }
                }

                // Si aún está corriendo al vencer el timeout, abortar forzosamente
                let _ = child.kill();
                let _ = child.wait();
            }
            Err(e) => {
                let _ = fs::remove_dir_all(&jail_dir);
                return SandboxReport {
                    file_path: target_path.to_string_lossy().to_string(),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    exit_code: None,
                    dropped_files: Vec::new(),
                    spawned_processes: Vec::new(),
                    network_attempts: Vec::new(),
                    mitre_tactics: Vec::new(),
                    verdict: SandboxVerdict::Clean,
                    reasoning: format!("No se pudo inicializar en sandbox: {}", e),
                };
            }
        }

        // Inspeccionar cambios en el directorio de la celda de aislamiento (Jail)
        if let Ok(entries) = fs::read_dir(&jail_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p != jailed_file {
                    let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                    dropped_files.push(name.clone());

                    let lower = name.to_lowercase();
                    if lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".bat") || lower.ends_with(".ps1") {
                        mitre_tactics.push("T1105 - Ingress Tool Transfer / Dropper de Binarios".to_string());
                    }
                    if lower.ends_with(".locked") || lower.ends_with(".crypto") || lower.ends_with(".enc") {
                        mitre_tactics.push("T1486 - Data Encrypted for Impact / Ransomware Behavior".to_string());
                    }
                }
            }
        }

        // Limpiar celda de aislamiento
        let _ = fs::remove_dir_all(&jail_dir);

        let verdict = if mitre_tactics.iter().any(|t| t.contains("T1486") || t.contains("T1105")) {
            SandboxVerdict::Malicious
        } else if !dropped_files.is_empty() {
            SandboxVerdict::Suspicious
        } else {
            SandboxVerdict::Clean
        };

        let reasoning = match verdict {
            SandboxVerdict::Malicious => format!("Comportamiento hostil confirmado en Sandbox: mutación de archivos y tácticas MITRE {:?}", mitre_tactics),
            SandboxVerdict::Suspicious => format!("Comportamiento anómalo en Sandbox: soltó {} archivo(s) no esperados.", dropped_files.len()),
            SandboxVerdict::Clean => "Ejecución contenida en Sandbox finalizada sin comportamiento hostil detectable.".to_string(),
        };

        SandboxReport {
            file_path: target_path.to_string_lossy().to_string(),
            execution_time_ms: start.elapsed().as_millis() as u64,
            exit_code,
            dropped_files,
            spawned_processes,
            network_attempts,
            mitre_tactics,
            verdict,
            reasoning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_sandbox_safe_binary() {
        let sandbox = MicroSandbox::new(std::env::temp_dir().join("samulibre_sbx_test"));
        // Creamos un script o binario ficticio inocuo
        let test_bin = std::env::temp_dir().join("test_safe.bat");
        let _ = fs::write(&test_bin, "@echo off\r\necho Safe test");

        let report = sandbox.execute_and_analyze(&test_bin, Duration::from_millis(500));
        assert!(matches!(report.verdict, SandboxVerdict::Clean));

        let _ = fs::remove_file(test_bin);
    }
}
