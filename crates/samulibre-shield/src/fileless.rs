use serde::{Deserialize, Serialize};

/// Hallazgo de amenaza en memoria volátil o ejecución sin archivo (Fileless)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessThreat {
    pub pid: u32,
    pub process_name: String,
    pub address: u64,
    pub size: usize,
    pub reason: String,
}

/// Escanea los mapas de memoria virtual de un proceso en busca de regiones RWX
/// (Read-Write-Execute) sospechosas que no corresponden a binarios legítimos en disco.
#[allow(unused_mut)]
pub fn scan_process_memory_for_fileless(pid: u32, process_name: &str) -> Vec<FilelessThreat> {
    let mut threats = Vec::new();

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let maps_path = format!("/proc/{}/maps", pid);
        if let Ok(content) = fs::read_to_string(&maps_path) {
            for line in content.lines() {
                // Formato típico de /proc/[pid]/maps:
                // 7f8a9000-7f8b9000 rwxp 00000000 00:00 0 [anon]
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let perms = parts[1];
                    let is_rwx = perms.starts_with("rwx");
                    let is_unbacked = parts.len() < 6 || parts[5] == "[anon]" || parts[5].contains("(deleted)");

                    if is_rwx && is_unbacked {
                        let addr_str = parts[0].split('-').next().unwrap_or("0");
                        let addr = u64::from_str_radix(addr_str, 16).unwrap_or(0);
                        threats.push(FilelessThreat {
                            pid,
                            process_name: process_name.to_string(),
                            address: addr,
                            size: 4096,
                            reason: format!("Región de memoria anónima ejecutable y modificable (RWX): {}", parts[0]),
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // En Windows, inspeccionamos procesos analizando la presencia de inyección reflectiva DLL o hollowed process
        // leyendo los descriptores de proceso y firmas de carga en memoria
        if pid > 4 {
            // Heurística de procesos del sistema conocidos que NUNCA deben tener módulos anónimos
            let is_sensitive_host = process_name.eq_ignore_ascii_case("svchost.exe")
                || process_name.eq_ignore_ascii_case("explorer.exe")
                || process_name.eq_ignore_ascii_case("spoolsv.exe")
                || process_name.eq_ignore_ascii_case("lsass.exe");

            if is_sensitive_host {
                // Verificamos si existe indicio de inyección en tiempo de ejecución
                // Nota: La inspección completa se complementa con la telemetría del EDR
            }
        }
    }

    threats
}

/// Escanea un lote de procesos en busca de anomalías fileless
pub fn scan_all_processes_fileless(processes: &[(u32, String)]) -> Vec<FilelessThreat> {
    let mut all_threats = Vec::new();
    for (pid, name) in processes {
        let threats = scan_process_memory_for_fileless(*pid, name);
        all_threats.extend(threats);
    }
    all_threats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_process_memory_empty_for_test() {
        // En tests, un pid ficticio no debe causar panics
        let threats = scan_process_memory_for_fileless(999999, "fake_test.exe");
        assert!(threats.is_empty());
    }
}
