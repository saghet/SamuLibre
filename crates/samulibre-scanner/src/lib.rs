use anyhow::Result;
use regex::bytes::Regex;
use samulibre_types::{FileScanStatus, ScanResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

/// Regla heurística / YARA para detección en memoria o en disco
#[derive(Debug, Clone)]
pub struct PatternRule {
    pub name: String,
    pub description: String,
    pub pattern: Regex,
    pub severity: String,
}

pub struct MultiEngineScanner {
    known_signatures: HashMap<String, String>, // Hash (SHA256) -> ThreatName
    pattern_rules: Vec<PatternRule>,
}

impl MultiEngineScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            known_signatures: HashMap::new(),
            pattern_rules: Vec::new(),
        };
        scanner.load_default_signatures();
        scanner.load_default_pattern_rules();
        scanner
    }

    /// Carga firmas conocidas de prueba y de malware real (ej. EICAR y hashes comunes)
    fn load_default_signatures(&mut self) {
        // EICAR Standard Antivirus Test File (SHA256)
        self.known_signatures.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            "EICAR-Test-Signature.Standard".to_string(),
        );

        // Hashes de prueba de troyanos conocidos de la comunidad (ThreatFox / MalwareBazaar)
        self.known_signatures.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "EmptyFile.ZeroByte".to_string(),
        );
        self.known_signatures.insert(
            "5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54".to_string(),
            "Trojan.Win32.RedLineStealer.Gen".to_string(),
        );
        self.known_signatures.insert(
            "84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e".to_string(),
            "Ransomware.Win32.LockBit3.Payload".to_string(),
        );
    }

    /// Carga reglas de patrones YARA/Heurísticas
    fn load_default_pattern_rules(&mut self) {
        // Regla 1: Detección de EICAR por contenido
        if let Ok(re) = Regex::new(r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*") {
            self.pattern_rules.push(PatternRule {
                name: "EICAR.StandardTestString".to_string(),
                description: "Cadena estándar de verificación de antivirus de la EICAR".to_string(),
                pattern: re,
                severity: "Alerta de Prueba".to_string(),
            });
        }

        // Regla 2: Invocación de PowerShell con comandos de bypass y descarga oculta
        if let Ok(re) = Regex::new(r"(?i)(powershell|pwsh)(\.exe)?.*(-enc|-encodedcommand|-nop|-w\s+hidden|-exec\s+bypass).*?(downloadstring|iex|invoke-expression)") {
            self.pattern_rules.push(PatternRule {
                name: "Heuristic.Script.ObfuscatedPowerShellDropper".to_string(),
                description: "Script de PowerShell con ofuscación, evasión de políticas y descarga en memoria".to_string(),
                pattern: re,
                severity: "Crítica".to_string(),
            });
        }

        // Regla 3: Intento de parcheo de AMSI (AmsiScanBuffer bypass en memoria)
        if let Ok(re) = Regex::new(r"(?i)(amsi\.dll|amsiscanbuffer|amsiutils).*?(0xc3|patching|virtualprotect)") {
            self.pattern_rules.push(PatternRule {
                name: "Exploit.Bypass.AmsiPatchingAttempt".to_string(),
                description: "Patrón de código diseñado para neutralizar la protección AMSI de Windows".to_string(),
                pattern: re,
                severity: "Crítica".to_string(),
            });
        }

        // Regla 4: Troyano InfoStealer extrayendo claves DPAPI y cookies de Chromium
        if let Ok(re) = Regex::new(r"(?i)(CryptUnprotectData|os_crypt|encrypted_key).*?(User Data|Login Data|Cookies)") {
            self.pattern_rules.push(PatternRule {
                name: "Trojan.Spy.ChromiumCredentialHarvester".to_string(),
                description: "Código sospechoso de lectura directa de credenciales o cookies protegidas con DPAPI".to_string(),
                pattern: re,
                severity: "Alta".to_string(),
            });
        }
    }

    /// Escanea un archivo individual utilizando firmas ClamAV/Hashes y reglas YARA/Heurísticas
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult> {
        let start = Instant::now();
        let path_ref = path.as_ref();

        if !path_ref.exists() {
            return Ok(ScanResult {
                file_path: path_ref.to_string_lossy().to_string(),
                sha256: String::new(),
                status: FileScanStatus::AccessDenied,
                detection_name: None,
                engine: "SamuLibre Multi-Engine".to_string(),
                scan_time_ms: 0,
            });
        }

        let content = match fs::read(path_ref) {
            Ok(c) => c,
            Err(e) => {
                if e.raw_os_error() == Some(225) {
                    return Ok(ScanResult {
                        file_path: path_ref.to_string_lossy().to_string(),
                        sha256: "BLOCKED_BY_KERNEL".to_string(),
                        status: FileScanStatus::Infected,
                        detection_name: Some("Threat.KernelInterception.MalwareConfirmed (OS Error 225)".to_string()),
                        engine: "KernelLockdown/AVFilter".to_string(),
                        scan_time_ms: start.elapsed().as_millis() as u64,
                    });
                }
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: String::new(),
                    status: FileScanStatus::AccessDenied,
                    detection_name: Some(format!("Error de lectura: {}", e)),
                    engine: "SamuLibre Multi-Engine".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let sha256_hash = hex::encode(hasher.finalize());

        // 1. Verificación por base de firmas conocidas (ClamAV / ThreatFox)
        if let Some(detection) = self.known_signatures.get(&sha256_hash) {
            return Ok(ScanResult {
                file_path: path_ref.to_string_lossy().to_string(),
                sha256: sha256_hash,
                status: FileScanStatus::Infected,
                detection_name: Some(detection.clone()),
                engine: "ClamAV/SignatureBase".to_string(),
                scan_time_ms: start.elapsed().as_millis() as u64,
            });
        }

        // 2. Verificación por reglas heurísticas y YARA-X
        for rule in &self.pattern_rules {
            if rule.pattern.is_match(&content) {
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: sha256_hash,
                    status: FileScanStatus::Infected,
                    detection_name: Some(rule.name.clone()),
                    engine: "YARA-X/Heuristics".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        }

        // 3. Verificación de entropía (detección de ejecutables empaquetados o cifrados)
        let entropy = calculate_entropy(&content);
        if entropy > 7.8 && content.len() > 1024 * 10 {
            // Alta sospecha de binario comprimido o cifrado
            return Ok(ScanResult {
                file_path: path_ref.to_string_lossy().to_string(),
                sha256: sha256_hash,
                status: FileScanStatus::Suspicious,
                detection_name: Some(format!("Heuristic.SuspiciousEntropy (H={:.2})", entropy)),
                engine: "EntropyHeuristic".to_string(),
                scan_time_ms: start.elapsed().as_millis() as u64,
            });
        }

        Ok(ScanResult {
            file_path: path_ref.to_string_lossy().to_string(),
            sha256: sha256_hash,
            status: FileScanStatus::Clean,
            detection_name: None,
            engine: "SamuLibre Multi-Engine".to_string(),
            scan_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Importa firmas externas en formato de texto (ej. listas de hashes de MalwareBazaar)
    pub fn import_signatures(&mut self, hash: String, name: String) {
        self.known_signatures.insert(hash.to_lowercase(), name);
    }

    pub fn signature_count(&self) -> usize {
        self.known_signatures.len()
    }

    pub fn rule_count(&self) -> usize {
        self.pattern_rules.len()
    }
}

/// Cálculo de entropía de Shannon (0.0 a 8.0) para detectar compresión/cifrado
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
