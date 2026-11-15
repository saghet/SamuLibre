use crate::models::ValidationStatus;
use anyhow::{anyhow, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;
use yara_x::{Compiler, Rules, Scanner};

/// Variables externas estándar soportadas por SamuLibre (compatibilidad signature-base / Yara-Rules)
pub const STANDARD_EXTERNAL_VARS: &[(&str, &str)] = &[
    ("filename", ""),
    ("filepath", ""),
    ("extension", ""),
    ("filetype", ""),
    ("owner", ""),
    ("md5", ""),
];

/// Regla YARA individual extraída de un archivo `.yar`/`.yara`
#[derive(Debug, Clone)]
pub struct ParsedYaraRule {
    pub rule_name: String,
    pub is_private: bool,
    pub is_global: bool,
    pub imports: Vec<String>,
    pub raw_source: String,
    pub content_hash: String,
    pub author: String,
    pub description: String,
    pub license: String,
    pub threat_name: String,
    pub malware_family: String,
    pub external_vars: Vec<String>,
}

/// Resultado de validación técnica de una regla YARA
#[derive(Debug, Clone)]
pub struct YaraValidationReport {
    pub status: ValidationStatus,
    pub score: u8,
    pub notes: String,
    pub compile_time_ms: u64,
    pub scan_benign_ms: u64,
    pub matched_benign: bool,
    pub required_modules: Vec<String>,
    pub external_vars: Vec<String>,
}

/// Coincidencia devuelta por el motor real YARA-X
#[derive(Debug, Clone)]
pub struct YaraMatchResult {
    pub rule_name: String,
    pub namespace: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub threat_name: Option<String>,
}

/// Validador técnico de reglas YARA usando `yara-x`
pub struct YaraRuleValidator;

impl YaraRuleValidator {
    /// Extrae reglas individuales de un archivo `.yar` conservando sus `import`s y metadatos
    pub fn split_yara_file(content: &str, default_license: &str) -> Vec<ParsedYaraRule> {
        let mut imports = Vec::new();
        let import_re = Regex::new(r#"(?m)^\s*import\s+"([^"]+)""#).unwrap();
        for cap in import_re.captures_iter(content) {
            let m = cap[1].to_string();
            if !imports.contains(&m) {
                imports.push(m);
            }
        }

        let mut rules = Vec::new();
        let bytes = content.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        // Escaneo léxico ligero para respetar strings, regexes y comentarios al delimitar llaves `{ ... }`
        while i < len {
            // Saltar comentarios de línea
            if i + 1 < len && &bytes[i..i + 2] == b"//" {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // Saltar comentarios de bloque
            if i + 1 < len && &bytes[i..i + 2] == b"/*" {
                i += 2;
                while i + 1 < len && &bytes[i..i + 2] != b"*/" {
                    i += 1;
                }
                i = (i + 2).min(len);
                continue;
            }

            // Buscar inicio de regla en límite de línea/palabra
            let at_word_boundary = i == 0
                || bytes[i - 1] == b'\n'
                || bytes[i - 1] == b'\r'
                || bytes[i - 1] == b' '
                || bytes[i - 1] == b'\t';

            if at_word_boundary {
                let rest = &content[i..];
                if let Some((header_len, rule_name, is_private, is_global)) =
                    Self::match_rule_header(rest)
                {
                    let body_start = i + header_len;
                    if let Some(body_end) = Self::find_matching_brace(bytes, body_start - 1) {
                        let rule_body = &content[i..=body_end];
                        let full_source = Self::build_standalone_source(&imports, rule_body);
                        let parsed = Self::extract_rule_metadata(
                            rule_name,
                            is_private,
                            is_global,
                            imports.clone(),
                            full_source,
                            default_license,
                        );
                        rules.push(parsed);
                        i = body_end + 1;
                        continue;
                    }
                }
            }
            i += 1;
        }

        rules
    }

    fn match_rule_header(slice: &str) -> Option<(usize, String, bool, bool)> {
        let line_end = slice.find('{')?;
        let header = slice[..line_end].trim();
        // Evitar falsos positivos dentro de bloques o líneas muy largas
        if header.len() > 240 || header.contains('\n') && header.lines().count() > 3 {
            return None;
        }
        let tokens: Vec<&str> = header.split_whitespace().collect();
        let mut idx = 0;
        let mut is_private = false;
        let mut is_global = false;
        while idx < tokens.len() {
            match tokens[idx] {
                "private" => {
                    is_private = true;
                    idx += 1;
                }
                "global" => {
                    is_global = true;
                    idx += 1;
                }
                "rule" => {
                    idx += 1;
                    break;
                }
                _ => return None,
            }
        }
        let name_raw = *tokens.get(idx)?;
        let rule_name = name_raw.split(':').next()?.trim();
        if rule_name.is_empty()
            || !rule_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return None;
        }
        Some((line_end + 1, rule_name.to_string(), is_private, is_global))
    }

    fn find_matching_brace(bytes: &[u8], open_brace_idx: usize) -> Option<usize> {
        if bytes.get(open_brace_idx) != Some(&b'{') {
            return None;
        }
        let mut depth = 0i32;
        let mut i = open_brace_idx;
        let len = bytes.len();
        let mut in_string = false;
        let mut in_regex = false;

        while i < len {
            if !in_string && !in_regex && i + 1 < len && &bytes[i..i + 2] == b"//" {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if !in_string && !in_regex && i + 1 < len && &bytes[i..i + 2] == b"/*" {
                i += 2;
                while i + 1 < len && &bytes[i..i + 2] != b"*/" {
                    i += 1;
                }
                i = (i + 2).min(len);
                continue;
            }

            let b = bytes[i];
            if in_string {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    in_string = false;
                }
            } else if in_regex {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == b'/' {
                    in_regex = false;
                }
            } else {
                match b {
                    b'"' => in_string = true,
                    b'/' if i > 0 && (bytes[i - 1] == b'=' || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') => {
                        in_regex = true;
                    }
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        None
    }

    fn build_standalone_source(imports: &[String], rule_body: &str) -> String {
        let mut out = String::new();
        for imp in imports {
            if rule_body.contains(&format!("{}.", imp)) {
                out.push_str(&format!("import \"{}\"\n", imp));
            }
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(rule_body.trim());
        out.push('\n');
        out
    }

    fn extract_rule_metadata(
        rule_name: String,
        is_private: bool,
        is_global: bool,
        imports: Vec<String>,
        raw_source: String,
        default_license: &str,
    ) -> ParsedYaraRule {
        let mut author = "Desconocido".to_string();
        let mut description = format!("Regla YARA {}", rule_name);
        let mut license = default_license.to_string();
        let mut threat_name = rule_name.clone();
        let mut malware_family = "Generic".to_string();

        let meta_re = Regex::new(r#"(?m)^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]*)""#).unwrap();
        for cap in meta_re.captures_iter(&raw_source) {
            let key = cap[1].to_ascii_lowercase();
            let val = cap[2].trim().to_string();
            if val.is_empty() {
                continue;
            }
            match key.as_str() {
                "author" => author = val,
                "description" | "desc" => description = val,
                "license" => license = val,
                "malware_family" | "family" => malware_family = val,
                "threat_name" | "malware" => threat_name = val,
                _ => {}
            }
        }

        if malware_family == "Generic" {
            malware_family = Self::infer_family_from_name(&rule_name);
        }

        let mut external_vars = Vec::new();
        for &(var_name, _) in STANDARD_EXTERNAL_VARS {
            let pat = format!(r"\b{}\b", regex::escape(var_name));
            if let Ok(re) = Regex::new(&pat) {
                if re.is_match(&raw_source) {
                    external_vars.push(var_name.to_string());
                }
            }
        }

        let normalized = raw_source
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let content_hash = hex::encode(Sha256::digest(normalized.as_bytes()));

        ParsedYaraRule {
            rule_name,
            is_private,
            is_global,
            imports,
            raw_source,
            content_hash,
            author,
            description,
            license,
            threat_name,
            malware_family,
            external_vars,
        }
    }

    fn infer_family_from_name(name: &str) -> String {
        let lower = name.to_ascii_lowercase();
        for fam in [
            "emotet", "mirai", "mimikatz", "cobaltstrike", "cobalt", "lockbit", "ransom",
            "conti", "ryuk", "qakbot", "icedid", "trickbot", "agenttesla", "redline", "remcos",
            "nanocore", "njrat", "asyncrat", "lazarus", "apt", "webshell", "eicar", "wannacry",
        ] {
            if lower.contains(fam) {
                return fam.to_string();
            }
        }
        "Generic".to_string()
    }

    /// Ejecuta la validación técnica completa de una regla YARA individual contra `yara-x`
    pub fn validate_rule(rule: &ParsedYaraRule, is_duplicate: bool) -> YaraValidationReport {
        let mut score: i32 = 100;
        let mut notes: Vec<String> = Vec::new();

        if is_duplicate {
            score -= 40;
            notes.push("Duplicado exacto de contenido detectado en otra regla activa".to_string());
        }

        if rule.is_private {
            return YaraValidationReport {
                status: ValidationStatus::AprobadaConRestricciones,
                score: 75,
                notes: "Regla auxiliar 'private': válida solo como dependencia interna".to_string(),
                compile_time_ms: 0,
                scan_benign_ms: 0,
                matched_benign: false,
                required_modules: rule.imports.clone(),
                external_vars: rule.external_vars.clone(),
            };
        }

        // Análisis heurístico de condiciones demasiado generales
        if Self::has_overly_general_condition(&rule.raw_source) {
            return YaraValidationReport {
                status: ValidationStatus::Rechazada,
                score: 10,
                notes: "Condición demasiado general (ej. `condition: true` o `filesize` sin selectores)".to_string(),
                compile_time_ms: 0,
                scan_benign_ms: 0,
                matched_benign: false,
                required_modules: rule.imports.clone(),
                external_vars: rule.external_vars.clone(),
            };
        }

        // Compilación real con yara-x
        let t_compile = Instant::now();
        let mut compiler = Compiler::new();
        for &(var_name, default_val) in STANDARD_EXTERNAL_VARS {
            if let Err(e) = compiler.define_global(var_name, default_val) {
                notes.push(format!("Error definiendo variable externa {}: {}", var_name, e));
            }
        }

        if let Err(e) = compiler.add_source(rule.raw_source.as_str()) {
            return YaraValidationReport {
                status: ValidationStatus::Rechazada,
                score: 0,
                notes: format!("Error de sintaxis o compatibilidad YARA-X: {}", e),
                compile_time_ms: t_compile.elapsed().as_millis() as u64,
                scan_benign_ms: 0,
                matched_benign: false,
                required_modules: rule.imports.clone(),
                external_vars: rule.external_vars.clone(),
            };
        }

        let rules = compiler.build();
        let compile_time_ms = t_compile.elapsed().as_millis() as u64;
        if compile_time_ms > 500 {
            score -= 15;
            notes.push(format!("Compilación lenta ({} ms)", compile_time_ms));
        }

        // Prueba contra corpus benigno sintético (texto limpio + stub PE mínimo)
        let t_scan = Instant::now();
        let mut scanner = Scanner::new(&rules);
        for &(var_name, default_val) in STANDARD_EXTERNAL_VARS {
            let _ = scanner.set_global(var_name, default_val);
        }

        let benign_text = b"SamuLibre clean benign verification document v2.0.20 - standard office text.";
        let benign_ps1 = b"# PowerShell policy verification probe\nWrite-Output 'PowerShell OK'\n";
        let benign_json = br#"{"app":"samulibre","ip":"127.0.0.1","url":"https://localhost/health"}"#;
        let mut benign_pe = vec![0u8; 512];
        benign_pe[0..2].copy_from_slice(b"MZ");
        benign_pe[60..64].copy_from_slice(&128u32.to_le_bytes());
        benign_pe[128..132].copy_from_slice(b"PE\0\0");

        let mut matched_benign = false;
        for sample in [
            benign_text.as_slice(),
            benign_ps1.as_slice(),
            benign_json.as_slice(),
            benign_pe.as_slice(),
        ] {
            if let Ok(res) = scanner.scan(sample) {
                if res.matching_rules().len() > 0 {
                    matched_benign = true;
                    break;
                }
            }
        }
        let scan_benign_ms = t_scan.elapsed().as_millis() as u64;

        if matched_benign {
            return YaraValidationReport {
                status: ValidationStatus::Rechazada,
                score: 5,
                notes: "Falso positivo inmediato sobre corpus benigno de validación".to_string(),
                compile_time_ms,
                scan_benign_ms,
                matched_benign: true,
                required_modules: rule.imports.clone(),
                external_vars: rule.external_vars.clone(),
            };
        }

        if scan_benign_ms > 100 {
            score -= 20;
            notes.push(format!("Evaluación lenta en corpus benigno ({} ms)", scan_benign_ms));
        }
        if !rule.external_vars.is_empty() {
            score -= 5;
            notes.push(format!("Usa variables externas: {}", rule.external_vars.join(", ")));
        }
        if rule.author == "Desconocido" {
            score -= 5;
            notes.push("Sin metadato de autor explícito".to_string());
        }

        let final_score = score.clamp(0, 100) as u8;
        let status = if is_duplicate {
            ValidationStatus::Rechazada
        } else if final_score >= 85 {
            ValidationStatus::Aprobada
        } else if final_score >= 65 {
            ValidationStatus::AprobadaConRestricciones
        } else {
            ValidationStatus::EnObservacion
        };

        if notes.is_empty() {
            notes.push("Validación YARA-X superada sin observaciones".to_string());
        }

        YaraValidationReport {
            status,
            score: final_score,
            notes: notes.join("; "),
            compile_time_ms,
            scan_benign_ms,
            matched_benign,
            required_modules: rule.imports.clone(),
            external_vars: rule.external_vars.clone(),
        }
    }

    fn has_overly_general_condition(source: &str) -> bool {
        let cond_re = Regex::new(r"(?is)\bcondition\s*:\s*([^\}]+)").unwrap();
        if let Some(cap) = cond_re.captures(source) {
            let cond = cap[1].trim().to_ascii_lowercase();
            if cond == "true" || cond == "1" || cond == "not false" {
                return true;
            }
        }
        false
    }
}

/// Motor de ejecución en producción basado en `yara-x` compilado
pub struct CompiledYaraRuntime {
    rules: Rules,
    compiled_count: usize,
    failed_count: usize,
}

impl std::fmt::Debug for CompiledYaraRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledYaraRuntime")
            .field("compiled_count", &self.compiled_count)
            .field("failed_count", &self.failed_count)
            .finish()
    }
}

const YARA_BIN_MAGIC: &[u8; 8] = b"SAMUYARA";
const YARA_BIN_XOR_KEY: &[u8; 16] = b"SamuLibreYaraKey";

impl CompiledYaraRuntime {
    /// Compila todas las reglas aprobadas desde pares `(namespace, rule_source)`
    pub fn compile_rules<'a, I>(items: I) -> Result<Self>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut compiler = Compiler::new();
        for &(var_name, default_val) in STANDARD_EXTERNAL_VARS {
            compiler
                .define_global(var_name, default_val)
                .map_err(|e| anyhow!("Error definiendo variable global {}: {}", var_name, e))?;
        }

        let mut compiled_count = 0usize;
        let mut failed_count = 0usize;
        let mut seen_namespaces: HashSet<String> = HashSet::new();

        for (idx, (ns_raw, source)) in items.into_iter().enumerate() {
            let mut ns = if ns_raw.is_empty() {
                format!("ns_{}", idx)
            } else {
                ns_raw.to_string()
            };
            if !seen_namespaces.insert(ns.clone()) {
                ns = format!("{}_{}", ns, idx);
                seen_namespaces.insert(ns.clone());
            }
            compiler.new_namespace(&ns);
            match compiler.add_source(source) {
                Ok(_) => compiled_count += 1,
                Err(_) => failed_count += 1,
            }
        }

        let rules = compiler.build();
        Ok(Self {
            rules,
            compiled_count,
            failed_count,
        })
    }

    pub fn compiled_count(&self) -> usize {
        self.compiled_count
    }

    pub fn failed_count(&self) -> usize {
        self.failed_count
    }

    fn apply_ctr_keystream(nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter: u64 = 0;
        for chunk in data.chunks(32) {
            let mut hasher = Sha256::new();
            hasher.update(YARA_BIN_XOR_KEY);
            hasher.update(nonce);
            hasher.update(counter.to_le_bytes());
            let mask = hasher.finalize();
            for (b, m) in chunk.iter().zip(mask.iter()) {
                out.push(b ^ m);
            }
            counter += 1;
        }
        out
    }

    /// Serializa las reglas compiladas a disco (cifrado de flujo con nonce para evitar falsos positivos de Defender)
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = self
            .rules
            .serialize()
            .map_err(|e| anyhow!("Error serializando reglas YARA-X: {}", e))?;
        let nonce: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
        let encrypted = Self::apply_ctr_keystream(&nonce, &raw);
        let mut out = Vec::with_capacity(8 + 16 + encrypted.len());
        out.extend_from_slice(b"SAMUYAR2");
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&encrypted);
        std::fs::write(path, out)?;
        Ok(())
    }

    /// Carga reglas YARA-X precompiladas desde disco
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path)?;
        let raw: Vec<u8> = if data.starts_with(b"SAMUYAR2") && data.len() >= 24 {
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&data[8..24]);
            Self::apply_ctr_keystream(&nonce, &data[24..])
        } else if data.starts_with(YARA_BIN_MAGIC) {
            data[YARA_BIN_MAGIC.len()..]
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ YARA_BIN_XOR_KEY[i % YARA_BIN_XOR_KEY.len()])
                .collect()
        } else {
            data
        };
        let rules = Rules::deserialize(&raw)
            .map_err(|e| anyhow!("Error deserializando reglas YARA-X: {}", e))?;
        let count = rules.iter().count();
        Ok(Self {
            rules,
            compiled_count: count,
            failed_count: 0,
        })
    }

    /// Escanea un buffer de bytes en memoria con contexto de archivo (variables externas)
    pub fn scan_bytes(
        &self,
        data: &[u8],
        filename: &str,
        filepath: &str,
        extension: &str,
        filetype: &str,
    ) -> Result<Vec<YaraMatchResult>> {
        let mut scanner = Scanner::new(&self.rules);
        let _ = scanner.set_global("filename", filename);
        let _ = scanner.set_global("filepath", filepath);
        let _ = scanner.set_global("extension", extension);
        let _ = scanner.set_global("filetype", filetype);
        let _ = scanner.set_global("owner", "");
        let _ = scanner.set_global("md5", "");

        let results = scanner
            .scan(data)
            .map_err(|e| anyhow!("Error ejecutando escaneo YARA-X: {}", e))?;

        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            let mut author = None;
            let mut description = None;
            let mut threat_name = None;
            for (k, v) in rule.metadata() {
                match k.to_ascii_lowercase().as_str() {
                    "author" => author = Some(format!("{:?}", v).trim_matches('"').to_string()),
                    "description" | "desc" => {
                        description = Some(format!("{:?}", v).trim_matches('"').to_string())
                    }
                    "threat_name" | "malware" => {
                        threat_name = Some(format!("{:?}", v).trim_matches('"').to_string())
                    }
                    _ => {}
                }
            }
            matches.push(YaraMatchResult {
                rule_name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                author,
                description,
                threat_name,
            });
        }
        Ok(matches)
    }
}

/// Puerta de promoción formal (`LABORATORIO -> EN_OBSERVACION -> APROBADA`) con prueba de regresión
pub struct YaraPromotionGate;

impl YaraPromotionGate {
    /// Evalúa una regla en Laboratorio/Observación, ejecuta prueba de regresión con EICAR y corpus limpio,
    /// y la promueve o rechaza registrando trazabilidad en `indicator_history`.
    pub fn evaluate_and_promote(
        db: &crate::db::IntelDatabase,
        indicator_id: &str,
        rule_source: &str,
        license: &str,
        target_status: ValidationStatus,
    ) -> Result<ValidationStatus> {
        if !crate::licensing::LicensingAndManifestManager::is_commercial_production_allowed(license) {
            let _ = db.update_validation_status(
                indicator_id,
                ValidationStatus::Rechazada,
                "Promoción denegada: licencia no comercial (CC BY-NC)",
            )?;
            return Ok(ValidationStatus::Rechazada);
        }

        let parsed = YaraRuleValidator::split_yara_file(rule_source, license);
        let Some(rule) = parsed.into_iter().next() else {
            let _ = db.update_validation_status(
                indicator_id,
                ValidationStatus::Rechazada,
                "Promoción denegada: regla YARA vacía o malformada",
            )?;
            return Ok(ValidationStatus::Rechazada);
        };

        let val = YaraRuleValidator::validate_rule(&rule, false);
        if !val.status.is_production_active() {
            let _ = db.update_validation_status(indicator_id, val.status, &val.notes)?;
            return Ok(val.status);
        }

        // Prueba de regresión: la regla candidata compilada junto al control EICAR no debe romper EICAR ni disparar en corpus limpio
        let eicar_control = r#"rule samulibre_regression_eicar { strings: $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" condition: $e }"#;
        let runtime = CompiledYaraRuntime::compile_rules([
            ("regression_eicar", eicar_control),
            ("candidate", rule.raw_source.as_str()),
        ])?;
        let eicar_hits = runtime.scan_bytes(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "eicar.com",
            "eicar.com",
            "com",
            "text",
        )?;
        let clean_hits = runtime.scan_bytes(
            b"# PowerShell policy test\nWrite-Output 'SamuLibre clean regression sample'\n",
            "clean.ps1",
            "clean.ps1",
            "ps1",
            "text",
        )?;

        if eicar_hits.is_empty() || !clean_hits.is_empty() {
            let _ = db.update_validation_status(
                indicator_id,
                ValidationStatus::Rechazada,
                "Fallo en puerta de regresión (FP sobre corpus limpio o rotura de control EICAR)",
            )?;
            return Ok(ValidationStatus::Rechazada);
        }

        let _ = db.update_validation_status(
            indicator_id,
            target_status,
            &format!("Promovida a {:?} tras superar validación y puerta de regresión", target_status),
        )?;
        Ok(target_status)
    }
}
