use anyhow::Result;
use chrono::Utc;
use samulibre_types::{DefenderThreatEvent, FpClassification, FpInvestigationRecord};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;

/// Motor de investigación de falsos positivos y análisis forense de alertas de Windows Defender
pub struct FalsePositiveInvestigator;

impl FalsePositiveInvestigator {
    /// Consulta los eventos recientes de detección en el registro de Windows Defender
    /// Utiliza exclusivamente APIs y comandos oficiales de lectura de Windows Event Log (IDs 1116, 1117, 1006)
    pub fn query_defender_events(max_events: usize) -> Vec<DefenderThreatEvent> {
        info!("Consultando eventos de detección en Microsoft-Windows-Windows Defender/Operational...");

        #[cfg(target_os = "windows")]
        {
            let script = format!(
                "$events = Get-WinEvent -FilterHashtable @{{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 1006 }} -MaxEvents {} -ErrorAction SilentlyContinue; if ($events) {{ ($events | ForEach-Object {{ [PSCustomObject]@{{ EventId=$_.Id; TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o'); Message=$_.Message }} }}) | ConvertTo-Json -Depth 3 -Compress }} else {{ Write-Output '[]' }}",
                max_events
            );

            let mut cmd = Command::new("powershell");
            cmd.args(["-WindowStyle", "Hidden", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script]);
            cmd.stdin(std::process::Stdio::null());
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000 | 0x00000008); // CREATE_NO_WINDOW | DETACHED_PROCESS

            if let Ok(output) = cmd.output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(events) = Self::parse_powershell_events(&stdout) {
                    return events;
                }
            }
        }

        // Si no hay eventos o no estamos en Windows, devolvemos lista vacía
        Vec::new()
    }

    /// Parsea los eventos devueltos por PowerShell y extrae los campos clave
    fn parse_powershell_events(json_str: &str) -> Result<Vec<DefenderThreatEvent>> {
        let trimmed = json_str.trim();
        if trimmed.is_empty() || trimmed == "[]" {
            return Ok(Vec::new());
        }

        let parsed: serde_json::Value = serde_json::from_str(trimmed)?;
        let items = if parsed.is_array() {
            parsed.as_array().unwrap().clone()
        } else if parsed.is_object() {
            vec![parsed]
        } else {
            return Ok(Vec::new());
        };

        let mut events = Vec::new();
        for item in items {
            let event_id = item.get("EventId").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let time_created = item
                .get("TimeCreated")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let msg = item.get("Message").and_then(|v| v.as_str()).unwrap_or("");

            let threat_event = Self::parse_message_text(event_id, &time_created, msg);
            events.push(threat_event);
        }

        Ok(events)
    }

    /// Analiza el texto del mensaje del evento de Defender extrayendo sus metadatos
    pub fn parse_message_text(
        event_id: u32,
        time_created: &str,
        msg: &str,
    ) -> DefenderThreatEvent {
        let mut threat_name = String::new();
        let mut threat_id = String::new();
        let mut severity = String::new();
        let mut category = String::new();
        let mut file_path = String::new();
        let mut detection_origin = String::new();
        let mut detection_source = String::new();
        let mut process_name = String::new();
        let mut action_taken = String::new();
        let mut error_code = String::new();
        let mut security_intelligence_version = String::new();
        let mut engine_version = String::new();

        // Defender operational log outputs in key-value lines with delimiters
        for raw_line in msg.split(|c| c == '\n' || c == '%' || c == '\r') {
            let line = raw_line.trim();
            if line.contains("Nombre:") || line.contains("Name:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    threat_name = parts[1].trim().to_string();
                }
            } else if line.contains("Id.:") || line.contains("ID:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    threat_id = parts[1].trim().to_string();
                }
            } else if line.contains("Gravedad:") || line.contains("Severity:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    severity = parts[1].trim().to_string();
                }
            } else if line.contains("Categoría:") || line.contains("Category:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    category = parts[1].trim().to_string();
                }
            } else if line.contains("Ruta de acceso:") || line.contains("Path:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let raw_path = parts[1].trim().trim_start_matches("file:_");
                    file_path = raw_path.to_string();
                }
            } else if line.contains("Origen de detección:") || line.contains("Detection Origin:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 && detection_origin.is_empty() {
                    detection_origin = parts[1].trim().to_string();
                }
            } else if line.contains("Origen de detección:") || line.contains("Detection Source:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    detection_source = parts[1].trim().to_string();
                }
            } else if line.contains("Nombre de proceso:") || line.contains("Process Name:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    process_name = parts[1].trim().to_string();
                }
            } else if line.contains("Acción:") || line.contains("Action:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    action_taken = parts[1].trim().to_string();
                }
            } else if line.contains("Error Code:") || line.contains("Código de error:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    error_code = parts[1].trim().to_string();
                }
            } else if line.contains("Security intelligence Version:")
                || line.contains("Versión de inteligencia de seguridad:")
            {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    security_intelligence_version = parts[1].trim().to_string();
                }
            } else if line.contains("Engine Version:") || line.contains("Versión de motor:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    engine_version = parts[1].trim().to_string();
                }
            }
        }

        DefenderThreatEvent {
            event_id,
            threat_id,
            threat_name,
            severity,
            category,
            file_path,
            detection_origin,
            detection_source,
            process_name,
            action_taken,
            error_code,
            timestamp_utc: time_created.to_string(),
            security_intelligence_version,
            engine_version,
        }
    }

    /// Investiga a fondo un evento de detección recopilando la información forense del archivo
    pub fn investigate_event(event: &DefenderThreatEvent) -> FpInvestigationRecord {
        let path = Path::new(&event.file_path);
        let exists = path.exists();

        let mut file_sha256 = String::new();
        let mut file_size_bytes = 0;
        let compile_date = String::new();
        let file_version = "2.1.13".to_string();
        let mut digital_signature = "No Firmado / Desconocido".to_string();
        let publisher = "SamuLibre Security Community".to_string();

        if exists && path.is_file() {
            if let Ok(metadata) = fs::metadata(path) {
                file_size_bytes = metadata.len();
            }
            if let Ok(bytes) = fs::read(path) {
                file_sha256 = hex::encode(Sha256::digest(&bytes));
            }
        }

        // Consultar firma digital vía Authenticode si el archivo existe o con PowerShell
        #[cfg(target_os = "windows")]
        if exists {
            let script = format!(
                "(Get-AuthenticodeSignature -FilePath '{}').Status.ToString()",
                event.file_path
            );
            let mut cmd = Command::new("powershell");
            cmd.args(["-WindowStyle", "Hidden", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script]);
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000 | 0x00000008);
            if let Ok(out) = cmd.output() {
                let status_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !status_str.is_empty() {
                    digital_signature = status_str;
                }
            }
        }

        let is_samulibre_official_binary = event.process_name.to_lowercase().contains("samulibre")
            || event.file_path.to_lowercase().contains("samulibre");

        let is_quarantined = event.action_taken.to_lowercase().contains("cuarentena")
            || event.action_taken.to_lowercase().contains("quarantine")
            || !exists;

        // Clasificación inteligente
        let (classification, justification, recommended_action) =
            Self::classify_detection(event, is_samulibre_official_binary, &file_sha256);

        FpInvestigationRecord {
            threat_event: event.clone(),
            file_sha256,
            file_size_bytes,
            file_version,
            digital_signature,
            publisher,
            compile_date,
            responsible_process: event.process_name.clone(),
            classification,
            justification,
            is_samulibre_official_binary,
            is_quarantined,
            recommended_action,
        }
    }

    /// Clasifica de forma no destructiva la detección entre falso positivo, artefacto de test o malware
    fn classify_detection(
        event: &DefenderThreatEvent,
        is_samu: bool,
        _sha256: &str,
    ) -> (FpClassification, String, String) {
        let t_lower = event.threat_name.to_lowercase();
        let p_lower = event.file_path.to_lowercase();

        // 1. Detección de cadenas de prueba conocidas (EICAR / AMTSO)
        if t_lower.contains("eicar") || p_lower.contains("eicar") || p_lower.contains("amtso") {
            return (
                FpClassification::TestArtifactPayload,
                "La amenaza detectada corresponde al estándar de validación EICAR/AMTSO utilizado por las pruebas de SamuLibre para verificar la capacidad de detección sin riesgo real.".to_string(),
                "Ninguna acción de exclusión requerida. El sistema funciona correctamente al detectar y aislar el artefacto de prueba.".to_string(),
            );
        }

        // 2. Falso positivo en binario propio de SamuLibre
        if is_samu {
            if t_lower.contains("heur") || t_lower.contains("wacatac") || t_lower.contains("bearfoos") {
                return (
                    FpClassification::BenignFalsePositive,
                    "Falso positivo heurístico de Defender sobre un binario legítimo del proyecto SamuLibre. Provocado habitualmente por falta de reputación previa o patrones genéricos en compilaciones debug de Rust.".to_string(),
                    "Firmar el binario con certificado Authenticode oficial y remitir la muestra a Microsoft Security Intelligence (WDSI) para añadir a lista blanca global.".to_string(),
                );
            }
        }

        // 3. Archivo sospechoso no firmado
        if !is_samu && !p_lower.is_empty() {
            return (
                FpClassification::LegitimateCompromise,
                format!(
                    "Detección legítima de Defender sobre un archivo no perteneciente a SamuLibre: {}. Amenaza clasificada: {}.",
                    event.file_path, event.threat_name
                ),
                "Mantener la acción de cuarentena ejecutada por Defender. Registrar en el historial forense de SamuLibre para correlación EDR.".to_string(),
            );
        }

        (
            FpClassification::UnknownInvestigationRequired,
            "Alerta en evaluación forense. No se cumplen los criterios directos de falso positivo conocido.".to_string(),
            "Ejecutar escaneo profundo con el motor heurístico y comprobar integridad criptográfica del archivo.".to_string(),
        )
    }

    /// Genera un informe forense estructurado en formato Markdown
    pub fn generate_investigation_report(records: &[FpInvestigationRecord]) -> String {
        let mut md = String::new();
        md.push_str("# INFORME FORENSE: SAMULIBRE FALSE POSITIVE INVESTIGATION ENGINE\n\n");
        md.push_str(&format!("**Fecha y Hora UTC:** {}\n", Utc::now().to_rfc3339()));
        md.push_str(&format!("**Total de Alertas Investigadas:** {}\n\n", records.len()));

        md.push_str("| ID Amenaza | Nombre Amenaza | Archivo / Ruta | Proceso Responsable | Clasificación | Acción Defender |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for r in records {
            let clean_path = if r.threat_event.file_path.len() > 40 {
                format!("...{}", &r.threat_event.file_path[r.threat_event.file_path.len() - 37..])
            } else {
                r.threat_event.file_path.clone()
            };

            md.push_str(&format!(
                "| `{}` | **{}** | `{}` | `{}` | **{}** | `{}` |\n",
                r.threat_event.threat_id,
                r.threat_event.threat_name,
                clean_path,
                Path::new(&r.responsible_process).file_name().and_then(|n| n.to_str()).unwrap_or(&r.responsible_process),
                r.classification,
                r.threat_event.action_taken
            ));
        }

        md.push_str("\n---\n\n## DETALLE FORENSE POR ALERTA\n\n");
        for (i, r) in records.iter().enumerate() {
            md.push_str(&format!("### Alerta #{}: {}\n\n", i + 1, r.threat_event.threat_name));
            md.push_str(&format!("- **Threat ID:** {}\n", r.threat_event.threat_id));
            md.push_str(&format!("- **Gravedad:** {}\n", r.threat_event.severity));
            md.push_str(&format!("- **Ruta Completa:** `{}`\n", r.threat_event.file_path));
            md.push_str(&format!("- **SHA-256:** `{}`\n", if r.file_sha256.is_empty() { "No disponible (aislado)" } else { &r.file_sha256 }));
            md.push_str(&format!("- **Firma Digital:** {}\n", r.digital_signature));
            md.push_str(&format!("- **Proceso Responsable:** `{}`\n", r.responsible_process));
            md.push_str(&format!("- **Origen de Detección:** {}\n", r.threat_event.detection_source));
            md.push_str(&format!("- **Clasificación Forense:** **{}**\n", r.classification));
            md.push_str(&format!("- **Justificación:** {}\n", r.justification));
            md.push_str(&format!("- **Recomendación:** {}\n\n", r.recommended_action));
        }

        md
    }
}
