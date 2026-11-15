use chrono::Utc;
use samulibre_types::{
    AlertPriority, CveKbCorrelation, PatchStatus, PendingKbRecord, SecurityAlert, Severity,
};

pub struct SmartAlertEngine;

impl SmartAlertEngine {
    /// Genera y prioriza todas las alertas de seguridad a partir de la correlación y estado del sistema
    pub fn generate_alerts(
        pending_kbs: &[PendingKbRecord],
        correlations: &[CveKbCorrelation],
        reboot_pending: bool,
        reboot_reasons: &[String],
        is_vpn_connected: bool,
        is_kill_switch_active: bool,
    ) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();

        // 1. Alertas por vulnerabilidades explotadas activamente en CISA KEV
        for corr in correlations {
            if corr.cisa_kev && corr.virtual_patch_status != PatchStatus::NativePatchInstalled {
                let priority = AlertPriority::Critical;
                let title = format!("Amenaza Activa CISA KEV: {}", corr.cve);
                let desc = format!(
                    "La vulnerabilidad {} ({}) está siendo explotada activamente en ataques dirigidos. Afecta a {}.",
                    corr.cve, corr.title, corr.vulnerable_component
                );
                let rec = if corr.virtual_patch_status == PatchStatus::VirtualPatchActive {
                    format!(
                        "Protección compensatoria activa en SamuLibre. Instale la actualización oficial {} para mitigación definitiva.",
                        corr.corrective_kb
                    )
                } else if corr.virtual_patch_rule_id.is_some() {
                    format!(
                        "ACCIÓN URGENTE: Active el Parche Virtual para {} inmediatamente y programe {}.",
                        corr.cve, corr.corrective_kb
                    )
                } else {
                    format!("Instale con urgencia la actualización acumulativa {}.", corr.corrective_kb)
                };

                alerts.push(SecurityAlert {
                    id: format!("ALERT-KEV-{}", corr.cve),
                    timestamp: Utc::now().to_rfc3339(),
                    priority,
                    category: "Vulnerability Intelligence".to_string(),
                    title,
                    description: desc,
                    recommended_action: rec,
                    related_cve: Some(corr.cve.clone()),
                    related_kb: Some(corr.corrective_kb.clone()),
                    is_resolved: false,
                });
            }
        }

        // 2. Alertas por KBs Críticos pendientes
        for kb in pending_kbs {
            if kb.severity == Severity::Critical {
                alerts.push(SecurityAlert {
                    id: format!("ALERT-KB-CRIT-{}", kb.kb_id),
                    timestamp: Utc::now().to_rfc3339(),
                    priority: AlertPriority::Critical,
                    category: "Windows Updates".to_string(),
                    title: format!("Actualización Crítica de Windows Pendiente: {}", kb.kb_id),
                    description: format!(
                        "{}. Corrige {} vulnerabilidades conocidas.",
                        kb.title,
                        kb.fixed_cves.len()
                    ),
                    recommended_action: format!(
                        "Revise los parches asociados e inicie la instalación controlada de {} desde la consola.",
                        kb.kb_id
                    ),
                    related_cve: kb.fixed_cves.first().cloned(),
                    related_kb: Some(kb.kb_id.clone()),
                    is_resolved: false,
                });
            }
        }

        // 3. Alerta por reinicio pendiente en Windows Servicing Stack
        if reboot_pending {
            let reason_summary = if !reboot_reasons.is_empty() {
                reboot_reasons.join(" ")
            } else {
                "Actualizaciones de Windows instaladas requieren reiniciar el sistema para consolidar cambios.".to_string()
            };

            alerts.push(SecurityAlert {
                id: "ALERT-REBOOT-PENDING".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                priority: AlertPriority::Warning,
                category: "Windows Servicing".to_string(),
                title: "Reinicio de Sistema Pendiente".to_string(),
                description: format!("Windows ha aplicado parches que aún no están activos: {}", reason_summary),
                recommended_action: "Guarde su trabajo y reinicie el equipo cuando sea oportuno para completar la protección.".to_string(),
                related_cve: None,
                related_kb: None,
                is_resolved: false,
            });
        }

        // 4. Alerta por exposición de VPN y Kill Switch
        if !is_vpn_connected {
            alerts.push(SecurityAlert {
                id: "ALERT-VPN-DISCONNECTED".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                priority: AlertPriority::Info,
                category: "VPN & Privacy".to_string(),
                title: "Túnel VPN Inactivo".to_string(),
                description: "La dirección IP pública del equipo y las peticiones DNS están expuestas a la red local y al ISP.".to_string(),
                recommended_action: "Conecte la VPN de SamuLibre para cifrar su navegación y proteger el anonimato de red.".to_string(),
                related_cve: None,
                related_kb: None,
                is_resolved: false,
            });
        } else if !is_kill_switch_active {
            alerts.push(SecurityAlert {
                id: "ALERT-KILLSWITCH-OFF".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                priority: AlertPriority::Warning,
                category: "VPN & Privacy".to_string(),
                title: "Kill Switch Deshabilitado".to_string(),
                description: "Si ocurre un micro-corte en el túnel VPN, el tráfico podría salir sin cifrar hacia su ISP.".to_string(),
                recommended_action: "Habilite el Kill Switch en el panel VPN para garantizar aislamiento de red permanente.".to_string(),
                related_cve: None,
                related_kb: None,
                is_resolved: false,
            });
        }

        // Ordenar por prioridad: Critical -> High -> Warning -> Info
        alerts.sort_by_key(|a| match a.priority {
            AlertPriority::Critical => 0,
            AlertPriority::High => 1,
            AlertPriority::Warning => 2,
            AlertPriority::Info => 3,
        });

        alerts
    }
}
