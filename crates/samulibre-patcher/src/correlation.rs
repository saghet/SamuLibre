use samulibre_types::{
    CveKbCorrelation, InstalledKbRecord, PatchStatus, PendingKbRecord, Severity,
    VirtualPatchRule, WindowsSystemInventory,
};
use std::collections::{HashMap, HashSet};
use tracing::info;

use crate::windows_kb_service::MSRC_KB_CATALOG;

pub struct PatchCorrelationEngine;

impl PatchCorrelationEngine {
    /// Genera la matriz bidireccional de correlación entre CVEs, KBs de Microsoft y Parches Virtuales
    pub fn correlate_all(
        inventory: &WindowsSystemInventory,
        installed_kbs: &[InstalledKbRecord],
        pending_kbs: &[PendingKbRecord],
        rules: &[VirtualPatchRule],
    ) -> Vec<CveKbCorrelation> {
        let mut correlations = Vec::new();
        let installed_set: HashSet<String> = installed_kbs.iter().map(|k| k.kb_id.to_uppercase()).collect();
        let pending_set: HashSet<String> = pending_kbs.iter().map(|k| k.kb_id.to_uppercase()).collect();

        // 1. Mapa de KBs y sus supersedencias para resolver cadenas acumulativas
        let mut superseded_by_installed: HashMap<String, String> = HashMap::new();
        for entry in MSRC_KB_CATALOG {
            let entry_kb = entry.kb_id.to_uppercase();
            if installed_set.contains(&entry_kb) {
                for superseded in entry.supersedes {
                    superseded_by_installed.insert(superseded.to_uppercase(), entry_kb.clone());
                }
            }
        }

        // 2. Mapear reglas de Virtual Patching por CVE
        let rule_map: HashMap<String, &VirtualPatchRule> = rules
            .iter()
            .map(|r| (r.cve.to_uppercase(), r))
            .collect();

        // 3. Procesar catálogo MSRC y asociar con las reglas activas
        let mut processed_cves: HashSet<String> = HashSet::new();

        for entry in MSRC_KB_CATALOG {
            let corrective_kb = entry.kb_id.to_uppercase();
            let is_installed_directly = installed_set.contains(&corrective_kb);
            let superseding_installed_kb = superseded_by_installed.get(&corrective_kb);

            let (kb_status_str, is_effectively_patched) = if is_installed_directly {
                ("Instalado Oficialmente (CBS/WUA)".to_string(), true)
            } else if let Some(sup_kb) = superseding_installed_kb {
                (format!("Mitigado por Actualización Acumulativa ({})", sup_kb), true)
            } else if pending_set.contains(&corrective_kb) {
                ("Actualización Pendiente de Instalación".to_string(), false)
            } else {
                ("Actualización Publicada / No Instalada".to_string(), false)
            };

            for cve in entry.fixed_cves {
                let cve_upper = cve.to_uppercase();
                if processed_cves.contains(&cve_upper) {
                    continue;
                }
                processed_cves.insert(cve_upper.clone());

                let matching_rule = rule_map.get(&cve_upper);
                let (vpatch_id, vpatch_status) = if let Some(rule) = matching_rule {
                    (Some(rule.id.clone()), rule.status.clone())
                } else {
                    (None, if is_effectively_patched { PatchStatus::NativePatchInstalled } else { PatchStatus::Unmitigated })
                };

                let recommended_action = if is_effectively_patched {
                    "Vulnerabilidad corregida nativamente por Windows Update. Mantener monitoreo pasivo.".to_string()
                } else if vpatch_status == PatchStatus::VirtualPatchActive {
                    format!(
                        "Parche virtual activo protegiendo el endpoint. Programe la instalación de {} cuando sea conveniente.",
                        corrective_kb
                    )
                } else if matching_rule.is_some() {
                    format!(
                        "ALERTA: Vulnerabilidad expuesta. Active el Parche Virtual compensatorio de inmediato e instale {}.",
                        corrective_kb
                    )
                } else {
                    format!(
                        "Sin parche virtual disponible. Instale la actualización oficial {} de forma prioritaria.",
                        corrective_kb
                    )
                };

                let days = match cve_upper.as_str() {
                    "CVE-2024-43573" => 30,
                    "CVE-2024-43572" => 30,
                    "CVE-2024-38124" => 30,
                    "CVE-2023-28252" => 570,
                    "CVE-2022-30190" => 870,
                    "CVE-2021-34527" => 1220,
                    "CVE-2022-21907" => 1030,
                    "CVE-2017-0144" => 2790,
                    "CVE-2020-1472" => 1540,
                    _ => 150,
                };

                correlations.push(CveKbCorrelation {
                    cve: cve_upper,
                    title: entry.title.to_string(),
                    affected_product: entry.product.to_string(),
                    vulnerable_component: Self::extract_component(entry.title),
                    vulnerable_version_range: format!("{} (Build {})", inventory.display_version, inventory.current_build),
                    cvss_score: entry.cvss_score,
                    severity: entry.severity.clone(),
                    cisa_kev: entry.cisa_kev,
                    public_exploit_available: entry.cisa_kev || entry.cvss_score >= 9.0,
                    corrective_kb: corrective_kb.clone(),
                    kb_installation_status: kb_status_str.clone(),
                    virtual_patch_rule_id: vpatch_id,
                    virtual_patch_status: vpatch_status,
                    recommended_action,
                    days_since_disclosure: days,
                });
            }
        }

        // 4. Agregar cualquier CVE presente en las reglas de Virtual Patching que no esté en el catálogo MSRC base
        for rule in rules {
            let cve_upper = rule.cve.to_uppercase();
            if !processed_cves.contains(&cve_upper) {
                processed_cves.insert(cve_upper.clone());
                let required_kb = rule.required_kb.first().cloned().unwrap_or_else(|| "KB-Nativo".to_string());
                let is_installed = installed_set.contains(&required_kb.to_uppercase());

                let kb_status = if is_installed {
                    "Instalado (Confirmado)".to_string()
                } else {
                    "Pendiente / No detectado".to_string()
                };

                correlations.push(CveKbCorrelation {
                    cve: cve_upper,
                    title: rule.title.clone(),
                    affected_product: format!("Windows {} ({})", inventory.display_version, inventory.architecture),
                    vulnerable_component: rule.target_component.clone(),
                    vulnerable_version_range: format!("Windows Build {}", inventory.current_build),
                    cvss_score: match rule.severity {
                        Severity::Critical => 9.5,
                        Severity::High => 7.8,
                        Severity::Medium => 5.5,
                        Severity::Low => 3.2,
                    },
                    severity: rule.severity.clone(),
                    cisa_kev: rule.severity == Severity::Critical,
                    public_exploit_available: rule.severity == Severity::Critical,
                    corrective_kb: required_kb,
                    kb_installation_status: kb_status,
                    virtual_patch_rule_id: Some(rule.id.clone()),
                    virtual_patch_status: rule.status.clone(),
                    recommended_action: if rule.status == PatchStatus::VirtualPatchActive {
                        "Protección compensatoria activa.".to_string()
                    } else {
                        "Evaluar aplicación de regla de parche virtual.".to_string()
                    },
                    days_since_disclosure: 365,
                });
            }
        }

        // Ordenar correlaciones: CISA KEV primero, luego por CVSS descendente
        correlations.sort_by(|a, b| {
            b.cisa_kev.cmp(&a.cisa_kev).then_with(|| {
                b.cvss_score
                    .partial_cmp(&a.cvss_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        info!(
            "Correlación completada: {} vectores CVE <-> KB <-> Virtual Patching analizados",
            correlations.len()
        );

        correlations
    }

    fn extract_component(title: &str) -> String {
        if title.contains("Print Spooler") {
            "Servicio Spoolsv.exe (Print Spooler)".to_string()
        } else if title.contains("HTTP.sys") {
            "Controlador HTTP.sys (Kernel Web Listener)".to_string()
        } else if title.contains("Support Diagnostic Tool") || title.contains("Follina") {
            "Microsoft Support Diagnostic Tool (msdt.exe)".to_string()
        } else if title.contains("CLFS") {
            "Common Log File System (clfs.sys)".to_string()
        } else if title.contains("SMB") {
            "Server Message Block (srv.sys / srv2.sys)".to_string()
        } else if title.contains("Netlogon") {
            "Protocolo Netlogon RPC (lsass.exe)".to_string()
        } else if title.contains("MSHTML") {
            "Motor de renderizado MSHTML Platform".to_string()
        } else {
            "Subsistema Central del Kernel de Windows".to_string()
        }
    }
}
