use crate::learning::ProgramLearningEngine;
use crate::protected_system::ProtectedSystemGuard;
use crate::threat_intel::ThreatIntelManager;
use crate::types::{
    AppPolicy, AppTrustState, ConnectionRiskEvaluation, NetworkConnectionEntry, RiskFactor,
    RiskFactorCategory, RiskRecommendation, ThreatCorrelationEvent,
};
use std::collections::{HashMap, VecDeque};

const LOLBINS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "schtasks.exe",
    "wmic.exe",
    "nc.exe",
    "ncat.exe",
];

const C2_SUSPICIOUS_PORTS: &[u16] = &[1337, 4443, 4444, 4445, 5555, 6666, 7777, 8888, 9001, 9999, 31337];

pub struct RiskRecommender;

impl RiskRecommender {
    pub fn evaluate(
        conn: &NetworkConnectionEntry,
        intel: Option<&ThreatIntelManager>,
        app_policies: &HashMap<String, AppPolicy>,
        recent_av_events: &VecDeque<ThreatCorrelationEvent>,
        learning: &ProgramLearningEngine,
    ) -> ConnectionRiskEvaluation {
        let mut score: i16 = 0;
        let mut factors = Vec::new();
        let is_private = ProtectedSystemGuard::is_private_or_local_ip(&conn.remote_addr);
        let app_name_lower = conn.app_name.to_lowercase();
        let app_path_lower = conn.app_path.as_deref().unwrap_or("").to_lowercase();

        // 1. Correlación AV
        let has_av_alert = recent_av_events.iter().any(|ev| {
            ev.pid == Some(conn.pid)
                || (!app_path_lower.is_empty()
                    && ev.executable_path.as_deref().unwrap_or("").to_lowercase() == app_path_lower)
                || ev.process_name.eq_ignore_ascii_case(&conn.app_name)
        });
        if has_av_alert {
            score += 90;
            factors.push(RiskFactor {
                category: RiskFactorCategory::AvCorrelationIncident,
                severity: "Crítica".to_string(),
                score_impact: 90,
                title: "Detección Antivirus Activa".to_string(),
                description: format!(
                    "El proceso '{}' (PID {}) tiene una alerta reciente en el motor Antivirus.",
                    conn.app_name, conn.pid
                ),
                mitre_technique: None,
            });
        }

        // 2. Threat Intelligence (IP externa)
        if let Some(intel_mgr) = intel {
            if !is_private {
                if let Some(ind) = intel_mgr.check_ip(&conn.remote_addr, 50) {
                    let impact = if ind.confidence >= 80 { 85 } else { 45 };
                    score += impact;
                    factors.push(RiskFactor {
                        category: RiskFactorCategory::ThreatIntelHit,
                        severity: if ind.confidence >= 80 { "Crítica" } else { "Alta" }.to_string(),
                        score_impact: impact,
                        title: format!("Threat Intel ({})", ind.source_name),
                        description: format!(
                            "IP remota {} presente en {} ({}, confianza {}%).",
                            conn.remote_addr, ind.source_name, ind.description, ind.confidence
                        ),
                        mitre_technique: Some("T1071".to_string()),
                    });
                }
            }
        }

        // 3. LOLBin saliente hacia Internet pública
        let is_lolbin = LOLBINS.iter().any(|&l| app_name_lower == l || app_name_lower.contains(l));
        if is_lolbin && !is_private && conn.remote_port > 0 {
            score += 75;
            factors.push(RiskFactor {
                category: RiskFactorCategory::LolbinOutbound,
                severity: "Crítica".to_string(),
                score_impact: 75,
                title: "LOLBin Saliente a Internet".to_string(),
                description: format!(
                    "Utilidad del sistema ('{}') conectándose a IP pública externa {}:{}.",
                    conn.app_name, conn.remote_addr, conn.remote_port
                ),
                mitre_technique: Some("T1059 / T1218".to_string()),
            });
        }

        // 4. Puerto C2 conocido hacia WAN
        if C2_SUSPICIOUS_PORTS.contains(&conn.remote_port) && !is_private {
            score += 70;
            factors.push(RiskFactor {
                category: RiskFactorCategory::KnownC2Port,
                severity: "Crítica".to_string(),
                score_impact: 70,
                title: "Puerto Sospechoso C2".to_string(),
                description: format!(
                    "Puerto destino {} asociado frecuentemente a reverse shells o C2.",
                    conn.remote_port
                ),
                mitre_technique: Some("T1571".to_string()),
            });
        }

        // 5. Ejecutable en carpeta temporal / volátil
        if (app_path_lower.contains("\\temp\\") || app_path_lower.contains("\\appdata\\local\\temp\\"))
            && !app_path_lower.is_empty()
        {
            let impact = if !is_private { 40 } else { 20 };
            score += impact;
            factors.push(RiskFactor {
                category: RiskFactorCategory::VolatileDirectoryExecution,
                severity: "Alta".to_string(),
                score_impact: impact,
                title: "Ejecutable en Carpeta Temporal".to_string(),
                description: format!(
                    "Proceso ejecutándose desde carpeta temporal: {}",
                    conn.app_path.as_deref().unwrap_or("-")
                ),
                mitre_technique: Some("T1036.005".to_string()),
            });
        }

        // 6. Políticas y detección de binario modificado
        if let Some(policy) = app_policies.get(&app_path_lower) {
            match policy.trust_state {
                AppTrustState::Blocked => {
                    score += 95;
                    factors.push(RiskFactor {
                        category: RiskFactorCategory::PolicyRestrictedApp,
                        severity: "Crítica".to_string(),
                        score_impact: 95,
                        title: "Bloqueada por Política".to_string(),
                        description: "Aplicación marcada como bloqueada en el firewall.".to_string(),
                        mitre_technique: None,
                    });
                }
                AppTrustState::ModifiedNeedsReeval => {
                    score += 80;
                    factors.push(RiskFactor {
                        category: RiskFactorCategory::BinaryTamperedMismatch,
                        severity: "Crítica".to_string(),
                        score_impact: 80,
                        title: "Binario Modificado".to_string(),
                        description: "El hash SHA-256 cambió respecto al aprobado; requiere reevaluación.".to_string(),
                        mitre_technique: Some("T1036".to_string()),
                    });
                }
                AppTrustState::Trusted => {
                    score -= 45;
                }
                _ => {}
            }
        }

        // 7. Puertos sensibles en escucha
        if conn.state == "LISTEN" && matches!(conn.local_port, 135 | 139 | 445 | 3389 | 5985 | 5986) {
            score += 45;
            factors.push(RiskFactor {
                category: RiskFactorCategory::SensitiveExposedService,
                severity: "Alta".to_string(),
                score_impact: 45,
                title: "Puerto Administrativo Expuesto".to_string(),
                description: format!("Puerto {} en escucha (SMB/RPC/RDP/WinRM).", conn.local_port),
                mitre_technique: Some("T1021".to_string()),
            });
        }

        // 8. Mitigadores (Loopback/LAN y Línea Base Aprendida)
        if is_private {
            score -= 35;
            factors.push(RiskFactor {
                category: RiskFactorCategory::BenignContextDampener,
                severity: "Informativa".to_string(),
                score_impact: -35,
                title: "Tráfico Local / LAN".to_string(),
                description: "Comunicación interna loopback o red privada RFC 1918.".to_string(),
                mitre_technique: None,
            });
        }
        if !app_path_lower.is_empty() && learning.is_learned_safe(&app_path_lower) {
            score -= 25;
            factors.push(RiskFactor {
                category: RiskFactorCategory::BenignContextDampener,
                severity: "Informativa".to_string(),
                score_impact: -25,
                title: "Aprendida como Esencial/Segura".to_string(),
                description: "Aplicación incluida en la línea base de software requerido.".to_string(),
                mitre_technique: None,
            });
        }

        let final_score = score.clamp(0, 100) as u8;
        let (recommendation, primary_reason, suggested_action, should_isolate_pid) = if final_score >= 70 {
            let primary = factors
                .iter()
                .find(|f| f.score_impact >= 70)
                .map(|f| f.description.clone())
                .unwrap_or_else(|| "Riesgo crítico detectado por múltiples señales.".to_string());
            (
                RiskRecommendation::RecommendedBlock,
                primary,
                "Se recomienda bloquear esta conexión en WFP".to_string(),
                is_lolbin || has_av_alert,
            )
        } else if final_score >= 35 {
            let primary = factors
                .iter()
                .find(|f| f.score_impact >= 35)
                .map(|f| f.description.clone())
                .unwrap_or_else(|| "Conexión anómala; revisar antes de permitir.".to_string());
            (
                RiskRecommendation::Review,
                primary,
                "Revisar legitimidad del proceso".to_string(),
                false,
            )
        } else {
            (
                RiskRecommendation::SafeLearned,
                "Tráfico operativo normal o aplicación esencial aprendida".to_string(),
                "No requiere bloqueo".to_string(),
                false,
            )
        };

        ConnectionRiskEvaluation {
            recommendation,
            total_risk_score: final_score,
            primary_reason,
            factors,
            suggested_action,
            should_isolate_pid,
        }
    }
}
