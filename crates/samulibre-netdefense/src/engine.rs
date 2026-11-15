use crate::av_correlation::correlate_av_detection_with_network;
use crate::dns_proxy::SecureDnsProxy;
use crate::learning::ProgramLearningEngine;
use crate::risk_recommender::RiskRecommender;
use crate::socket_monitor::SocketMonitor;
use crate::threat_intel::ThreatIntelManager;
use crate::tor_protection::TorSecureModeManager;
use crate::types::{
    AppPolicy, AppTrustState, DnsConfig, FirewallRule, HealthColor, NetDefenseDashboardSnapshot,
    NetDefenseEventLog, NetProtocol, NetworkConnectionEntry, RiskRecommendation, RuleAction,
    RuleScope, ThreatCorrelationEvent, TorProtectionHealth, TorSecureModeConfig,
    TorSecureModeState, TrafficDirection,
};
use crate::wfp::WfpController;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

const MAX_EVENT_LOGS: usize = 1000;
const MAX_CORRELATION_EVENTS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedNetDefenseState {
    pub firewall_enabled: bool,
    pub rules: Vec<FirewallRule>,
    pub app_policies: Vec<AppPolicy>,
    pub dns_config: DnsConfig,
    pub tor_config: TorSecureModeConfig,
}

impl Default for PersistedNetDefenseState {
    fn default() -> Self {
        Self {
            firewall_enabled: true,
            rules: Vec::new(),
            app_policies: Vec::new(),
            dns_config: DnsConfig::default(),
            tor_config: TorSecureModeConfig::default(),
        }
    }
}

pub struct NetworkDefenseEngine {
    #[allow(dead_code)]
    data_dir: PathBuf,
    state_file: PathBuf,
    pub firewall_enabled: bool,
    pub wfp: WfpController,
    pub socket_monitor: SocketMonitor,
    pub rules: Vec<FirewallRule>,
    pub app_policies: HashMap<String, AppPolicy>,
    pub intel: Arc<Mutex<ThreatIntelManager>>,
    pub dns_proxy: SecureDnsProxy,
    pub tor_manager: TorSecureModeManager,
    pub event_logs: VecDeque<NetDefenseEventLog>,
    pub correlation_events: VecDeque<ThreatCorrelationEvent>,
    pub learning_engine: ProgramLearningEngine,
    pub blocked_connections_count: u64,
    last_connections_cache: Vec<NetworkConnectionEntry>,
}

impl NetworkDefenseEngine {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let dir = data_dir.as_ref().join("netdefense");
        let _ = fs::create_dir_all(&dir);
        let state_file = dir.join("netdefense_state.json");

        let persisted: PersistedNetDefenseState = if state_file.exists() {
            fs::read_to_string(&state_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            PersistedNetDefenseState::default()
        };

        let mut app_policies = HashMap::new();
        for pol in persisted.app_policies {
            app_policies.insert(pol.executable_path.to_lowercase(), pol);
        }

        let intel = Arc::new(Mutex::new(ThreatIntelManager::new(&dir)));
        let dns_proxy = SecureDnsProxy::new(persisted.dns_config.clone(), Arc::clone(&intel));
        let tor_manager = TorSecureModeManager::new(persisted.tor_config.clone());
        let learning_engine = ProgramLearningEngine::new(&dir);
        let mut wfp = WfpController::new();
        let _ = wfp.initialize();

        let mut engine = Self {
            data_dir: dir,
            state_file,
            firewall_enabled: persisted.firewall_enabled,
            wfp,
            socket_monitor: SocketMonitor::new(),
            rules: persisted.rules,
            app_policies,
            intel,
            dns_proxy,
            tor_manager,
            event_logs: VecDeque::with_capacity(MAX_EVENT_LOGS),
            correlation_events: VecDeque::with_capacity(MAX_CORRELATION_EVENTS),
            learning_engine,
            blocked_connections_count: 0,
            last_connections_cache: Vec::new(),
        };

        // Restaurar reglas persistentes en WFP si el motor WFP está inicializado
        if engine.firewall_enabled && engine.wfp.status().initialized {
            engine.reapply_all_wfp_rules();
        }
        if engine.tor_manager.config.enabled {
            let _ = engine.tor_manager.sync_policies(&mut engine.wfp);
        }

        engine.log_event(
            "NetworkDefense",
            "INFO",
            "EngineInitialized",
            "SamuLibre Network Defense Engine iniciado",
            &format!(
                "WFP={} | Reglas={} | Políticas App={}",
                engine.wfp.status().initialized,
                engine.rules.len(),
                engine.app_policies.len()
            ),
        );

        engine
    }

    pub fn save_state(&self) -> Result<()> {
        let state = PersistedNetDefenseState {
            firewall_enabled: self.firewall_enabled,
            rules: self.rules.clone(),
            app_policies: self.app_policies.values().cloned().collect(),
            dns_config: self.dns_proxy.config.lock().unwrap().clone(),
            tor_config: self.tor_manager.config.clone(),
        };
        let json = serde_json::to_string_pretty(&state)?;
        fs::write(&self.state_file, json)?;
        Ok(())
    }

    pub fn log_event(
        &mut self,
        subsystem: &str,
        severity: &str,
        event_type: &str,
        summary: &str,
        details: &str,
    ) {
        if self.event_logs.len() >= MAX_EVENT_LOGS {
            self.event_logs.pop_back();
        }
        self.event_logs.push_front(NetDefenseEventLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            subsystem: subsystem.to_string(),
            severity: severity.to_string(),
            event_type: event_type.to_string(),
            summary: summary.to_string(),
            details: details.to_string(),
        });
    }

    /// Reaplica todas las reglas habilitadas y no expiradas en WFP.
    pub fn reapply_all_wfp_rules(&mut self) {
        let _ = self.wfp.clear_all_samulibre_filters();
        self.prune_expired_rules();

        for rule in &mut self.rules {
            rule.wfp_filter_ids.clear();
            if rule.enabled && self.firewall_enabled {
                if let Ok(ids) = self.wfp.apply_rule(rule) {
                    rule.wfp_filter_ids = ids;
                }
            }
        }
        let _ = self.save_state();
    }

    pub fn prune_expired_rules(&mut self) -> usize {
        let now = Utc::now();
        let before = self.rules.len();
        let mut to_remove_wfp = Vec::new();
        self.rules.retain(|r| {
            let keep = match (r.scope, r.expires_at) {
                (RuleScope::Temporary, Some(exp)) => exp > now,
                _ => true,
            };
            if !keep {
                to_remove_wfp.extend(r.wfp_filter_ids.iter().copied());
            }
            keep
        });
        if !to_remove_wfp.is_empty() {
            self.wfp.remove_filters(&to_remove_wfp);
        }
        before.saturating_sub(self.rules.len())
    }

    /// Añade una regla permanente o temporal, valida seguridad contra bloqueos esenciales, la aplica en WFP y cierra flujos TCP activos si es bloqueo.
    pub fn add_rule(&mut self, mut rule: FirewallRule) -> Result<FirewallRule> {
        self.learning_engine
            .validate_firewall_rule_safety(&rule)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        if rule.enabled && self.firewall_enabled && self.wfp.status().initialized {
            match self.wfp.apply_rule(&rule) {
                Ok(ids) => rule.wfp_filter_ids = ids,
                Err(e) => warn!("No se pudo aplicar filtro WFP para regla {}: {}", rule.name, e),
            }
            if rule.action == RuleAction::Block {
                let closed = self.socket_monitor.terminate_matching_connections(
                    rule.remote_ip.as_deref(),
                    rule.remote_port,
                    rule.app_path.as_deref(),
                );
                if closed > 0 {
                    info!("Regla '{}': cerradas {} conexión(es) TCP activas.", rule.name, closed);
                }
            }
        }
        self.rules.push(rule.clone());
        self.save_state()?;
        self.log_event(
            "Firewall",
            "INFO",
            "RuleAdded",
            &format!("Regla añadida: {}", rule.name),
            &format!("{:?} {:?} {:?}", rule.action, rule.direction, rule.protocol),
        );
        Ok(rule)
    }

    pub fn remove_rule(&mut self, rule_id: Uuid) -> Result<bool> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            let removed = self.rules.remove(pos);
            if !removed.wfp_filter_ids.is_empty() {
                self.wfp.remove_filters(&removed.wfp_filter_ids);
            }
            self.save_state()?;
            self.log_event(
                "Firewall",
                "INFO",
                "RuleRemoved",
                &format!("Regla eliminada: {}", removed.name),
                "",
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Registra o actualiza la política de confianza de una aplicación usando ruta completa + hash SHA-256.
    pub fn set_app_policy(
        &mut self,
        app_name: &str,
        exe_path: &str,
        trust_state: AppTrustState,
        notes: &str,
    ) -> Result<AppPolicy> {
        let sha = self
            .socket_monitor
            .get_executable_sha256(exe_path)
            .unwrap_or_default();

        let (allow_internet, allow_lan, allow_dns, tor_only) = match trust_state {
            AppTrustState::Trusted => (true, true, true, false),
            AppTrustState::Restricted => (false, true, true, false),
            AppTrustState::Ask => (true, true, true, false),
            AppTrustState::Blocked => (false, false, false, false),
            AppTrustState::TorOnly => (false, true, false, true),
            AppTrustState::ModifiedNeedsReeval => (false, false, false, false),
        };

        let policy = AppPolicy {
            id: Uuid::new_v4(),
            app_name: app_name.to_string(),
            executable_path: exe_path.to_string(),
            expected_sha256: sha.clone(),
            last_verified_sha256: sha,
            trust_state,
            allow_internet,
            allow_lan,
            allow_dns,
            tor_only,
            allowed_ports: Vec::new(),
            blocked_ports: Vec::new(),
            updated_at: Utc::now(),
            notes: notes.to_string(),
        };

        self.app_policies
            .insert(exe_path.to_lowercase(), policy.clone());

        // Si está bloqueada, crear/aplicar regla WFP de bloqueo
        if trust_state == AppTrustState::Blocked {
            let block_rule = FirewallRule {
                id: Uuid::new_v4(),
                name: format!("AppBlock_{}", app_name),
                app_path: Some(exe_path.to_string()),
                app_hash_sha256: if policy.expected_sha256.is_empty() {
                    None
                } else {
                    Some(policy.expected_sha256.clone())
                },
                remote_ip: None,
                remote_port: None,
                local_port: None,
                protocol: NetProtocol::Any,
                direction: TrafficDirection::Both,
                action: RuleAction::Block,
                scope: RuleScope::Permanent,
                expires_at: None,
                interface_alias: None,
                ipv4: true,
                ipv6: true,
                enabled: true,
                created_at: Utc::now(),
                hit_count: 0,
                wfp_filter_ids: Vec::new(),
                reason: format!("Política de aplicación: {:?} ({})", trust_state, notes),
            };
            let _ = self.add_rule(block_rule);
        }

        self.save_state()?;
        Ok(policy)
    }

    /// Verifica integridad SHA-256 de ejecutables con política registrada.
    /// Si el binario cambió en disco, marca `ModifiedNeedsReeval` para no confiar ciegamente por nombre.
    pub fn verify_app_policy_integrity(&mut self, exe_path: &str) -> Option<AppTrustState> {
        let key = exe_path.to_lowercase();
        let expected = self
            .app_policies
            .get(&key)
            .map(|p| (p.expected_sha256.clone(), p.trust_state))?;

        if expected.0.is_empty() {
            return Some(expected.1);
        }

        if let Some(current_sha) = self.socket_monitor.get_executable_sha256(exe_path) {
            if current_sha != expected.0 {
                if let Some(pol) = self.app_policies.get_mut(&key) {
                    pol.last_verified_sha256 = current_sha.clone();
                    pol.trust_state = AppTrustState::ModifiedNeedsReeval;
                    pol.allow_internet = false;
                    pol.updated_at = Utc::now();
                }
                self.log_event(
                    "AppControl",
                    "WARN",
                    "BinaryModified",
                    &format!("Binario modificado detectado: {}", exe_path),
                    "El hash SHA-256 cambió respecto a la política aprobada; requiere reevaluación.",
                );
                let _ = self.save_state();
                return Some(AppTrustState::ModifiedNeedsReeval);
            }
        }
        Some(expected.1)
    }

    /// Obtiene snapshot en vivo de conexiones enriquecidas con aprendizaje de programas y Risk Recommender.
    pub fn refresh_live_connections(&mut self) -> Vec<NetworkConnectionEntry> {
        self.prune_expired_rules();
        let mut conns = self.socket_monitor.snapshot_connections();

        // Alimentar el motor de aprendizaje de programas sin bloquear software esencial
        for conn in &conns {
            let sha = conn
                .app_path
                .as_deref()
                .and_then(|p| self.socket_monitor.get_executable_sha256(p))
                .unwrap_or_default();
            self.learning_engine.observe_connection(conn, &sha);
        }

        let intel_guard = self.intel.lock().ok();
        let intel_ref = intel_guard.as_deref();

        for conn in &mut conns {
            // 1. Verificar reglas por app o IP/puerto
            for rule in &self.rules {
                if !rule.enabled {
                    continue;
                }
                let app_match = match (&rule.app_path, &conn.app_path) {
                    (Some(rp), Some(cp)) => rp.eq_ignore_ascii_case(cp),
                    (None, _) => true,
                    _ => false,
                };
                let ip_match = rule
                    .remote_ip
                    .as_ref()
                    .map(|ip| ip == &conn.remote_addr)
                    .unwrap_or(true);
                let port_match = rule
                    .remote_port
                    .map(|p| p == conn.remote_port)
                    .unwrap_or(true);
                if app_match && ip_match && port_match {
                    conn.action_taken = match rule.action {
                        RuleAction::Allow => "Permitida (Regla)".to_string(),
                        RuleAction::Block => "Bloqueada (WFP/Regla)".to_string(),
                        RuleAction::TorOnly => "Solo Tor".to_string(),
                    };
                    break;
                }
            }

            // 2. Evaluar con Risk Recommender explicable
            let eval = RiskRecommender::evaluate(
                conn,
                intel_ref,
                &self.app_policies,
                &self.correlation_events,
                &self.learning_engine,
            );
            conn.recommendation = eval.recommendation;
            conn.risk_score = eval.total_risk_score;
            conn.primary_reason = eval.primary_reason.clone();
            conn.risk_factors = eval.factors;
            conn.suggested_action = eval.suggested_action;
            conn.is_risky = matches!(
                eval.recommendation,
                RiskRecommendation::RecommendedBlock | RiskRecommendation::Review
            );
            conn.risk_reason = Some(eval.primary_reason);
        }

        self.last_connections_cache = conns.clone();
        conns
    }

    /// Correlaciona una alerta del Antivirus con las conexiones activas y bloquea en WFP si corresponde.
    pub fn handle_av_threat_correlation(
        &mut self,
        pid: Option<u32>,
        process_name: &str,
        exe_path: Option<&str>,
        av_alert_title: &str,
        remote_target: &str,
    ) -> ThreatCorrelationEvent {
        let intel_match = self
            .intel
            .lock()
            .ok()
            .and_then(|i| i.check_ip(remote_target, 60).map(|ind| ind.source_name.clone()));

        let (event, maybe_rule, maybe_policy) = correlate_av_detection_with_network(
            pid,
            process_name,
            exe_path,
            av_alert_title,
            remote_target,
            intel_match.as_deref(),
        );

        if let Some(rule) = maybe_rule {
            let _ = self.add_rule(rule);
            self.blocked_connections_count += 1;
        }
        if let Some(pol) = maybe_policy {
            self.app_policies
                .insert(pol.executable_path.to_lowercase(), pol);
        }

        if self.correlation_events.len() >= MAX_CORRELATION_EVENTS {
            self.correlation_events.pop_back();
        }
        self.correlation_events.push_front(event.clone());
        self.log_event(
            "AV-Correlation",
            "CRITICAL",
            "AvNetworkContainment",
            &format!("Contención de red por detección AV: {}", process_name),
            &event.action_taken,
        );
        let _ = self.save_state();
        event
    }

    pub fn set_tor_secure_mode(&mut self, config: TorSecureModeConfig) -> TorSecureModeState {
        self.tor_manager.config = config;
        let state = self.tor_manager.sync_policies(&mut self.wfp);
        let _ = self.save_state();
        self.log_event(
            "TorSecureMode",
            if state.health == TorProtectionHealth::TorDownKillSwitchActive {
                "WARN"
            } else {
                "INFO"
            },
            "TorPolicyUpdated",
            &state.status_message,
            &format!("Filtros WFP aplicados: {}", state.wfp_filters_applied),
        );
        state
    }

    /// Genera el snapshot completo con estados reales del backend (nunca valores simulados) para la GUI.
    pub fn get_dashboard_snapshot(&mut self) -> NetDefenseDashboardSnapshot {
        let wfp_status = self.wfp.status();
        let dns_stats = self.dns_proxy.stats.lock().unwrap().clone();
        let tor_state = self.tor_manager.sync_policies(&mut self.wfp);

        let connected_apps: HashSet<String> = self
            .last_connections_cache
            .iter()
            .filter(|c| c.state == "ESTABLISHED")
            .map(|c| c.app_name.clone())
            .collect();

        let firewall_color = if !self.firewall_enabled {
            HealthColor::Red
        } else if wfp_status.initialized {
            HealthColor::Green
        } else {
            HealthColor::Yellow
        };

        let wfp_color = if !wfp_status.available {
            HealthColor::Gray
        } else if wfp_status.initialized && wfp_status.sublayer_registered {
            HealthColor::Green
        } else if wfp_status.last_error.is_some() {
            HealthColor::Yellow
        } else {
            HealthColor::Red
        };

        let dns_cfg = self.dns_proxy.config.lock().unwrap().clone();
        let dns_color = if !dns_cfg.enabled {
            HealthColor::Red
        } else if dns_stats.running {
            HealthColor::Green
        } else {
            HealthColor::Yellow
        };

        let tor_color = match tor_state.health {
            TorProtectionHealth::Protected => HealthColor::Green,
            TorProtectionHealth::Degraded => HealthColor::Yellow,
            TorProtectionHealth::TorDownKillSwitchActive => HealthColor::Red,
            TorProtectionHealth::Inactive => HealthColor::Gray,
        };

        let (feeds_count, total_indicators_count) = self
            .intel
            .lock()
            .map(|i| {
                (
                    i.store.feeds.len(),
                    i.store.domain_indicators.len() + i.store.ip_indicators.len(),
                )
            })
            .unwrap_or((0, 0));

        NetDefenseDashboardSnapshot {
            firewall_enabled: self.firewall_enabled,
            firewall_color,
            wfp_status,
            wfp_color,
            active_connections_count: self.last_connections_cache.len(),
            blocked_connections_count: self.blocked_connections_count,
            connected_apps_count: connected_apps.len(),
            blocked_domains_count: dns_stats.blocked_queries,
            threats_detected_count: self.correlation_events.len(),
            dns_stats,
            dns_color,
            tor_state,
            tor_color,
            rules_count: self.rules.len(),
            app_policies_count: self.app_policies.len(),
            feeds_count,
            total_indicators_count,
        }
    }

    /// Limpieza segura de filtros WFP al desinstalar o ejecutar recuperación de emergencia.
    pub fn emergency_cleanup(&mut self) -> Result<usize> {
        self.dns_proxy.stop();
        self.tor_manager.config.enabled = false;
        self.tor_manager.applied_filter_ids.clear();
        let removed = self.wfp.clear_all_samulibre_filters()?;
        info!("Limpieza WFP de emergencia completada ({} filtros removidos).", removed);
        Ok(removed)
    }
}
