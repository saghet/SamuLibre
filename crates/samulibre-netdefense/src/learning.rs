use crate::protected_system::ProtectedSystemGuard;
use crate::types::{AppPolicy, AppTrustState, FirewallRule, NetProtocol, NetworkConnectionEntry, RuleAction};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearningEngineMode {
    ActiveLearning,
    Enforcing,
    ContinuousAudit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppBaselineCategory {
    CriticalSystem,
    HardwareOemService,
    DeveloperToolchain,
    VerifiedCommercialApp,
    LoopbackIpcOnly,
    StandardUserApp,
    UnverifiedOrSuspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineApprovalStatus {
    AutoApproved,
    UnderObservation,
    UserApproved,
    FlaggedSuspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservedNetworkProfile {
    pub protocols: HashSet<NetProtocol>,
    pub local_listening_ports: HashSet<u16>,
    pub remote_ports_contacted: HashSet<u16>,
    pub uses_loopback: bool,
    pub uses_lan: bool,
    pub uses_wan: bool,
    pub total_connections_observed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedAppRecord {
    pub app_name: String,
    pub executable_path: String,
    pub sha256: String,
    pub category: AppBaselineCategory,
    pub is_protected_system: bool,
    pub protection_reason: Option<String>,
    pub network_profile: ObservedNetworkProfile,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: BaselineApprovalStatus,
    pub suggested_policy: AppTrustState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedAppsDatabase {
    pub version: u32,
    pub mode: LearningEngineMode,
    pub learning_started_at: DateTime<Utc>,
    pub last_saved_at: DateTime<Utc>,
    pub total_connections_profiled: u64,
    pub apps: HashMap<String, LearnedAppRecord>,
}

impl Default for LearnedAppsDatabase {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            version: 1,
            mode: LearningEngineMode::ActiveLearning,
            learning_started_at: now,
            last_saved_at: now,
            total_connections_profiled: 0,
            apps: HashMap::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuleSafetyError {
    #[error("Protección activa: '{0}' es un binario crítico del sistema ({1}) y no puede bloquearse.")]
    ProtectedSystemBinaryBlocked(String, String),
    #[error("Protección activa: No se permite bloquear tráfico local Loopback IPC (127.0.0.1 / ::1).")]
    LoopbackBlockProhibited,
}

/// Motor de aprendizaje de comportamiento de programas para evitar bloquear software esencial del sistema o del usuario.
pub struct ProgramLearningEngine {
    db_path: PathBuf,
    pub db: LearnedAppsDatabase,
    dirty_observations: u64,
}

impl ProgramLearningEngine {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let db_path = data_dir.as_ref().join("learned_apps.json");
        let db = if db_path.exists() {
            fs::read_to_string(&db_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            LearnedAppsDatabase::default()
        };
        Self {
            db_path,
            db,
            dirty_observations: 0,
        }
    }

    pub fn save_database(&mut self) -> Result<()> {
        self.db.last_saved_at = Utc::now();
        let tmp_path = self.db_path.with_extension("tmp");
        let bak_path = self.db_path.with_extension("bak");
        let json = serde_json::to_string_pretty(&self.db)?;
        fs::write(&tmp_path, json)?;
        if self.db_path.exists() {
            let _ = fs::copy(&self.db_path, &bak_path);
        }
        fs::rename(&tmp_path, &self.db_path)?;
        self.dirty_observations = 0;
        Ok(())
    }

    pub fn observe_connection(&mut self, conn: &NetworkConnectionEntry, sha256: &str) {
        self.db.total_connections_profiled += 1;
        self.dirty_observations += 1;

        let exe_path = match &conn.app_path {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                if conn.pid == 4 || conn.app_name.eq_ignore_ascii_case("system") {
                    "C:\\Windows\\System32\\ntoskrnl.exe".to_string()
                } else {
                    return;
                }
            }
        };

        let key = exe_path.to_lowercase();
        let now = Utc::now();
        let is_loopback = ProtectedSystemGuard::is_loopback_ip(&conn.remote_addr);
        let is_private = ProtectedSystemGuard::is_private_or_local_ip(&conn.remote_addr);
        let is_lan = is_private && !is_loopback && conn.remote_addr != "0.0.0.0" && conn.remote_addr != "::";
        let is_wan = !is_private;

        let (is_protected, protection_reason) =
            ProtectedSystemGuard::evaluate_protection(Path::new(&exe_path), &conn.app_name);

        let name_lower = conn.app_name.to_lowercase();
        let category = if is_protected {
            AppBaselineCategory::CriticalSystem
        } else if ProtectedSystemGuard::is_oem_or_system_path(&key) {
            AppBaselineCategory::HardwareOemService
        } else if matches!(
            name_lower.as_str(),
            "cargo.exe" | "rustc.exe" | "git.exe" | "python.exe" | "node.exe" | "code.exe" | "antigravity.exe"
        ) {
            AppBaselineCategory::DeveloperToolchain
        } else if matches!(
            name_lower.as_str(),
            "chrome.exe" | "msedge.exe" | "firefox.exe" | "brave.exe" | "explorer.exe"
        ) {
            AppBaselineCategory::VerifiedCommercialApp
        } else if key.contains("\\temp\\") || key.contains("\\appdata\\local\\temp\\") {
            AppBaselineCategory::UnverifiedOrSuspicious
        } else if is_loopback && !is_wan {
            AppBaselineCategory::LoopbackIpcOnly
        } else {
            AppBaselineCategory::StandardUserApp
        };

        let proto = match conn.protocol.to_uppercase().as_str() {
            "TCP" => NetProtocol::Tcp,
            "UDP" => NetProtocol::Udp,
            _ => NetProtocol::Any,
        };

        let auto_safe = is_protected
            || matches!(
                category,
                AppBaselineCategory::HardwareOemService
                    | AppBaselineCategory::DeveloperToolchain
                    | AppBaselineCategory::VerifiedCommercialApp
                    | AppBaselineCategory::LoopbackIpcOnly
            );

        let entry = self.db.apps.entry(key).or_insert_with(|| LearnedAppRecord {
            app_name: conn.app_name.clone(),
            executable_path: exe_path.clone(),
            sha256: sha256.to_string(),
            category,
            is_protected_system: is_protected,
            protection_reason: protection_reason.clone(),
            network_profile: ObservedNetworkProfile::default(),
            first_seen: now,
            last_seen: now,
            status: if auto_safe {
                BaselineApprovalStatus::AutoApproved
            } else {
                BaselineApprovalStatus::UnderObservation
            },
            suggested_policy: if auto_safe {
                AppTrustState::Trusted
            } else {
                AppTrustState::Ask
            },
        });

        entry.last_seen = now;
        if !sha256.is_empty() && entry.sha256.is_empty() {
            entry.sha256 = sha256.to_string();
        }
        entry.network_profile.total_connections_observed += 1;
        entry.network_profile.protocols.insert(proto);
        if conn.local_port > 0 {
            entry.network_profile.local_listening_ports.insert(conn.local_port);
        }
        if conn.remote_port > 0 {
            entry.network_profile.remote_ports_contacted.insert(conn.remote_port);
        }
        if is_loopback {
            entry.network_profile.uses_loopback = true;
        }
        if is_lan {
            entry.network_profile.uses_lan = true;
        }
        if is_wan {
            entry.network_profile.uses_wan = true;
        }

        if self.dirty_observations >= 50 {
            let _ = self.save_database();
        }
    }

    /// Impide bloquear accidentalmente binarios críticos del sistema o tráfico Loopback IPC (127.0.0.1 / ::1).
    pub fn validate_firewall_rule_safety(&self, rule: &FirewallRule) -> std::result::Result<(), RuleSafetyError> {
        if rule.action != RuleAction::Block {
            return Ok(());
        }

        if let Some(ref remote_ip) = rule.remote_ip {
            if ProtectedSystemGuard::is_loopback_ip(remote_ip) {
                return Err(RuleSafetyError::LoopbackBlockProhibited);
            }
        }

        if let Some(ref app_path) = rule.app_path {
            let key = app_path.to_lowercase();
            let file_name = Path::new(app_path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default();

            if let Some(rec) = self.db.apps.get(&key) {
                if rec.is_protected_system {
                    return Err(RuleSafetyError::ProtectedSystemBinaryBlocked(
                        rec.app_name.clone(),
                        rec.protection_reason
                            .clone()
                            .unwrap_or_else(|| "Componente esencial del SO".to_string()),
                    ));
                }
            }

            let (is_prot, reason) = ProtectedSystemGuard::evaluate_protection(Path::new(app_path), file_name);
            if is_prot {
                return Err(RuleSafetyError::ProtectedSystemBinaryBlocked(
                    file_name.to_string(),
                    reason.unwrap_or_else(|| "Binario crítico del sistema".to_string()),
                ));
            }
        }

        Ok(())
    }

    pub fn is_learned_safe(&self, exe_path: &str) -> bool {
        self.db
            .apps
            .get(&exe_path.to_lowercase())
            .map(|r| {
                r.is_protected_system
                    || r.status == BaselineApprovalStatus::AutoApproved
                    || r.status == BaselineApprovalStatus::UserApproved
            })
            .unwrap_or(false)
    }

    pub fn consolidate_baseline_policies(&mut self) -> Vec<AppPolicy> {
        let now = Utc::now();
        let mut policies = Vec::new();
        for rec in self.db.apps.values_mut() {
            if rec.status == BaselineApprovalStatus::FlaggedSuspicious {
                continue;
            }
            let trust = match rec.category {
                AppBaselineCategory::UnverifiedOrSuspicious => AppTrustState::Ask,
                _ => AppTrustState::Trusted,
            };
            rec.status = BaselineApprovalStatus::AutoApproved;
            rec.suggested_policy = trust;
            policies.push(AppPolicy {
                id: Uuid::new_v4(),
                app_name: rec.app_name.clone(),
                executable_path: rec.executable_path.clone(),
                expected_sha256: rec.sha256.clone(),
                last_verified_sha256: rec.sha256.clone(),
                trust_state: trust,
                allow_internet: !matches!(rec.category, AppBaselineCategory::LoopbackIpcOnly),
                allow_lan: true,
                allow_dns: true,
                tor_only: false,
                allowed_ports: rec.network_profile.remote_ports_contacted.iter().copied().collect(),
                blocked_ports: Vec::new(),
                updated_at: now,
                notes: format!("Aprendida automáticamente ({:?})", rec.category),
            });
        }
        let _ = self.save_database();
        policies
    }
}
