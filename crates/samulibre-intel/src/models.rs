use serde::{Deserialize, Serialize};

/// Tipo de indicador almacenado en la Base Central de Inteligencia de SamuLibre
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Sha256,
    YaraRule,
    C2Ip,
    Domain,
    Url,
    BehaviorRule,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::YaraRule => "yara_rule",
            Self::C2Ip => "c2_ip",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::BehaviorRule => "behavior_rule",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sha256" => Some(Self::Sha256),
            "yara_rule" => Some(Self::YaraRule),
            "c2_ip" => Some(Self::C2Ip),
            "domain" => Some(Self::Domain),
            "url" => Some(Self::Url),
            "behavior_rule" => Some(Self::BehaviorRule),
            _ => None,
        }
    }
}

/// Estado de validación y ciclo de vida de una regla o indicador
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStatus {
    Laboratorio,
    Aprobada,
    AprobadaConRestricciones,
    EnObservacion,
    Rechazada,
    Obsoleta,
}

impl ValidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Laboratorio => "LABORATORIO",
            Self::Aprobada => "APROBADA",
            Self::AprobadaConRestricciones => "APROBADA_CON_RESTRICCIONES",
            Self::EnObservacion => "EN_OBSERVACION",
            Self::Rechazada => "RECHAZADA",
            Self::Obsoleta => "OBSOLETA",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "LABORATORIO" => Self::Laboratorio,
            "APROBADA" => Self::Aprobada,
            "APROBADA_CON_RESTRICCIONES" => Self::AprobadaConRestricciones,
            "EN_OBSERVACION" => Self::EnObservacion,
            "RECHAZADA" => Self::Rechazada,
            "OBSOLETA" => Self::Obsoleta,
            _ => Self::EnObservacion,
        }
    }

    pub fn is_production_active(&self) -> bool {
        matches!(self, Self::Aprobada | Self::AprobadaConRestricciones)
    }
}

/// Registro completo de un indicador o regla en la Base Central de Inteligencia
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicatorRecord {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub payload: String,
    pub content_hash: String,
    pub malware_family: String,
    pub threat_name: String,
    pub category: String,
    pub source_name: String,
    pub repo_origin: String,
    pub rule_author: String,
    pub license: String,
    pub source_url: String,
    pub first_seen: String,
    pub last_modified: String,
    pub expires_at: Option<String>,
    pub confidence: u8,
    pub validation_status: ValidationStatus,
    pub validation_score: u8,
    pub validation_notes: String,
    pub version: u32,
    pub external_vars: Vec<String>,
    pub required_modules: Vec<String>,
}

/// Entrada del historial de cambios de un indicador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorHistoryEntry {
    pub id: i64,
    pub indicator_id: String,
    pub action: String,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub old_status: Option<String>,
    pub new_status: Option<String>,
    pub changed_at: String,
    pub details: String,
}

/// Estado y métricas de una fuente de inteligencia (repositorio Git o API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSource {
    pub source_id: String,
    pub name: String,
    pub source_kind: String,
    pub url: String,
    pub last_sync_at: Option<String>,
    pub last_commit: Option<String>,
    pub status: String,
    pub received_count: usize,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub last_error: Option<String>,
    pub response_time_ms: u64,
    pub license_default: String,
}

/// Resumen estadístico real consultado directamente desde SQLite
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelStats {
    pub total_indicators: usize,
    pub sha256_approved: usize,
    pub yara_total: usize,
    pub yara_lab: usize,
    pub yara_approved: usize,
    pub yara_restricted: usize,
    pub yara_observation: usize,
    pub yara_rejected: usize,
    pub yara_obsolete: usize,
    pub c2_ips_approved: usize,
    pub domains_approved: usize,
    pub urls_approved: usize,
    pub behavior_rules_approved: usize,
    pub loldrivers_count: usize,
    pub connected_sources: usize,
}

/// Fila paginada de catálogo con metadatos de procedencia y licencia
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntryRow {
    pub kind: String,
    pub identifier: String,
    pub family: String,
    pub source: String,
    pub added_at: String,
    pub license: String,
    pub source_url: String,
    pub rule_author: String,
    pub validation_status: String,
    pub validation_score: u8,
}

/// Resultado paginado directo desde SQLite (sin truncamiento)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatalogPageResult {
    pub total_filtered: usize,
    pub entries: Vec<CatalogEntryRow>,
}
