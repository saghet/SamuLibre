pub mod anti_fp;
pub mod behavior_adapter;
pub mod db;
pub mod driver_intel;
pub mod feeds;
pub mod git_sync;
pub mod licensing;
pub mod models;
pub mod yara_engine;

pub use anti_fp::{
    AntiFalsePositiveEngine, FpEvaluationDecision, FpEvaluationInput, ThreatDecisionLevel,
};
pub use behavior_adapter::{
    BehaviorAdapterReport, BehaviorRuleAdapter, SamuBehaviorCategory, SamuBehaviorRule,
};
pub use db::IntelDatabase;
pub use driver_intel::{DriverAuditReport, DriverSecurityIntel, InstalledDriverFinding};
pub use feeds::{FeedConnectorConfig, FeedSyncReport, IntelKeysStatus, ThreatFeedConnectors};
pub use licensing::{
    IntelManifest, LicenseCompatibility, LicenseSummaryEntry, LicensingAndManifestManager,
    SbomInventory,
};
pub use git_sync::{GitRepoConfig, GitSyncReport, GitSyncService, YaraForgePackage};
pub use models::{
    CatalogEntryRow, CatalogPageResult, IndicatorHistoryEntry, IndicatorType, IntelSource,
    IntelStats, ThreatIndicatorRecord, ValidationStatus,
};
pub use yara_engine::{
    CompiledYaraRuntime, ParsedYaraRule, YaraMatchResult, YaraPromotionGate, YaraRuleValidator,
    YaraValidationReport,
};
