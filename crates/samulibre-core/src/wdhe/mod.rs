pub mod code_signing;
pub mod coexistence;
pub mod compatibility_audit;
pub mod compatibility_center;
pub mod fp_investigator;
pub mod performance_lab;
pub mod resilience_tests;
pub mod resource_governor;
pub mod safe_exclusions;
pub mod security_center;
pub mod security_validation;
pub mod smart_scan;

pub use code_signing::*;
pub use coexistence::*;
pub use compatibility_audit::*;
pub use compatibility_center::*;
pub use fp_investigator::*;
pub use performance_lab::*;
pub use resilience_tests::*;
pub use resource_governor::*;
pub use safe_exclusions::*;
pub use security_center::*;
pub use security_validation::*;
pub use smart_scan::*;

use anyhow::Result;
use samulibre_types::{
    CompatibilityAuditSummary, FpInvestigationRecord, SafeExclusionProposal,
    WdheBenchmarkScenario, WdheMode, WdheResourceProfile, WscAntivirusProduct,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Orquestador integral del Windows Defender Harmony Engine (WDHE)
pub struct WdheOrchestrator {
    pub engine: Arc<WdheEngine>,
    pub smart_scan: Arc<SmartScanCoordinator>,
    pub governor: Arc<SamuLibreResourceGovernor>,
    data_dir: PathBuf,
}

impl WdheOrchestrator {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let p = data_dir.as_ref().to_path_buf();
        let engine = Arc::new(WdheEngine::new(&p));
        let smart_scan = Arc::new(SmartScanCoordinator::new(&p));
        let governor = Arc::new(SamuLibreResourceGovernor::new());

        Self {
            engine,
            smart_scan,
            governor,
            data_dir: p,
        }
    }

    /// Ejecuta la auditoría completa de compatibilidad (Fase 1)
    pub fn run_compatibility_audit(&self) -> CompatibilityAuditSummary {
        CompatibilityAuditor::run_audit()
    }

    /// Investiga las alertas y eventos recientes de Microsoft Defender (Fase 2)
    pub fn investigate_recent_alerts(&self, max_events: usize) -> Vec<FpInvestigationRecord> {
        let events = FalsePositiveInvestigator::query_defender_events(max_events);
        events
            .iter()
            .map(FalsePositiveInvestigator::investigate_event)
            .collect()
    }

    /// Establece el modo de coexistencia (Fase 3)
    pub fn set_coexistence_mode(&self, mode: WdheMode) -> Result<()> {
        self.engine.set_mode(mode)
    }

    /// Asigna el perfil del Resource Governor (Fase 5)
    pub fn set_resource_profile(&self, profile: WdheResourceProfile) {
        self.governor.set_profile(profile);
        match profile {
            WdheResourceProfile::Silent => self.smart_scan.set_concurrency_limit(1),
            WdheResourceProfile::Balanced => self.smart_scan.set_concurrency_limit(3),
            WdheResourceProfile::Performance => self.smart_scan.set_concurrency_limit(6),
            WdheResourceProfile::DeepAnalysis => self.smart_scan.set_concurrency_limit(2),
        }
    }

    /// Evalúa una solicitud de exclusión segura (Fase 6)
    pub fn evaluate_exclusion(
        &self,
        target_path: &str,
        rule_type: &str,
        justification: &str,
        conflict_id: &str,
    ) -> Result<SafeExclusionProposal> {
        SafeExclusionManager::evaluate_exclusion_request(
            target_path,
            rule_type,
            justification,
            conflict_id,
        )
    }

    /// Genera el manifiesto de binarios oficiales (Fase 7)
    pub fn generate_binary_manifest(&self) -> OfficialBinaryManifest {
        CodeSigningManager::generate_official_manifest(Path::new("."))
    }

    /// Consulta los proveedores de Windows Security Center (Fase 8)
    pub fn query_wsc_providers(&self) -> Vec<WscAntivirusProduct> {
        WindowsSecurityCenterManager::query_registered_products()
    }

    /// Genera el dashboard del Compatibility Center (Fase 9)
    pub fn get_compatibility_dashboard(&self) -> CompatibilityCenterDashboard {
        let telemetry = self.governor.get_telemetry();
        let metrics = self.smart_scan.get_metrics();

        CompatibilityCenter::build_dashboard(
            self.engine.get_mode(),
            &telemetry,
            metrics.lock_conflicts_avoided,
            metrics.cache_hits,
            0,
        )
    }

    /// Ejecuta el laboratorio de evaluación comparativa de rendimiento (Fase 10)
    pub fn run_performance_benchmarks(&self) -> Vec<WdheBenchmarkScenario> {
        let bench_dir = self.data_dir.join("benchmark_temp");
        PerformanceLab::run_all_scenarios(bench_dir)
    }

    /// Ejecuta la validación de seguridad con EICAR (Fase 11)
    pub fn run_security_validation(&self) -> SecurityValidationTestResult {
        let test_sandbox = self.data_dir.join("security_test_sandbox");
        SecurityValidator::run_eicar_validation(test_sandbox)
    }

    /// Ejecuta las pruebas de resiliencia y recuperación (Fase 12)
    pub fn run_resilience_tests(&self) -> Vec<ResilienceSimulationResult> {
        ResilienceTester::run_resilience_suite()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wdhe_compatibility_audit() {
        let audit = CompatibilityAuditor::run_audit();
        assert_eq!(audit.total_components, 15);
        assert!(audit.compatible_count > 0);
        assert!(audit.confirmed_false_positives_count > 0);
    }

    #[test]
    fn test_wdhe_mode_transitions() {
        let temp_dir = std::env::temp_dir().join(format!("wdhe_test_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let engine = WdheEngine::new(&temp_dir);

        assert_eq!(engine.get_mode(), WdheMode::Complementary);
        assert!(engine.set_mode(WdheMode::Development).is_ok());
        assert_eq!(engine.get_mode(), WdheMode::Development);

        assert!(engine.set_mode(WdheMode::PrimaryAntivirus).is_ok());
        assert_eq!(engine.get_mode(), WdheMode::PrimaryAntivirus);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_safe_exclusions_rejection_rules() {
        // 1. Rechazo de unidad de disco completa
        let r1 = SafeExclusionManager::evaluate_exclusion_request("C:\\", "folder", "test", "C1");
        assert!(r1.is_err());

        // 2. Rechazo de Windows
        let r2 = SafeExclusionManager::evaluate_exclusion_request("C:\\Windows\\System32", "folder", "test", "C2");
        assert!(r2.is_err());

        // 3. Rechazo de comodín de extensión
        let r3 = SafeExclusionManager::evaluate_exclusion_request("*.exe", "extension", "test", "C3");
        assert!(r3.is_err());
    }

    #[test]
    fn test_wsc_product_state_decoding() {
        // Defender típico: 397568 = 0x061100
        let state = WindowsSecurityCenterManager::decode_product_state(397568);
        assert_eq!(state.raw_state_hex, "0x061100");
        assert!(state.is_enabled);
        assert!(state.is_up_to_date);

        // Trend Micro inactivo: 393216 = 0x060000
        let state_tm = WindowsSecurityCenterManager::decode_product_state(393216);
        assert_eq!(state_tm.raw_state_hex, "0x060000");
        assert!(!state_tm.is_enabled);
        assert!(state_tm.is_up_to_date);
    }

    #[test]
    fn test_resilience_suite_simulation() {
        let results = ResilienceTester::run_resilience_suite();
        assert_eq!(results.len(), 8);
        assert!(results.iter().all(|r| r.passed && r.system_protection_preserved));
    }
}
