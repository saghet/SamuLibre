use anyhow::Result;
use chrono::Utc;
use samulibre_patcher::VirtualPatcher;
use samulibre_scanner::MultiEngineScanner;
use samulibre_shield::EndpointShield;
use samulibre_types::{SuiteStatus, ThreatAlert};
use samulibre_vpn::VpnManager;
use samulibre_watcher::RealTimeWatcher;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub struct SamuLibreCore {
    pub patcher: Arc<Mutex<VirtualPatcher>>,
    pub shield: Arc<Mutex<EndpointShield>>,
    pub scanner: Arc<MultiEngineScanner>,
    pub vpn: Arc<Mutex<VpnManager>>,
    pub watcher: Arc<Mutex<RealTimeWatcher>>,
    alerts_history: Arc<Mutex<Vec<ThreatAlert>>>,
}

impl SamuLibreCore {
    pub fn new(canary_dir: impl AsRef<Path>, vpn_dir: impl AsRef<Path>, dry_run: bool) -> Self {
        let patcher = Arc::new(Mutex::new(VirtualPatcher::new(dry_run)));
        let shield = Arc::new(Mutex::new(EndpointShield::new(canary_dir)));
        let scanner = Arc::new(MultiEngineScanner::new());
        let vpn = Arc::new(Mutex::new(VpnManager::new(vpn_dir)));
        let watcher = Arc::new(Mutex::new(RealTimeWatcher::new(Arc::clone(&scanner), Path::new("data").join("quarantine"))));

        Self {
            patcher,
            shield,
            scanner,
            vpn,
            watcher,
            alerts_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Inicializa todos los subsistemas de protección
    pub fn initialize(&self) -> Result<()> {
        info!("Iniciando SamuLibre Core: Suite de Seguridad 100% Libre...");

        // 1. Desplegar trampas canario anti-ransomware
        if let Ok(mut shield) = self.shield.lock() {
            let count = shield.deploy_canaries()?;
            info!("Módulo Escudo: {} archivos trampa canario activos.", count);
        }

        // 2. Realizar escaneo inicial de vulnerabilidades y aplicar parchado virtual
        if let Ok(mut patcher) = self.patcher.lock() {
            let (unmitigated, active, native) = patcher.scan_and_evaluate(None);
            info!(
                "Módulo Parchado Virtual: {} vulnerabilidades abiertas, {} parches virtuales activos, {} corregidas nativamente.",
                unmitigated, active, native
            );
            if unmitigated > 0 {
                let applied = patcher.apply_virtual_patches()?;
                info!("Parchado Virtual: {} reglas de mitigación aplicadas.", applied);
            }
        }

        info!("SamuLibre Core inicializado exitosamente.");
        Ok(())
    }

    /// Ejecuta una ronda de inspección periódica en segundo plano
    pub fn execute_heartbeat(&self) -> Vec<ThreatAlert> {
        let mut new_alerts = Vec::new();

        // 1. Verificar integridad de canarios anti-ransomware
        if let Ok(shield) = self.shield.lock() {
            let canary_alerts = shield.check_canary_integrity();
            for alert in canary_alerts {
                warn!("[CRITICAL] Trampa de Ransomware activada: {}", alert.details);
                new_alerts.push(alert);
            }
        }

        // 2. Inspeccionar procesos activos en busca de ataques a LSASS
        if let Ok(mut shield) = self.shield.lock() {
            let lsass_alerts = shield.scan_processes_for_lsass_dumpers();
            for alert in lsass_alerts {
                warn!("[CRITICAL] Ataque de robo de credenciales neutralizado: {}", alert.details);
                new_alerts.push(alert);
            }

            // 3. Inspeccionar procesos buscando ladrones de cookies/tokens de navegador
            let stealer_alerts = shield.scan_processes_for_browser_token_stealers();
            for alert in stealer_alerts {
                warn!("[HIGH] Intento de robo de sesiones de navegador: {}", alert.details);
                new_alerts.push(alert);
            }
        }

        // 4. Verificar si el SO ya instaló KBs oficiales y retirar parches virtuales obsoletos
        if let Ok(mut patcher) = self.patcher.lock() {
            if let Ok(reverted) = patcher.check_and_deactivate_obsolete_patches(None) {
                if reverted > 0 {
                    info!("Parchado Virtual: {} reglas retiradas automáticamente por instalación nativa del SO.", reverted);
                }
            }
        }

        // Guardar en historial
        if let Ok(mut hist) = self.alerts_history.lock() {
            hist.extend(new_alerts.clone());
        }

        new_alerts
    }

    /// Obtiene el estado actual consolidado de la suite
    pub fn get_status(&self) -> SuiteStatus {
        let (active_vpatches, native_fixed) = if let Ok(patcher) = self.patcher.lock() {
            let mut active = 0;
            let mut native = 0;
            for r in patcher.get_rules() {
                match r.status {
                    samulibre_types::PatchStatus::VirtualPatchActive => active += 1,
                    samulibre_types::PatchStatus::NativePatchInstalled => native += 1,
                    _ => {}
                }
            }
            (active, native)
        } else {
            (0, 0)
        };

        let canaries = if let Ok(shield) = self.shield.lock() {
            shield.get_canary_count()
        } else {
            0
        };

        let alerts_count = if let Ok(hist) = self.alerts_history.lock() {
            hist.len() as u64
        } else {
            0
        };

        SuiteStatus {
            core_running: true,
            scanner_active: true,
            shield_active: true,
            virtual_patcher_active: true,
            vpn_active: false,
            active_virtual_patches_count: active_vpatches,
            native_repaired_cves_count: native_fixed,
            threats_blocked_total: alerts_count,
            canaries_deployed_count: canaries,
            last_scan_timestamp: Some(Utc::now()),
        }
    }

    pub fn get_alerts_history(&self) -> Vec<ThreatAlert> {
        if let Ok(hist) = self.alerts_history.lock() {
            hist.clone()
        } else {
            Vec::new()
        }
    }
}
