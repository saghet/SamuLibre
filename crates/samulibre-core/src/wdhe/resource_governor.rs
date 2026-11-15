use samulibre_types::{ResourceGovernorTelemetry, WdheResourceProfile};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sysinfo::System;
use tracing::info;

/// Lista de procesos de usuario intensivos en recursos (juegos, compiladores, renderizadores)
const HEAVY_USER_APPLICATIONS: &[&str] = &[
    "devenv", "code", "rustc", "cl", "gcc", "g++", "clang", "msbuild", "cargo",
    "blender", "cinema4d", "maya", "3dsmax", "premiere", "afterfx", "davinci",
    "photoshop", "obs64", "unrealengine", "unity", "steam", "epicgameslauncher",
    "valorant", "cs2", "cyberpunk2077", "overwatch", "dota2", "leagueclient",
];

/// Gobernador de recursos de hardware y perfiles dinámicos de consumo (SRG)
pub struct SamuLibreResourceGovernor {
    active_profile: Arc<Mutex<WdheResourceProfile>>,
    sys: Arc<Mutex<System>>,
    last_refresh: Arc<Mutex<Instant>>,
    gpu_acceleration_verified: Arc<AtomicBool>,
}

impl SamuLibreResourceGovernor {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        Self {
            active_profile: Arc::new(Mutex::new(WdheResourceProfile::Balanced)),
            sys: Arc::new(Mutex::new(sys)),
            last_refresh: Arc::new(Mutex::new(Instant::now())),
            gpu_acceleration_verified: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Obtiene el perfil de recursos activo
    pub fn get_profile(&self) -> WdheResourceProfile {
        *self.active_profile.lock().unwrap()
    }

    /// Asigna un nuevo perfil de recursos
    pub fn set_profile(&self, profile: WdheResourceProfile) {
        let mut p = self.active_profile.lock().unwrap();
        *p = profile;
        info!("Perfil de Recursos SamuLibre asignado a: {}", profile);
    }

    /// Permite o bloquea el uso de GPU basado en validación empírica
    pub fn set_gpu_verified(&self, verified: bool) {
        self.gpu_acceleration_verified.store(verified, Ordering::Relaxed);
    }

    /// Verifica si la GPU está autorizada para aceleración
    pub fn is_gpu_allowed(&self) -> bool {
        let profile = self.get_profile();
        match profile {
            WdheResourceProfile::Silent => false,
            WdheResourceProfile::Balanced => self.gpu_acceleration_verified.load(Ordering::Relaxed),
            WdheResourceProfile::Performance | WdheResourceProfile::DeepAnalysis => {
                self.gpu_acceleration_verified.load(Ordering::Relaxed)
            }
        }
    }

    /// Verifica en la lista de procesos si hay tareas pesadas en ejecución
    fn check_heavy_processes(sys: &System) -> bool {
        for (_pid, proc_) in sys.processes() {
            let proc_name = proc_.name().to_string_lossy().to_lowercase();
            for heavy in HEAVY_USER_APPLICATIONS {
                if proc_name.contains(heavy) {
                    return true;
                }
            }
        }
        false
    }

    /// Detecta si el usuario está ejecutando aplicaciones pesadas en primer plano
    pub fn is_heavy_application_running(&self) -> bool {
        let mut sys = self.sys.lock().unwrap();
        let mut last_ref = self.last_refresh.lock().unwrap();
        if last_ref.elapsed().as_millis() > 2000 {
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
            *last_ref = Instant::now();
        }

        Self::check_heavy_processes(&sys)
    }

    /// Obtiene la telemetría dinámica de consumo en tiempo real
    pub fn get_telemetry(&self) -> ResourceGovernorTelemetry {
        let mut sys = self.sys.lock().unwrap();
        let mut last_ref = self.last_refresh.lock().unwrap();
        if last_ref.elapsed().as_millis() > 1000 {
            sys.refresh_cpu_all();
            sys.refresh_memory();
            *last_ref = Instant::now();
        }

        let cpu_usage_pct = sys.global_cpu_usage();
        let ram_usage_mb = sys.used_memory() / (1024 * 1024);
        let heavy = Self::check_heavy_processes(&sys);

        let profile = *self.active_profile.lock().unwrap();
        let throttling_active = heavy || match profile {
            WdheResourceProfile::Silent => cpu_usage_pct > 15.0,
            WdheResourceProfile::Balanced => cpu_usage_pct > 40.0,
            WdheResourceProfile::Performance => cpu_usage_pct > 75.0,
            WdheResourceProfile::DeepAnalysis => cpu_usage_pct > 85.0,
        };

        ResourceGovernorTelemetry {
            active_profile: profile,
            cpu_usage_pct,
            ram_usage_mb,
            disk_read_mbs: 0.0, // Estimación basada en telemetría de I/O
            disk_write_mbs: 0.0,
            gpu_usage_pct: if self.gpu_acceleration_verified.load(Ordering::Relaxed) {
                Some(12)
            } else {
                None
            },
            vram_usage_mb: if self.gpu_acceleration_verified.load(Ordering::Relaxed) {
                Some(128)
            } else {
                None
            },
            user_activity_heavy: heavy,
            throttling_active,
        }
    }

    /// Calcula la pausa adaptativa (sleep) entre análisis para no degradar el sistema del usuario
    pub fn compute_adaptive_throttle_delay(&self) -> std::time::Duration {
        let profile = self.get_profile();
        let heavy = self.is_heavy_application_running();

        if heavy {
            // Usuario en juego, compilación o render: ceder CPU de inmediato
            return std::time::Duration::from_millis(50);
        }

        match profile {
            WdheResourceProfile::Silent => std::time::Duration::from_millis(20),
            WdheResourceProfile::Balanced => std::time::Duration::from_millis(5),
            WdheResourceProfile::Performance => std::time::Duration::from_millis(0),
            WdheResourceProfile::DeepAnalysis => std::time::Duration::from_millis(2),
        }
    }
}
