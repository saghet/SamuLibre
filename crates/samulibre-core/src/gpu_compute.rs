//! SHCE GPU Compute Backend — Direct3D 11 Compute Shaders (CS 5.0) reales.
//!
//! Enumera TODOS los adaptadores DXGI de hardware (iGPU AMD Radeon 780M, dGPU NVIDIA RTX 4060, Intel…),
//! crea un dispositivo D3D11 por adaptador, compila en tiempo de ejecución un compute shader de
//! histogramas de bytes por lotes (groupshared + InterlockedAdd) y despacha trabajo real a la GPU.
//! El trabajo se ejecuta en la cola gráfica (motor "3D" / "Compute" en el Administrador de tareas).
//!
//! Seguridad operativa:
//! - Si un dispositivo falla (DXGI_ERROR_DEVICE_REMOVED, TDR, etc.) se desactiva y se cae a CPU.
//! - Respeta el límite de utilización de GPU (duty-cycle: tiempo GPU / (tiempo GPU + reposo)).
//! - Cada adaptador está protegido por su propio Mutex (el immediate context no es thread-safe).

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Preferencia de adaptador seleccionada por el usuario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuPreference {
    /// Reparte la carga entre todas las GPUs (dGPU primero, iGPU cuando la dGPU está ocupada).
    HybridAuto = 0,
    /// Solo la GPU dedicada (alto rendimiento).
    Dedicated = 1,
    /// Solo la GPU integrada (bajo consumo).
    Integrated = 2,
    /// Sin GPU.
    CpuOnly = 3,
}

impl GpuPreference {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Dedicated,
            2 => Self::Integrated,
            3 => Self::CpuOnly,
            _ => Self::HybridAuto,
        }
    }
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" | "hybrid" | "hybridauto" | "hibrido" => Some(Self::HybridAuto),
            "dedicated" | "dgpu" | "dedicada" | "nvidia" => Some(Self::Dedicated),
            "integrated" | "igpu" | "integrada" => Some(Self::Integrated),
            "cpu" | "cpuonly" | "none" => Some(Self::CpuOnly),
            _ => None,
        }
    }
    pub fn as_key(&self) -> &'static str {
        match self {
            Self::HybridAuto => "auto",
            Self::Dedicated => "dedicated",
            Self::Integrated => "integrated",
            Self::CpuOnly => "cpu",
        }
    }
}

/// Telemetría en vivo por adaptador (serializable para la GUI / CLI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAdapterStats {
    pub index: u32,
    pub name: String,
    pub vendor_id: u32,
    pub dedicated_vram_mb: u64,
    pub shared_mem_mb: u64,
    pub is_integrated: bool,
    pub ready: bool,
    pub last_error: Option<String>,
    pub dispatches: u64,
    pub bytes_processed: u64,
    pub gpu_busy_ms: u64,
}

/// Estado global del pool GPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuPoolStatus {
    pub available: bool,
    pub preference: GpuPreference,
    pub utilization_limit_pct: u8,
    pub init_error: Option<String>,
    pub adapters: Vec<GpuAdapterStats>,
}

struct Worker {
    index: u32,
    name: String,
    vendor_id: u32,
    dedicated_mb: u64,
    shared_mb: u64,
    is_integrated: bool,
    disabled: AtomicBool,
    last_error: Mutex<Option<String>>,
    dispatches: AtomicU64,
    bytes: AtomicU64,
    busy_us: AtomicU64,
    #[cfg(windows)]
    device: Mutex<Option<imp::D3dCompute>>,
}

pub struct GpuComputePool {
    workers: Vec<Worker>,
    rr: AtomicUsize,
    init_error: Option<String>,
}

static POOL: OnceLock<GpuComputePool> = OnceLock::new();
static PREF: AtomicU8 = AtomicU8::new(GpuPreference::HybridAuto as u8);
static LIMIT: AtomicU8 = AtomicU8::new(75);

impl GpuComputePool {
    /// Pool global (inicialización perezosa: enumeración DXGI + compilación del shader por adaptador).
    pub fn global() -> &'static GpuComputePool {
        POOL.get_or_init(Self::init)
    }

    /// Indica si el pool ya fue inicializado (evita inicializarlo solo para consultar estado).
    pub fn is_initialized() -> bool {
        POOL.get().is_some()
    }

    #[cfg(windows)]
    fn init() -> Self {
        let mut workers = Vec::new();
        let mut init_error = None;
        match imp::enumerate_and_create() {
            Ok(list) => {
                for (info, dev) in list {
                    let ready = dev.is_ok();
                    let err = dev.as_ref().err().cloned();
                    if let Some(e) = &err {
                        tracing::warn!("[SHCE/GPU] Adaptador {} ({}) no disponible: {}", info.index, info.name, e);
                    } else {
                        tracing::info!(
                            "[SHCE/GPU] Adaptador {} listo: {} ({} MB VRAM dedicada, {})",
                            info.index,
                            info.name,
                            info.dedicated_mb,
                            if info.is_integrated { "iGPU" } else { "dGPU" }
                        );
                    }
                    workers.push(Worker {
                        index: info.index,
                        name: info.name,
                        vendor_id: info.vendor_id,
                        dedicated_mb: info.dedicated_mb,
                        shared_mb: info.shared_mb,
                        is_integrated: info.is_integrated,
                        disabled: AtomicBool::new(!ready),
                        last_error: Mutex::new(err),
                        dispatches: AtomicU64::new(0),
                        bytes: AtomicU64::new(0),
                        busy_us: AtomicU64::new(0),
                        device: Mutex::new(dev.ok()),
                    });
                }
            }
            Err(e) => {
                tracing::warn!("[SHCE/GPU] No se pudo enumerar adaptadores DXGI: {}", e);
                init_error = Some(e);
            }
        }
        Self {
            workers,
            rr: AtomicUsize::new(0),
            init_error,
        }
    }

    #[cfg(not(windows))]
    fn init() -> Self {
        Self {
            workers: Vec::new(),
            rr: AtomicUsize::new(0),
            init_error: Some("Backend Direct3D 11 solo disponible en Windows".to_string()),
        }
    }

    pub fn set_preference_global(pref: GpuPreference) {
        PREF.store(pref as u8, Ordering::SeqCst);
    }

    pub fn set_utilization_limit_global(pct: u8) {
        LIMIT.store(pct.clamp(10, 100), Ordering::SeqCst);
    }

    pub fn preference_global() -> GpuPreference {
        GpuPreference::from_u8(PREF.load(Ordering::SeqCst))
    }

    pub fn set_preference(&self, pref: GpuPreference) {
        PREF.store(pref as u8, Ordering::SeqCst);
    }

    pub fn preference(&self) -> GpuPreference {
        GpuPreference::from_u8(PREF.load(Ordering::SeqCst))
    }

    pub fn set_utilization_limit(&self, pct: u8) {
        LIMIT.store(pct.clamp(10, 100), Ordering::SeqCst);
    }

    /// ¿Existe al menos un adaptador operativo compatible con la preferencia actual?
    pub fn is_available(&self) -> bool {
        !self.eligible().is_empty()
    }

    fn eligible(&self) -> Vec<&Worker> {
        let pref = self.preference();
        if pref == GpuPreference::CpuOnly {
            return Vec::new();
        }
        let mut v: Vec<&Worker> = self
            .workers
            .iter()
            .filter(|w| !w.disabled.load(Ordering::Relaxed))
            .filter(|w| match pref {
                GpuPreference::Dedicated => !w.is_integrated,
                GpuPreference::Integrated => w.is_integrated,
                _ => true,
            })
            .collect();
        // Si se pidió una clase concreta y no existe, no forzamos otra (respeto a la elección del usuario).
        // En modo híbrido: dGPU primero.
        v.sort_by_key(|w| w.is_integrated);
        v
    }

    #[cfg(windows)]
    fn dispatch_on_worker(&self, w: &Worker, segments: &[&[u8]]) -> Option<Vec<[u32; 256]>> {
        if segments.is_empty() {
            return Some(Vec::new());
        }
        let mut guard = w.device.lock().ok()?;
        let dev = guard.as_mut()?;
        let t0 = std::time::Instant::now();
        let res = dev.histograms(segments);
        let elapsed = t0.elapsed();
        match res {
            Ok(h) => {
                drop(guard); // Liberar el mutex antes del reposo para no bloquear otros hilos
                let total: usize = segments.iter().map(|s| s.len()).sum();
                w.dispatches.fetch_add(1, Ordering::Relaxed);
                w.bytes.fetch_add(total as u64, Ordering::Relaxed);
                w.busy_us.fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
                // Duty-cycle: limitar la utilización de GPU al porcentaje configurado (por defecto 75%).
                let limit = LIMIT.load(Ordering::Relaxed).clamp(10, 100) as u32;
                if limit < 100 && elapsed >= std::time::Duration::from_millis(4) {
                    let rest = elapsed * (100 - limit) / limit;
                    if rest > std::time::Duration::from_micros(250) {
                        std::thread::sleep(rest.min(std::time::Duration::from_millis(2)));
                    }
                }
                Some(h)
            }
            Err(e) => {
                tracing::warn!("[SHCE/GPU] Fallo en adaptador {} ({}): {}. Fallback a CPU.", w.index, w.name, e);
                w.disabled.store(true, Ordering::SeqCst);
                if let Ok(mut le) = w.last_error.lock() {
                    *le = Some(e);
                }
                *guard = None;
                None
            }
        }
    }

    /// Calcula histogramas de bytes de múltiples segmentos en la(s) GPU(s).
    /// En modo `HybridAuto` con 2+ GPUs, divide el lote y despacha en paralelo a todas las GPUs activas.
    /// Devuelve `None` si no hay GPU elegible o si el despacho falla (→ fallback CPU).
    pub fn histograms(&self, segments: &[&[u8]]) -> Option<Vec<[u32; 256]>> {
        #[cfg(windows)]
        {
            let workers = self.eligible();
            if workers.is_empty() || segments.is_empty() {
                return None;
            }
            let total_bytes: usize = segments.iter().map(|s| s.len()).sum();

            // Modo Dual-GPU / Multi-GPU paralelo: dividir segmentos ponderando dGPU (60%) vs iGPU (40%)
            if self.preference() == GpuPreference::HybridAuto
                && workers.len() >= 2
                && segments.len() >= 2
                && total_bytes >= 32 * 1024
            {
                let weights: Vec<usize> = workers
                    .iter()
                    .map(|w| if w.is_integrated { 2 } else { 3 })
                    .collect();
                let weight_sum: usize = weights.iter().sum();

                let mut slices: Vec<(&Worker, &[&[u8]])> = Vec::with_capacity(workers.len());
                let mut offset = 0usize;
                for (idx, w) in workers.iter().enumerate() {
                    if offset >= segments.len() {
                        break;
                    }
                    let count = if idx + 1 == workers.len() {
                        segments.len() - offset
                    } else {
                        ((segments.len() * weights[idx]) / weight_sum).max(1).min(segments.len() - offset)
                    };
                    if count > 0 {
                        slices.push((w, &segments[offset..offset + count]));
                        offset += count;
                    }
                }

                if slices.len() >= 2 {
                    let results: Vec<Option<Vec<[u32; 256]>>> = std::thread::scope(|s| {
                        let handles: Vec<_> = slices
                            .iter()
                            .map(|(w, seg_slice)| {
                                s.spawn(move || self.dispatch_on_worker(w, seg_slice))
                            })
                            .collect();
                        handles.into_iter().map(|h| h.join().ok().flatten()).collect()
                    });

                    let mut merged = Vec::with_capacity(segments.len());
                    for (res_opt, (_, seg_slice)) in results.into_iter().zip(slices.iter()) {
                        if let Some(part) = res_opt {
                            merged.extend(part);
                        } else {
                            // Si un adaptador falló en paralelo, reintentar ese trozo en el primer adaptador sano o CPU
                            let fallback_worker = workers
                                .iter()
                                .find(|w| !w.disabled.load(Ordering::Relaxed));
                            if let Some(fw) = fallback_worker.and_then(|w| self.dispatch_on_worker(w, seg_slice)) {
                                merged.extend(fw);
                            } else {
                                for seg in *seg_slice {
                                    let mut c = [0u32; 256];
                                    for &b in seg.iter() {
                                        c[b as usize] += 1;
                                    }
                                    merged.push(c);
                                }
                            }
                        }
                    }
                    return Some(merged);
                }
            }

            // Camino de un solo adaptador (Dedicated, Integrated o lote pequeño): elegir libre o rotar
            let start = self.rr.fetch_add(1, Ordering::Relaxed);
            let n = workers.len();
            let chosen = workers
                .iter()
                .enumerate()
                .find_map(|(k, _)| {
                    let w = workers[(start + k) % n];
                    w.device.try_lock().ok().map(|guard| {
                        drop(guard);
                        w
                    })
                })
                .unwrap_or(workers[start % n]);

            self.dispatch_on_worker(chosen, segments)
        }
        #[cfg(not(windows))]
        {
            let _ = segments;
            None
        }
    }

    /// Reintenta reactivar adaptadores deshabilitados por error (recrea el dispositivo D3D11).
    pub fn reset_failed_adapters(&self) {
        #[cfg(windows)]
        for w in &self.workers {
            if w.disabled.load(Ordering::SeqCst) {
                if let Ok(dev) = imp::create_for_index(w.index) {
                    if let Ok(mut g) = w.device.lock() {
                        *g = Some(dev);
                        w.disabled.store(false, Ordering::SeqCst);
                        if let Ok(mut le) = w.last_error.lock() {
                            *le = None;
                        }
                    }
                }
            }
        }
    }

    pub fn status(&self) -> GpuPoolStatus {
        GpuPoolStatus {
            available: self.is_available(),
            preference: self.preference(),
            utilization_limit_pct: LIMIT.load(Ordering::Relaxed),
            init_error: self.init_error.clone(),
            adapters: self
                .workers
                .iter()
                .map(|w| GpuAdapterStats {
                    index: w.index,
                    name: w.name.clone(),
                    vendor_id: w.vendor_id,
                    dedicated_vram_mb: w.dedicated_mb,
                    shared_mem_mb: w.shared_mb,
                    is_integrated: w.is_integrated,
                    ready: !w.disabled.load(Ordering::Relaxed),
                    last_error: w.last_error.lock().ok().and_then(|e| e.clone()),
                    dispatches: w.dispatches.load(Ordering::Relaxed),
                    bytes_processed: w.bytes.load(Ordering::Relaxed),
                    gpu_busy_ms: w.busy_us.load(Ordering::Relaxed) / 1000,
                })
                .collect(),
        }
    }
}

#[cfg(windows)]
mod imp {
    use windows::core::{s, Interface, PCSTR};
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Direct3D::Fxc::{D3DCompile, D3DCOMPILE_OPTIMIZATION_LEVEL3};
    use windows::Win32::Graphics::Direct3D::{
        ID3DBlob, D3D11_SRV_DIMENSION_BUFFEREX, D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL,
        D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
    };
    use windows::Win32::Graphics::Direct3D11::*;
    use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_R32_TYPELESS;
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, IDXGIAdapter, IDXGIAdapter1, IDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE,
    };

    const HLSL: &str = r#"
cbuffer Params : register(b0) { uint g_GroupsX; uint g_SegCount; uint2 g_Pad; };
ByteAddressBuffer   g_Data : register(t0);
ByteAddressBuffer   g_Seg  : register(t1);
RWByteAddressBuffer g_Hist : register(u0);
groupshared uint s_hist[256];

[numthreads(256, 1, 1)]
void CSMain(uint3 gid : SV_GroupID, uint gi : SV_GroupIndex)
{
    s_hist[gi] = 0;
    GroupMemoryBarrierWithGroupSync();

    uint2 seg = g_Seg.Load2(gid.y * 8);
    uint words = (seg.y + 3) >> 2;
    uint stride = 256 * g_GroupsX;
    for (uint w = gid.x * 256 + gi; w < words; w += stride)
    {
        uint v = g_Data.Load(seg.x + (w << 2));
        uint rem = seg.y - (w << 2);
        InterlockedAdd(s_hist[v & 0xFF], 1);
        if (rem > 1) InterlockedAdd(s_hist[(v >> 8) & 0xFF], 1);
        if (rem > 2) InterlockedAdd(s_hist[(v >> 16) & 0xFF], 1);
        if (rem > 3) InterlockedAdd(s_hist[(v >> 24) & 0xFF], 1);
    }
    GroupMemoryBarrierWithGroupSync();

    uint c = s_hist[gi];
    if (c != 0) g_Hist.InterlockedAdd((gid.y * 256 + gi) * 4, c);
}
"#;

    pub struct AdapterInfo {
        pub index: u32,
        pub name: String,
        pub vendor_id: u32,
        pub dedicated_mb: u64,
        pub shared_mb: u64,
        pub is_integrated: bool,
    }

    struct RawBuf {
        buf: ID3D11Buffer,
        view: Option<ID3D11ShaderResourceView>,
        capacity: u32,
    }

    struct HistBuf {
        buf: ID3D11Buffer,
        uav: ID3D11UnorderedAccessView,
        staging: ID3D11Buffer,
        capacity: u32,
    }

    pub struct D3dCompute {
        device: ID3D11Device,
        ctx: ID3D11DeviceContext,
        shader: ID3D11ComputeShader,
        cbuf: ID3D11Buffer,
        data: Option<RawBuf>,
        segs: Option<RawBuf>,
        hist: Option<HistBuf>,
    }

    // SAFETY: ID3D11Device es free-threaded; el immediate context se usa exclusivamente bajo el Mutex del Worker.
    unsafe impl Send for D3dCompute {}

    fn hr<T>(r: windows::core::Result<T>, what: &str) -> Result<T, String> {
        r.map_err(|e| format!("{}: {}", what, e))
    }

    fn adapter_info(index: u32, a: &IDXGIAdapter1) -> Option<(AdapterInfo, bool)> {
        let d = unsafe { a.GetDesc1() }.ok()?;
        let len = d.Description.iter().position(|&c| c == 0).unwrap_or(d.Description.len());
        let name = String::from_utf16_lossy(&d.Description[..len]).trim().to_string();
        let software = (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0
            || d.VendorId == 0x1414; // Microsoft Basic Render Driver
        let dedicated_mb = (d.DedicatedVideoMemory as u64) / (1024 * 1024);
        let shared_mb = (d.SharedSystemMemory as u64) / (1024 * 1024);
        // Intel siempre integrado salvo Arc; AMD/NVIDIA: integrada si VRAM dedicada < 2 GB (APU / UMA).
        let lname = name.to_lowercase();
        let is_integrated = if d.VendorId == 0x8086 {
            !lname.contains("arc")
        } else {
            dedicated_mb < 2048
        };
        Some((
            AdapterInfo { index, name, vendor_id: d.VendorId, dedicated_mb, shared_mb, is_integrated },
            software,
        ))
    }

    pub fn enumerate_and_create() -> Result<Vec<(AdapterInfo, Result<D3dCompute, String>)>, String> {
        let factory: IDXGIFactory1 = hr(unsafe { CreateDXGIFactory1() }, "CreateDXGIFactory1")?;
        let mut out = Vec::new();
        let mut i = 0u32;
        while let Ok(adapter) = unsafe { factory.EnumAdapters1(i) } {
            if let Some((info, software)) = adapter_info(i, &adapter) {
                if !software {
                    let dev = D3dCompute::new(&adapter);
                    out.push((info, dev));
                }
            }
            i += 1;
        }
        Ok(out)
    }

    pub fn create_for_index(index: u32) -> Result<D3dCompute, String> {
        let factory: IDXGIFactory1 = hr(unsafe { CreateDXGIFactory1() }, "CreateDXGIFactory1")?;
        let adapter = hr(unsafe { factory.EnumAdapters1(index) }, "EnumAdapters1")?;
        D3dCompute::new(&adapter)
    }

    fn compile_shader() -> Result<Vec<u8>, String> {
        let mut code: Option<ID3DBlob> = None;
        let mut errs: Option<ID3DBlob> = None;
        let r = unsafe {
            D3DCompile(
                HLSL.as_ptr() as *const _,
                HLSL.len(),
                s!("shce_histogram.hlsl"),
                None,
                None,
                s!("CSMain"),
                s!("cs_5_0"),
                D3DCOMPILE_OPTIMIZATION_LEVEL3,
                0,
                &mut code,
                Some(&mut errs),
            )
        };
        if let Err(e) = r {
            let msg = errs
                .map(|b| unsafe {
                    let p = b.GetBufferPointer() as *const u8;
                    String::from_utf8_lossy(std::slice::from_raw_parts(p, b.GetBufferSize())).to_string()
                })
                .unwrap_or_default();
            return Err(format!("D3DCompile: {} {}", e, msg));
        }
        let blob = code.ok_or("D3DCompile sin bytecode")?;
        Ok(unsafe { std::slice::from_raw_parts(blob.GetBufferPointer() as *const u8, blob.GetBufferSize()).to_vec() })
    }

    impl D3dCompute {
        fn new(adapter: &IDXGIAdapter1) -> Result<Self, String> {
            let base: IDXGIAdapter = hr(adapter.cast(), "cast IDXGIAdapter")?;
            let levels: [D3D_FEATURE_LEVEL; 2] = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
            let mut device: Option<ID3D11Device> = None;
            let mut ctx: Option<ID3D11DeviceContext> = None;
            hr(
                unsafe {
                    D3D11CreateDevice(
                        &base,
                        D3D_DRIVER_TYPE_UNKNOWN,
                        HMODULE::default(),
                        D3D11_CREATE_DEVICE_FLAG(0),
                        Some(&levels),
                        D3D11_SDK_VERSION,
                        Some(&mut device),
                        None,
                        Some(&mut ctx),
                    )
                },
                "D3D11CreateDevice",
            )?;
            let device = device.ok_or("D3D11CreateDevice sin dispositivo")?;
            let ctx = ctx.ok_or("D3D11CreateDevice sin contexto")?;

            let bytecode = compile_shader()?;
            let mut shader: Option<ID3D11ComputeShader> = None;
            hr(unsafe { device.CreateComputeShader(&bytecode, None, Some(&mut shader)) }, "CreateComputeShader")?;
            let shader = shader.ok_or("CreateComputeShader nulo")?;

            let cdesc = D3D11_BUFFER_DESC {
                ByteWidth: 16,
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_CONSTANT_BUFFER.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
                StructureByteStride: 0,
            };
            let mut cbuf: Option<ID3D11Buffer> = None;
            hr(unsafe { device.CreateBuffer(&cdesc, None, Some(&mut cbuf)) }, "CreateBuffer(cb)")?;

            let mut me = Self {
                device,
                ctx,
                shader,
                cbuf: cbuf.ok_or("cbuffer nulo")?,
                data: None,
                segs: None,
                hist: None,
            };
            // Autoverificación de paridad GPU vs CPU antes de habilitar el adaptador.
            let sample: Vec<u8> = (0..70_001u32).map(|i| ((i.wrapping_mul(2654435761)) >> 13) as u8).collect();
            let segs: Vec<&[u8]> = vec![&sample[..], &sample[3..1027], &sample[5000..5001]];
            let got = me.histograms(&segs)?;
            for (s, h) in segs.iter().zip(got.iter()) {
                let mut c = [0u32; 256];
                for &b in s.iter() {
                    c[b as usize] += 1;
                }
                if &c != h {
                    return Err("Paridad GPU/CPU fallida en autoverificación".to_string());
                }
            }
            Ok(me)
        }

        fn ensure_raw(&self, slot: &mut Option<RawBuf>, needed: u32) -> Result<(), String> {
            if slot.as_ref().map(|b| b.capacity >= needed).unwrap_or(false) {
                return Ok(());
            }
            let cap = needed.next_power_of_two().max(64 * 1024);
            let desc = D3D11_BUFFER_DESC {
                ByteWidth: cap,
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS.0 as u32,
                StructureByteStride: 0,
            };
            let mut buf: Option<ID3D11Buffer> = None;
            hr(unsafe { self.device.CreateBuffer(&desc, None, Some(&mut buf)) }, "CreateBuffer(raw)")?;
            let buf = buf.ok_or("raw buffer nulo")?;
            let vdesc = D3D11_SHADER_RESOURCE_VIEW_DESC {
                Format: DXGI_FORMAT_R32_TYPELESS,
                ViewDimension: D3D11_SRV_DIMENSION_BUFFEREX,
                Anonymous: D3D11_SHADER_RESOURCE_VIEW_DESC_0 {
                    BufferEx: D3D11_BUFFEREX_SRV {
                        FirstElement: 0,
                        NumElements: cap / 4,
                        Flags: D3D11_BUFFEREX_SRV_FLAG_RAW.0 as u32,
                    },
                },
            };
            let mut view: Option<ID3D11ShaderResourceView> = None;
            hr(unsafe { self.device.CreateShaderResourceView(&buf, Some(&vdesc), Some(&mut view)) }, "CreateSRV")?;
            *slot = Some(RawBuf { buf, view, capacity: cap });
            Ok(())
        }

        fn ensure_hist(&mut self, needed: u32) -> Result<(), String> {
            if self.hist.as_ref().map(|b| b.capacity >= needed).unwrap_or(false) {
                return Ok(());
            }
            let cap = needed.next_power_of_two().max(4096);
            let desc = D3D11_BUFFER_DESC {
                ByteWidth: cap,
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_UNORDERED_ACCESS.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS.0 as u32,
                StructureByteStride: 0,
            };
            let mut buf: Option<ID3D11Buffer> = None;
            hr(unsafe { self.device.CreateBuffer(&desc, None, Some(&mut buf)) }, "CreateBuffer(hist)")?;
            let buf = buf.ok_or("hist nulo")?;
            let udesc = D3D11_UNORDERED_ACCESS_VIEW_DESC {
                Format: DXGI_FORMAT_R32_TYPELESS,
                ViewDimension: D3D11_UAV_DIMENSION_BUFFER,
                Anonymous: D3D11_UNORDERED_ACCESS_VIEW_DESC_0 {
                    Buffer: D3D11_BUFFER_UAV { FirstElement: 0, NumElements: cap / 4, Flags: D3D11_BUFFER_UAV_FLAG_RAW.0 as u32 },
                },
            };
            let mut uav: Option<ID3D11UnorderedAccessView> = None;
            hr(unsafe { self.device.CreateUnorderedAccessView(&buf, Some(&udesc), Some(&mut uav)) }, "CreateUAV")?;
            let sdesc = D3D11_BUFFER_DESC {
                ByteWidth: cap,
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
                StructureByteStride: 0,
            };
            let mut staging: Option<ID3D11Buffer> = None;
            hr(unsafe { self.device.CreateBuffer(&sdesc, None, Some(&mut staging)) }, "CreateBuffer(staging)")?;
            self.hist = Some(HistBuf {
                buf,
                uav: uav.ok_or("uav nulo")?,
                staging: staging.ok_or("staging nulo")?,
                capacity: cap,
            });
            Ok(())
        }

        fn upload(&self, buf: &ID3D11Buffer, bytes: &[u8]) {
            let b = D3D11_BOX { left: 0, top: 0, front: 0, right: bytes.len() as u32, bottom: 1, back: 1 };
            unsafe { self.ctx.UpdateSubresource(buf, 0, Some(&b), bytes.as_ptr() as *const _, 0, 0) };
        }

        pub fn histograms(&mut self, segments: &[&[u8]]) -> Result<Vec<[u32; 256]>, String> {
            let nseg = segments.len();
            if nseg == 0 {
                return Ok(Vec::new());
            }
            if nseg > 65_535 {
                return Err("Demasiados segmentos para un Dispatch".to_string());
            }
            // Empaquetar segmentos alineados a 4 bytes + tabla (offset, len).
            let mut packed: Vec<u8> = Vec::with_capacity(segments.iter().map(|s| s.len() + 4).sum::<usize>() + 4);
            let mut table: Vec<u8> = Vec::with_capacity(nseg * 8);
            let mut max_len = 0usize;
            for s in segments {
                let off = packed.len() as u32;
                packed.extend_from_slice(s);
                while packed.len() % 4 != 0 {
                    packed.push(0);
                }
                table.extend_from_slice(&off.to_le_bytes());
                table.extend_from_slice(&(s.len() as u32).to_le_bytes());
                max_len = max_len.max(s.len());
            }
            packed.extend_from_slice(&[0u8; 4]);
            if packed.len() > 256 * 1024 * 1024 {
                return Err("Lote demasiado grande".to_string());
            }

            let mut data = self.data.take();
            let r1 = self.ensure_raw(&mut data, packed.len() as u32);
            self.data = data;
            r1?;
            let mut segs = self.segs.take();
            let r2 = self.ensure_raw(&mut segs, table.len() as u32);
            self.segs = segs;
            r2?;
            let hist_bytes = (nseg * 256 * 4) as u32;
            self.ensure_hist(hist_bytes)?;

            let data = self.data.as_ref().unwrap();
            let segb = self.segs.as_ref().unwrap();
            let hist = self.hist.as_ref().unwrap();

            let words = (max_len as u32 + 3) / 4;
            let groups_x = ((words + 256 * 8 - 1) / (256 * 8)).clamp(1, 64);
            let params: [u32; 4] = [groups_x, nseg as u32, 0, 0];

            unsafe {
                self.upload(&data.buf, &packed);
                self.upload(&segb.buf, &table);
                self.ctx.UpdateSubresource(&self.cbuf, 0, None, params.as_ptr() as *const _, 0, 0);
                self.ctx.ClearUnorderedAccessViewUint(&hist.uav, &[0u32; 4]);

                self.ctx.CSSetShader(&self.shader, None);
                self.ctx.CSSetConstantBuffers(0, Some(&[Some(self.cbuf.clone())]));
                self.ctx.CSSetShaderResources(0, Some(&[data.view.clone(), segb.view.clone()]));
                let uavs = [Some(hist.uav.clone())];
                self.ctx.CSSetUnorderedAccessViews(0, 1, Some(uavs.as_ptr()), None);

                self.ctx.Dispatch(groups_x, nseg as u32, 1);

                // Desvincular recursos
                let none_uav: [Option<ID3D11UnorderedAccessView>; 1] = [None];
                self.ctx.CSSetUnorderedAccessViews(0, 1, Some(none_uav.as_ptr()), None);
                self.ctx.CSSetShaderResources(0, Some(&[None, None]));

                self.ctx.CopyResource(&hist.staging, &hist.buf);
                let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                hr(self.ctx.Map(&hist.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)), "Map(staging)")?;
                let src = std::slice::from_raw_parts(mapped.pData as *const u32, nseg * 256);
                let mut out = vec![[0u32; 256]; nseg];
                for (i, h) in out.iter_mut().enumerate() {
                    h.copy_from_slice(&src[i * 256..(i + 1) * 256]);
                }
                self.ctx.Unmap(&hist.staging, 0);

                // Detección de dispositivo perdido (TDR / driver reset)
                if let Err(e) = self.device.GetDeviceRemovedReason() {
                    return Err(format!("Dispositivo GPU perdido: {}", e));
                }
                let _ = PCSTR::null();
                Ok(out)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_gpu_dispatch_parity_and_telemetry() {
        let pool = GpuComputePool::global();
        let st = pool.status();
        println!("GPU pool: available={} init_error={:?}", st.available, st.init_error);
        for a in &st.adapters {
            println!("  [{}] {} vendor=0x{:04X} vram={}MB igpu={} ready={} err={:?}",
                a.index, a.name, a.vendor_id, a.dedicated_vram_mb, a.is_integrated, a.ready, a.last_error);
        }
        if !st.available {
            println!("Sin GPU disponible: se omite la verificación de despacho.");
            return;
        }
        let data: Vec<u8> = (0..1_000_003u32).map(|i| (i.wrapping_mul(2246822519) >> 11) as u8).collect();
        let segs: Vec<&[u8]> = std::iter::once(&data[..]).chain(data.chunks(1024)).collect();
        for pref in [GpuPreference::Dedicated, GpuPreference::Integrated, GpuPreference::HybridAuto] {
            GpuComputePool::set_preference_global(pref);
            if !pool.is_available() { println!("{:?}: sin adaptador de esa clase", pref); continue; }
            let t = std::time::Instant::now();
            let h = pool.histograms(&segs).expect("despacho GPU");
            println!("{:?}: {} segmentos en {:?}", pref, segs.len(), t.elapsed());
            for (s, g) in segs.iter().zip(h.iter()) {
                let mut c = [0u32; 256];
                for &b in s.iter() { c[b as usize] += 1; }
                assert_eq!(&c, g, "paridad GPU/CPU");
            }
        }
        GpuComputePool::set_preference_global(GpuPreference::HybridAuto);
        for a in pool.status().adapters {
            println!("  [{}] {} dispatches={} bytes={} busy={}ms", a.index, a.name, a.dispatches, a.bytes_processed, a.gpu_busy_ms);
        }
    }
}