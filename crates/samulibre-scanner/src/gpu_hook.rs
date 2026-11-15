//! Punto de enganche (hook) de aceleración GPU para el motor de escaneo.
//!
//! El crate `samulibre-scanner` no puede depender de `samulibre-core` (dependencia circular),
//! por lo que el motor SHCE de `samulibre-core` registra aquí un proveedor de histogramas
//! de bytes acelerado por GPU (Direct3D 11 Compute Shader). Si no hay proveedor registrado
//! o la GPU falla, todas las funciones caen de forma transparente al cálculo en CPU.

use std::sync::{Arc, RwLock};

/// Proveedor de histogramas por lotes: recibe N segmentos de bytes y devuelve N histogramas de 256 bins.
/// Devuelve `None` si la GPU no está disponible / está deshabilitada → fallback CPU.
pub type HistogramProvider = dyn Fn(&[&[u8]]) -> Option<Vec<[u32; 256]>> + Send + Sync;

static PROVIDER: RwLock<Option<Arc<HistogramProvider>>> = RwLock::new(None);

/// Tamaño mínimo total (bytes) a partir del cual compensa enviar el trabajo a la GPU.
const MIN_GPU_BYTES: usize = 8 * 1024;

/// Registra (o elimina con `None`) el proveedor de histogramas acelerado por GPU.
pub fn set_histogram_provider(provider: Option<Arc<HistogramProvider>>) {
    if let Ok(mut p) = PROVIDER.write() {
        *p = provider;
    }
}

/// Indica si hay un proveedor GPU registrado.
pub fn has_gpu_provider() -> bool {
    PROVIDER.read().map(|p| p.is_some()).unwrap_or(false)
}

/// Calcula histogramas de varios segmentos usando la GPU si está disponible.
pub fn gpu_histograms(segments: &[&[u8]]) -> Option<Vec<[u32; 256]>> {
    let total: usize = segments.iter().map(|s| s.len()).sum();
    if total < MIN_GPU_BYTES || segments.is_empty() {
        return None;
    }
    let provider = PROVIDER.read().ok()?.clone()?;
    let res = provider(segments)?;
    if res.len() == segments.len() {
        Some(res)
    } else {
        None
    }
}

/// Entropía de Shannon a partir de un histograma ya calculado.
pub fn entropy_from_histogram(hist: &[u32; 256], len: usize) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let len_f = len as f64;
    let mut entropy = 0.0;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Histograma en CPU (fallback).
pub fn cpu_histogram(data: &[u8]) -> [u32; 256] {
    let mut h = [0u32; 256];
    for &b in data {
        h[b as usize] += 1;
    }
    h
}

/// Entropía de un único búfer: GPU si es posible, si no CPU.
pub fn accelerated_entropy(data: &[u8]) -> f64 {
    if let Some(h) = gpu_histograms(&[data]) {
        return entropy_from_histogram(&h[0], data.len());
    }
    entropy_from_histogram(&cpu_histogram(data), data.len())
}
