use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Indicador de amenaza compartido en la red comunitaria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityThreatIndicator {
    pub sha256: String,
    pub threat_name: String,
    pub confidence: f32,
    pub reports_count: u32,
    pub category: String,
}

/// Motor de Reputación Comunitario con K-Anonimato
/// Protege la privacidad del usuario compartiendo y consultando únicamente prefijos truncados (K-Anonymity)
pub struct CommunityReputationEngine {
    // Almacenamiento indexado por prefijo de 5 caracteres hex (K-Anonymity bucket)
    prefix_buckets: HashMap<String, Vec<CommunityThreatIndicator>>,
}

impl CommunityReputationEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            prefix_buckets: HashMap::new(),
        };
        engine.load_builtin_threat_feed();
        engine
    }

    /// Carga indicadores iniciales de la comunidad
    fn load_builtin_threat_feed(&mut self) {
        let defaults = [
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-Test-File", "Test", 999),
            ("5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54", "Trojan.Win32.RedLineStealer", "Infostealer", 42),
            ("84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e", "Ransomware.Win32.LockBit3", "Ransomware", 128),
        ];

        for (hash, name, cat, count) in defaults {
            self.submit_indicator(CommunityThreatIndicator {
                sha256: hash.to_string(),
                threat_name: name.to_string(),
                confidence: 0.98,
                reports_count: count,
                category: cat.to_string(),
            });
        }
    }

    /// Registra un nuevo indicador en el bucket correspondiente a su prefijo de K-anonimato (5 caracteres)
    pub fn submit_indicator(&mut self, indicator: CommunityThreatIndicator) {
        if indicator.sha256.len() < 5 {
            return;
        }
        let prefix = indicator.sha256[..5].to_lowercase();
        let bucket = self.prefix_buckets.entry(prefix).or_default();

        // Si ya existe el hash en el bucket, actualizar conteo de reportes comunitarios
        if let Some(existing) = bucket.iter_mut().find(|i| i.sha256.eq_ignore_ascii_case(&indicator.sha256)) {
            existing.reports_count += 1;
            existing.confidence = (existing.confidence * 0.9 + indicator.confidence * 0.1).min(1.0);
        } else {
            bucket.push(indicator);
        }
    }

    /// Consulta anónima por K-Anonimato: el cliente envía únicamente los primeros 5 caracteres del hash.
    /// El servidor o nodo comunitario responde con todos los candidatos que comparten ese prefijo.
    /// El cliente resuelve la coincidencia en local, sin revelar el hash completo del archivo a la red.
    pub fn query_by_k_anonymity_prefix(&self, prefix_5chars: &str) -> Vec<CommunityThreatIndicator> {
        let p = prefix_5chars.to_lowercase();
        self.prefix_buckets.get(&p).cloned().unwrap_or_default()
    }

    /// Consulta local directa: verifica si el hash completo coincide con algún registro verificado
    pub fn lookup_hash(&self, full_sha256: &str) -> Option<CommunityThreatIndicator> {
        if full_sha256.len() < 5 {
            return None;
        }
        let prefix = full_sha256[..5].to_lowercase();
        let bucket = self.prefix_buckets.get(&prefix)?;
        bucket.iter().find(|i| i.sha256.eq_ignore_ascii_case(full_sha256)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_anonymity_query() {
        let engine = CommunityReputationEngine::new();
        // EICAR hash: 275a021b...
        let prefix = "275a0";
        let candidates = engine.query_by_k_anonymity_prefix(prefix);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].threat_name, "EICAR-Standard-Test-File");

        // Búsqueda completa
        let found = engine.lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        assert!(found.is_some());
    }

    #[test]
    fn test_unknown_hash_returns_empty() {
        let engine = CommunityReputationEngine::new();
        let candidates = engine.query_by_k_anonymity_prefix("fffff");
        assert!(candidates.is_empty());
    }
}
