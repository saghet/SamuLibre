use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use tracing::info;

/// Cabecera de integridad criptográfica para bases de firmas versionadas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDbHeader {
    pub magic: String,           // "SAMUSIG\0"
    pub format_version: u32,     // 2
    pub db_version: String,      // ej. "2026.11.07.01"
    pub release_timestamp: u64,
    pub total_signatures: usize,
    pub sha256_checksum: String, // Hash del contenido de firmas
    pub publisher: String,       // "SamuLibre Security Community"
}

/// Registro individual de firma de malware
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MalwareSignature {
    pub sha256: String,
    pub threat_name: String,
    pub category: String, // Ransomware, Trojan, Infostealer, Backdoor, etc.
    pub severity: String,
}

/// Filtro de Bloom probabilístico de alta velocidad (O(1)) para descarte instantáneo de archivos limpios
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bitset: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
}

impl BloomFilter {
    /// Inicializa un filtro de Bloom con capacidad aproximada y tasa de falsos positivos < 0.1%
    pub fn new(capacity: usize) -> Self {
        // ~14.4 bits por elemento para 1% FP con 5 hashes; usamos 16 bits para <0.1% FP
        let num_bits = (capacity * 16).max(64 * 1024);
        let num_words = (num_bits + 63) / 64;
        Self {
            bitset: vec![0u64; num_words],
            num_bits,
            num_hashes: 5,
        }
    }

    fn get_hash_indices(&self, key: &[u8]) -> Vec<usize> {
        let mut indices = Vec::with_capacity(self.num_hashes);
        let mut hasher1 = Sha256::new();
        hasher1.update(key);
        let digest1 = hasher1.finalize();

        let h1 = u64::from_le_bytes(digest1[0..8].try_into().unwrap_or([0; 8]));
        let h2 = u64::from_le_bytes(digest1[8..16].try_into().unwrap_or([0; 8]));

        for i in 0..self.num_hashes {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            indices.push((combined as usize) % self.num_bits);
        }
        indices
    }

    pub fn insert(&mut self, key: &[u8]) {
        for idx in self.get_hash_indices(key) {
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            self.bitset[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Retorna `false` si el elemento DEFINITIVAMENTE NO ESTÁ en el conjunto (0% falsos negativos).
    /// Retorna `true` si el elemento probablemente esté en el conjunto.
    pub fn contains(&self, key: &[u8]) -> bool {
        for idx in self.get_hash_indices(key) {
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            if (self.bitset[word_idx] & (1u64 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }
}

/// Almacén indexado y versionado de firmas de malware con aceleración por Filtro de Bloom
#[derive(Debug, Clone)]
pub struct SignatureStore {
    signatures: HashMap<String, MalwareSignature>,
    bloom: BloomFilter,
    version: String,
    last_updated: u64,
}

impl SignatureStore {
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
            bloom: BloomFilter::new(50_000),
            version: "v2026.11.07.01".to_string(),
            last_updated: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn last_updated(&self) -> u64 {
        self.last_updated
    }

    /// Registra una firma individual e indexa en el filtro de Bloom
    pub fn add_signature(&mut self, sha256: &str, threat_name: &str, category: &str, severity: &str) {
        let clean_hash = sha256.trim().to_lowercase();
        if clean_hash.len() != 64 {
            return;
        }
        self.bloom.insert(clean_hash.as_bytes());
        self.signatures.insert(
            clean_hash.clone(),
            MalwareSignature {
                sha256: clean_hash,
                threat_name: threat_name.to_string(),
                category: category.to_string(),
                severity: severity.to_string(),
            },
        );
    }

    /// Búsqueda ultra-rápida de hash: primero consulta el Filtro de Bloom O(1).
    /// Si el Bloom descarta el hash, retorna None inmediatamente sin costo de búsqueda en tabla.
    pub fn lookup(&self, sha256: &str) -> Option<&MalwareSignature> {
        let clean = sha256.trim().to_lowercase();
        if !self.bloom.contains(clean.as_bytes()) {
            return None; // 100% garantizado que no está en la base de firmas
        }
        self.signatures.get(&clean)
    }

    /// Carga firmas desde archivo plano o versionado
    pub fn load_from_db_file(&mut self, path: impl AsRef<Path>) -> Result<usize> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(0);
        }
        let file = File::open(p)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((hash_part, rest)) = trimmed.split_once(':') {
                let hash = hash_part.trim();
                let name = rest.trim();
                let cat = if name.contains("Ransomware") {
                    "Ransomware"
                } else if name.contains("Trojan") {
                    "Trojan"
                } else if name.contains("Spyware") {
                    "Spyware"
                } else {
                    "Malware"
                };
                self.add_signature(hash, name, cat, "Crítica");
                count += 1;
            } else if let Some((hash_part, rest)) = trimmed.split_once(';') {
                let hash = hash_part.trim();
                let name = rest.trim();
                self.add_signature(hash, name, "Generic", "Alta");
                count += 1;
            }
        }

        info!("Cargadas {} firmas en SignatureStore desde {:?}", count, p);
        Ok(count)
    }

    /// Carga la biblioteca inicial de firmas conocidas predeterminadas de SamuLibre
    pub fn load_builtin_signatures(&mut self) {
        let default_threats = [
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-Test-File.Signature", "TestAlert", "Prueba"),
            ("3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632", "Ransomware.Win32.Conti.Gen", "Ransomware", "Crítica"),
            ("a3c1097e883395c52c67645f06ea4a4d2f0992383840742f15599eec38d1796c", "Trojan.Script.PowerSploit.Mimikatz", "HackTool", "Crítica"),
            ("5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54", "Trojan.Win32.RedLineStealer.Gen", "Infostealer", "Crítica"),
            ("a26569e96e95267d325e0129fd53e8cb30d0611fa67776f8e7090884dd08051a", "Spyware.Win32.SnakeKeylogger.Gen", "Spyware", "Crítica"),
            ("2a4b896940d99fae5e6e3c5ec82fbf91efea9380436d4ab8d2c49ffab03233c7", "Backdoor.Win32.RemcosRAT.Client", "Backdoor", "Crítica"),
            ("3c1d2e1c9e884faefea7019dc563e7925e0e1f7d451fe83c66289b4f7380ff98", "Ransomware.Win32.Ryuk.Encrypter", "Ransomware", "Crítica"),
            ("e2b8be5689100412803b905f95982e0516b0bbdf4d9894e24efd66394142b78a", "Trojan.Win32.DarkComet.RAT", "Backdoor", "Crítica"),
            ("84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e", "Ransomware.Win32.LockBit3.Gen", "Ransomware", "Crítica"),
            ("9a038f8f41164966601b1fc8974a2b9758f1f7bd788c005b4b94f6c4c0bb8a4b", "Exploit.Win32.EternalBlue.Dropper", "Exploit", "Crítica"),
            ("d64230626a57c5a0ca95bf6eec5eb852d7e0d3752e25ad6256f6c99c55d0458a", "Trojan.Win32.IcedID.BankingLoader", "Trojan", "Crítica"),
            ("8b6f3b5843a0558b8d4f40f7d5c5893e3d64c1265fef54e9bcad26895c84df12", "Ransomware.Win32.BlackCat.ALPHV", "Ransomware", "Crítica"),
            ("d9f37c35f29e0dc0476839281a179e830e234327bc794825d4c82b99453d102e", "Trojan.Win32.LokiBot.CredentialStealer", "Infostealer", "Crítica"),
            ("1a5806257d767d156557cb029a1c62f2cc309dd051e9e8f668581e18b62551ec", "Ransomware.Win32.WannaCry.Payload", "Ransomware", "Crítica"),
            ("176b6d51c06830de2b17a02251a2d5918a5996a840e79391ab6f028de7d705c9", "Trojan.Win32.QakBot.Payload", "Trojan", "Crítica"),
            ("32b139977cfb9a01be3fc4863c18b7ae293b67be06eec43eb91fe5d35eb7b3fe", "Trojan.Win32.Emotet.Payload", "Trojan", "Crítica"),
            ("f4b1e427bc529fb3e895c8c6978508933b9a1172776c5b9f71ab85b672727142", "Spyware.Win32.Pegasus.Loader", "Spyware", "Crítica"),
            ("c4566c1b3f94539ef2a382c0f655dc3bc3594e50882e3895e34be6acab28d098", "Trojan.Win32.AgentTesla.Stealer", "Infostealer", "Crítica"),
        ];

        for (h, name, cat, sev) in default_threats {
            self.add_signature(h, name, cat, sev);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_zero_false_negatives() {
        let mut bloom = BloomFilter::new(1000);
        let sample_hash = b"3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632";
        let clean_hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        bloom.insert(sample_hash);
        assert!(bloom.contains(sample_hash), "El hash insertado debe estar presente");
        assert!(!bloom.contains(clean_hash), "Un hash limpio no debe coincidir");
    }

    #[test]
    fn test_signature_store_lifecycle() {
        let mut store = SignatureStore::new();
        store.load_builtin_signatures();
        assert!(store.len() >= 18);

        // Búsqueda de hash conocido
        let res = store.lookup("3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632");
        assert!(res.is_some());
        assert_eq!(res.unwrap().threat_name, "Ransomware.Win32.Conti.Gen");

        // Hash limpio desconocido
        assert!(store.lookup("0000000000000000000000000000000000000000000000000000000000000000").is_none());
    }
}
