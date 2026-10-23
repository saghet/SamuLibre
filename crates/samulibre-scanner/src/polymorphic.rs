use serde::{Deserialize, Serialize};

/// Calcula la entropía de Shannon sobre un conjunto de bytes (rango 0.0 a 8.0).
/// Datos planos en texto: 3.5 - 5.0.
/// Código binario normal: 5.5 - 6.8.
/// Código comprimido, cifrado o polimórfico: > 7.2.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Genera un hash difuso (Fuzzy Similarity Hash) de ventana deslizante
/// que permite correlacionar dos binarios mutados por crypters o empaquetadores polimórficos.
pub fn compute_fuzzy_hash(data: &[u8]) -> String {
    if data.is_empty() {
        return "0:0:0".to_string();
    }
    const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let block_size = (data.len() / 64).max(32);

    let mut hash_part1 = String::with_capacity(64);
    let mut hash_part2 = String::with_capacity(32);

    // Ventana deslizante de Adler/Rolling
    let mut roll: u32 = 0;
    let mut chunk_sum: u32 = 0;

    for (i, &b) in data.iter().enumerate() {
        roll = (roll.wrapping_shl(5).wrapping_add(roll) ^ (b as u32)) & 0xFFFFFF;
        chunk_sum = chunk_sum.wrapping_add(b as u32);

        if (i + 1) % block_size == 0 && hash_part1.len() < 64 {
            let idx = (roll ^ chunk_sum) as usize % 64;
            hash_part1.push(B64_CHARS[idx] as char);
            roll = 0;
            chunk_sum = 0;
        }

        if (i + 1) % (block_size * 2) == 0 && hash_part2.len() < 32 {
            let idx = (roll ^ (chunk_sum.wrapping_mul(3))) as usize % 64;
            hash_part2.push(B64_CHARS[idx] as char);
        }
    }

    if hash_part1.is_empty() {
        hash_part1.push('A');
    }
    if hash_part2.is_empty() {
        hash_part2.push('A');
    }

    format!("{}:{}:{}", block_size, hash_part1, hash_part2)
}

/// Compara dos hashes difusos y retorna un puntaje de similitud entre 0 y 100%.
pub fn compare_fuzzy_hashes(h1: &str, h2: &str) -> u32 {
    let p1: Vec<&str> = h1.split(':').collect();
    let p2: Vec<&str> = h2.split(':').collect();

    if p1.len() != 3 || p2.len() != 3 {
        return 0;
    }

    // Si los tamaños de bloque difieren por más de un factor de 2, la similitud es baja
    let b1: u64 = p1[0].parse().unwrap_or(0);
    let b2: u64 = p2[0].parse().unwrap_or(0);
    if b1 == 0 || b2 == 0 {
        return 0;
    }
    if b1 != b2 && b1 * 2 != b2 && b2 * 2 != b1 {
        return 0;
    }

    let s1 = p1[1].as_bytes();
    let s2 = p2[1].as_bytes();
    let min_len = s1.len().min(s2.len());
    if min_len == 0 {
        return 0;
    }

    let mut matches = 0usize;
    for i in 0..min_len {
        if s1[i] == s2[i] {
            matches += 1;
        }
    }

    let max_len = s1.len().max(s2.len());
    ((matches as f64 / max_len as f64) * 100.0).round() as u32
}

/// Evaluación de empaquetamiento y mutación polimórfica
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymorphicProfile {
    pub is_likely_polymorphic: bool,
    pub overall_entropy: f64,
    pub high_entropy_blocks: usize,
    pub total_blocks: usize,
    pub reason: Option<String>,
}

/// Analiza un archivo en bloques de 1024 bytes en busca de secciones de alta entropía
/// intercaladas con código ofuscador característico de troyanos polimórficos.
pub fn analyze_polymorphic_entropy(data: &[u8], file_name: &str) -> PolymorphicProfile {
    if data.len() < 1024 {
        return PolymorphicProfile {
            is_likely_polymorphic: false,
            overall_entropy: calculate_shannon_entropy(data),
            high_entropy_blocks: 0,
            total_blocks: 1,
            reason: None,
        };
    }

    let overall = calculate_shannon_entropy(data);
    let mut high_entropy_blocks = 0usize;
    let mut total_blocks = 0usize;

    for chunk in data.chunks(1024) {
        total_blocks += 1;
        let e = calculate_shannon_entropy(chunk);
        if e > 7.15 {
            high_entropy_blocks += 1;
        }
    }

    // Un archivo binario (.exe, .dll, .so, .bin) con más del 65% de bloques con entropía > 7.15
    // suele ser un payload empaquetado o cifrado polimórficamente.
    let is_exec = file_name.ends_with(".exe")
        || file_name.ends_with(".dll")
        || file_name.ends_with(".so")
        || file_name.ends_with(".bin")
        || file_name.ends_with(".elf")
        || data.starts_with(b"MZ")
        || data.starts_with(b"\x7fELF");

    let ratio = high_entropy_blocks as f64 / total_blocks.max(1) as f64;
    let is_poly = is_exec && ratio >= 0.65 && overall > 7.2;

    let reason = if is_poly {
        Some(format!(
            "Payload empaquetado con patrón polimórfico detectado: entropía total {:.2}, {:.1}% de bloques con cifrado denso.",
            overall,
            ratio * 100.0
        ))
    } else {
        None
    };

    PolymorphicProfile {
        is_likely_polymorphic: is_poly,
        overall_entropy: overall,
        high_entropy_blocks,
        total_blocks,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        let zeroes = vec![0u8; 1024];
        assert_eq!(calculate_shannon_entropy(&zeroes), 0.0);

        let text = b"The quick brown fox jumps over the lazy dog";
        let e_text = calculate_shannon_entropy(text);
        assert!(e_text > 3.0 && e_text < 5.0);

        // High entropy pseudo-random sequence
        let mut pseudo_rand = vec![0u8; 4096];
        for (i, b) in pseudo_rand.iter_mut().enumerate() {
            *b = ((i * 137 + 59) % 256) as u8;
        }
        let e_rand = calculate_shannon_entropy(&pseudo_rand);
        assert!(e_rand > 7.5);
    }

    #[test]
    fn test_fuzzy_hash_similarity() {
        let b1 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234567890";
        let b2 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234567899";
        let h1 = compute_fuzzy_hash(b1);
        let h2 = compute_fuzzy_hash(b2);
        let sim = compare_fuzzy_hashes(&h1, &h2);
        assert!(sim > 70, "Similar binaries should have high fuzzy match score: {}", sim);

        let totally_different = b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ9876543210";
        let h3 = compute_fuzzy_hash(totally_different);
        let sim_diff = compare_fuzzy_hashes(&h1, &h3);
        assert!(sim_diff < sim);
    }

    #[test]
    fn test_polymorphic_packer_detection() {
        let mut packed_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF".to_vec();
        let mut pseudo_rand = vec![0u8; 8192];
        for (i, b) in pseudo_rand.iter_mut().enumerate() {
            *b = ((i * 163 + 71) % 256) as u8;
        }
        packed_pe.extend_from_slice(&pseudo_rand);

        let profile = analyze_polymorphic_entropy(&packed_pe, "packed_trojan.exe");
        assert!(profile.is_likely_polymorphic);
        assert!(profile.overall_entropy > 7.2);
    }
}

