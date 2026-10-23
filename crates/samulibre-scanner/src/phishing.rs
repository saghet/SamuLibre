use serde::{Deserialize, Serialize};

/// Veredicto del motor de Anti-Phishing con IA y análisis heurístico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingVerdict {
    pub is_phishing: bool,
    pub confidence: f32, // 0.0 a 1.0
    pub threat_category: String,
    pub domain: String,
    pub indicators: Vec<String>,
}

/// Marcas financieras y corporativas frecuentemente suplantadas
const HIGH_VALUE_BRANDS: &[&str] = &[
    "google", "microsoft", "apple", "amazon", "paypal", "netflix", "facebook", "instagram",
    "whatsapp", "binance", "coinbase", "santander", "bbva", "chase", "wellsfargo", "banco",
    "bancolombia", "mercadolibre", "office365", "outlook", "dhl", "fedex", "appleid",
];

/// TLDs de bajo costo frecuentemente abusados en campañas masivas de phishing
const SUSPICIOUS_TLDS: &[&str] = &[
    ".top", ".xyz", ".click", ".work", ".rest", ".cam", ".surf", ".buzz", ".monster", ".fit",
    ".gq", ".ml", ".cf", ".ga", ".tk", ".country", ".kim", ".icu",
];

/// Caracteres homóglifos comunes (Cirílico / Griego a Latino)
fn has_homoglyphs(domain: &str) -> bool {
    for c in domain.chars() {
        match c {
            // Letras cirílicas idénticas a latinas (а, с, е, о, р, х, у, etc.)
            '\u{0430}' | '\u{0441}' | '\u{0435}' | '\u{043E}' | '\u{0440}' | '\u{0445}'
            | '\u{0443}' | '\u{0456}' | '\u{0408}' | '\u{0455}' => return true,
            // Letras griegas que imitan latinas (α, ο, etc.)
            '\u{03B1}' | '\u{03BF}' | '\u{03BD}' => return true,
            _ => {}
        }
    }
    false
}

/// Analiza una URL o enlace web para determinar si es fraudulento o phishing
pub fn analyze_url(url_str: &str) -> PhishingVerdict {
    let lower = url_str.trim().to_lowercase();
    let mut indicators = Vec::new();
    let mut score: f32 = 0.0;

    // 1. Detección de homóglifos cirílicos o griegos
    if has_homoglyphs(&lower) {
        indicators.push("Ataque homógrafo detectado: caracteres cirílicos/griegos suplantando alfabeto latino".to_string());
        score += 0.85;
    }

    // 2. Detección de Punycode (IDN deceptive domain)
    if lower.contains("xn--") {
        indicators.push("Dominio codificado en Punycode (posible spoofing visual IDN)".to_string());
        score += 0.50;
    }

    // Extraer dominio aproximado
    let domain_part = if let Some(idx) = lower.find("://") {
        &lower[idx + 3..]
    } else {
        &lower
    };
    let domain = domain_part.split(&['/', '?', '#', ':'][..]).next().unwrap_or("").to_string();

    // 3. Dirección IP cruda en lugar de nombre de dominio
    let is_ip_host = domain.chars().all(|c| c.is_ascii_digit() || c == '.');
    if is_ip_host && domain.split('.').count() == 4 {
        indicators.push("Uso de dirección IP directa en lugar de nombre de dominio calificado".to_string());
        score += 0.40;
    }

    // 4. Marca conocida en subdominio o combinación engañosa
    for &brand in HIGH_VALUE_BRANDS {
        if domain.contains(brand) {
            // Verificar si es el dominio oficial exacto (ej. paypal.com o login.microsoft.com)
            let is_official = domain == format!("{}.com", brand)
                || domain.ends_with(&format!(".{}.com", brand))
                || domain.ends_with(&format!(".{}.net", brand))
                || domain.ends_with(&format!(".{}.org", brand))
                || domain.ends_with(&format!(".{}.es", brand))
                || domain.ends_with(&format!(".{}.com.co", brand));

            if !is_official {
                indicators.push(format!("Suplantación de marca corporativa detectada: '{}' en dominio no oficial '{}'", brand, domain));
                score += 0.70;
            }
        }
    }

    // 5. TLDs sospechosos de spam/phishing
    for &tld in SUSPICIOUS_TLDS {
        if domain.ends_with(tld) {
            indicators.push(format!("TLD de alta incidencia de fraude: {}", tld));
            score += 0.30;
            break;
        }
    }

    // 6. Profundidad excesiva de subdominios (ej: login.verify.secure.bank.com.fake.top)
    let dot_count = domain.chars().filter(|&c| c == '.').count();
    if dot_count >= 4 {
        indicators.push(format!("Estructura de subdominios sospechosamente profunda ({} niveles)", dot_count));
        score += 0.25;
    }

    // 7. Parámetros sospechosos de recolección de credenciales
    if lower.contains("login") || lower.contains("signin") || lower.contains("verify") || lower.contains("recover") || lower.contains("password") {
        if score > 0.3 {
            indicators.push("Patrón de captura de sesión / credenciales en URL fraudulenta".to_string());
            score += 0.20;
        }
    }

    let confidence = score.min(1.0);
    let is_phishing = confidence >= 0.65;

    let threat_category = if is_phishing {
        if indicators.iter().any(|i| i.contains("homógrafo") || i.contains("Punycode")) {
            "Phishing.IDN.HomoglyphSpoofing".to_string()
        } else if indicators.iter().any(|i| i.contains("Suplantación")) {
            "Phishing.BrandImpersonation.Deceptive".to_string()
        } else {
            "Phishing.Heuristic.SuspiciousDomain".to_string()
        }
    } else {
        "Clean".to_string()
    };

    PhishingVerdict {
        is_phishing,
        confidence,
        threat_category,
        domain,
        indicators,
    }
}

/// Escanea un texto (ej. correo electrónico, HTML o mensaje) extrayendo todas las URLs
/// y analizando si contienen enlaces a sitios de phishing
pub fn scan_text_for_phishing(text: &str) -> Vec<(String, PhishingVerdict)> {
    let mut detected = Vec::new();
    let re = regex::Regex::new(r#"https?://[^\s<>"]+"#).unwrap();

    for mat in re.find_iter(text) {
        let url = mat.as_str();
        let verdict = analyze_url(url);
        if verdict.is_phishing {
            detected.push((url.to_string(), verdict));
        }
    }

    detected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homoglyph_detection() {
        // 'о' es cirílico \u{043E}
        let fake_google = "https://g\u{043E}\u{043E}gle.com/login";
        let res = analyze_url(fake_google);
        assert!(res.is_phishing);
        assert!(res.confidence >= 0.85);
        assert!(res.indicators.iter().any(|i| i.contains("homógrafo")));
    }

    #[test]
    fn test_brand_impersonation() {
        let fake_paypal = "http://paypal.security-account-verification.top/update";
        let res = analyze_url(fake_paypal);
        assert!(res.is_phishing);
        assert!(res.indicators.iter().any(|i| i.contains("Suplantación")));
    }

    #[test]
    fn test_official_brand_clean() {
        let real_google = "https://accounts.google.com/signin";
        let res = analyze_url(real_google);
        assert!(!res.is_phishing);
    }

    #[test]
    fn test_scan_text_phishing() {
        let email = "Estimado cliente, actualice su cuenta en http://paypal-recovery-urgent.xyz/now antes de 24h.";
        let findings = scan_text_for_phishing(email);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.is_phishing);
    }
}
