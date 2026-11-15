use crate::threat_intel::ThreatIntelManager;
use crate::types::{DnsConfig, DnsQueryLog, DnsStats, DnsTransport};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rustls::pki_types::ServerName;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct CachedDnsPacket {
    wire_response: Vec<u8>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ParsedDnsQuestion {
    pub tx_id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Parsea la cabecera y la primera pregunta de un paquete DNS en formato wire (RFC 1035).
pub fn parse_dns_question(packet: &[u8]) -> Result<ParsedDnsQuestion> {
    if packet.len() < 12 {
        return Err(anyhow!("Paquete DNS demasiado corto (< 12 bytes)"));
    }
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err(anyhow!("Paquete DNS sin sección de pregunta"));
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();
    let mut jumps = 0usize;
    loop {
        if pos >= packet.len() {
            return Err(anyhow!("QNAME truncado en paquete DNS"));
        }
        let len = packet[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() || jumps > 8 {
                return Err(anyhow!("Puntero DNS inválido"));
            }
            let offset = (((len & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            pos = offset;
            jumps += 1;
            continue;
        }
        let llen = len as usize;
        pos += 1;
        if pos + llen > packet.len() {
            return Err(anyhow!("Etiqueta DNS fuera de rango"));
        }
        let label = String::from_utf8_lossy(&packet[pos..pos + llen]).to_string();
        labels.push(label);
        pos += llen;
    }

    if pos + 4 > packet.len() {
        return Err(anyhow!("Faltan QTYPE/QCLASS en paquete DNS"));
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);

    Ok(ParsedDnsQuestion {
        tx_id,
        qname: labels.join(".").to_lowercase(),
        qtype,
        qclass,
    })
}

/// Construye una respuesta DNS NXDOMAIN (RCODE=3) válida para bloquear dominios maliciosos o rebinding.
pub fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut resp = query.to_vec();
    // QR=1 (Response), OPCODE preserved, RD preserved, RA=1, RCODE=3 (NXDOMAIN)
    resp[2] = (query[2] & 0x79) | 0x80;
    resp[3] = 0x83;
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    resp
}

/// Extrae direcciones IP (A / AAAA) de la sección Answer de una respuesta DNS wire para detectar DNS Rebinding.
pub fn extract_resolved_ips(packet: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if packet.len() < 12 {
        return ips;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12usize;

    // Saltar preguntas
    for _ in 0..qdcount {
        pos = match skip_dns_name(packet, pos) {
            Some(p) => p + 4,
            None => return ips,
        };
    }

    // Leer respuestas
    for _ in 0..ancount {
        pos = match skip_dns_name(packet, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > packet.len() {
            break;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > packet.len() {
            break;
        }
        if rtype == 1 && rdlength == 4 {
            let v4 = Ipv4Addr::new(packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]);
            ips.push(IpAddr::V4(v4));
        } else if rtype == 28 && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[pos..pos + 16]);
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        pos += rdlength;
    }
    ips
}

fn skip_dns_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    let mut steps = 0;
    while pos < packet.len() && steps < 64 {
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return if pos + 2 <= packet.len() { Some(pos + 2) } else { None };
        }
        pos += 1 + (len as usize);
        steps += 1;
    }
    None
}

pub fn is_private_or_rebinding_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

pub fn qtype_to_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Motor de Resolución DNS Seguro (DoH / DoT) con filtrado de amenazas y protección contra DNS Rebinding.
pub struct SecureDnsProxy {
    pub config: Arc<Mutex<DnsConfig>>,
    pub stats: Arc<Mutex<DnsStats>>,
    pub query_logs: Arc<Mutex<VecDeque<DnsQueryLog>>>,
    cache: Arc<Mutex<HashMap<String, CachedDnsPacket>>>,
    intel: Arc<Mutex<ThreatIntelManager>>,
    running_flag: Arc<AtomicBool>,
}

impl SecureDnsProxy {
    pub fn new(config: DnsConfig, intel: Arc<Mutex<ThreatIntelManager>>) -> Self {
        let listen_addr = config.listen_addr.clone();
        Self {
            config: Arc::new(Mutex::new(config)),
            stats: Arc::new(Mutex::new(DnsStats {
                listen_addr,
                ..Default::default()
            })),
            query_logs: Arc::new(Mutex::new(VecDeque::with_capacity(500))),
            cache: Arc::new(Mutex::new(HashMap::new())),
            intel,
            running_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running_flag.load(Ordering::SeqCst)
    }

    /// Inicia el servidor UDP DNS en un hilo dedicado en segundo plano.
    /// Si el puerto 53 está ocupado o requiere elevación, registra el error real sin simular éxito.
    pub fn start(&self) -> Result<()> {
        if self.running_flag.load(Ordering::SeqCst) {
            return Ok(());
        }
        let listen_addr = self.config.lock().unwrap().listen_addr.clone();
        let socket = match UdpSocket::bind(&listen_addr) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("No se pudo enlazar DNS Proxy en {}: {}", listen_addr, e);
                if let Ok(mut st) = self.stats.lock() {
                    st.running = false;
                    st.last_error = Some(msg.clone());
                }
                return Err(anyhow!(msg));
            }
        };
        let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));

        self.running_flag.store(true, Ordering::SeqCst);
        if let Ok(mut st) = self.stats.lock() {
            st.running = true;
            st.listen_addr = listen_addr.clone();
            st.last_error = None;
        }

        let flag = Arc::clone(&self.running_flag);
        let cfg_arc = Arc::clone(&self.config);
        let stats_arc = Arc::clone(&self.stats);
        let logs_arc = Arc::clone(&self.query_logs);
        let cache_arc = Arc::clone(&self.cache);
        let intel_arc = Arc::clone(&self.intel);

        std::thread::spawn(move || {
            info!("SamuLibre Secure DNS Proxy escuchando en {}", listen_addr);
            let mut buf = [0u8; 4096];
            while flag.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buf) {
                    Ok((len, peer)) => {
                        let query = buf[..len].to_vec();
                        let cfg = cfg_arc.lock().unwrap().clone();
                        let resp = process_dns_query(
                            &query,
                            &cfg,
                            &stats_arc,
                            &logs_arc,
                            &cache_arc,
                            &intel_arc,
                        );
                        if !resp.is_empty() {
                            let _ = socket.send_to(&resp, peer);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                        continue;
                    }
                    Err(e) => {
                        warn!("Error en recv_from DNS Proxy: {}", e);
                    }
                }
            }
            if let Ok(mut st) = stats_arc.lock() {
                st.running = false;
            }
            info!("SamuLibre Secure DNS Proxy detenido.");
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running_flag.store(false, Ordering::SeqCst);
    }

    /// Evalúa y resuelve una consulta DNS directamente (útil para pruebas unitarias e integración).
    pub fn resolve_query_wire(&self, query: &[u8]) -> Vec<u8> {
        let cfg = self.config.lock().unwrap().clone();
        process_dns_query(
            query,
            &cfg,
            &self.stats,
            &self.query_logs,
            &self.cache,
            &self.intel,
        )
    }
}

pub fn process_dns_query(
    query: &[u8],
    cfg: &DnsConfig,
    stats_arc: &Arc<Mutex<DnsStats>>,
    logs_arc: &Arc<Mutex<VecDeque<DnsQueryLog>>>,
    cache_arc: &Arc<Mutex<HashMap<String, CachedDnsPacket>>>,
    intel_arc: &Arc<Mutex<ThreatIntelManager>>,
) -> Vec<u8> {
    let start = Instant::now();
    let parsed = match parse_dns_question(query) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };

    if let Ok(mut st) = stats_arc.lock() {
        st.total_queries += 1;
    }

    let qname = parsed.qname.clone();
    let qtype_str = qtype_to_str(parsed.qtype).to_string();

    // 1. Dominios permitidos explícitamente
    let is_custom_allowed = cfg
        .custom_allowed_domains
        .iter()
        .any(|d| qname == d.to_lowercase() || qname.ends_with(&format!(".{}", d.to_lowercase())));

    // 2. Verificar sufijos corporativos / internos / mDNS (no romper redes corporativas o VPN)
    let is_internal_domain = !qname.contains('.')
        || cfg
            .corporate_bypass_suffixes
            .iter()
            .any(|suf| qname.ends_with(&suf.to_lowercase()));

    // 3. Evaluar listas de bloqueo y Threat Intelligence (si no es dominio interno ni permitido explícitamente)
    if !is_custom_allowed && !is_internal_domain {
        let custom_blocked = cfg
            .custom_blocked_domains
            .iter()
            .any(|d| qname == d.to_lowercase() || qname.ends_with(&format!(".{}", d.to_lowercase())));

        if custom_blocked {
            record_block(stats_arc, logs_arc, &qname, &qtype_str, "Lista de bloqueo personalizada", start);
            return build_nxdomain_response(query);
        }

        if let Ok(intel) = intel_arc.lock() {
            if let Some(ind) = intel.check_domain(&qname, cfg.block_malware, cfg.block_phishing, cfg.block_trackers) {
                let reason = format!("{:?} ({}, conf {}%)", ind.category, ind.source_name, ind.confidence);
                record_block(stats_arc, logs_arc, &qname, &qtype_str, &reason, start);
                return build_nxdomain_response(query);
            }
        }
    }

    // 4. Caché TTL en memoria
    let cache_key = format!("{}:{}", qname, parsed.qtype);
    if let Ok(mut cache) = cache_arc.lock() {
        if let Some(hit) = cache.get(&cache_key) {
            if hit.expires_at > Instant::now() {
                let mut resp = hit.wire_response.clone();
                if resp.len() >= 2 {
                    let id_bytes = parsed.tx_id.to_be_bytes();
                    resp[0] = id_bytes[0];
                    resp[1] = id_bytes[1];
                }
                if let Ok(mut st) = stats_arc.lock() {
                    st.cache_hits += 1;
                }
                return resp;
            }
        }
        if cache.len() > 4096 {
            cache.clear();
        }
    }

    // 5. Reenviar al upstream seguro (DoH o DoT)
    let upstream_res = match cfg.transport {
        DnsTransport::DoH => forward_doh(&cfg.doh_url, query),
        DnsTransport::DoT => forward_dot(&cfg.dot_host, cfg.dot_port, query),
    };

    match upstream_res {
        Ok(resp) => {
            let ips = extract_resolved_ips(&resp);

            // 6. Protección contra DNS Rebinding (solo para dominios públicos externos)
            if cfg.rebinding_protection && !is_internal_domain && !is_custom_allowed {
                if ips.iter().any(is_private_or_rebinding_ip) {
                    if let Ok(mut st) = stats_arc.lock() {
                        st.blocked_queries += 1;
                        st.rebinding_blocked += 1;
                    }
                    push_log(
                        logs_arc,
                        DnsQueryLog {
                            timestamp: Utc::now(),
                            domain: qname,
                            qtype: qtype_str,
                            action: "BLOCKED_REBINDING".to_string(),
                            reason: "Respuesta apunta a IP privada/loopback (DNS Rebinding)".to_string(),
                            upstream: format!("{:?}", cfg.transport),
                            latency_ms: start.elapsed().as_millis() as u64,
                            resolved_ips: ips.iter().map(|i| i.to_string()).collect(),
                        },
                    );
                    return build_nxdomain_response(query);
                }
            }

            if let Ok(mut cache) = cache_arc.lock() {
                cache.insert(
                    cache_key,
                    CachedDnsPacket {
                        wire_response: resp.clone(),
                        expires_at: Instant::now() + Duration::from_secs(60),
                    },
                );
            }

            push_log(
                logs_arc,
                DnsQueryLog {
                    timestamp: Utc::now(),
                    domain: qname,
                    qtype: qtype_str,
                    action: "ALLOWED".to_string(),
                    reason: "Resuelto por DNS cifrado".to_string(),
                    upstream: match cfg.transport {
                        DnsTransport::DoH => cfg.doh_url.clone(),
                        DnsTransport::DoT => format!("{}:{}", cfg.dot_host, cfg.dot_port),
                    },
                    latency_ms: start.elapsed().as_millis() as u64,
                    resolved_ips: ips.iter().map(|i| i.to_string()).collect(),
                },
            );
            resp
        }
        Err(e) => {
            if let Ok(mut st) = stats_arc.lock() {
                st.upstream_errors += 1;
                st.last_error = Some(e.to_string());
            }
            build_nxdomain_response(query)
        }
    }
}

fn record_block(
    stats_arc: &Arc<Mutex<DnsStats>>,
    logs_arc: &Arc<Mutex<VecDeque<DnsQueryLog>>>,
    domain: &str,
    qtype: &str,
    reason: &str,
    start: Instant,
) {
    if let Ok(mut st) = stats_arc.lock() {
        st.blocked_queries += 1;
    }
    push_log(
        logs_arc,
        DnsQueryLog {
            timestamp: Utc::now(),
            domain: domain.to_string(),
            qtype: qtype.to_string(),
            action: "BLOCKED".to_string(),
            reason: reason.to_string(),
            upstream: "LocalFilter".to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
            resolved_ips: Vec::new(),
        },
    );
}

fn push_log(logs_arc: &Arc<Mutex<VecDeque<DnsQueryLog>>>, entry: DnsQueryLog) {
    if let Ok(mut logs) = logs_arc.lock() {
        if logs.len() >= 500 {
            logs.pop_back();
        }
        logs.push_front(entry);
    }
}

/// Envía consulta DNS wire vía DNS-over-HTTPS (RFC 8484)
pub fn forward_doh(doh_url: &str, query: &[u8]) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(4))
        .timeout_read(Duration::from_secs(5))
        .build();

    let resp = agent
        .post(doh_url)
        .set("Content-Type", "application/dns-message")
        .set("Accept", "application/dns-message")
        .send_bytes(query)
        .map_err(|e| anyhow!("DoH error: {}", e))?;

    let mut bytes = Vec::with_capacity(512);
    resp.into_reader()
        .take(65536)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Envía consulta DNS wire vía DNS-over-TLS (RFC 7858, puerto 853)
pub fn forward_dot(host: &str, port: u16, query: &[u8]) -> Result<Vec<u8>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let server_name: ServerName<'static> = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("Hostname DoT inválido: {}", host))?;
    let mut conn = rustls::ClientConnection::new(config, server_name)?;

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            (host, port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("No se pudo resolver endpoint DoT"))
        })?;

    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(4))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let len_prefix = (query.len() as u16).to_be_bytes();
    tls.write_all(&len_prefix)?;
    tls.write_all(query)?;
    tls.flush()?;

    let mut resp_len_buf = [0u8; 2];
    tls.read_exact(&mut resp_len_buf)?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tls.read_exact(&mut resp)?;
    Ok(resp)
}
