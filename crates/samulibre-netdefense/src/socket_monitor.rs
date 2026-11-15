use crate::types::{NetworkConnectionEntry, RiskRecommendation};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Debug, Clone)]
struct CachedHashEntry {
    sha256: String,
    cached_at: Instant,
}

/// Monitor nativo de conexiones de red en tiempo real usando `iphlpapi.dll` (GetExtendedTcpTable / GetExtendedUdpTable).
/// Evita el spawn de subprocesos `netstat.exe` para mantener bajo consumo de CPU y latencia mínima.
pub struct SocketMonitor {
    system: System,
    hash_cache: HashMap<String, CachedHashEntry>,
    last_process_refresh: Instant,
}

impl SocketMonitor {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::All);
        Self {
            system,
            hash_cache: HashMap::new(),
            last_process_refresh: Instant::now(),
        }
    }

    /// Calcula (con caché TTL de 60s) el SHA-256 de un ejecutable para validar integridad de políticas por aplicación.
    pub fn get_executable_sha256(&mut self, exe_path: &str) -> Option<String> {
        if let Some(entry) = self.hash_cache.get(exe_path) {
            if entry.cached_at.elapsed() < Duration::from_secs(60) {
                return Some(entry.sha256.clone());
            }
        }

        let mut file = File::open(exe_path).ok()?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest = hex::encode(hasher.finalize());
        if self.hash_cache.len() > 2048 {
            self.hash_cache.clear();
        }
        self.hash_cache.insert(
            exe_path.to_string(),
            CachedHashEntry {
                sha256: digest.clone(),
                cached_at: Instant::now(),
            },
        );
        Some(digest)
    }

    pub fn refresh_processes_if_needed(&mut self) {
        if self.last_process_refresh.elapsed() >= Duration::from_secs(2) {
            self.system.refresh_processes(ProcessesToUpdate::All);
            self.last_process_refresh = Instant::now();
        }
    }

    pub fn resolve_process(&self, pid: u32) -> (String, Option<String>) {
        if pid == 0 {
            return ("System Idle".to_string(), None);
        }
        if pid == 4 {
            return ("System".to_string(), None);
        }
        if let Some(proc) = self.system.process(Pid::from_u32(pid)) {
            (
                proc.name().to_string_lossy().to_string(),
                proc.exe().map(|p| p.to_string_lossy().to_string()),
            )
        } else {
            (format!("PID {}", pid), None)
        }
    }

    /// Enumera todas las conexiones TCP y UDP (IPv4 e IPv6) activas en el sistema con su PID y ruta de ejecutable.
    pub fn snapshot_connections(&mut self) -> Vec<NetworkConnectionEntry> {
        self.refresh_processes_if_needed();
        let mut entries = Vec::new();
        let now = Utc::now();

        #[cfg(target_os = "windows")]
        {
            self.collect_tcp_v4(&mut entries, now);
            self.collect_tcp_v6(&mut entries, now);
            self.collect_udp_v4(&mut entries, now);
            self.collect_udp_v6(&mut entries, now);
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = now;
        }

        entries
    }

    #[cfg(target_os = "windows")]
    fn tcp_state_name(state: u32) -> &'static str {
        match state {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN",
        }
    }

    #[cfg(target_os = "windows")]
    fn port_from_dw(dw: u32) -> u16 {
        u16::from_be((dw & 0xFFFF) as u16)
    }

    #[cfg(target_os = "windows")]
    fn collect_tcp_v4(&self, out: &mut Vec<NetworkConnectionEntry>, now: chrono::DateTime<Utc>) {
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            let res = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if res != NO_ERROR.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
                return;
            }
            if res != NO_ERROR.0 {
                return;
            }
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                let local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr)));
                let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)));
                let local_port = Self::port_from_dw(row.dwLocalPort);
                let remote_port = Self::port_from_dw(row.dwRemotePort);
                let pid = row.dwOwningPid;
                let (app_name, app_path) = self.resolve_process(pid);
                out.push(Self::make_entry(
                    pid,
                    app_name,
                    app_path,
                    "TCP",
                    4,
                    local_ip.to_string(),
                    local_port,
                    remote_ip.to_string(),
                    remote_port,
                    Self::tcp_state_name(row.dwState).to_string(),
                    now,
                ));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_tcp_v6(&self, out: &mut Vec<NetworkConnectionEntry>, now: chrono::DateTime<Utc>) {
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            let res = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if res != NO_ERROR.0 {
                return;
            }
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
                let remote_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
                let local_port = Self::port_from_dw(row.dwLocalPort);
                let remote_port = Self::port_from_dw(row.dwRemotePort);
                let pid = row.dwOwningPid;
                let (app_name, app_path) = self.resolve_process(pid);
                out.push(Self::make_entry(
                    pid,
                    app_name,
                    app_path,
                    "TCP",
                    6,
                    local_ip.to_string(),
                    local_port,
                    remote_ip.to_string(),
                    remote_port,
                    Self::tcp_state_name(row.dwState).to_string(),
                    now,
                ));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_udp_v4(&self, out: &mut Vec<NetworkConnectionEntry>, now: chrono::DateTime<Utc>) {
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            let res = GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if res != NO_ERROR.0 {
                return;
            }
            let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                let local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr)));
                let local_port = Self::port_from_dw(row.dwLocalPort);
                let pid = row.dwOwningPid;
                let (app_name, app_path) = self.resolve_process(pid);
                out.push(Self::make_entry(
                    pid,
                    app_name,
                    app_path,
                    "UDP",
                    4,
                    local_ip.to_string(),
                    local_port,
                    "0.0.0.0".to_string(),
                    0,
                    "BOUND".to_string(),
                    now,
                ));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_udp_v6(&self, out: &mut Vec<NetworkConnectionEntry>, now: chrono::DateTime<Utc>) {
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            let res = GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if res != NO_ERROR.0 {
                return;
            }
            let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
                let local_port = Self::port_from_dw(row.dwLocalPort);
                let pid = row.dwOwningPid;
                let (app_name, app_path) = self.resolve_process(pid);
                out.push(Self::make_entry(
                    pid,
                    app_name,
                    app_path,
                    "UDP",
                    6,
                    local_ip.to_string(),
                    local_port,
                    "::".to_string(),
                    0,
                    "BOUND".to_string(),
                    now,
                ));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_entry(
        pid: u32,
        app_name: String,
        app_path: Option<String>,
        protocol: &str,
        ip_version: u8,
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
        state: String,
        now: chrono::DateTime<Utc>,
    ) -> NetworkConnectionEntry {
        let is_c2_port = matches!(remote_port, 1337 | 4444 | 4445 | 5555 | 6666 | 7777 | 8888 | 9999 | 31337);
        let is_risky_listen = state == "LISTEN" && matches!(local_port, 135 | 139 | 445 | 3389 | 5985 | 5986);
        let is_risky = is_c2_port || is_risky_listen;
        let risk_reason = if is_c2_port {
            Some(format!("Puerto remoto sospechoso C2 ({})", remote_port))
        } else if is_risky_listen {
            Some(format!("Puerto de servicio sensible expuesto ({})", local_port))
        } else {
            None
        };

        NetworkConnectionEntry {
            id: format!("{}-{}-{}:{}-{}:{}", protocol, pid, local_addr, local_port, remote_addr, remote_port),
            pid,
            app_name,
            app_path,
            protocol: protocol.to_string(),
            ip_version,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            domain: None,
            country_code: None,
            state,
            action_taken: "Monitoreada".to_string(),
            timestamp: now,
            bytes_sent: None,
            bytes_recv: None,
            is_risky,
            risk_reason: risk_reason.clone(),
            recommendation: if is_risky {
                RiskRecommendation::Review
            } else {
                RiskRecommendation::SafeLearned
            },
            risk_score: if is_c2_port { 70 } else if is_risky_listen { 45 } else { 0 },
            primary_reason: risk_reason.unwrap_or_else(|| "Conexión estándar monitoreada".to_string()),
            risk_factors: Vec::new(),
            suggested_action: if is_risky {
                "Revisar conexión".to_string()
            } else {
                "Permitir".to_string()
            },
        }
    }

    /// Cierra inmediatamente una conexión TCP IPv4 activa usando SetTcpEntry (MIB_TCP_STATE_DELETE_TCB = 12).
    #[cfg(target_os = "windows")]
    pub fn terminate_tcp_v4(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> anyhow::Result<()> {
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                dwState: 12, // MIB_TCP_STATE_DELETE_TCB
            },
            dwLocalAddr: u32::from_ne_bytes(local_ip.octets()),
            dwLocalPort: (local_port as u32).to_be() >> 16,
            dwRemoteAddr: u32::from_ne_bytes(remote_ip.octets()),
            dwRemotePort: (remote_port as u32).to_be() >> 16,
        };
        let ret = unsafe { SetTcpEntry(&row) };
        if ret == 0 {
            Ok(())
        } else {
            anyhow::bail!("SetTcpEntry retornó código {}", ret)
        }
    }

    /// Cierra todas las conexiones TCP IPv4 activas que coincidan con la IP/puerto remoto o ruta de aplicación.
    pub fn terminate_matching_connections(
        &mut self,
        target_ip: Option<&str>,
        target_port: Option<u16>,
        app_path: Option<&str>,
    ) -> usize {
        #[cfg(target_os = "windows")]
        {
            let conns = self.snapshot_connections();
            let mut closed = 0usize;
            for c in conns {
                if c.protocol != "TCP" || c.ip_version != 4 || c.state == "LISTEN" {
                    continue;
                }
                let ip_ok = target_ip.map(|ip| ip == c.remote_addr).unwrap_or(true);
                let port_ok = target_port.map(|p| p == c.remote_port).unwrap_or(true);
                let app_ok = match (app_path, c.app_path.as_deref()) {
                    (Some(ap), Some(cp)) => ap.eq_ignore_ascii_case(cp),
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                if ip_ok && port_ok && app_ok {
                    if let (Ok(lip), Ok(rip)) = (c.local_addr.parse::<Ipv4Addr>(), c.remote_addr.parse::<Ipv4Addr>()) {
                        if Self::terminate_tcp_v4(lip, c.local_port, rip, c.remote_port).is_ok() {
                            closed += 1;
                        }
                    }
                }
            }
            closed
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (target_ip, target_port, app_path);
            0
        }
    }
}
