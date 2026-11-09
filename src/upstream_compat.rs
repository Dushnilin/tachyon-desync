//! Слой совместимости для прямой компиляции апстримного движка `outbound/desync` и `outbound/tlsspoof`
//! из `tachyon-core` без единого изменения исходников апстрима и без включения прокси-крейтов.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// Индекс физического сетевого интерфейса по умолчанию (Windows) для исключения петли через Wintun.
pub static WIN_OUTBOUND_IF_INDEX: AtomicU32 = AtomicU32::new(0);

/// Индекс физического сетевого интерфейса по умолчанию (macOS) для исключения петли через utun.
pub static MACOS_OUTBOUND_IF_INDEX: AtomicU32 = AtomicU32::new(0);

/// Режим чистого DNS-резолвера (защита от подмены DNS-ответов):
/// 0 = system, 1 = auto (1253/5353 + 1.1.1.1 + 8.8.8.8), 2 = cloudflare, 3 = google, 4 = port1253.
pub static CLEAN_DNS_MODE: AtomicU32 = AtomicU32::new(1);

pub fn set_clean_dns_mode_from_str(mode: &str) {
    let val = match mode.trim().to_ascii_lowercase().as_str() {
        "system" | "off" => 0,
        "cloudflare" | "cf" => 2,
        "google" => 3,
        "port1253" | "altport" => 4,
        _ => 1,
    };
    CLEAN_DNS_MODE.store(val, Ordering::Relaxed);
}

/// Метка `SO_MARK` для исходящих сокетов на Linux.
pub const LINUX_BYPASS_SO_MARK: u32 = 0x2022;

/// Привязать исходящий сокет к физическому интерфейсу / метке маршрутизации для обхода TUN-петли.
pub fn bind_outbound_socket<'s, S: Into<socket2::SockRef<'s>>>(sock: S, is_ipv6: bool) {
    let sock = sock.into();
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let if_idx = WIN_OUTBOUND_IF_INDEX.load(Ordering::Relaxed);
        if if_idx != 0 {
            let raw = sock.as_raw_socket() as usize;
            unsafe {
                if !is_ipv6 {
                    const IPPROTO_IP: i32 = 0;
                    const IP_UNICAST_IF: i32 = 31;
                    let idx_be = if_idx.to_be();
                    let _ = windows_sys::Win32::Networking::WinSock::setsockopt(
                        raw,
                        IPPROTO_IP,
                        IP_UNICAST_IF,
                        &idx_be as *const _ as *const u8,
                        std::mem::size_of::<u32>() as i32,
                    );
                } else {
                    const IPPROTO_IPV6: i32 = 41;
                    const IPV6_UNICAST_IF: i32 = 31;
                    let _ = windows_sys::Win32::Networking::WinSock::setsockopt(
                        raw,
                        IPPROTO_IPV6,
                        IPV6_UNICAST_IF,
                        &if_idx as *const _ as *const u8,
                        std::mem::size_of::<u32>() as i32,
                    );
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = is_ipv6;
        let _ = sock.set_mark(LINUX_BYPASS_SO_MARK);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let if_idx = MACOS_OUTBOUND_IF_INDEX.load(Ordering::Relaxed);
        if if_idx != 0 {
            let fd = sock.as_raw_fd();
            unsafe {
                if !is_ipv6 {
                    const IP_BOUND_IF: libc::c_int = 25;
                    let _ = libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        IP_BOUND_IF,
                        &if_idx as *const _ as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    );
                } else {
                    const IPV6_BOUND_IF: libc::c_int = 125;
                    let _ = libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        IPV6_BOUND_IF,
                        &if_idx as *const _ as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    );
                }
            }
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (sock, is_ipv6);
    }
}

/// Модуль логирования, ожидаемый апстримным `engine.rs` (`crate::logging::debug`).
pub mod logging {
    #[inline]
    pub fn debug(_args: std::fmt::Arguments<'_>) {}
    #[inline]
    pub fn info(_args: std::fmt::Arguments<'_>) {}
    #[inline]
    pub fn warn(_args: std::fmt::Arguments<'_>) {}
}

/// Модуль постоянного хранилища `cache.db`, ожидаемый апстримным `engine.rs` (`crate::cache_file`).
pub mod cache_file {
    use super::*;
    use serde::{Deserialize, Serialize};

    pub const BUCKET_DESYNC: &str = "desync";
    pub type SharedCacheFile = Arc<Mutex<CacheFile>>;

    #[derive(Debug, Clone, Default)]
    pub struct CacheFileOptions {
        pub enabled: bool,
        pub path: String,
        pub flush_interval: std::time::Duration,
    }

    #[derive(Default, Serialize, Deserialize)]
    struct DiskBuckets {
        buckets: HashMap<String, HashMap<String, Vec<u8>>>,
    }

    pub struct CacheFile {
        path: Option<PathBuf>,
        data: DiskBuckets,
    }

    impl CacheFile {
        pub fn open(opts: CacheFileOptions) -> std::io::Result<Option<Self>> {
            if !opts.enabled || opts.path.is_empty() {
                return Ok(None);
            }
            let path = PathBuf::from(&opts.path);
            let data: DiskBuckets = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(Some(Self {
                path: Some(path),
                data,
            }))
        }

        pub fn open_shared(path: PathBuf) -> SharedCacheFile {
            let data: DiskBuckets = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Arc::new(Mutex::new(Self {
                path: Some(path),
                data,
            }))
        }

        pub fn flush(&mut self) -> std::io::Result<()> {
            self.flush_to_disk();
            Ok(())
        }

        pub fn flush_to_disk(&self) {
            if let Some(ref p) = self.path {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(json) = serde_json::to_string(&self.data) {
                    let _ = std::fs::write(p, json);
                }
            }
        }

        pub fn get(&self, bucket: &str, key: &[u8]) -> Option<Vec<u8>> {
            let k_str = String::from_utf8_lossy(key);
            self.data.buckets.get(bucket)?.get(k_str.as_ref()).cloned()
        }

        pub fn put(&mut self, bucket: &str, key: &[u8], val: Vec<u8>) {
            let k_str = String::from_utf8_lossy(key).into_owned();
            self.data
                .buckets
                .entry(bucket.to_string())
                .or_default()
                .insert(k_str, val);
            self.flush_to_disk();
        }

        pub fn delete(&mut self, bucket: &str, key: &[u8]) {
            let k_str = String::from_utf8_lossy(key);
            if let Some(b) = self.data.buckets.get_mut(bucket) {
                b.remove(k_str.as_ref());
                self.flush_to_disk();
            }
        }

        pub fn keys(&self, bucket: &str) -> Vec<String> {
            self.data
                .buckets
                .get(bucket)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        }

        pub fn raw_keys(&self, bucket: &str) -> Vec<Vec<u8>> {
            self.data
                .buckets
                .get(bucket)
                .map(|m| m.keys().map(|k| k.as_bytes().to_vec()).collect())
                .unwrap_or_default()
        }
    }
}

/// Модуль `crate::inbound`, ожидаемый апстримным `outbound/desync/mod.rs`.
pub mod inbound {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    #[derive(Debug, Clone)]
    pub enum Target {
        Ip(SocketAddr),
        Domain(String, u16),
    }

    pub enum Conn {
        Desync(Box<TcpStream>, Arc<crate::outbound::desync::DesyncConfig>),
    }
}

/// Минимальная чистая реализация `core_tls` для генерации шаблонов TLS 1.3 ClientHello в `tlsspoof.rs` и `payload.rs`
/// без подключения внешних TLS-крейтов.
pub mod core_tls {
    pub mod fingerprints {
        #[derive(Debug, Clone)]
        pub struct Template {
            pub include_mlkem: bool,
        }

        impl Template {
            pub fn without_mlkem_share(mut self) -> Result<Self, &'static str> {
                self.include_mlkem = false;
                Ok(self)
            }
        }

        pub fn chrome() -> Template {
            Template {
                include_mlkem: true,
            }
        }
    }

    pub mod hello {
        use super::fingerprints::Template;
        use std::io;

        #[derive(Debug, Clone)]
        pub struct ParsedHello {
            pub sni: String,
        }

        pub fn build(
            template: &Template,
            random: &[u8; 32],
            session_id: &[u8],
            sni: &str,
            alpn: &[&[u8]],
            _extra: Option<&[u8]>,
        ) -> io::Result<Vec<u8>> {
            let host_bytes = sni.trim().as_bytes();
            let host_len = host_bytes.len().min(253);
            let host_bytes = &host_bytes[..host_len];

            let mut x25519_pub = [0u8; 32];
            let _ = getrandom::fill(&mut x25519_pub);

            let mut exts = Vec::with_capacity(if template.include_mlkem { 1550 } else { 280 });
            // GREASE (0x1a1a)
            exts.extend_from_slice(&[0x1a, 0x1a, 0x00, 0x00]);

            // 1. server_name (0x0000)
            let sni_list_len = (host_len + 3) as u16;
            let sni_ext_len = sni_list_len + 2;
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&sni_ext_len.to_be_bytes());
            exts.extend_from_slice(&sni_list_len.to_be_bytes());
            exts.push(0x00);
            exts.extend_from_slice(&(host_len as u16).to_be_bytes());
            exts.extend_from_slice(host_bytes);

            // 2. extended_master_secret (0x0017) & renegotiation_info (0xff01)
            exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
            exts.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

            // 3. supported_groups (0x000a)
            exts.extend_from_slice(&[
                0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x2a, 0x2a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
            ]);

            // 4. ec_point_formats (0x000b) & session_ticket (0x0023)
            exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
            exts.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

            // 5. ALPN (0x0010)
            if !alpn.is_empty() {
                let mut alpn_list = Vec::new();
                for proto in alpn {
                    if !proto.is_empty() && proto.len() < 255 {
                        alpn_list.push(proto.len() as u8);
                        alpn_list.extend_from_slice(proto);
                    }
                }
                let list_len = alpn_list.len() as u16;
                let ext_len = list_len + 2;
                exts.extend_from_slice(&[0x00, 0x10]);
                exts.extend_from_slice(&ext_len.to_be_bytes());
                exts.extend_from_slice(&list_len.to_be_bytes());
                exts.extend_from_slice(&alpn_list);
            }

            // 6. status_request (0x0005) & signature_algorithms (0x000d)
            exts.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
            exts.extend_from_slice(&[
                0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
                0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
            ]);

            // 7. key_share (0x0033)
            if template.include_mlkem {
                // Гибридный X25519MLKEM768 (0x11ec, 1216 байт) + X25519 (0x001d, 32 байта)
                let mlkem_len: u16 = 1216;
                let x25519_len: u16 = 32;
                let shares_len: u16 = 4 + mlkem_len + 4 + x25519_len;
                let ext_len: u16 = 2 + shares_len;
                exts.extend_from_slice(&[0x00, 0x33]);
                exts.extend_from_slice(&ext_len.to_be_bytes());
                exts.extend_from_slice(&shares_len.to_be_bytes());
                // Share 1: X25519MLKEM768 (0x11ec)
                exts.extend_from_slice(&[0x11, 0xec]);
                exts.extend_from_slice(&mlkem_len.to_be_bytes());
                let mut pq_bytes = vec![0x5au8; mlkem_len as usize];
                let _ = getrandom::fill(&mut pq_bytes[..64]);
                exts.extend_from_slice(&pq_bytes);
                // Share 2: X25519 (0x001d)
                exts.extend_from_slice(&[0x00, 0x1d]);
                exts.extend_from_slice(&x25519_len.to_be_bytes());
                exts.extend_from_slice(&x25519_pub);
            } else {
                // Компактный односегментный X25519 (32 байта)
                exts.extend_from_slice(&[
                    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
                ]);
                exts.extend_from_slice(&x25519_pub);
            }

            // 8. psk_key_exchange_modes (0x002d) & supported_versions (0x002b)
            exts.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);
            exts.extend_from_slice(&[
                0x00, 0x2b, 0x00, 0x07, 0x06, 0x3a, 0x3a, 0x03, 0x04, 0x03, 0x03,
            ]);

            let cipher_suites: &[u8] = &[
                0x4a, 0x4a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8,
            ];

            let sid_len = session_id.len().min(32);
            let mut ch_body = Vec::with_capacity(64 + cipher_suites.len() + exts.len());
            ch_body.extend_from_slice(&[0x03, 0x03]);
            ch_body.extend_from_slice(random);
            ch_body.push(sid_len as u8);
            ch_body.extend_from_slice(&session_id[..sid_len]);
            ch_body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
            ch_body.extend_from_slice(cipher_suites);
            ch_body.extend_from_slice(&[0x01, 0x00]);
            ch_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            ch_body.extend_from_slice(&exts);

            let hs_len = ch_body.len();
            let rec_len = hs_len + 4;
            let mut out = Vec::with_capacity(5 + rec_len);
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(rec_len as u16).to_be_bytes());
            out.push(0x01);
            out.push(((hs_len >> 16) & 0xFF) as u8);
            out.push(((hs_len >> 8) & 0xFF) as u8);
            out.push((hs_len & 0xFF) as u8);
            out.extend_from_slice(&ch_body);
            Ok(out)
        }

        pub fn parse_record(buf: &[u8]) -> io::Result<ParsedHello> {
            if buf.len() < 43 || buf[0] != 0x16 || buf[1] != 0x03 || buf[5] != 0x01 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not a TLS ClientHello record",
                ));
            }
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if 5 + rec_len != buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record length mismatch",
                ));
            }
            let hs_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | (buf[8] as usize);
            if 4 + hs_len != rec_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "handshake length mismatch",
                ));
            }
            let Some(m) = crate::outbound::desync::packet::find_sni(buf) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "SNI not found"));
            };
            Ok(ParsedHello {
                sni: m.host.to_string(),
            })
        }
    }
}

/// Модуль `crate::outbound`, включающий `dial`, апстримный `tlsspoof` и апстримный `desync`.
pub mod outbound {
    use super::*;

    pub mod dial {
        use super::*;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct DialOptions {
            pub connect_timeout_ms: Option<u64>,
        }

        impl DialOptions {
            pub fn parse(
                _obj: &serde_json::Map<String, serde_json::Value>,
            ) -> Result<Self, String> {
                Ok(Self::default())
            }
        }

        type DnsCacheMap = HashMap<String, (Vec<Ipv4Addr>, std::time::Instant)>;
        static DNS_CACHE: std::sync::OnceLock<Mutex<DnsCacheMap>> = std::sync::OnceLock::new();

        fn dns_cache() -> &'static Mutex<DnsCacheMap> {
            DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
        }

        fn active_dns_servers() -> &'static [SocketAddr] {
            const AUTO_SERVERS: &[SocketAddr] = &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)), 1253),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), 5353),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)), 53),
            ];
            const CF_SERVERS: &[SocketAddr] = &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), 5353),
            ];
            const GOOGLE_SERVERS: &[SocketAddr] = &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)), 1253),
            ];
            const ALTPORT_SERVERS: &[SocketAddr] = &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)), 1253),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), 5353),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)), 5353),
            ];
            match CLEAN_DNS_MODE.load(Ordering::Relaxed) {
                2 => CF_SERVERS,
                3 => GOOGLE_SERVERS,
                4 => ALTPORT_SERVERS,
                _ => AUTO_SERVERS,
            }
        }

        pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if let Ok(ip) = clean.parse::<IpAddr>() {
                return Ok(vec![SocketAddr::new(ip, port)]);
            }

            // 0. Проверяем пользовательские DNS-переопределения (домен=IP / локальный hosts)
            if let Some(ov_ip) = crate::lists::lookup_custom_dns_override(&clean) {
                crate::lists::record_dns_mapping(ov_ip, &clean);
                return Ok(vec![SocketAddr::new(ov_ip, port)]);
            }

            let dns_mode = CLEAN_DNS_MODE.load(Ordering::Relaxed);

            // 1. Проверяем быстрый кэш в памяти (TTL 240 с)
            if let Ok(guard) = dns_cache().lock()
                && let Some((cached_ips, ts)) = guard.get(&clean)
                && ts.elapsed() < Duration::from_secs(240)
                && !cached_ips.is_empty()
            {
                return Ok(cached_ips
                    .iter()
                    .map(|&ip| SocketAddr::new(IpAddr::V4(ip), port))
                    .collect());
            }

            // 2. Если включён Чистый DNS (dns_mode != 0) или активен режим TUN, сначала выполняем
            // прямой анти-спуфинг запрос к внешним резолверам в обход системного Dnscache
            if (dns_mode != 0 || WIN_OUTBOUND_IF_INDEX.load(Ordering::Relaxed) != 0)
                && let Ok(ips) = direct_dns_query_v4(&clean).await
                && !ips.is_empty()
            {
                if let Ok(mut guard) = dns_cache().lock() {
                    if guard.len() > 2048 {
                        guard.clear();
                    }
                    guard.insert(clean.clone(), (ips.clone(), std::time::Instant::now()));
                }
                return Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
                    .collect());
            }

            if let Ok(iter) = tokio::net::lookup_host(format!("{clean}:{port}")).await {
                let addrs: Vec<SocketAddr> = iter
                    .filter(|a| {
                        if clean.eq_ignore_ascii_case("localhost") {
                            return true;
                        }
                        if a.ip().is_loopback() || a.ip().is_unspecified() {
                            return false;
                        }
                        if let IpAddr::V4(v4) = a.ip()
                            && is_fake_ip_v4(v4)
                        {
                            return false;
                        }
                        true
                    })
                    .collect();
                if !addrs.is_empty() {
                    return Ok(addrs);
                }
            }

            // Резервный прямой DNS-резолвер (RFC 1035 A-запрос к 77.88.8.8:1253 / 208.67.222.222:5353 / 8.8.8.8:53),
            // если системный DNS вернул WSANO_DATA (11004), FakeIP (198.18.0.0/15), NXDOMAIN или заглушку.
            let fallback_ips = direct_dns_query_v4(&clean).await?;
            if fallback_ips.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("DNS returned no addresses for {clean}"),
                ));
            }
            if let Ok(mut guard) = dns_cache().lock() {
                guard.insert(
                    clean.clone(),
                    (fallback_ips.clone(), std::time::Instant::now()),
                );
            }
            Ok(fallback_ips
                .into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
                .collect())
        }

        /// Переслать сырой DNS-пакет (UDP/53 из TUN) через чистые резолверы с фильтрацией подменённых/FakeIP ответов.
        pub async fn forward_clean_dns_udp_packet(
            query_pkt: &[u8],
            orig_dst: SocketAddr,
        ) -> io::Result<Vec<u8>> {
            // 0. Проверяем пользовательские DNS-переопределения (домен=IP): мгновенный синтетический ответ
            if let Some((qname, qtype, qend)) = parse_dns_question_section(query_pkt)
                && let Some(IpAddr::V4(v4)) = crate::lists::lookup_custom_dns_override(&qname)
                && qtype == 1
            {
                crate::lists::record_dns_mapping(IpAddr::V4(v4), &qname);
                return Ok(build_synthetic_dns_a_response(query_pkt, qend, v4));
            }

            let raw_sock = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            bind_outbound_socket(&raw_sock, false);
            raw_sock.set_nonblocking(true)?;
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            raw_sock.bind(&bind_addr.into())?;
            let std_udp: std::net::UdpSocket = raw_sock.into();
            let sock = UdpSocket::from_std(std_udp)?;

            if CLEAN_DNS_MODE.load(Ordering::Relaxed) != 0 {
                for &srv in active_dns_servers() {
                    let _ = sock.send_to(query_pkt, srv).await;
                }
            }
            if orig_dst.is_ipv4() {
                let _ = sock.send_to(query_pkt, orig_dst).await;
            }

            let mut buf = [0u8; 1500];
            let mut fallback_pkt: Option<Vec<u8>> = None;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(1600);
            while tokio::time::Instant::now() < deadline {
                let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                let Ok(Ok((n, _))) = tokio::time::timeout(rem, sock.recv_from(&mut buf)).await
                else {
                    break;
                };
                if n < 12 {
                    continue;
                }
                let pkt = &buf[..n];
                crate::lists::snoop_dns_response_packet(pkt);
                let a_ips = parse_dns_a_records(pkt);
                if !a_ips.iter().any(|&ip| is_fake_ip_v4(ip)) {
                    return Ok(pkt.to_vec());
                }
                if fallback_pkt.is_none() {
                    fallback_pkt = Some(pkt.to_vec());
                }
            }
            fallback_pkt.ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS timeout"))
        }

        #[inline]
        fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
            let oct = ip.octets();
            oct[0] == 198 && (oct[1] == 18 || oct[1] == 19)
        }

        fn parse_dns_question_section(pkt: &[u8]) -> Option<(String, u16, usize)> {
            if pkt.len() < 17 {
                return None;
            }
            let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
            if qdcount == 0 {
                return None;
            }
            let mut pos = 12usize;
            let mut labels = Vec::with_capacity(4);
            while pos < pkt.len() {
                let len = pkt[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len > 63 || pos + 1 + len > pkt.len() {
                    return None;
                }
                if let Ok(s) = std::str::from_utf8(&pkt[pos + 1..pos + 1 + len]) {
                    labels.push(s.to_ascii_lowercase());
                } else {
                    return None;
                }
                pos += 1 + len;
            }
            if pos + 4 > pkt.len() || labels.is_empty() {
                return None;
            }
            let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
            Some((labels.join("."), qtype, pos + 4))
        }

        fn build_synthetic_dns_a_response(query_pkt: &[u8], qend: usize, ip: Ipv4Addr) -> Vec<u8> {
            let mut resp = Vec::with_capacity(qend + 16);
            resp.extend_from_slice(&query_pkt[..qend]);
            // Flags: QR=1, RD=1, RA=1, RCODE=0 (0x8180)
            resp[2] = 0x81;
            resp[3] = 0x80;
            // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
            resp[4] = 0x00;
            resp[5] = 0x01;
            resp[6] = 0x00;
            resp[7] = 0x01;
            resp[8] = 0x00;
            resp[9] = 0x00;
            resp[10] = 0x00;
            resp[11] = 0x00;
            // Answer RR: Name pointer 0xC00C, Type A (1), Class IN (1), TTL 120s, RDLENGTH 4, RDATA
            resp.extend_from_slice(&[
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,
            ]);
            resp.extend_from_slice(&ip.octets());
            resp
        }

        async fn direct_dns_query_v4(host: &str) -> io::Result<Vec<Ipv4Addr>> {
            let mut pkt = Vec::with_capacity(64);
            // Header: ID=0x5444, Flags=0x0100 (RD=1), QDCOUNT=1
            pkt.extend_from_slice(&[
                0x54, 0x44, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
            for label in host.split('.') {
                let b = label.as_bytes();
                if b.is_empty() || b.len() > 63 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid domain",
                    ));
                }
                pkt.push(b.len() as u8);
                pkt.extend_from_slice(b);
            }
            pkt.push(0x00);
            // QTYPE = A (1), QCLASS = IN (1)
            pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

            let servers = active_dns_servers();

            let raw_sock = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            bind_outbound_socket(&raw_sock, false);
            raw_sock.set_nonblocking(true)?;
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            raw_sock.bind(&bind_addr.into())?;
            let std_udp: std::net::UdpSocket = raw_sock.into();
            let sock = UdpSocket::from_std(std_udp)?;
            for &srv in servers {
                let _ = sock.send_to(&pkt, srv).await;
            }

            let mut buf = [0u8; 512];
            let mut fake_fallback = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
            while tokio::time::Instant::now() < deadline {
                let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                let Ok(Ok((n, _))) = tokio::time::timeout(rem, sock.recv_from(&mut buf)).await
                else {
                    break;
                };
                if n < 12 {
                    continue;
                }
                crate::lists::snoop_dns_response_packet(&buf[..n]);
                let ips = parse_dns_a_records(&buf[..n]);
                let real_ips: Vec<Ipv4Addr> = ips
                    .iter()
                    .copied()
                    .filter(|&ip| !is_fake_ip_v4(ip))
                    .collect();
                if !real_ips.is_empty() {
                    return Ok(real_ips);
                }
                if fake_fallback.is_empty() && !ips.is_empty() {
                    fake_fallback = ips;
                }
            }
            if !fake_fallback.is_empty() {
                return Ok(fake_fallback);
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Direct DNS lookup failed for {host}"),
            ))
        }

        fn parse_dns_a_records(pkt: &[u8]) -> Vec<Ipv4Addr> {
            let mut out = Vec::new();
            if pkt.len() < 12 {
                return out;
            }
            let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
            let mut pos = 12usize;

            for _ in 0..qdcount {
                pos = match skip_dns_name(pkt, pos) {
                    Some(p) if p + 4 <= pkt.len() => p + 4,
                    _ => return out,
                };
            }
            for _ in 0..ancount {
                pos = match skip_dns_name(pkt, pos) {
                    Some(p) => p,
                    None => break,
                };
                if pos + 10 > pkt.len() {
                    break;
                }
                let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
                pos += 10;
                if pos + rdlen > pkt.len() {
                    break;
                }
                if rtype == 1 && rdlen == 4 {
                    let ip = Ipv4Addr::new(pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]);
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        out.push(ip);
                    }
                }
                pos += rdlen;
            }
            out
        }

        fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
            let mut jumps = 0usize;
            while pos < pkt.len() {
                let b = pkt[pos];
                if b == 0 {
                    return Some(pos + 1);
                }
                if (b & 0xC0) == 0xC0 {
                    if pos + 2 > pkt.len() {
                        return None;
                    }
                    return Some(pos + 2);
                }
                let len = (b & 0x3F) as usize;
                pos = pos.checked_add(1 + len)?;
                jumps += 1;
                if jumps > 64 {
                    return None;
                }
            }
            None
        }

        pub async fn connect_tcp_addr(
            dst: SocketAddr,
            dial: &DialOptions,
        ) -> io::Result<TcpStream> {
            let timeout = Duration::from_millis(dial.connect_timeout_ms.unwrap_or(4500));
            let sock = if dst.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            bind_outbound_socket(&sock, dst.is_ipv6());
            let _ = sock.set_nodelay(true);

            tokio::time::timeout(timeout, sock.connect(dst))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))?
        }

        pub async fn connect_tcp(
            host: &str,
            port: u16,
            dial: &DialOptions,
        ) -> io::Result<TcpStream> {
            let addrs = resolve(host, port).await?;
            let target = addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.first())
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
            connect_tcp_addr(target, dial).await
        }

        pub async fn connect_udp(dst: SocketAddr, _dial: &DialOptions) -> io::Result<UdpSocket> {
            let domain = if dst.is_ipv6() {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            };
            let sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            bind_outbound_socket(&sock, dst.is_ipv6());
            sock.set_nonblocking(true)?;
            let bind_addr: SocketAddr = if dst.is_ipv6() {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            };
            sock.bind(&bind_addr.into())?;
            sock.connect(&dst.into())?;
            let std_udp: std::net::UdpSocket = sock.into();
            UdpSocket::from_std(std_udp)
        }
    }

    include!(concat!(env!("OUT_DIR"), "/upstream_desync/bridge.rs"));
}
