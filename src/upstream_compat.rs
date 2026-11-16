//! Слой совместимости для прямой компиляции апстримного движка `outbound/desync` и `outbound/tlsspoof`
//! из `tachyon-core` без единого изменения исходников апстрима и без включения прокси-крейтов.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// Индекс физического сетевого интерфейса по умолчанию (Windows) для исключения петли через Wintun.
pub static WIN_OUTBOUND_IF_INDEX: AtomicU32 = AtomicU32::new(0);

/// Индекс физического сетевого интерфейса по умолчанию (macOS) для исключения петли через utun.
pub static MACOS_OUTBOUND_IF_INDEX: AtomicU32 = AtomicU32::new(0);

/// Признак активного режима `auto_route` на Linux `tun` (`1` = активен, `0` = выключен).
pub static LINUX_TUN_AUTO_ROUTE_ACTIVE: AtomicU32 = AtomicU32::new(0);

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

/// Вспомогательные монотонные часы, ожидаемые апстримным `tlsspoof.rs` (`crate::util::mono_now_ms`).
pub mod util {
    use std::sync::OnceLock;
    use std::time::Instant;

    #[inline]
    pub fn mono_now_ms() -> u64 {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
    }
}

/// Режим алгоритма контроля перегрузки TCP (`smoltcp` в TUN и Linux `TCP_CONGESTION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TcpCongestionMode {
    /// Целочисленный BBR без плавающей точки (`vendor/smoltcp`, по умолчанию в ядре 0.5.7+).
    #[default]
    Bbr,
    Cubic,
    Reno,
    None,
}

impl TcpCongestionMode {
    pub const ALL: [Self; 4] = [Self::Bbr, Self::Cubic, Self::Reno, Self::None];

    pub fn from_code(code: &str) -> Self {
        match code.trim().to_ascii_lowercase().as_str() {
            "cubic" => Self::Cubic,
            "reno" | "new_reno" | "newreno" => Self::Reno,
            "none" | "off" => Self::None,
            _ => Self::Bbr,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::Reno => "reno",
            Self::None => "none",
        }
    }

    pub fn label_ru(self) -> &'static str {
        match self {
            Self::Bbr => "BBR (целочисленный)",
            Self::Cubic => "CUBIC",
            Self::Reno => "NewReno",
            Self::None => "Без ограничения",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Self::Bbr => "BBR (Integer)",
            Self::Cubic => "CUBIC",
            Self::Reno => "NewReno",
            Self::None => "No Control",
        }
    }
}

/// Профиль размера TCP-буферов `smoltcp` (`set_auto_tune_max`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunBufferMode {
    /// Адаптивный подбор по ОЗУ и числу активных потоков (`64 KiB` -> `1..2 MiB`).
    #[default]
    Auto,
    /// Экономный профиль для систем с малым объёмом памяти (`32 KiB` -> `256 KiB`).
    Eco32k,
    /// Сбалансированный профиль (`64 KiB` -> `512 KiB`).
    Balanced64k,
    /// Скоростной профиль для 4K/8K потоков и высокоскоростных каналов (`128 KiB` -> `2 MiB`).
    Turbo2m,
}

impl TunBufferMode {
    pub const ALL: [Self; 4] = [Self::Auto, Self::Eco32k, Self::Balanced64k, Self::Turbo2m];

    pub fn label_ru(self) -> &'static str {
        match self {
            Self::Auto => "Авто (по RAM)",
            Self::Eco32k => "Экономный (32 KiB)",
            Self::Balanced64k => "Сбалансированный (64..512 KiB)",
            Self::Turbo2m => "Турбо 4K/8K (до 2 MiB)",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Self::Auto => "Auto (by RAM)",
            Self::Eco32k => "Eco (32 KiB)",
            Self::Balanced64k => "Balanced (64..512 KiB)",
            Self::Turbo2m => "Turbo 4K/8K (up to 2 MiB)",
        }
    }
}

/// Гибкие настройки сетевого стека и производительности ядра `tachyon-core 0.5.7+`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NetworkTuningConfig {
    pub tcp_congestion: TcpCongestionMode,
    pub tun_buffer_mode: TunBufferMode,
    pub tun_mss_clamp: bool,
    pub tun_mtu: u16,
    pub tun_ipv6: bool,
    pub happy_eyeballs: bool,
    pub quic_fast_failover: bool,
    pub stream_verify_192k: bool,
}

impl Default for NetworkTuningConfig {
    fn default() -> Self {
        Self {
            tcp_congestion: TcpCongestionMode::Bbr,
            tun_buffer_mode: TunBufferMode::Auto,
            tun_mss_clamp: true,
            tun_mtu: 1420,
            tun_ipv6: false,
            happy_eyeballs: true,
            quic_fast_failover: true,
            stream_verify_192k: false,
        }
    }
}

pub static ACTIVE_TCP_CONGESTION: AtomicU8 = AtomicU8::new(0);
pub static ACTIVE_TUN_BUFFER_MODE: AtomicU8 = AtomicU8::new(0);
pub static ACTIVE_TUN_MSS_CLAMP: AtomicBool = AtomicBool::new(true);
pub static ACTIVE_TUN_MTU: AtomicU16 = AtomicU16::new(1420);
pub static ACTIVE_TUN_IPV6: AtomicBool = AtomicBool::new(false);
pub static ACTIVE_HAPPY_EYEBALLS: AtomicBool = AtomicBool::new(true);
pub static ACTIVE_QUIC_FAST_FAILOVER: AtomicBool = AtomicBool::new(true);

pub fn sanitize_network_tuning(cfg: &mut NetworkTuningConfig) -> bool {
    let mut changed = false;
    let clamped_mtu = cfg.tun_mtu.clamp(1280, 9000);
    if clamped_mtu != cfg.tun_mtu {
        cfg.tun_mtu = clamped_mtu;
        changed = true;
    }
    changed
}

pub fn apply_network_tuning(cfg: &NetworkTuningConfig) {
    let cc = match cfg.tcp_congestion {
        TcpCongestionMode::Bbr => 0,
        TcpCongestionMode::Cubic => 1,
        TcpCongestionMode::Reno => 2,
        TcpCongestionMode::None => 3,
    };
    ACTIVE_TCP_CONGESTION.store(cc, Ordering::Release);
    let bm = match cfg.tun_buffer_mode {
        TunBufferMode::Auto => 0,
        TunBufferMode::Eco32k => 1,
        TunBufferMode::Balanced64k => 2,
        TunBufferMode::Turbo2m => 3,
    };
    ACTIVE_TUN_BUFFER_MODE.store(bm, Ordering::Release);
    ACTIVE_TUN_MSS_CLAMP.store(cfg.tun_mss_clamp, Ordering::Release);
    ACTIVE_TUN_MTU.store(cfg.tun_mtu.clamp(1280, 9000), Ordering::Release);
    ACTIVE_TUN_IPV6.store(cfg.tun_ipv6, Ordering::Release);
    ACTIVE_HAPPY_EYEBALLS.store(cfg.happy_eyeballs, Ordering::Release);
    ACTIVE_QUIC_FAST_FAILOVER.store(cfg.quic_fast_failover, Ordering::Release);
}

#[inline]
pub fn active_tcp_congestion_mode() -> TcpCongestionMode {
    match ACTIVE_TCP_CONGESTION.load(Ordering::Acquire) {
        1 => TcpCongestionMode::Cubic,
        2 => TcpCongestionMode::Reno,
        3 => TcpCongestionMode::None,
        _ => TcpCongestionMode::Bbr,
    }
}

#[inline]
pub fn active_tun_buffer_mode() -> TunBufferMode {
    match ACTIVE_TUN_BUFFER_MODE.load(Ordering::Acquire) {
        1 => TunBufferMode::Eco32k,
        2 => TunBufferMode::Balanced64k,
        3 => TunBufferMode::Turbo2m,
        _ => TunBufferMode::Auto,
    }
}

/// Профиль аппаратных ресурсов (`tachyon-core` parity): детекция ОЗУ, ядер CPU и авто-подбор буферов.
pub mod hardware {
    use super::*;
    use std::sync::OnceLock;

    #[derive(Debug, Clone, Copy)]
    pub struct HardwareProfile {
        pub total_ram_mb: u64,
        pub cpu_count: usize,
        pub tun_max_tcp_sessions: usize,
    }

    static LAST_CONNECT_RTT_US: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub fn record_connect_rtt_us(us: u64) {
        if us > 0 {
            LAST_CONNECT_RTT_US.store(us, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn last_connect_rtt_us() -> u64 {
        LAST_CONNECT_RTT_US.load(Ordering::Relaxed)
    }

    fn detect_total_ram_mb() -> u64 {
        #[cfg(target_os = "windows")]
        {
            #[repr(C)]
            struct MemoryStatusEx {
                dw_length: u32,
                dw_memory_load: u32,
                ull_total_phys: u64,
                ull_avail_phys: u64,
                ull_total_page_file: u64,
                ull_avail_page_file: u64,
                ull_total_virtual: u64,
                ull_avail_virtual: u64,
                ull_avail_extended_virtual: u64,
            }
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
            }
            let mut st: MemoryStatusEx = unsafe { std::mem::zeroed() };
            st.dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
            if unsafe { GlobalMemoryStatusEx(&mut st) } != 0 && st.ull_total_phys > 0 {
                return (st.ull_total_phys / (1024 * 1024)).max(64);
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if let Some(rest) = line.strip_prefix("MemTotal:") {
                        if let Some(kb_str) = rest.split_whitespace().next()
                            && let Ok(kb) = kb_str.parse::<u64>()
                        {
                            return (kb / 1024).max(64);
                        }
                    }
                }
            }
        }
        2048
    }

    impl HardwareProfile {
        #[inline]
        pub fn detect() -> &'static Self {
            static PROFILE: OnceLock<HardwareProfile> = OnceLock::new();
            PROFILE.get_or_init(|| {
                let total_ram_mb = detect_total_ram_mb();
                let cpu_count = std::thread::available_parallelism()
                    .map(std::num::NonZeroUsize::get)
                    .unwrap_or(2);
                let tun_max_tcp_sessions = if total_ram_mb < 96 {
                    256
                } else if total_ram_mb <= 256 {
                    944
                } else if total_ram_mb < 1500 {
                    2048
                } else {
                    4096
                };
                Self {
                    total_ram_mb,
                    cpu_count,
                    tun_max_tcp_sessions,
                }
            })
        }

        #[inline]
        pub fn current_tun_max_tcp_sessions(&self) -> usize {
            self.tun_max_tcp_sessions
        }
    }

    pub fn smol_tcp_init_buf() -> usize {
        match super::active_tun_buffer_mode() {
            super::TunBufferMode::Eco32k => 32 * 1024,
            super::TunBufferMode::Balanced64k | super::TunBufferMode::Auto => {
                if HardwareProfile::detect().total_ram_mb < 128 {
                    32 * 1024
                } else {
                    64 * 1024
                }
            }
            super::TunBufferMode::Turbo2m => 128 * 1024,
        }
    }

    pub fn smol_tcp_max_buf() -> usize {
        match super::active_tun_buffer_mode() {
            super::TunBufferMode::Eco32k => 256 * 1024,
            super::TunBufferMode::Balanced64k => 512 * 1024,
            super::TunBufferMode::Turbo2m => 2 * 1024 * 1024,
            super::TunBufferMode::Auto => {
                let ram = HardwareProfile::detect().total_ram_mb as usize;
                if ram < 128 {
                    512 * 1024
                } else if ram <= 512 {
                    1024 * 1024
                } else {
                    ((ram.saturating_mul(4096)).next_power_of_two())
                        .clamp(1024 * 1024, 2 * 1024 * 1024)
                }
            }
        }
    }

    pub fn smol_tcp_fair_max_buf(active_streams: usize) -> usize {
        let base_max = smol_tcp_max_buf();
        if active_streams <= 1 {
            return base_max;
        }
        let ram = HardwareProfile::detect().total_ram_mb;
        let stack_cap = if ram < 128 {
            1024 * 1024
        } else if ram <= 512 {
            2 * 1024 * 1024
        } else {
            8 * 1024 * 1024
        };
        let budget = base_max.saturating_mul(2).min(stack_cap);
        let per_sock = (budget / active_streams).next_power_of_two();
        per_sock.clamp(smol_tcp_init_buf(), base_max)
    }
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
        pub buffer_size: usize,
    }

    #[derive(Default, Serialize, Deserialize)]
    struct DiskBuckets {
        buckets: HashMap<String, HashMap<String, Vec<u8>>>,
    }

    pub struct CacheFile {
        path: Option<PathBuf>,
        data: DiskBuckets,
        last_flush: std::time::Instant,
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
                last_flush: std::time::Instant::now(),
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
                last_flush: std::time::Instant::now(),
            }))
        }

        pub fn flush(&mut self) -> std::io::Result<()> {
            self.flush_to_disk();
            self.last_flush = std::time::Instant::now();
            Ok(())
        }

        pub fn flush_to_disk(&self) {
            if let Some(ref p) = self.path {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(json) = serde_json::to_string(&self.data) {
                    let tmp = p.with_extension("json.tmp");
                    if std::fs::write(&tmp, &json).is_ok() {
                        if std::fs::rename(&tmp, p).is_err() {
                            let _ = std::fs::write(p, &json);
                            let _ = std::fs::remove_file(&tmp);
                        }
                    } else {
                        let _ = std::fs::write(p, &json);
                    }
                }
            }
        }

        fn maybe_flush_throttled(&mut self) {
            if self.last_flush.elapsed() >= Duration::from_secs(10) {
                self.flush_to_disk();
                self.last_flush = std::time::Instant::now();
            }
        }

        pub fn get(&self, bucket: &str, key: &[u8]) -> Option<Vec<u8>> {
            let k_str = String::from_utf8_lossy(key);
            self.data.buckets.get(bucket)?.get(k_str.as_ref()).cloned()
        }

        pub fn contains_key(&self, bucket: &str, key: &[u8]) -> bool {
            let k_str = String::from_utf8_lossy(key);
            self.data
                .buckets
                .get(bucket)
                .is_some_and(|b| b.contains_key(k_str.as_ref()))
        }

        pub fn bucket_len(&self, bucket: &str) -> usize {
            self.data.buckets.get(bucket).map_or(0, HashMap::len)
        }

        pub fn put(&mut self, bucket: &str, key: &[u8], val: Vec<u8>) {
            let k_str = String::from_utf8_lossy(key).into_owned();
            self.data
                .buckets
                .entry(bucket.to_string())
                .or_default()
                .insert(k_str, val);
            self.maybe_flush_throttled();
        }

        pub fn delete(&mut self, bucket: &str, key: &[u8]) {
            let k_str = String::from_utf8_lossy(key);
            if let Some(b) = self.data.buckets.get_mut(bucket) {
                b.remove(k_str.as_ref());
                self.maybe_flush_throttled();
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

/// Модуль `crate::inbound`, ожидаемый апстримными `outbound/desync/mod.rs` и `outbound/tlsspoof.rs`.
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

    pub mod tun {
        use std::sync::atomic::Ordering;

        #[inline]
        pub fn active_auto_route_mark() -> Option<u32> {
            if crate::upstream_compat::LINUX_TUN_AUTO_ROUTE_ACTIVE.load(Ordering::Acquire) > 0 {
                Some(crate::upstream_compat::LINUX_BYPASS_SO_MARK)
            } else {
                None
            }
        }
    }
}

/// Минимальный модуль `crate::dns`, ожидаемый апстримным `outbound/desync/mod.rs`.
pub mod dns {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub enum Strategy {
        PreferIPv4,
        PreferIPv6,
        IPv4Only,
        IPv6Only,
    }

    pub struct DnsServiceStub(pub Strategy);

    impl DnsServiceStub {
        #[inline]
        pub fn strategy(&self) -> Strategy {
            self.0
        }
    }

    #[inline]
    pub fn current() -> Option<DnsServiceStub> {
        crate::dns_resolver::active_upstream_dns_strategy().map(DnsServiceStub)
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
        pub use super::fingerprints::Template;
        use std::io;

        /// Нормализовать имя хоста для TLS SNI: убрать внешние `[...]` и `%zone_id` для IPv6.
        pub fn normalize_server_name(raw: &str) -> &str {
            let trimmed = raw.trim();
            let unbracketed = trimmed
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .unwrap_or(trimmed);
            if let Some((addr, _zone)) = unbracketed.split_once('%')
                && addr.parse::<std::net::IpAddr>().is_ok()
            {
                addr
            } else {
                unbracketed
            }
        }

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

            // 1. server_name (0x0000) — опускается при пустом SNI (`sni_del` / ECH-only)
            if !host_bytes.is_empty() {
                let sni_list_len = (host_len + 3) as u16;
                let sni_ext_len = sni_list_len + 2;
                exts.extend_from_slice(&[0x00, 0x00]);
                exts.extend_from_slice(&sni_ext_len.to_be_bytes());
                exts.extend_from_slice(&sni_list_len.to_be_bytes());
                exts.push(0x00);
                exts.extend_from_slice(&(host_len as u16).to_be_bytes());
                exts.extend_from_slice(host_bytes);
            }

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

            // 9. encrypted_client_hello GREASE (0xfe0d, RFC 9849) для идентичности с Chrome uTLS
            let mut ech_rand = [0u8; 65];
            let _ = getrandom::fill(&mut ech_rand);
            exts.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x4a, 0x00, 0x00, 0x01, 0x00, 0x01]);
            exts.push(ech_rand[0]);
            exts.extend_from_slice(&[0x00, 0x20]);
            exts.extend_from_slice(&ech_rand[1..33]);
            exts.extend_from_slice(&[0x00, 0x20]);
            exts.extend_from_slice(&ech_rand[33..65]);

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
        use std::future::Future;

        const DEFAULT_FALLBACK_DELAY: Duration = Duration::from_millis(300);

        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct DialOptions {
            pub connect_timeout_ms: Option<u64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub connect_timeout: Option<Duration>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub domain_strategy: Option<crate::dns::Strategy>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub fallback_delay: Option<Duration>,
            #[serde(default)]
            pub parallel: bool,
            #[serde(default)]
            pub disable_tcp_keep_alive: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tcp_keep_alive: Option<Duration>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tcp_keep_alive_interval: Option<Duration>,
        }

        impl DialOptions {
            pub fn parse(
                _obj: &serde_json::Map<String, serde_json::Value>,
            ) -> Result<Self, String> {
                Ok(Self::default())
            }

            #[inline]
            pub fn fallback_delay(&self) -> Duration {
                self.fallback_delay
                    .filter(|delay| !delay.is_zero())
                    .unwrap_or(DEFAULT_FALLBACK_DELAY)
            }
        }

        /// Разобрать IP-литерал (включая `[ipv6%zone]` / `ipv6%zone`) в `(IpAddr, scope_id)`.
        pub fn parse_ip_literal_or_scoped(host: &str) -> Option<(IpAddr, u32)> {
            let trimmed = host.trim();
            let inner = trimmed
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(trimmed);
            if let Ok(ip) = inner.parse::<IpAddr>() {
                return Some((ip, 0));
            }
            let (ip_part, zone) = inner.split_once('%')?;
            let v6 = ip_part.parse::<Ipv6Addr>().ok()?;
            #[cfg(unix)]
            let scope_id = zone.parse::<u32>().unwrap_or_else(|_| {
                std::ffi::CString::new(zone)
                    .map_or(0, |cz| unsafe { libc::if_nametoindex(cz.as_ptr()) })
            });
            #[cfg(not(unix))]
            let scope_id = zone.parse::<u32>().unwrap_or_default();
            Some((IpAddr::V6(v6), scope_id))
        }

        #[inline]
        pub fn scoped_socket_addr(ip: IpAddr, scope_id: u32, port: u16) -> SocketAddr {
            match ip {
                IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
                IpAddr::V6(v6) => {
                    let eff = if v6.is_unicast_link_local()
                        || (v6.is_multicast() && (v6.segments()[0] & 0x000f) != 0x000e)
                    {
                        scope_id
                    } else {
                        0
                    };
                    SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, eff))
                }
            }
        }

        #[cfg(target_os = "linux")]
        fn apply_tcp_congestion_sock(sock: &tokio::net::TcpSocket) {
            use std::os::fd::AsRawFd;
            let env_override = std::env::var("TACHYON_TCP_CONGESTION")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let algo_name: &str = if let Some(ref ov) = env_override {
                ov.as_str()
            } else {
                match crate::upstream_compat::active_tcp_congestion_mode() {
                    crate::upstream_compat::TcpCongestionMode::Bbr => "bbr",
                    crate::upstream_compat::TcpCongestionMode::Cubic => "cubic",
                    crate::upstream_compat::TcpCongestionMode::Reno => "reno",
                    crate::upstream_compat::TcpCongestionMode::None => return,
                }
            };
            let Ok(cstr) = std::ffi::CString::new(algo_name) else {
                return;
            };
            let len = cstr.to_bytes().len() as libc::socklen_t;
            let _ = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    cstr.as_ptr().cast(),
                    len,
                )
            };
        }

        #[inline]
        fn apply_wan_tcp_keepalive(stream: &TcpStream, dst: SocketAddr, dial: &DialOptions) {
            if dial.disable_tcp_keep_alive || dst.ip().to_canonical().is_loopback() {
                return;
            }
            let idle = dial
                .tcp_keep_alive
                .filter(|&d| !d.is_zero())
                .unwrap_or_else(|| Duration::from_secs(30));
            let interval = dial
                .tcp_keep_alive_interval
                .filter(|&d| !d.is_zero())
                .unwrap_or_else(|| Duration::from_secs(15));
            let ka = socket2::TcpKeepalive::new()
                .with_time(idle)
                .with_interval(interval);
            #[cfg(target_os = "linux")]
            let ka = ka.with_retries(3);
            let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
        }

        /// Проверить наличие рабочего глобального маршрута IPv6 (с кэшем 5 сек).
        pub fn has_usable_ipv6() -> bool {
            static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            static LAST_CHECK_MS: AtomicU64 = AtomicU64::new(0);
            static CACHED_USABLE: AtomicBool = AtomicBool::new(false);

            let now_ms = EPOCH
                .get_or_init(std::time::Instant::now)
                .elapsed()
                .as_millis() as u64;
            let prev = LAST_CHECK_MS.load(Ordering::Relaxed);
            if prev != 0 && now_ms.saturating_sub(prev) < 5_000 {
                return CACHED_USABLE.load(Ordering::Relaxed);
            }
            let usable = probe_usable_ipv6();
            CACHED_USABLE.store(usable, Ordering::Relaxed);
            LAST_CHECK_MS.store(now_ms.max(1), Ordering::Release);
            usable
        }

        fn probe_usable_ipv6() -> bool {
            #[cfg(target_os = "linux")]
            {
                if let Ok(if_inet6) = std::fs::read_to_string("/proc/net/if_inet6") {
                    for line in if_inet6.lines() {
                        if let Some(hex) = line.split_whitespace().next()
                            && hex.len() == 32
                            && let Ok(val) = u128::from_str_radix(hex, 16)
                        {
                            let v6 = Ipv6Addr::from(val);
                            if !v6.is_loopback()
                                && !v6.is_unspecified()
                                && !v6.is_unicast_link_local()
                                && (v6.segments()[0] & 0xfe00) != 0xfc00
                            {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            #[cfg(not(target_os = "linux"))]
            {
                if let Ok(sock) = std::net::UdpSocket::bind("[::]:0")
                    && sock.connect("[2001:4860:4860::8888]:443").is_ok()
                    && let Ok(local) = sock.local_addr()
                    && let IpAddr::V6(v6) = local.ip()
                {
                    return !v6.is_loopback()
                        && !v6.is_unspecified()
                        && !v6.is_unicast_link_local();
                }
                false
            }
        }

        /// Чередовать адреса IPv6 и IPv4 по RFC 8305 (`Happy Eyeballs v2`).
        pub fn interleave_addrs(addrs: &[SocketAddr], prefer_ipv6: bool) -> Vec<SocketAddr> {
            let mut pref = Vec::new();
            let mut alt = Vec::new();
            for &addr in addrs {
                if addr.is_ipv6() == prefer_ipv6 {
                    pref.push(addr);
                } else {
                    alt.push(addr);
                }
            }
            let mut out = Vec::with_capacity(addrs.len());
            let mut pi = pref.into_iter();
            let mut ai = alt.into_iter();
            loop {
                match (pi.next(), ai.next()) {
                    (Some(p), Some(a)) => {
                        out.push(p);
                        out.push(a);
                    }
                    (Some(p), None) => {
                        out.push(p);
                        out.extend(pi);
                        break;
                    }
                    (None, Some(a)) => {
                        out.push(a);
                        out.extend(ai);
                        break;
                    }
                    (None, None) => break,
                }
            }
            out
        }

        /// Упорядочить список целевых адресов по стратегии DNS и RFC 8305 `Happy Eyeballs v2`.
        pub fn order_addrs_for_strategy(
            mut addrs: Vec<SocketAddr>,
            strategy: Option<crate::dns::Strategy>,
        ) -> Vec<SocketAddr> {
            let eff = strategy.or_else(|| crate::dns::current().map(|s| s.strategy()));
            match eff {
                Some(crate::dns::Strategy::IPv4Only) => {
                    addrs.retain(SocketAddr::is_ipv4);
                    addrs
                }
                Some(crate::dns::Strategy::IPv6Only) => {
                    addrs.retain(SocketAddr::is_ipv6);
                    addrs
                }
                Some(crate::dns::Strategy::PreferIPv6) => interleave_addrs(&addrs, true),
                Some(crate::dns::Strategy::PreferIPv4) => interleave_addrs(&addrs, false),
                None => {
                    let has_v4 = addrs.iter().any(SocketAddr::is_ipv4);
                    let has_v6 = addrs.iter().any(SocketAddr::is_ipv6);
                    if has_v4 && has_v6 {
                        interleave_addrs(&addrs, has_usable_ipv6())
                    } else {
                        addrs
                    }
                }
            }
        }

        pub async fn resolve_for_dial(
            host: &str,
            port: u16,
            _dial: &DialOptions,
        ) -> io::Result<Vec<SocketAddr>> {
            resolve(host, port).await
        }

        pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            crate::dns_resolver::resolve_hostname(host, port).await
        }

        /// Переслать сырой DNS-пакет (UDP/53 из TUN) через чистый DNS-резолвер (UDP / DoT / DoH).
        pub async fn forward_clean_dns_udp_packet(
            query_pkt: &[u8],
            orig_dst: SocketAddr,
        ) -> io::Result<Vec<u8>> {
            crate::dns_resolver::forward_tun_dns_packet(query_pkt, orig_dst).await
        }

        pub async fn connect_tcp_addr(
            dst: SocketAddr,
            dial: &DialOptions,
        ) -> io::Result<TcpStream> {
            connect_tcp_addr_with_window(dst, dial, 0, None).await
        }

        pub async fn connect_tcp_addr_with_window(
            dst: SocketAddr,
            dial: &DialOptions,
            wsize: u32,
            wscale: Option<u8>,
        ) -> io::Result<TcpStream> {
            let timeout = dial
                .connect_timeout
                .filter(|d| !d.is_zero())
                .or_else(|| dial.connect_timeout_ms.map(Duration::from_millis))
                .unwrap_or_else(|| Duration::from_millis(4500));
            let sock = if dst.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            bind_outbound_socket(&sock, dst.is_ipv6());
            let _ = sock.set_nodelay(true);
            #[cfg(target_os = "linux")]
            apply_tcp_congestion_sock(&sock);
            if wscale.is_some() && !dst.ip().to_canonical().is_loopback() {
                super::tlsspoof::apply_preconnect_tcp_window_sock(
                    &socket2::SockRef::from(&sock),
                    wsize,
                    wscale,
                );
            }

            let t0 = std::time::Instant::now();
            let stream = tokio::time::timeout(timeout, sock.connect(dst))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;
            let connect_us = t0.elapsed().as_micros() as u64;
            if !dst.ip().to_canonical().is_loopback() || connect_us >= 5_000 {
                crate::hardware::record_connect_rtt_us(connect_us);
            }
            apply_wan_tcp_keepalive(&stream, dst, dial);
            Ok(stream)
        }

        pub async fn dial_serial<F, Fut, T>(addrs: Vec<SocketAddr>, dial: F) -> io::Result<T>
        where
            F: FnMut(SocketAddr) -> Fut + Send + 'static,
            Fut: Future<Output = io::Result<T>> + Send,
            T: Send + 'static,
        {
            dial_serial_slice(&addrs, dial).await
        }

        async fn dial_serial_slice<F, Fut, T>(addrs: &[SocketAddr], mut dial: F) -> io::Result<T>
        where
            F: FnMut(SocketAddr) -> Fut,
            Fut: Future<Output = io::Result<T>>,
        {
            let mut last = None;
            for &addr in addrs {
                match dial(addr).await {
                    Ok(value) => return Ok(value),
                    Err(err) => last = Some(err),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::other("no address to dial")))
        }

        pub async fn dial_fast_fallback<F, Fut, T>(
            addrs: &[SocketAddr],
            prefer_ipv6: bool,
            fallback_delay: Duration,
            dial: F,
        ) -> io::Result<T>
        where
            F: Fn(SocketAddr) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = io::Result<T>> + Send,
            T: Send + 'static,
        {
            let has_primary = addrs.iter().any(|addr| addr.is_ipv6() == prefer_ipv6);
            let has_fallback = addrs.iter().any(|addr| addr.is_ipv6() != prefer_ipv6);
            if !has_primary || !has_fallback {
                return dial_serial_slice(addrs, dial).await;
            }
            let (primaries, fallbacks): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
                .iter()
                .copied()
                .partition(|addr| addr.is_ipv6() == prefer_ipv6);

            let primary_fut = dial_serial(primaries, dial.clone());
            tokio::pin!(primary_fut);
            let wait = tokio::time::sleep(fallback_delay);
            tokio::pin!(wait);

            let early_primary = tokio::select! {
                res = &mut primary_fut => Some(res),
                _ = &mut wait => None,
            };
            if let Some(res) = early_primary {
                if res.is_ok() {
                    return res;
                }
                return match dial_serial(fallbacks, dial).await {
                    Ok(val) => Ok(val),
                    Err(_) => res,
                };
            }

            let fallback_fut = dial_serial(fallbacks, dial);
            tokio::pin!(fallback_fut);
            let mut primary_err: Option<io::Error> = None;
            let mut fallback_done = false;
            loop {
                tokio::select! {
                    res = &mut primary_fut, if primary_err.is_none() => match res {
                        Ok(val) => return Ok(val),
                        Err(err) => {
                            if fallback_done {
                                return Err(err);
                            }
                            primary_err = Some(err);
                        }
                    },
                    res = &mut fallback_fut, if !fallback_done => match res {
                        Ok(val) => return Ok(val),
                        Err(_) => {
                            if let Some(err) = primary_err.take() {
                                return Err(err);
                            }
                            fallback_done = true;
                        }
                    },
                }
            }
        }

        pub async fn connect_tcp(
            host: &str,
            port: u16,
            dial: &DialOptions,
        ) -> io::Result<TcpStream> {
            let addrs = order_addrs_for_strategy(resolve(host, port).await?, dial.domain_strategy);
            if addrs.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no address"));
            }
            if ACTIVE_HAPPY_EYEBALLS.load(Ordering::Relaxed) && addrs.len() > 1 {
                let eff = dial
                    .domain_strategy
                    .or_else(|| crate::dns::current().map(|s| s.strategy()));
                let prefer_ipv6 = matches!(
                    eff,
                    Some(crate::dns::Strategy::PreferIPv6 | crate::dns::Strategy::IPv6Only)
                ) || (eff.is_none() && has_usable_ipv6());
                let dial_owned = dial.clone();
                return dial_fast_fallback(
                    &addrs,
                    prefer_ipv6,
                    dial.fallback_delay(),
                    move |addr| {
                        let opts = dial_owned.clone();
                        async move { connect_tcp_addr(addr, &opts).await }
                    },
                )
                .await;
            }
            connect_tcp_addr(addrs[0], dial).await
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
