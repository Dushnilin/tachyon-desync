//! Подсистема DNS-резолвера с поддержкой UDP, DoT и DoH поверх чистого Rust TLS 1.3,
//! локальным LRU-кэшем, failover/recovery, бенчмарком, автонастройкой и тестом скорости.

use crate::desync::{DesyncConfig, DesyncPreset};
use crate::lists::{
    ListProfile, clear_dns_mapping_cache, lookup_custom_dns_override, record_dns_mapping,
    set_reverse_mapping_enabled, snoop_dns_response_packet,
};
use crate::outbound::desync::DesyncConfig as UpstreamDesyncConfig;
use crate::outbound::desync::probe::{Tls13ClientStream, connect_tls13_stream};
use crate::upstream_compat::{CLEAN_DNS_MODE, bind_outbound_socket};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    Doh,
    Dot,
    #[default]
    Udp,
}

impl DnsProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Doh => "doh",
            Self::Dot => "dot",
            Self::Udp => "udp",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "doh" | "https" => Self::Doh,
            "dot" | "tls" => Self::Dot,
            _ => Self::Udp,
        }
    }

    pub fn label_ru(self) -> &'static str {
        match self {
            Self::Doh => "DoH (HTTPS)",
            Self::Dot => "DoT (TLS)",
            Self::Udp => "UDP",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Self::Doh => "DoH (HTTPS)",
            Self::Dot => "DoT (TLS)",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsUpstreamMode {
    Sequential,
    #[default]
    Parallel,
}

impl DnsUpstreamMode {
    pub fn label_ru(self) -> &'static str {
        match self {
            Self::Sequential => "Последовательно",
            Self::Parallel => "Параллельно",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Self::Sequential => "Sequential",
            Self::Parallel => "Parallel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsIpStrategy {
    #[default]
    PreferIpv4,
    Ipv4Only,
    PreferIpv6,
    Ipv6Only,
    AsIs,
}

impl DnsIpStrategy {
    pub const ALL: [Self; 5] = [
        Self::PreferIpv4,
        Self::Ipv4Only,
        Self::PreferIpv6,
        Self::Ipv6Only,
        Self::AsIs,
    ];

    pub fn label_ru(self) -> &'static str {
        match self {
            Self::PreferIpv4 => "Предпочитать IPv4",
            Self::Ipv4Only => "Только IPv4",
            Self::PreferIpv6 => "Предпочитать IPv6",
            Self::Ipv6Only => "Только IPv6",
            Self::AsIs => "Как есть (IPv4 + IPv6)",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Self::PreferIpv4 => "Prefer IPv4",
            Self::Ipv4Only => "IPv4 Only",
            Self::PreferIpv6 => "Prefer IPv6",
            Self::Ipv6Only => "IPv6 Only",
            Self::AsIs => "As Is (IPv4 + IPv6)",
        }
    }

    fn to_upstream(self) -> Option<crate::dns::Strategy> {
        match self {
            Self::PreferIpv4 => Some(crate::dns::Strategy::PreferIPv4),
            Self::Ipv4Only => Some(crate::dns::Strategy::IPv4Only),
            Self::PreferIpv6 => Some(crate::dns::Strategy::PreferIPv6),
            Self::Ipv6Only => Some(crate::dns::Strategy::IPv6Only),
            Self::AsIs => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettings {
    pub enabled: bool,
    pub protocol: DnsProtocol,
    pub upstream_mode: DnsUpstreamMode,
    pub servers: Vec<String>,
    pub bootstrap_servers: Vec<String>,
    pub fallback_servers: Vec<String>,
    pub fallback_system_dns: bool,
    pub desync_doh_dot: bool,
    pub split_local_ru: bool,
    pub strategy: DnsIpStrategy,
    pub check_interval_secs: u32,
    pub recovery_check_interval_secs: u32,
    pub check_timeout_ms: u32,
    pub failure_threshold: u8,
    pub recovery_threshold: u8,
    pub rewrite_ttl_secs: u32,
    pub local_cache: bool,
    pub cache_size: usize,
    pub turbo_cache: bool,
    pub reverse_mapping: bool,
    pub reject_fake_ip: bool,
    pub speed_test_domains: Vec<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol: DnsProtocol::Udp,
            upstream_mode: DnsUpstreamMode::Parallel,
            servers: vec![
                "77.88.8.8:1253".to_string(),
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string(),
            ],
            bootstrap_servers: vec![
                "77.88.8.8:1253".to_string(),
                "77.88.8.8".to_string(),
                "1.1.1.1".to_string(),
            ],
            fallback_servers: vec!["208.67.222.222:5353".to_string(), "1.0.0.1".to_string()],
            fallback_system_dns: false,
            desync_doh_dot: true,
            split_local_ru: true,
            strategy: DnsIpStrategy::PreferIpv4,
            check_interval_secs: 30,
            recovery_check_interval_secs: 60,
            check_timeout_ms: 2000,
            failure_threshold: 3,
            recovery_threshold: 3,
            rewrite_ttl_secs: 60,
            local_cache: true,
            cache_size: 4096,
            turbo_cache: false,
            reverse_mapping: true,
            reject_fake_ip: true,
            speed_test_domains: default_speed_test_domains(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DnsPresetItem {
    pub provider: &'static str,
    pub protocol: DnsProtocol,
    pub servers: &'static [&'static str],
    pub bootstrap_ip: &'static str,
    pub tag: &'static str,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsRuntimeStatus {
    pub enabled: bool,
    pub protocol: DnsProtocol,
    pub upstream_mode: DnsUpstreamMode,
    pub active_primary: String,
    pub active_index: usize,
    pub primary_count: usize,
    pub consecutive_failures: u8,
    pub cache_entries: usize,
    pub cache_capacity: usize,
    pub approx_ram_kb: usize,
    pub total_queries: u64,
    pub cache_hits: u64,
    pub encrypted_queries: u64,
    pub failover_switches: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBenchRow {
    pub id: String,
    pub provider: String,
    pub protocol: DnsProtocol,
    pub address: String,
    pub tag: String,
    pub latency_ms: i32,
    pub loss_pct: u8,
    pub score: i32,
    pub rating: String,
    pub used_desync: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecommendation {
    pub protocol: DnsProtocol,
    pub upstream_mode: DnsUpstreamMode,
    pub servers: Vec<String>,
    pub bootstrap_servers: Vec<String>,
    pub fallback_servers: Vec<String>,
    pub reason_ru: String,
    pub reason_en: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsBenchmarkState {
    pub running: bool,
    pub progress_pct: u8,
    pub current_target: String,
    pub results: Vec<DnsBenchRow>,
    pub recommendation: Option<DnsRecommendation>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDomainSample {
    pub domain: String,
    pub ok: bool,
    pub ms: i32,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSpeedServerReport {
    pub server: String,
    pub protocol: DnsProtocol,
    pub role: String,
    pub min_ms: i32,
    pub median_ms: i32,
    pub avg_ms: i32,
    pub max_ms: i32,
    pub success_count: usize,
    pub total_count: usize,
    pub samples: Vec<DnsDomainSample>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsSpeedTestState {
    pub running: bool,
    pub progress_pct: u8,
    pub current_target: String,
    pub reports: Vec<DnsSpeedServerReport>,
    pub error: Option<String>,
}

/// Список доменов по умолчанию для многодоменного теста скорости DNS.
pub fn default_speed_test_domains() -> Vec<String> {
    [
        "google.com",
        "youtube.com",
        "discord.com",
        "github.com",
        "cloudflare.com",
        "wikipedia.org",
        "x.com",
        "whatsapp.com",
        "reddit.com",
        "chatgpt.com",
        "instagram.com",
        "amazon.com",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

const UDP_PRESETS: &[DnsPresetItem] = &[
    DnsPresetItem {
        provider: "Cloudflare",
        protocol: DnsProtocol::Udp,
        servers: &["1.1.1.1", "1.0.0.1"],
        bootstrap_ip: "1.1.1.1",
        tag: "Fast",
    },
    DnsPresetItem {
        provider: "Google",
        protocol: DnsProtocol::Udp,
        servers: &["8.8.8.8", "8.8.4.4"],
        bootstrap_ip: "8.8.8.8",
        tag: "Fast",
    },
    DnsPresetItem {
        provider: "Quad9",
        protocol: DnsProtocol::Udp,
        servers: &["9.9.9.9", "149.112.112.112"],
        bootstrap_ip: "9.9.9.9",
        tag: "Security",
    },
    DnsPresetItem {
        provider: "AdGuard",
        protocol: DnsProtocol::Udp,
        servers: &["94.140.14.14", "94.140.15.15"],
        bootstrap_ip: "94.140.14.14",
        tag: "Filter",
    },
    DnsPresetItem {
        provider: "Control D",
        protocol: DnsProtocol::Udp,
        servers: &["76.76.2.0", "76.76.10.0"],
        bootstrap_ip: "76.76.2.0",
        tag: "Fast",
    },
    DnsPresetItem {
        provider: "Mullvad",
        protocol: DnsProtocol::Udp,
        servers: &["194.242.2.2"],
        bootstrap_ip: "194.242.2.2",
        tag: "Privacy",
    },
    DnsPresetItem {
        provider: "DNS.SB",
        protocol: DnsProtocol::Udp,
        servers: &["185.222.222.222", "45.11.45.11"],
        bootstrap_ip: "185.222.222.222",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "DNS0.EU",
        protocol: DnsProtocol::Udp,
        servers: &["193.110.81.0", "185.253.5.0"],
        bootstrap_ip: "193.110.81.0",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "CZ.NIC ODVR",
        protocol: DnsProtocol::Udp,
        servers: &["193.17.47.1", "185.43.135.1"],
        bootstrap_ip: "193.17.47.1",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "OpenDNS",
        protocol: DnsProtocol::Udp,
        servers: &["208.67.222.222", "208.67.220.220"],
        bootstrap_ip: "208.67.222.222",
        tag: "Standard",
    },
    DnsPresetItem {
        provider: "OpenDNS Alt",
        protocol: DnsProtocol::Udp,
        servers: &["208.67.222.222:5353", "208.67.220.220:5353"],
        bootstrap_ip: "208.67.222.222:5353",
        tag: "Alt-Port UDP",
    },
    DnsPresetItem {
        provider: "Comss.one",
        protocol: DnsProtocol::Udp,
        servers: &["92.223.109.31"],
        bootstrap_ip: "92.223.109.31",
        tag: "Smart DNS",
    },
    DnsPresetItem {
        provider: "AliDNS",
        protocol: DnsProtocol::Udp,
        servers: &["223.5.5.5", "223.6.6.6"],
        bootstrap_ip: "223.5.5.5",
        tag: "Fast",
    },
    DnsPresetItem {
        provider: "CleanBrowsing",
        protocol: DnsProtocol::Udp,
        servers: &["185.228.168.9", "185.228.169.9"],
        bootstrap_ip: "185.228.168.9",
        tag: "Security",
    },
    DnsPresetItem {
        provider: "Yandex",
        protocol: DnsProtocol::Udp,
        servers: &["77.88.8.8", "77.88.8.1"],
        bootstrap_ip: "77.88.8.8",
        tag: "Local",
    },
    DnsPresetItem {
        provider: "Yandex Alt",
        protocol: DnsProtocol::Udp,
        servers: &["77.88.8.8:1253"],
        bootstrap_ip: "77.88.8.8:1253",
        tag: "Alt-Port UDP",
    },
];

const DOT_PRESETS: &[DnsPresetItem] = &[
    DnsPresetItem {
        provider: "Cloudflare",
        protocol: DnsProtocol::Dot,
        servers: &["1.1.1.1", "1.0.0.1"],
        bootstrap_ip: "1.1.1.1",
        tag: "DoT Fast",
    },
    DnsPresetItem {
        provider: "Google",
        protocol: DnsProtocol::Dot,
        servers: &["dns.google"],
        bootstrap_ip: "8.8.8.8",
        tag: "DoT Fast",
    },
    DnsPresetItem {
        provider: "Quad9",
        protocol: DnsProtocol::Dot,
        servers: &["dns.quad9.net"],
        bootstrap_ip: "9.9.9.9",
        tag: "DoT Security",
    },
    DnsPresetItem {
        provider: "AdGuard",
        protocol: DnsProtocol::Dot,
        servers: &["dns.adguard-dns.com"],
        bootstrap_ip: "94.140.14.14",
        tag: "DoT Filter",
    },
    DnsPresetItem {
        provider: "Control D",
        protocol: DnsProtocol::Dot,
        servers: &["p0.freedns.controld.com"],
        bootstrap_ip: "76.76.2.0",
        tag: "DoT Fast",
    },
    DnsPresetItem {
        provider: "Mullvad",
        protocol: DnsProtocol::Dot,
        servers: &["dns.mullvad.net"],
        bootstrap_ip: "194.242.2.2",
        tag: "DoT Privacy",
    },
    DnsPresetItem {
        provider: "NextDNS",
        protocol: DnsProtocol::Dot,
        servers: &["dns.nextdns.io"],
        bootstrap_ip: "",
        tag: "DoT Custom",
    },
    DnsPresetItem {
        provider: "DNS.SB",
        protocol: DnsProtocol::Dot,
        servers: &["dot.sb"],
        bootstrap_ip: "185.222.222.222",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "DNS0.EU",
        protocol: DnsProtocol::Dot,
        servers: &["zero.dns0.eu"],
        bootstrap_ip: "193.110.81.0",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "CZ.NIC ODVR",
        protocol: DnsProtocol::Dot,
        servers: &["odvr.nic.cz"],
        bootstrap_ip: "193.17.47.1",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "CleanBrowsing",
        protocol: DnsProtocol::Dot,
        servers: &["family-filter-dns.cleanbrowsing.org"],
        bootstrap_ip: "185.228.168.9",
        tag: "DoT Security",
    },
    DnsPresetItem {
        provider: "Yandex",
        protocol: DnsProtocol::Dot,
        servers: &["common.dot.dns.yandex.net"],
        bootstrap_ip: "77.88.8.8",
        tag: "DoT Local",
    },
];

const DOH_PRESETS: &[DnsPresetItem] = &[
    DnsPresetItem {
        provider: "Cloudflare",
        protocol: DnsProtocol::Doh,
        servers: &["https://cloudflare-dns.com/dns-query"],
        bootstrap_ip: "1.1.1.1",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "Google",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.google/dns-query"],
        bootstrap_ip: "8.8.8.8",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "Quad9",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.quad9.net/dns-query"],
        bootstrap_ip: "9.9.9.9",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "AdGuard",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.adguard-dns.com/dns-query"],
        bootstrap_ip: "94.140.14.14",
        tag: "DoH Filter",
    },
    DnsPresetItem {
        provider: "Control D",
        protocol: DnsProtocol::Doh,
        servers: &["https://freedns.controld.com/p0"],
        bootstrap_ip: "76.76.2.0",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "Mullvad",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.mullvad.net/dns-query"],
        bootstrap_ip: "194.242.2.2",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "NextDNS",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.nextdns.io/dns-query"],
        bootstrap_ip: "",
        tag: "DoH Custom",
    },
    DnsPresetItem {
        provider: "DNS.SB",
        protocol: DnsProtocol::Doh,
        servers: &["https://doh.dns.sb/dns-query"],
        bootstrap_ip: "185.222.222.222",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "DNS0.EU",
        protocol: DnsProtocol::Doh,
        servers: &["https://zero.dns0.eu"],
        bootstrap_ip: "193.110.81.0",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "CZ.NIC ODVR",
        protocol: DnsProtocol::Doh,
        servers: &["https://odvr.nic.cz/doh"],
        bootstrap_ip: "193.17.47.1",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "OpenDNS",
        protocol: DnsProtocol::Doh,
        servers: &["https://doh.opendns.com/dns-query"],
        bootstrap_ip: "208.67.222.222",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "Comss.one",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.comss.one/dns-query"],
        bootstrap_ip: "92.223.109.31",
        tag: "Smart DNS",
    },
    DnsPresetItem {
        provider: "DNS4EU",
        protocol: DnsProtocol::Doh,
        servers: &["https://unfiltered.joindns4.eu/dns-query"],
        bootstrap_ip: "86.54.11.100",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "AliDNS",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.alidns.com/dns-query"],
        bootstrap_ip: "223.5.5.5",
        tag: "DoH Encrypted",
    },
    DnsPresetItem {
        provider: "CleanBrowsing",
        protocol: DnsProtocol::Doh,
        servers: &["https://doh.cleanbrowsing.org/doh/family-filter/"],
        bootstrap_ip: "185.228.168.9",
        tag: "DoH Security",
    },
    DnsPresetItem {
        provider: "Yandex",
        protocol: DnsProtocol::Doh,
        servers: &["https://common.dot.dns.yandex.net/dns-query"],
        bootstrap_ip: "77.88.8.8",
        tag: "DoH Local",
    },
    DnsPresetItem {
        provider: "Restena",
        protocol: DnsProtocol::Doh,
        servers: &["https://dnspub.restena.lu/dns-query"],
        bootstrap_ip: "",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "Digitale Gesellschaft",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.digitale-gesellschaft.ch/dns-query"],
        bootstrap_ip: "",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "SWITCH",
        protocol: DnsProtocol::Doh,
        servers: &["https://dns.switch.ch/dns-query"],
        bootstrap_ip: "",
        tag: "EU Anycast",
    },
    DnsPresetItem {
        provider: "LibreDNS",
        protocol: DnsProtocol::Doh,
        servers: &["https://doh.libredns.gr/dns-query"],
        bootstrap_ip: "",
        tag: "EU Anycast",
    },
];

const BOOTSTRAP_PRESETS: &[(&str, &[&str])] = &[
    ("Yandex Alt (1253)", &["77.88.8.8:1253", "77.88.8.8"]),
    (
        "OpenDNS Alt (5353)",
        &["208.67.222.222:5353", "208.67.220.220:5353"],
    ),
    ("Cloudflare UDP", &["1.1.1.1", "1.0.0.1"]),
    ("Google UDP", &["8.8.8.8", "8.8.4.4"]),
    ("Quad9 UDP", &["9.9.9.9", "149.112.112.112"]),
    ("AdGuard UDP", &["94.140.14.14", "94.140.15.15"]),
    ("Control D UDP", &["76.76.2.0", "76.76.10.0"]),
    ("Mullvad UDP", &["194.242.2.2"]),
    ("DNS.SB UDP", &["185.222.222.222"]),
    ("DNS0.EU UDP", &["193.110.81.0"]),
];

pub fn presets_for_protocol(proto: DnsProtocol) -> &'static [DnsPresetItem] {
    match proto {
        DnsProtocol::Doh => DOH_PRESETS,
        DnsProtocol::Dot => DOT_PRESETS,
        DnsProtocol::Udp => UDP_PRESETS,
    }
}

pub fn bootstrap_presets() -> &'static [(&'static str, &'static [&'static str])] {
    BOOTSTRAP_PRESETS
}

/// Проверить и нормализовать запись DNS-сервера для указанного протокола.
pub fn validate_dns_server_entry(entry: &str, proto: DnsProtocol) -> Result<String, String> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err("Пустая запись DNS-сервера".to_string());
    }
    if raw.chars().any(char::is_whitespace) {
        return Err("Адрес DNS-сервера не должен содержать пробелы".to_string());
    }
    match proto {
        DnsProtocol::Doh => {
            let parsed = parse_doh_url(raw)?;
            Ok(parsed.canonical)
        }
        DnsProtocol::Dot => {
            let stripped = raw.strip_prefix("tls://").unwrap_or(raw);
            let (host, port) = parse_host_port_parts(stripped, 853)?;
            if port == 0 {
                return Err("Некорректный порт DoT".to_string());
            }
            if port == 853 {
                Ok(host)
            } else if host.contains(':') {
                Ok(format!("[{host}]:{port}"))
            } else {
                Ok(format!("{host}:{port}"))
            }
        }
        DnsProtocol::Udp => {
            let stripped = raw.strip_prefix("udp://").unwrap_or(raw);
            let (host, port) = parse_host_port_parts(stripped, 53)?;
            if port == 0 {
                return Err("Некорректный порт UDP DNS".to_string());
            }
            if host.parse::<IpAddr>().is_err() && !is_valid_hostname(&host) {
                return Err(format!("Некорректный IP или домен UDP DNS: {host}"));
            }
            if port == 53 {
                Ok(host)
            } else if host.contains(':') {
                Ok(format!("[{host}]:{port}"))
            } else {
                Ok(format!("{host}:{port}"))
            }
        }
    }
}

/// Проверить и нормализовать `DnsSettings`. Возвращает `true`, если какие-то поля были скорректированы.
pub fn sanitize_dns_settings(s: &mut DnsSettings) -> bool {
    let mut changed = false;

    let clamp_u32 = |val: &mut u32, min_v: u32, max_v: u32, ch: &mut bool| {
        let clamped = (*val).clamp(min_v, max_v);
        if clamped != *val {
            *val = clamped;
            *ch = true;
        }
    };
    clamp_u32(&mut s.check_interval_secs, 5, 600, &mut changed);
    clamp_u32(&mut s.recovery_check_interval_secs, 10, 1800, &mut changed);
    clamp_u32(&mut s.check_timeout_ms, 300, 10_000, &mut changed);
    clamp_u32(&mut s.rewrite_ttl_secs, 0, 3600, &mut changed);

    let ft = s.failure_threshold.clamp(1, 10);
    if ft != s.failure_threshold {
        s.failure_threshold = ft;
        changed = true;
    }
    let rt = s.recovery_threshold.clamp(1, 10);
    if rt != s.recovery_threshold {
        s.recovery_threshold = rt;
        changed = true;
    }
    let cs = s.cache_size.clamp(256, 65_536);
    if cs != s.cache_size {
        s.cache_size = cs;
        changed = true;
    }

    let dedup_valid = |list: &mut Vec<String>, proto: DnsProtocol, ch: &mut bool| {
        let mut out = Vec::with_capacity(list.len());
        let mut seen = HashSet::new();
        for item in list.iter() {
            if let Ok(norm) = validate_dns_server_entry(item, proto) {
                if &norm != item {
                    *ch = true;
                }
                let key = norm.to_ascii_lowercase();
                if seen.insert(key) {
                    out.push(norm);
                } else {
                    *ch = true;
                }
            } else {
                *ch = true;
            }
        }
        if out.len() != list.len() {
            *ch = true;
        }
        *list = out;
    };

    dedup_valid(&mut s.servers, s.protocol, &mut changed);
    dedup_valid(&mut s.bootstrap_servers, DnsProtocol::Udp, &mut changed);
    dedup_valid(&mut s.fallback_servers, DnsProtocol::Udp, &mut changed);

    if s.servers.is_empty() {
        s.servers = match s.protocol {
            DnsProtocol::Doh => vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            DnsProtocol::Dot => vec!["1.1.1.1".to_string(), "dns.google".to_string()],
            DnsProtocol::Udp => DnsSettings::default().servers,
        };
        changed = true;
    }
    if s.bootstrap_servers.is_empty() {
        s.bootstrap_servers = DnsSettings::default().bootstrap_servers;
        changed = true;
    }

    let mut clean_domains = Vec::new();
    let mut seen_dom = HashSet::new();
    for raw in &s.speed_test_domains {
        let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if is_valid_hostname(&d) && seen_dom.insert(d.clone()) {
            clean_domains.push(d);
            if clean_domains.len() >= 32 {
                break;
            }
        } else {
            changed = true;
        }
    }
    if clean_domains.is_empty() {
        clean_domains = default_speed_test_domains();
        changed = true;
    }
    if clean_domains != s.speed_test_domains {
        s.speed_test_domains = clean_domains;
        changed = true;
    }

    changed
}

/// Оценка потребления ОЗУ локальным DNS-кэшем (~320 байт на запись, минимум 64 КБ).
pub fn estimate_cache_ram_kb(cache_size: usize) -> usize {
    cache_size.saturating_mul(320).div_ceil(1024).max(64)
}

// ---------------------------------------------------------------------------
// Глобальное состояние резолвера, кэши и счётчики
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CachedResolveEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WireCacheKey {
    qname: String,
    qtype: u16,
}

#[derive(Debug, Clone)]
struct CachedWireEntry {
    packet: Vec<u8>,
    expires_at: Instant,
}

struct PooledTlsConn {
    stream: Tls13ClientStream,
    last_used: Instant,
}

struct FailoverState {
    active_index: AtomicUsize,
    consecutive_failures: AtomicU8,
    recovery_successes: AtomicU8,
    failover_switches: AtomicU64,
    total_queries: AtomicU64,
    cache_hits: AtomicU64,
    encrypted_queries: AtomicU64,
}

impl Default for FailoverState {
    fn default() -> Self {
        Self {
            active_index: AtomicUsize::new(0),
            consecutive_failures: AtomicU8::new(0),
            recovery_successes: AtomicU8::new(0),
            failover_switches: AtomicU64::new(0),
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            encrypted_queries: AtomicU64::new(0),
        }
    }
}

struct GlobalDnsState {
    settings: std::sync::RwLock<DnsSettings>,
    resolve_cache: Mutex<LruCache<String, CachedResolveEntry>>,
    wire_cache: Mutex<LruCache<WireCacheKey, CachedWireEntry>>,
    bootstrap_host_cache: Mutex<LruCache<String, (Vec<IpAddr>, Instant)>>,
    tls_pool: Mutex<LruCache<String, Arc<AsyncMutex<Option<PooledTlsConn>>>>>,
    failover: FailoverState,
}

static DNS_STATE: OnceLock<GlobalDnsState> = OnceLock::new();

fn global_state() -> &'static GlobalDnsState {
    DNS_STATE.get_or_init(|| {
        let def = DnsSettings::default();
        let cap = NonZeroUsize::new(def.cache_size.clamp(256, 65_536)).unwrap();
        GlobalDnsState {
            settings: std::sync::RwLock::new(def),
            resolve_cache: Mutex::new(LruCache::new(cap)),
            wire_cache: Mutex::new(LruCache::new(cap)),
            bootstrap_host_cache: Mutex::new(LruCache::new(NonZeroUsize::new(512).unwrap())),
            tls_pool: Mutex::new(LruCache::new(NonZeroUsize::new(8).unwrap())),
            failover: FailoverState::default(),
        }
    })
}

fn sync_legacy_clean_dns_atomic(settings: &DnsSettings) {
    let val = if !settings.enabled {
        0
    } else if settings
        .servers
        .iter()
        .any(|s| s.contains("1.1.1.1") || s.contains("cloudflare"))
    {
        2
    } else if settings
        .servers
        .iter()
        .any(|s| s.contains("8.8.8.8") || s.contains("dns.google"))
    {
        3
    } else if settings.servers.iter().any(|s| s.contains(":1253")) {
        4
    } else {
        1
    };
    CLEAN_DNS_MODE.store(val, Ordering::Relaxed);
}

pub fn apply_dns_settings(settings: &DnsSettings) {
    let mut clean = settings.clone();
    sanitize_dns_settings(&mut clean);

    set_reverse_mapping_enabled(clean.reverse_mapping);
    sync_legacy_clean_dns_atomic(&clean);

    let st = global_state();
    let new_cap = NonZeroUsize::new(clean.cache_size.clamp(256, 65_536)).unwrap();
    if let Ok(mut rc) = st.resolve_cache.lock() {
        rc.resize(new_cap);
        if !clean.local_cache {
            rc.clear();
        }
    }
    if let Ok(mut wc) = st.wire_cache.lock() {
        wc.resize(new_cap);
        if !clean.local_cache {
            wc.clear();
        }
    }
    if let Ok(mut guard) = st.settings.write() {
        let reset_failover = guard.protocol != clean.protocol
            || guard.servers != clean.servers
            || guard.upstream_mode != clean.upstream_mode;
        *guard = clean;
        if reset_failover {
            st.failover.active_index.store(0, Ordering::Relaxed);
            st.failover.consecutive_failures.store(0, Ordering::Relaxed);
            st.failover.recovery_successes.store(0, Ordering::Relaxed);
        }
    }
}

pub fn current_dns_settings() -> DnsSettings {
    global_state()
        .settings
        .read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

pub fn current_dns_status() -> DnsRuntimeStatus {
    let st = global_state();
    let settings = current_dns_settings();
    let primary_count = settings.servers.len();
    let active_index = if primary_count == 0 {
        0
    } else {
        st.failover.active_index.load(Ordering::Relaxed) % primary_count
    };
    let active_primary = if !settings.enabled {
        "System DNS".to_string()
    } else {
        settings
            .servers
            .get(active_index)
            .cloned()
            .unwrap_or_else(|| "-".to_string())
    };
    let rc_len = st.resolve_cache.lock().map(|c| c.len()).unwrap_or(0);
    let wc_len = st.wire_cache.lock().map(|c| c.len()).unwrap_or(0);
    let cache_entries = rc_len + wc_len;

    DnsRuntimeStatus {
        enabled: settings.enabled,
        protocol: settings.protocol,
        upstream_mode: settings.upstream_mode,
        active_primary,
        active_index,
        primary_count,
        consecutive_failures: st.failover.consecutive_failures.load(Ordering::Relaxed),
        cache_entries,
        cache_capacity: settings.cache_size,
        approx_ram_kb: estimate_cache_ram_kb(cache_entries.max(settings.cache_size)),
        total_queries: st.failover.total_queries.load(Ordering::Relaxed),
        cache_hits: st.failover.cache_hits.load(Ordering::Relaxed),
        encrypted_queries: st.failover.encrypted_queries.load(Ordering::Relaxed),
        failover_switches: st.failover.failover_switches.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
pub(crate) fn test_dns_state_lock() -> &'static tokio::sync::Mutex<()> {
    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &TEST_LOCK
}

static DNS_SERVICE_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn set_dns_service_active(active: bool) {
    DNS_SERVICE_ACTIVE.store(active, Ordering::Relaxed);
}

pub fn active_upstream_dns_strategy() -> Option<crate::dns::Strategy> {
    if !DNS_SERVICE_ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    let settings = current_dns_settings();
    if !settings.enabled {
        return None;
    }
    settings.strategy.to_upstream()
}

pub fn flush_dns_caches() {
    let st = global_state();
    if let Ok(mut rc) = st.resolve_cache.lock() {
        rc.clear();
    }
    if let Ok(mut wc) = st.wire_cache.lock() {
        wc.clear();
    }
    if let Ok(mut bc) = st.bootstrap_host_cache.lock() {
        bc.clear();
    }
    if let Ok(mut pool) = st.tls_pool.lock() {
        pool.clear();
    }
    clear_dns_mapping_cache();
}

// ---------------------------------------------------------------------------
// Разбор адресов и статическая bootstrap-карта известных резолверов
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DohEndpoint {
    host: String,
    port: u16,
    path: String,
    host_header: String,
    canonical: String,
}

fn parse_doh_url(raw: &str) -> Result<DohEndpoint, String> {
    let trimmed = raw.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| "DoH URL должен начинаться с https://".to_string())?;
    let (authority, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/dns-query"),
    };
    if authority.is_empty() {
        return Err("В DoH URL не указан хост".to_string());
    }
    let (host, port) = parse_host_port_parts(authority, 443)?;
    if host.is_empty() || (host.parse::<IpAddr>().is_err() && !is_valid_hostname(&host)) {
        return Err(format!("Некорректный хост DoH: {host}"));
    }
    let path = if path_part.is_empty() {
        "/dns-query".to_string()
    } else {
        path_part.to_string()
    };
    let host_header = if port == 443 {
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        }
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let canonical = format!("https://{host_header}{path}");
    Ok(DohEndpoint {
        host,
        port,
        path,
        host_header,
        canonical,
    })
}

fn parse_host_port_parts(raw: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = raw.trim();
    if let Some(after_open) = s.strip_prefix('[') {
        let Some(close_idx) = after_open.find(']') else {
            return Err("Незакрытая скобка IPv6-адреса".to_string());
        };
        let host = &after_open[..close_idx];
        let rem = &after_open[close_idx + 1..];
        let port = if let Some(p_str) = rem.strip_prefix(':') {
            p_str
                .parse::<u16>()
                .map_err(|_| format!("Некорректный порт в '{raw}'"))?
        } else if rem.is_empty() {
            default_port
        } else {
            return Err(format!("Некорректный формат адреса '{raw}'"));
        };
        return Ok((host.to_string(), port));
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip.to_string(), default_port));
    }

    if let Some((host, port_str)) = s.rsplit_once(':')
        && !host.contains(':')
    {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Некорректный порт в '{raw}'"))?;
        return Ok((host.to_ascii_lowercase(), port));
    }

    Ok((s.to_ascii_lowercase(), default_port))
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.is_empty() {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

fn known_resolver_ips(host: &str) -> Option<&'static [IpAddr]> {
    static CF: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    ];
    static GOOGLE: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    ];
    static QUAD9: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    ];
    static ADGUARD: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)),
        IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)),
    ];
    static CONTROLD: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(76, 76, 2, 0)),
        IpAddr::V4(Ipv4Addr::new(76, 76, 10, 0)),
    ];
    static MULLVAD: &[IpAddr] = &[IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2))];
    static DNSSB: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(185, 222, 222, 222)),
        IpAddr::V4(Ipv4Addr::new(45, 11, 45, 11)),
    ];
    static DNS0: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(193, 110, 81, 0)),
        IpAddr::V4(Ipv4Addr::new(185, 253, 5, 0)),
    ];
    static CZNIC: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(193, 17, 47, 1)),
        IpAddr::V4(Ipv4Addr::new(185, 43, 135, 1)),
    ];
    static OPENDNS: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
    ];
    static COMSS: &[IpAddr] = &[IpAddr::V4(Ipv4Addr::new(92, 223, 109, 31))];
    static DNS4EU: &[IpAddr] = &[IpAddr::V4(Ipv4Addr::new(86, 54, 11, 100))];
    static ALIDNS: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
    ];
    static CLEANBROWSING: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(185, 228, 168, 9)),
        IpAddr::V4(Ipv4Addr::new(185, 228, 169, 9)),
    ];
    static YANDEX: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(77, 88, 8, 1)),
    ];

    match host.trim().to_ascii_lowercase().as_str() {
        "cloudflare-dns.com" | "1dot1dot1dot1.cloudflare-dns.com" => Some(CF),
        "dns.google" | "dns.google.com" => Some(GOOGLE),
        "dns.quad9.net" => Some(QUAD9),
        "dns.adguard-dns.com" | "dns.adguard.com" => Some(ADGUARD),
        "freedns.controld.com" | "p0.freedns.controld.com" => Some(CONTROLD),
        "dns.mullvad.net" => Some(MULLVAD),
        "doh.dns.sb" | "dot.sb" => Some(DNSSB),
        "zero.dns0.eu" => Some(DNS0),
        "odvr.nic.cz" => Some(CZNIC),
        "doh.opendns.com" => Some(OPENDNS),
        "dns.comss.one" => Some(COMSS),
        "unfiltered.joindns4.eu" => Some(DNS4EU),
        "dns.alidns.com" => Some(ALIDNS),
        "doh.cleanbrowsing.org" | "family-filter-dns.cleanbrowsing.org" => Some(CLEANBROWSING),
        "common.dot.dns.yandex.net" => Some(YANDEX),
        _ => None,
    }
}

fn is_cloudflare_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 1 && (o[1] == 1 || o[1] == 0) && o[2] == 1)
                || (o[0] == 104 && (16..=31).contains(&o[1]))
                || (o[0] == 172 && (64..=71).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x2606 && s[1] == 0x4700
        }
    }
}

fn is_local_or_ru_domain(host: &str) -> bool {
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    for suffix in [
        ".ru",
        ".su",
        ".рф",
        ".xn--p1ai",
        ".lan",
        ".local",
        ".home.arpa",
        ".internal",
    ] {
        if clean.ends_with(suffix) || clean == suffix.trim_start_matches('.') {
            return true;
        }
    }
    !clean.contains('.')
}

// ---------------------------------------------------------------------------
// RFC 1035 wire-кодек и фильтрация адресов
// ---------------------------------------------------------------------------

pub fn is_disallowed_ip(ip: IpAddr, reject_fake_ip: bool) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() || v4.is_broadcast() {
                return true;
            }
            if reject_fake_ip {
                let o = v4.octets();
                if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                    return true;
                }
                if (o[0] == 192 && o[1] == 0 && o[2] == 2)
                    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                {
                    return true;
                }
            }
            false
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if (s[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            if reject_fake_ip && s[0] == 0x2001 && s[1] == 0x0db8 {
                return true;
            }
            false
        }
    }
}

/// Построить RFC 1035 DNS-запрос (`QCLASS = IN`).
pub fn build_dns_query(domain: &str, qtype: u16, txid: u16) -> io::Result<Vec<u8>> {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid domain length",
        ));
    }
    let mut pkt = Vec::with_capacity(clean.len() + 18);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in clean.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS label",
            ));
        }
        pkt.push(b.len() as u8);
        pkt.extend_from_slice(b);
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    Ok(pkt)
}

fn read_dns_name(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::with_capacity(6);
    let mut pos = start;
    let mut end_after_first_jump = None;
    let mut jumps = 0usize;

    loop {
        if pos >= pkt.len() || jumps > 16 {
            return None;
        }
        let b = pkt[pos];
        if b == 0 {
            let final_pos = end_after_first_jump.unwrap_or(pos + 1);
            return Some((labels.join("."), final_pos));
        }
        if (b & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() {
                return None;
            }
            if end_after_first_jump.is_none() {
                end_after_first_jump = Some(pos + 2);
            }
            let ptr = (((b & 0x3F) as usize) << 8) | (pkt[pos + 1] as usize);
            if ptr >= pkt.len() {
                return None;
            }
            pos = ptr;
            jumps += 1;
            continue;
        }
        if (b & 0xC0) != 0 {
            return None;
        }
        let len = b as usize;
        if pos + 1 + len > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += 1 + len;
    }
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0usize;
    while pos < pkt.len() {
        let b = pkt[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            return (pos + 2 <= pkt.len()).then_some(pos + 2);
        }
        if (b & 0xC0) != 0 {
            return None;
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

fn parse_dns_question_section(pkt: &[u8]) -> Option<(String, u16, u16, usize)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, next_pos) = read_dns_name(pkt, 12)?;
    if next_pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[next_pos], pkt[next_pos + 1]]);
    let qclass = u16::from_be_bytes([pkt[next_pos + 2], pkt[next_pos + 3]]);
    Some((qname, qtype, qclass, next_pos + 4))
}

#[derive(Debug)]
struct ParsedDnsRecords {
    ips: Vec<IpAddr>,
    total_addr_records: usize,
    min_ttl: u32,
}

fn parse_dns_answer_ips(pkt: &[u8], reject_fake_ip: bool) -> Option<ParsedDnsRecords> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    if qdcount > 16 || ancount > 128 {
        return None;
    }
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(pkt, pos)?;
        if pos + 4 > pkt.len() {
            return None;
        }
        pos += 4;
    }

    let mut ips = Vec::new();
    let mut total_addr_records = 0usize;
    let mut min_ttl = u32::MAX;

    for _ in 0..ancount {
        pos = match skip_dns_name(pkt, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let ttl = u32::from_be_bytes([pkt[pos + 4], pkt[pos + 5], pkt[pos + 6], pkt[pos + 7]]);
        let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > pkt.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            total_addr_records += 1;
            let ip = IpAddr::V4(Ipv4Addr::new(
                pkt[pos],
                pkt[pos + 1],
                pkt[pos + 2],
                pkt[pos + 3],
            ));
            if !is_disallowed_ip(ip, reject_fake_ip) {
                ips.push(ip);
                min_ttl = min_ttl.min(ttl);
            }
        } else if rtype == 28 && rdlen == 16 {
            total_addr_records += 1;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[pos..pos + 16]);
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            if !is_disallowed_ip(ip, reject_fake_ip) {
                ips.push(ip);
                min_ttl = min_ttl.min(ttl);
            }
        }
        pos += rdlen;
    }
    if min_ttl == u32::MAX {
        min_ttl = 60;
    }
    Some(ParsedDnsRecords {
        ips,
        total_addr_records,
        min_ttl,
    })
}

fn rewrite_dns_response_packet(
    resp: &[u8],
    req_txid: u16,
    rewrite_ttl_secs: u32,
    reject_fake_ip: bool,
) -> Option<(Vec<u8>, u32)> {
    let parsed = parse_dns_answer_ips(resp, reject_fake_ip)?;
    if parsed.total_addr_records > 0 && parsed.ips.is_empty() {
        return None;
    }
    let mut out = resp.to_vec();
    out[0..2].copy_from_slice(&req_txid.to_be_bytes());

    if rewrite_ttl_secs > 0 {
        let ttl_bytes = rewrite_ttl_secs.to_be_bytes();
        let qdcount = u16::from_be_bytes([out[4], out[5]]) as usize;
        let ancount = u16::from_be_bytes([out[6], out[7]]) as usize;
        let nscount = u16::from_be_bytes([out[8], out[9]]) as usize;
        let arcount = u16::from_be_bytes([out[10], out[11]]) as usize;
        let mut pos = 12usize;
        for _ in 0..qdcount {
            let Some(next) = skip_dns_name(&out, pos) else {
                return Some((out, rewrite_ttl_secs));
            };
            if next + 4 > out.len() {
                return Some((out, rewrite_ttl_secs));
            }
            pos = next + 4;
        }
        let total_rr = ancount.saturating_add(nscount).saturating_add(arcount);
        for _ in 0..total_rr.min(128) {
            let Some(next) = skip_dns_name(&out, pos) else {
                break;
            };
            pos = next;
            if pos + 10 > out.len() {
                break;
            }
            let rtype = u16::from_be_bytes([out[pos], out[pos + 1]]);
            if rtype != 41 {
                out[pos + 4..pos + 8].copy_from_slice(&ttl_bytes);
            }
            let rdlen = u16::from_be_bytes([out[pos + 8], out[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > out.len() {
                break;
            }
            pos += rdlen;
        }
        return Some((out, rewrite_ttl_secs));
    }

    Some((out, parsed.min_ttl))
}

fn append_soa_authority_record(resp: &mut Vec<u8>, ttl: u32) {
    // ROOT name 0x00, TYPE=SOA(6), CLASS=IN(1), TTL, RDLENGTH
    // MNAME = ns.local. (10 bytes), RNAME = hostmaster.local. (18 bytes), 5*u32 (20 bytes) = 48 bytes
    resp.extend_from_slice(&[0x00, 0x00, 0x06, 0x00, 0x01]);
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&48u16.to_be_bytes());
    resp.extend_from_slice(&[2, b'n', b's', 5, b'l', b'o', b'c', b'a', b'l', 0]);
    resp.extend_from_slice(&[
        10, b'h', b'o', b's', b't', b'm', b'a', b's', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a',
        b'l', 0,
    ]);
    resp.extend_from_slice(&1u32.to_be_bytes()); // serial
    resp.extend_from_slice(&7200u32.to_be_bytes()); // refresh
    resp.extend_from_slice(&900u32.to_be_bytes()); // retry
    resp.extend_from_slice(&1_209_600u32.to_be_bytes()); // expire
    resp.extend_from_slice(&ttl.to_be_bytes()); // minimum
}

fn build_synthetic_dns_response(
    query_pkt: &[u8],
    qend: usize,
    ip: Option<IpAddr>,
    ttl_secs: u32,
) -> Vec<u8> {
    let ttl = if ttl_secs > 0 { ttl_secs } else { 120 };
    let mut resp = Vec::with_capacity(qend + 80);
    resp.extend_from_slice(&query_pkt[..qend]);
    // Flags: QR=1, RD=copy, RA=1, RCODE=0
    resp[2] = 0x80 | (query_pkt[2] & 0x01);
    resp[3] = 0x80;
    resp[4] = 0x00;
    resp[5] = 0x01;
    resp[6] = 0x00;
    resp[7] = if ip.is_some() { 0x01 } else { 0x00 };
    resp[8..12].fill(0x00);

    match ip {
        Some(IpAddr::V4(v4)) => {
            resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x04]);
            resp.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01]);
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x10]);
            resp.extend_from_slice(&v6.octets());
        }
        None => {
            // RFC 2308 NODATA с синтетической записью SOA
            resp[9] = 0x01; // NSCOUNT = 1
            append_soa_authority_record(&mut resp, ttl.min(120));
        }
    }
    resp
}

fn parse_ptr_arpa(name: &str) -> Option<IpAddr> {
    let s = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(prefix) = s.strip_suffix(".in-addr.arpa") {
        let mut octets = [0u8; 4];
        let mut count = 0usize;
        for part in prefix.split('.') {
            if count >= 4 {
                return None;
            }
            octets[3 - count] = part.parse::<u8>().ok()?;
            count += 1;
        }
        return (count == 4).then(|| IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if let Some(prefix) = s.strip_suffix(".ip6.arpa") {
        let mut nibbles = [0u8; 32];
        let mut count = 0usize;
        for part in prefix.split('.') {
            if count >= 32 || part.len() != 1 {
                return None;
            }
            nibbles[31 - count] = u8::from_str_radix(part, 16).ok()?;
            count += 1;
        }
        if count != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

fn build_synthetic_ptr_response(
    query_pkt: &[u8],
    qend: usize,
    domain: Option<&str>,
    ttl_secs: u32,
) -> Vec<u8> {
    let ttl = if ttl_secs > 0 { ttl_secs } else { 120 };
    let mut resp = Vec::with_capacity(qend + 96);
    resp.extend_from_slice(&query_pkt[..qend]);
    resp[2] = 0x80 | (query_pkt[2] & 0x01);
    resp[4..12].fill(0x00);
    resp[5] = 0x01; // QDCOUNT = 1

    if let Some(dom) = domain {
        let clean = dom.trim().trim_end_matches('.');
        let mut rdata = Vec::with_capacity(clean.len() + 2);
        let mut valid = !clean.is_empty() && clean.len() <= 253;
        if valid {
            for label in clean.split('.') {
                let b = label.as_bytes();
                if b.is_empty() || b.len() > 63 {
                    valid = false;
                    break;
                }
                rdata.push(b.len() as u8);
                rdata.extend_from_slice(b);
            }
            rdata.push(0x00);
        }
        if valid {
            resp[3] = 0x80; // RA=1, RCODE=0
            resp[7] = 0x01; // ANCOUNT = 1
            resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x0C, 0x00, 0x01]);
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&rdata);
            return resp;
        }
    }

    resp[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
    resp[9] = 0x01; // NSCOUNT = 1
    append_soa_authority_record(&mut resp, ttl.min(120));
    resp
}

/// Удалить `ipv4hint` (key 4) и/или `ipv6hint` (key 6) из RDATA записей `SVCB`/`HTTPS` (`TYPE 64/65`)
/// в соответствии со стратегией IP (`Ipv4Only`/`Ipv6Only`), чтобы браузер/ОС не подключались к отфильтрованному семейству.
fn rewrite_svcb_https_hints(resp: &[u8], strip_v4: bool, strip_v6: bool) -> Vec<u8> {
    if (!strip_v4 && !strip_v6) || resp.len() < 12 {
        return resp.to_vec();
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    if qdcount == 0 || ancount == 0 || nscount > 0 || ancount > 8 {
        return resp.to_vec();
    }

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(resp, pos) else {
            return resp.to_vec();
        };
        if next + 4 > resp.len() {
            return resp.to_vec();
        }
        pos = next + 4;
    }

    let mut out = resp[..pos].to_vec();
    let mut changed = false;
    for _ in 0..ancount {
        let rr_start = pos;
        let Some(name_end) = skip_dns_name(resp, pos) else {
            return resp.to_vec();
        };
        if name_end + 10 > resp.len() {
            return resp.to_vec();
        }
        // Не трогаем, если имя RR содержит абсолютный указатель >= rr_start
        let rtype = u16::from_be_bytes([resp[name_end], resp[name_end + 1]]);
        let rdlen_off = name_end + 8;
        let rdlen = u16::from_be_bytes([resp[rdlen_off], resp[rdlen_off + 1]]) as usize;
        let rdata_start = rdlen_off + 2;
        let rdata_end = rdata_start.saturating_add(rdlen);
        if rdata_end > resp.len() {
            return resp.to_vec();
        }

        if (rtype == 64 || rtype == 65)
            && let Some(new_rdata) =
                strip_svcb_rdata_hints(&resp[rdata_start..rdata_end], strip_v4, strip_v6)
        {
            out.extend_from_slice(&resp[rr_start..rdlen_off]);
            out.extend_from_slice(&(new_rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&new_rdata);
            changed = true;
        } else {
            out.extend_from_slice(&resp[rr_start..rdata_end]);
        }
        pos = rdata_end;
    }

    if !changed {
        return resp.to_vec();
    }
    // Сбрасываем Additionals (где могут быть glue A/AAAA записи на удалённый hint или смещённые указатели).
    out[10] = 0;
    out[11] = 0;
    out
}

fn strip_svcb_rdata_hints(rdata: &[u8], strip_v4: bool, strip_v6: bool) -> Option<Vec<u8>> {
    if rdata.len() < 3 {
        return None;
    }
    // 2 bytes priority + target name (uncompressed labels)
    let mut tpos = 2usize;
    while tpos < rdata.len() {
        let len = rdata[tpos] as usize;
        if len == 0 {
            tpos += 1;
            break;
        }
        if (len & 0xC0) != 0 || tpos + 1 + len > rdata.len() {
            return None;
        }
        tpos += 1 + len;
    }
    if tpos > rdata.len() {
        return None;
    }
    let mut params_out = Vec::with_capacity(rdata.len() - tpos);
    let mut changed = false;
    let mut p = tpos;
    while p + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[p], rdata[p + 1]]);
        let vlen = u16::from_be_bytes([rdata[p + 2], rdata[p + 3]]) as usize;
        if p + 4 + vlen > rdata.len() {
            return None;
        }
        let val = &rdata[p + 4..p + 4 + vlen];
        if (key == 4 && strip_v4) || (key == 6 && strip_v6) {
            changed = true;
        } else if key == 0 && vlen >= 2 && vlen.is_multiple_of(2) {
            let mut mvals = Vec::with_capacity(vlen);
            for chunk in val.as_chunks::<2>().0 {
                let mk = u16::from_be_bytes([chunk[0], chunk[1]]);
                if (mk == 4 && strip_v4) || (mk == 6 && strip_v6) {
                    changed = true;
                } else {
                    mvals.extend_from_slice(chunk);
                }
            }
            if !mvals.is_empty() {
                params_out.extend_from_slice(&key.to_be_bytes());
                params_out.extend_from_slice(&(mvals.len() as u16).to_be_bytes());
                params_out.extend_from_slice(&mvals);
            }
        } else {
            params_out.extend_from_slice(&rdata[p..p + 4 + vlen]);
        }
        p += 4 + vlen;
    }
    if p != rdata.len() || !changed {
        return None;
    }
    let mut rebuilt = Vec::with_capacity(tpos + params_out.len());
    rebuilt.extend_from_slice(&rdata[..tpos]);
    rebuilt.extend_from_slice(&params_out);
    Some(rebuilt)
}

// ---------------------------------------------------------------------------
// Сетевые транспорты: UDP, DoT (TLS 1.3), DoH (HTTP/1.1 + TLS 1.3)
// ---------------------------------------------------------------------------

async fn query_udp_raw(
    dst: SocketAddr,
    query_pkt: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let domain = if dst.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let raw_sock =
        socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    bind_outbound_socket(&raw_sock, dst.is_ipv6());
    raw_sock.set_nonblocking(true)?;
    let bind_addr: SocketAddr = if dst.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    raw_sock.bind(&bind_addr.into())?;
    raw_sock.connect(&dst.into())?;
    let std_udp: std::net::UdpSocket = raw_sock.into();
    let sock = UdpSocket::from_std(std_udp)?;
    sock.send(query_pkt).await?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP DNS timeout"))??;
    if n < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated UDP DNS reply",
        ));
    }
    Ok(buf[..n].to_vec())
}

async fn resolve_server_host_ips(
    host: &str,
    bootstrap_servers: &[String],
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if let Some(ips) = known_resolver_ips(host) {
        return Ok(ips.to_vec());
    }
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(mut guard) = global_state().bootstrap_host_cache.lock()
        && let Some((ips, ts)) = guard.get(&clean)
        && ts.elapsed() < Duration::from_secs(300)
        && !ips.is_empty()
    {
        return Ok(ips.clone());
    }

    let query = build_dns_query(&clean, 1, 0x4253)?;
    let mut found = Vec::new();
    for bs in bootstrap_servers {
        let Ok((h, port)) = parse_host_port_parts(bs.strip_prefix("udp://").unwrap_or(bs), 53)
        else {
            continue;
        };
        let Ok(ip) = h.parse::<IpAddr>() else {
            continue;
        };
        let addr = SocketAddr::new(ip, port);
        if let Ok(resp) =
            query_udp_raw(addr, &query, timeout.min(Duration::from_millis(1500))).await
            && let Some(parsed) = parse_dns_answer_ips(&resp, true)
            && !parsed.ips.is_empty()
        {
            found = parsed.ips;
            break;
        }
    }
    if found.is_empty()
        && let Ok(iter) = tokio::net::lookup_host(format!("{clean}:443")).await
    {
        for a in iter {
            if !is_disallowed_ip(a.ip(), true) {
                found.push(a.ip());
            }
        }
    }
    if found.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to bootstrap DNS server host {clean}"),
        ));
    }
    if let Ok(mut guard) = global_state().bootstrap_host_cache.lock() {
        guard.put(clean, (found.clone(), Instant::now()));
    }
    Ok(found)
}

async fn connect_dns_tls_with_policy(
    dst: SocketAddr,
    sni: &str,
    alpn: &[u8],
    desync_doh_dot: bool,
    timeout: Duration,
) -> io::Result<(Tls13ClientStream, bool)> {
    if !desync_doh_dot {
        let stream = connect_tls13_stream(dst, sni, alpn, None, timeout).await?;
        return Ok((stream, false));
    }

    let tlsrec_cfg: UpstreamDesyncConfig =
        DesyncConfig::from_preset(DesyncPreset::TlsRec).to_upstream();
    match connect_tls13_stream(dst, sni, alpn, Some(&tlsrec_cfg), timeout).await {
        Ok(stream) => Ok((stream, true)),
        Err(first_err) => {
            if is_cloudflare_ip(dst.ip()) {
                return Err(first_err);
            }
            let fake_split_cfg: UpstreamDesyncConfig =
                DesyncConfig::from_preset(DesyncPreset::FakeSplit).to_upstream();
            let stream =
                connect_tls13_stream(dst, sni, alpn, Some(&fake_split_cfg), timeout).await?;
            Ok((stream, true))
        }
    }
}

fn pool_slot(key: &str) -> Arc<AsyncMutex<Option<PooledTlsConn>>> {
    let mut pool = global_state()
        .tls_pool
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = pool.get(key) {
        return Arc::clone(slot);
    }
    let slot = Arc::new(AsyncMutex::new(None));
    pool.put(key.to_string(), Arc::clone(&slot));
    slot
}

async fn exchange_dot_on_stream(
    stream: &mut Tls13ClientStream,
    query_pkt: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let len_u16 = u16::try_from(query_pkt.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large"))?;
    let mut frame = Vec::with_capacity(2 + query_pkt.len());
    frame.extend_from_slice(&len_u16.to_be_bytes());
    frame.extend_from_slice(query_pkt);
    stream.write_all_encrypted(&frame, timeout).await?;

    let mut rx = Vec::with_capacity(512);
    let deadline = Instant::now() + timeout;
    while rx.len() < 2 {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DoT length timeout",
            ));
        }
        let n = stream.read_decrypted_chunk(&mut rx, rem).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DoT peer closed before length",
            ));
        }
    }
    let msg_len = u16::from_be_bytes([rx[0], rx[1]]) as usize;
    if !(12..=65_535).contains(&msg_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DoT DNS frame length",
        ));
    }
    while rx.len() < 2 + msg_len {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DoT body timeout"));
        }
        let n = stream.read_decrypted_chunk(&mut rx, rem).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DoT peer closed mid-frame",
            ));
        }
    }
    Ok(rx[2..2 + msg_len].to_vec())
}

async fn exchange_doh_on_stream(
    stream: &mut Tls13ClientStream,
    ep: &DohEndpoint,
    query_pkt: &[u8],
    timeout: Duration,
) -> io::Result<(Vec<u8>, bool)> {
    let req_hdr = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        ep.path,
        ep.host_header,
        query_pkt.len()
    );
    let mut req = Vec::with_capacity(req_hdr.len() + query_pkt.len());
    req.extend_from_slice(req_hdr.as_bytes());
    req.extend_from_slice(query_pkt);
    stream.write_all_encrypted(&req, timeout).await?;

    const MAX_DOH_BYTES: usize = 65_536;
    let mut buf = Vec::with_capacity(1024);
    let deadline = Instant::now() + timeout;
    let hdr_end = loop {
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 16_384 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH response headers exceed 16 KiB",
            ));
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DoH header timeout",
            ));
        }
        let n = stream.read_decrypted_chunk(&mut buf, rem).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DoH peer closed before headers",
            ));
        }
    };

    let hdr_str = std::str::from_utf8(&buf[..hdr_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 DoH headers"))?;
    let mut lines = hdr_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut close_conn = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_l = k.trim().to_ascii_lowercase();
            let v_l = v.trim().to_ascii_lowercase();
            if k_l == "content-length" {
                content_length = v_l.parse::<usize>().ok();
            } else if k_l == "transfer-encoding" && v_l.contains("chunked") {
                chunked = true;
            } else if k_l == "connection" && v_l.contains("close") {
                close_conn = true;
            }
        }
    }

    let body_start = hdr_end + 4;
    let body = if let Some(cl) = content_length {
        if cl > MAX_DOH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH response exceeds 64 KiB limit",
            ));
        }
        while buf.len() < body_start + cl {
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "DoH body timeout"));
            }
            let n = stream.read_decrypted_chunk(&mut buf, rem).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DoH peer closed before Content-Length",
                ));
            }
        }
        buf[body_start..body_start + cl].to_vec()
    } else if chunked {
        loop {
            if let Some(decoded) = try_decode_chunked_body(&buf[body_start..], MAX_DOH_BYTES)? {
                break decoded;
            }
            if buf.len() > MAX_DOH_BYTES + 16_384 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DoH chunked response exceeds 64 KiB",
                ));
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DoH chunked body timeout",
                ));
            }
            let n = stream.read_decrypted_chunk(&mut buf, rem).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DoH peer closed before final chunk",
                ));
            }
        }
    } else {
        close_conn = true;
        loop {
            if buf.len() >= body_start + MAX_DOH_BYTES {
                break;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                break;
            }
            match stream.read_decrypted_chunk(&mut buf, rem).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        buf[body_start..].to_vec()
    };

    if status_code != 200 {
        return Err(io::Error::other(format!("DoH HTTP status {status_code}")));
    }
    if body.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DoH body shorter than DNS header",
        ));
    }
    Ok((body, close_conn || stream.is_closed()))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn try_decode_chunked_body(raw: &[u8], max_len: usize) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(rel_end) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&raw[pos..pos + rel_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hex chunk size"))?;
        pos += rel_end + 2;
        if chunk_len == 0 {
            if raw.len() < pos + 2 {
                return Ok(None);
            }
            return Ok(Some(out));
        }
        if out.len() + chunk_len > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked DoH payload exceeds 64 KiB",
            ));
        }
        if raw.len() < pos + chunk_len + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&raw[pos..pos + chunk_len]);
        pos += chunk_len + 2;
    }
}

async fn query_single_server(
    server: &str,
    proto: DnsProtocol,
    query_pkt: &[u8],
    bootstrap_servers: &[String],
    desync_doh_dot: bool,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    match proto {
        DnsProtocol::Udp => {
            let clean = server.strip_prefix("udp://").unwrap_or(server);
            let (host, port) = parse_host_port_parts(clean, 53)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let ip: IpAddr = if let Ok(ip) = host.parse() {
                ip
            } else {
                let ips = resolve_server_host_ips(&host, bootstrap_servers, timeout).await?;
                ips.into_iter()
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no server IP"))?
            };
            query_udp_raw(SocketAddr::new(ip, port), query_pkt, timeout).await
        }
        DnsProtocol::Dot => {
            let clean = server.strip_prefix("tls://").unwrap_or(server);
            let (host, port) = parse_host_port_parts(clean, 853)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let ips = resolve_server_host_ips(&host, bootstrap_servers, timeout).await?;
            let dst = SocketAddr::new(ips[0], port);
            let sni = if host.parse::<IpAddr>().is_ok() {
                ""
            } else {
                host.as_str()
            };
            let pool_key = format!("dot:{dst}:{sni}:{desync_doh_dot}");
            let slot = pool_slot(&pool_key);
            let mut guard = slot.lock().await;

            if let Some(conn) = guard.as_mut() {
                if !conn.stream.is_closed() && conn.last_used.elapsed() < Duration::from_secs(45) {
                    match exchange_dot_on_stream(&mut conn.stream, query_pkt, timeout).await {
                        Ok(resp) => {
                            conn.last_used = Instant::now();
                            return Ok(resp);
                        }
                        Err(_) => {
                            *guard = None;
                        }
                    }
                } else {
                    *guard = None;
                }
            }

            let (mut stream, _) =
                connect_dns_tls_with_policy(dst, sni, b"dot", desync_doh_dot, timeout).await?;
            let resp = exchange_dot_on_stream(&mut stream, query_pkt, timeout).await?;
            if !stream.is_closed() {
                *guard = Some(PooledTlsConn {
                    stream,
                    last_used: Instant::now(),
                });
            }
            Ok(resp)
        }
        DnsProtocol::Doh => {
            let ep = parse_doh_url(server)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let ips = resolve_server_host_ips(&ep.host, bootstrap_servers, timeout).await?;
            let dst = SocketAddr::new(ips[0], ep.port);
            let sni = if ep.host.parse::<IpAddr>().is_ok() {
                ""
            } else {
                ep.host.as_str()
            };
            let pool_key = format!("doh:{dst}:{sni}:{desync_doh_dot}");
            let slot = pool_slot(&pool_key);
            let mut guard = slot.lock().await;

            if let Some(conn) = guard.as_mut() {
                if !conn.stream.is_closed() && conn.last_used.elapsed() < Duration::from_secs(45) {
                    match exchange_doh_on_stream(&mut conn.stream, &ep, query_pkt, timeout).await {
                        Ok((resp, close_conn)) => {
                            if close_conn {
                                *guard = None;
                            } else {
                                conn.last_used = Instant::now();
                            }
                            return Ok(resp);
                        }
                        Err(_) => {
                            *guard = None;
                        }
                    }
                } else {
                    *guard = None;
                }
            }

            let (mut stream, _) =
                connect_dns_tls_with_policy(dst, sni, b"http/1.1", desync_doh_dot, timeout).await?;
            let (resp, close_conn) =
                exchange_doh_on_stream(&mut stream, &ep, query_pkt, timeout).await?;
            if !close_conn && !stream.is_closed() {
                *guard = Some(PooledTlsConn {
                    stream,
                    last_used: Instant::now(),
                });
            }
            Ok(resp)
        }
    }
}

async fn query_udp_parallel(
    servers: &[String],
    query_pkt: &[u8],
    timeout: Duration,
    req_txid: u16,
    rewrite_ttl_secs: u32,
    reject_fake_ip: bool,
) -> io::Result<(Vec<u8>, u32)> {
    let mut set = JoinSet::new();
    for srv in servers.iter().take(3) {
        let s = srv.clone();
        let q = query_pkt.to_vec();
        set.spawn(async move {
            query_single_server(&s, DnsProtocol::Udp, &q, &[], false, timeout).await
        });
    }
    let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "no UDP DNS response");
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(raw)) => {
                if let Some(rewritten) =
                    rewrite_dns_response_packet(&raw, req_txid, rewrite_ttl_secs, reject_fake_ip)
                {
                    set.abort_all();
                    return Ok(rewritten);
                }
            }
            Ok(Err(e)) => last_err = e,
            Err(e) => last_err = io::Error::other(e.to_string()),
        }
    }
    Err(last_err)
}

async fn query_upstream_with_policy(
    qname: &str,
    query_pkt: &[u8],
    req_txid: u16,
    settings: &DnsSettings,
    orig_dst: Option<SocketAddr>,
) -> io::Result<(Vec<u8>, u32)> {
    let st = global_state();
    st.failover.total_queries.fetch_add(1, Ordering::Relaxed);
    let timeout = Duration::from_millis(settings.check_timeout_ms.clamp(300, 10_000) as u64);

    if !settings.enabled {
        if let Some(dst) = orig_dst {
            let raw = query_udp_raw(dst, query_pkt, timeout).await?;
            return rewrite_dns_response_packet(&raw, req_txid, settings.rewrite_ttl_secs, false)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad system DNS reply"));
        }
        return Err(io::Error::other("custom DNS disabled"));
    }

    if settings.split_local_ru
        && is_local_or_ru_domain(qname)
        && !settings.bootstrap_servers.is_empty()
        && let Ok(ok) = query_udp_parallel(
            &settings.bootstrap_servers,
            query_pkt,
            timeout.min(Duration::from_millis(1600)),
            req_txid,
            settings.rewrite_ttl_secs,
            settings.reject_fake_ip,
        )
        .await
    {
        return Ok(ok);
    }

    if matches!(settings.protocol, DnsProtocol::Doh | DnsProtocol::Dot) {
        st.failover
            .encrypted_queries
            .fetch_add(1, Ordering::Relaxed);
    }

    let primary_res = match settings.upstream_mode {
        DnsUpstreamMode::Parallel => {
            let mut set = JoinSet::new();
            for srv in settings.servers.iter().take(3) {
                let s = srv.clone();
                let q = query_pkt.to_vec();
                let proto = settings.protocol;
                let boot = settings.bootstrap_servers.clone();
                let desync = settings.desync_doh_dot;
                set.spawn(async move {
                    query_single_server(&s, proto, &q, &boot, desync, timeout).await
                });
            }
            let mut out = None;
            let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "DNS parallel timeout");
            while let Some(res) = set.join_next().await {
                match res {
                    Ok(Ok(raw)) => {
                        if let Some(rewritten) = rewrite_dns_response_packet(
                            &raw,
                            req_txid,
                            settings.rewrite_ttl_secs,
                            settings.reject_fake_ip,
                        ) {
                            set.abort_all();
                            out = Some(rewritten);
                            break;
                        }
                    }
                    Ok(Err(e)) => last_err = e,
                    Err(e) => last_err = io::Error::other(e.to_string()),
                }
            }
            out.ok_or(last_err)
        }
        DnsUpstreamMode::Sequential => {
            let n = settings.servers.len();
            if n == 0 {
                Err(io::Error::new(io::ErrorKind::NotFound, "no DNS servers"))
            } else {
                let start_idx = st.failover.active_index.load(Ordering::Relaxed) % n;
                let mut out = None;
                let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "sequential DNS failed");
                for step in 0..n {
                    let idx = (start_idx + step) % n;
                    let srv = &settings.servers[idx];
                    match query_single_server(
                        srv,
                        settings.protocol,
                        query_pkt,
                        &settings.bootstrap_servers,
                        settings.desync_doh_dot,
                        timeout,
                    )
                    .await
                    {
                        Ok(raw) => {
                            if let Some(rewritten) = rewrite_dns_response_packet(
                                &raw,
                                req_txid,
                                settings.rewrite_ttl_secs,
                                settings.reject_fake_ip,
                            ) {
                                if step == 0 {
                                    st.failover.consecutive_failures.store(0, Ordering::Relaxed);
                                } else {
                                    let fails = st
                                        .failover
                                        .consecutive_failures
                                        .fetch_add(1, Ordering::Relaxed)
                                        + 1;
                                    if fails >= settings.failure_threshold {
                                        st.failover.active_index.store(idx, Ordering::Relaxed);
                                        st.failover
                                            .consecutive_failures
                                            .store(0, Ordering::Relaxed);
                                        st.failover
                                            .failover_switches
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                out = Some(rewritten);
                                break;
                            }
                        }
                        Err(e) => {
                            last_err = e;
                            if step == 0 {
                                let fails = st
                                    .failover
                                    .consecutive_failures
                                    .fetch_add(1, Ordering::Relaxed)
                                    + 1;
                                if fails >= settings.failure_threshold && n > 1 {
                                    let next_idx = (idx + 1) % n;
                                    st.failover.active_index.store(next_idx, Ordering::Relaxed);
                                    st.failover.consecutive_failures.store(0, Ordering::Relaxed);
                                    st.failover
                                        .failover_switches
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                out.ok_or(last_err)
            }
        }
    };

    if let Ok(ok) = primary_res {
        return Ok(ok);
    }

    if !settings.fallback_servers.is_empty()
        && let Ok(ok) = query_udp_parallel(
            &settings.fallback_servers,
            query_pkt,
            timeout,
            req_txid,
            settings.rewrite_ttl_secs,
            settings.reject_fake_ip,
        )
        .await
    {
        return Ok(ok);
    }

    if settings.fallback_system_dns
        && let Some(dst) = orig_dst
        && let Ok(raw) = query_udp_raw(dst, query_pkt, timeout).await
        && let Some(rewritten) = rewrite_dns_response_packet(
            &raw,
            req_txid,
            settings.rewrite_ttl_secs,
            settings.reject_fake_ip,
        )
    {
        return Ok(rewritten);
    }

    primary_res
}

// ---------------------------------------------------------------------------
// Основные точки входа: resolve_hostname и forward_tun_dns_packet
// ---------------------------------------------------------------------------

fn order_ips_by_strategy(ips: &[IpAddr], strategy: DnsIpStrategy) -> Vec<IpAddr> {
    let v4: Vec<IpAddr> = ips.iter().copied().filter(|ip| ip.is_ipv4()).collect();
    let v6: Vec<IpAddr> = ips.iter().copied().filter(|ip| ip.is_ipv6()).collect();
    match strategy {
        DnsIpStrategy::PreferIpv4 => [v4, v6].concat(),
        DnsIpStrategy::Ipv4Only => v4,
        DnsIpStrategy::PreferIpv6 => [v6, v4].concat(),
        DnsIpStrategy::Ipv6Only => v6,
        DnsIpStrategy::AsIs => ips.to_vec(),
    }
}

pub async fn resolve_hostname(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty host"));
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    if let Some(ov_ip) = lookup_custom_dns_override(&clean) {
        record_dns_mapping(ov_ip, &clean);
        return Ok(vec![SocketAddr::new(ov_ip, port)]);
    }

    let settings = current_dns_settings();
    let st = global_state();

    if settings.local_cache
        && let Ok(mut rc) = st.resolve_cache.lock()
        && let Some(entry) = rc.get(&clean)
        && entry.expires_at > Instant::now()
    {
        let ordered = order_ips_by_strategy(&entry.ips, settings.strategy);
        if !ordered.is_empty() {
            st.failover.cache_hits.fetch_add(1, Ordering::Relaxed);
            st.failover.total_queries.fetch_add(1, Ordering::Relaxed);
            return Ok(ordered
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }
    }

    if !settings.enabled {
        return resolve_via_system_dns(&clean, port, settings.strategy, settings.reject_fake_ip)
            .await;
    }

    let need_v4 = !matches!(settings.strategy, DnsIpStrategy::Ipv6Only);
    let need_v6 = !matches!(settings.strategy, DnsIpStrategy::Ipv4Only);

    let mut collected_ips = Vec::new();
    let mut min_ttl = 60u32;

    if need_v4 && need_v6 {
        let q4 = build_dns_query(&clean, 1, 0x5444)?;
        let q6 = build_dns_query(&clean, 28, 0x5446)?;
        let (r4, r6) = tokio::join!(
            query_upstream_with_policy(&clean, &q4, 0x5444, &settings, None),
            query_upstream_with_policy(&clean, &q6, 0x5446, &settings, None),
        );
        if let Ok((resp4, ttl4)) = r4
            && let Some(parsed) = parse_dns_answer_ips(&resp4, settings.reject_fake_ip)
        {
            min_ttl = min_ttl.min(ttl4);
            collected_ips.extend(parsed.ips);
        }
        if let Ok((resp6, ttl6)) = r6
            && let Some(parsed) = parse_dns_answer_ips(&resp6, settings.reject_fake_ip)
        {
            min_ttl = min_ttl.min(ttl6);
            collected_ips.extend(parsed.ips);
        }
    } else if need_v4 {
        let q4 = build_dns_query(&clean, 1, 0x5444)?;
        if let Ok((resp4, ttl4)) =
            query_upstream_with_policy(&clean, &q4, 0x5444, &settings, None).await
            && let Some(parsed) = parse_dns_answer_ips(&resp4, settings.reject_fake_ip)
        {
            min_ttl = min_ttl.min(ttl4);
            collected_ips.extend(parsed.ips);
        }
    } else if need_v6 {
        let q6 = build_dns_query(&clean, 28, 0x5446)?;
        if let Ok((resp6, ttl6)) =
            query_upstream_with_policy(&clean, &q6, 0x5446, &settings, None).await
            && let Some(parsed) = parse_dns_answer_ips(&resp6, settings.reject_fake_ip)
        {
            min_ttl = min_ttl.min(ttl6);
            collected_ips.extend(parsed.ips);
        }
    }

    if collected_ips.is_empty()
        && (settings.fallback_system_dns || clean == "localhost")
        && let Ok(sys_addrs) =
            resolve_via_system_dns(&clean, port, settings.strategy, settings.reject_fake_ip).await
    {
        return Ok(sys_addrs);
    }

    let ordered = order_ips_by_strategy(&collected_ips, settings.strategy);
    if ordered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS lookup returned no addresses for {clean}"),
        ));
    }

    for &ip in &ordered {
        record_dns_mapping(ip, &clean);
    }
    if settings.local_cache
        && let Ok(mut rc) = st.resolve_cache.lock()
    {
        let ttl = if settings.rewrite_ttl_secs > 0 {
            settings.rewrite_ttl_secs
        } else {
            min_ttl.clamp(5, 3600)
        };
        rc.put(
            clean,
            CachedResolveEntry {
                ips: collected_ips,
                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }

    Ok(ordered
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

async fn resolve_via_system_dns(
    clean: &str,
    port: u16,
    strategy: DnsIpStrategy,
    reject_fake_ip: bool,
) -> io::Result<Vec<SocketAddr>> {
    let iter = tokio::net::lookup_host(format!("{clean}:{port}")).await?;
    let mut ips = Vec::new();
    for a in iter {
        let ip = a.ip();
        if clean == "localhost" || !is_disallowed_ip(ip, reject_fake_ip) {
            ips.push(ip);
        }
    }
    let ordered = order_ips_by_strategy(&ips, strategy);
    if ordered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("system DNS returned no addresses for {clean}"),
        ));
    }
    for &ip in &ordered {
        record_dns_mapping(ip, clean);
    }
    Ok(ordered
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// Перехватить и обработать сырой UDP/53 запрос из TUN (IPv4 и IPv6).
pub async fn forward_tun_dns_packet(query_pkt: &[u8], orig_dst: SocketAddr) -> io::Result<Vec<u8>> {
    if query_pkt.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "short DNS packet",
        ));
    }
    let req_txid = u16::from_be_bytes([query_pkt[0], query_pkt[1]]);
    let settings = current_dns_settings();

    let Some((qname, qtype, _qclass, qend)) = parse_dns_question_section(query_pkt) else {
        return query_udp_raw(
            orig_dst,
            query_pkt,
            Duration::from_millis(settings.check_timeout_ms.clamp(300, 10_000) as u64),
        )
        .await;
    };

    if let Some(ov_ip) = lookup_custom_dns_override(&qname) {
        record_dns_mapping(ov_ip, &qname);
        let match_ip = match (qtype, ov_ip) {
            (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)) => Some(ov_ip),
            (1, IpAddr::V6(_)) | (28, IpAddr::V4(_)) => None,
            _ => None,
        };
        if qtype == 1 || qtype == 28 {
            return Ok(build_synthetic_dns_response(
                query_pkt,
                qend,
                match_ip,
                settings.rewrite_ttl_secs,
            ));
        }
    }

    // 0.1 Обратные PTR-запросы (*.in-addr.arpa, *.ip6.arpa): отвечаем локально из таблицы IP -> Домен
    // и не пропускаем приватные / FakeIP адреса во внешние резолверы.
    if settings.enabled
        && qtype == 12
        && let Some(ptr_ip) = parse_ptr_arpa(&qname)
    {
        if let Some(mapped_domain) = crate::lists::lookup_dns_mapping(ptr_ip) {
            return Ok(build_synthetic_ptr_response(
                query_pkt,
                qend,
                Some(&mapped_domain),
                settings.rewrite_ttl_secs,
            ));
        }
        if crate::lists::is_private_or_loopback(ptr_ip) || is_disallowed_ip(ptr_ip, true) {
            return Ok(build_synthetic_ptr_response(
                query_pkt,
                qend,
                None,
                settings.rewrite_ttl_secs,
            ));
        }
    }

    if settings.enabled
        && ((settings.strategy == DnsIpStrategy::Ipv4Only && qtype == 28)
            || (settings.strategy == DnsIpStrategy::Ipv6Only && qtype == 1))
    {
        return Ok(build_synthetic_dns_response(
            query_pkt,
            qend,
            None,
            settings.rewrite_ttl_secs,
        ));
    }

    let st = global_state();
    let cache_key = WireCacheKey {
        qname: qname.clone(),
        qtype,
    };
    if settings.enabled
        && settings.local_cache
        && let Ok(mut wc) = st.wire_cache.lock()
        && let Some(entry) = wc.get(&cache_key)
        && entry.expires_at > Instant::now()
    {
        st.failover.cache_hits.fetch_add(1, Ordering::Relaxed);
        st.failover.total_queries.fetch_add(1, Ordering::Relaxed);
        let mut pkt = entry.packet.clone();
        pkt[0..2].copy_from_slice(&req_txid.to_be_bytes());
        snoop_dns_response_packet(&pkt);
        return Ok(pkt);
    }

    let (mut resp, ttl) =
        query_upstream_with_policy(&qname, query_pkt, req_txid, &settings, Some(orig_dst)).await?;
    if settings.enabled && (qtype == 64 || qtype == 65) {
        let strip_v4 = settings.strategy == DnsIpStrategy::Ipv6Only
            || lookup_custom_dns_override(&qname).is_some();
        let strip_v6 = settings.strategy == DnsIpStrategy::Ipv4Only
            || lookup_custom_dns_override(&qname).is_some();
        if strip_v4 || strip_v6 {
            resp = rewrite_svcb_https_hints(&resp, strip_v4, strip_v6);
        }
    }
    snoop_dns_response_packet(&resp);

    if settings.enabled
        && settings.local_cache
        && ttl > 0
        && let Ok(mut wc) = st.wire_cache.lock()
    {
        wc.put(
            cache_key,
            CachedWireEntry {
                packet: resp.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl.clamp(5, 3600) as u64),
            },
        );
    }

    Ok(resp)
}

// ---------------------------------------------------------------------------
// Бенчмарк, автонастройка и многодоменный тест скорости
// ---------------------------------------------------------------------------

fn rate_latency(latency_ms: i32, loss_pct: u8) -> String {
    if latency_ms < 0 || loss_pct >= 100 {
        "failed".to_string()
    } else if loss_pct == 0 && latency_ms <= 65 {
        "excellent".to_string()
    } else if loss_pct <= 25 && latency_ms <= 140 {
        "good".to_string()
    } else if loss_pct <= 50 && latency_ms <= 280 {
        "fair".to_string()
    } else {
        "slow".to_string()
    }
}

fn select_diverse_rows<'a>(rows: &[&'a DnsBenchRow], max_n: usize) -> Vec<&'a DnsBenchRow> {
    let mut out = Vec::new();
    let mut seen_providers = HashSet::new();
    for r in rows {
        if out.len() >= max_n {
            break;
        }
        if seen_providers.insert(r.provider.as_str()) {
            out.push(*r);
        }
    }
    if out.len() < max_n {
        for r in rows {
            if out.len() >= max_n {
                break;
            }
            if !out.iter().any(|x| x.address == r.address) {
                out.push(*r);
            }
        }
    }
    out
}

/// Чистый алгоритм выбора оптимальной конфигурации DNS по итогам бенчмарка.
pub fn compute_dns_recommendation(results: &[DnsBenchRow]) -> DnsRecommendation {
    let mut working_udp: Vec<&DnsBenchRow> = results
        .iter()
        .filter(|r| r.protocol == DnsProtocol::Udp && r.latency_ms >= 0 && r.rating != "failed")
        .collect();
    working_udp.sort_by_key(|r| r.score);

    let mut working_enc: Vec<&DnsBenchRow> = results
        .iter()
        .filter(|r| {
            matches!(r.protocol, DnsProtocol::Doh | DnsProtocol::Dot)
                && r.latency_ms >= 0
                && r.rating != "failed"
        })
        .collect();
    working_enc.sort_by_key(|r| r.score);

    let top_boot = select_diverse_rows(&working_udp, 2);
    let bootstrap_servers: Vec<String> = if top_boot.is_empty() {
        DnsSettings::default().bootstrap_servers
    } else {
        top_boot.iter().map(|r| r.address.clone()).collect()
    };

    let remaining_udp: Vec<&DnsBenchRow> = working_udp
        .iter()
        .copied()
        .filter(|u| !bootstrap_servers.contains(&u.address))
        .collect();
    let top_fallback = if !remaining_udp.is_empty() {
        select_diverse_rows(&remaining_udp, 2)
    } else {
        select_diverse_rows(&working_udp, 2)
    };
    let fallback_servers: Vec<String> = if top_fallback.is_empty() {
        DnsSettings::default().fallback_servers
    } else {
        top_fallback.iter().map(|r| r.address.clone()).collect()
    };

    // Если среди зашифрованных есть DoH и DoT — предпочитаем лучший протокол по среднему топ-2 счёту (при равенстве DoH)
    let doh_only: Vec<&DnsBenchRow> = working_enc
        .iter()
        .copied()
        .filter(|r| r.protocol == DnsProtocol::Doh)
        .collect();
    let dot_only: Vec<&DnsBenchRow> = working_enc
        .iter()
        .copied()
        .filter(|r| r.protocol == DnsProtocol::Dot)
        .collect();

    let best_doh = select_diverse_rows(&doh_only, 2);
    let best_dot = select_diverse_rows(&dot_only, 2);

    let pick_enc = if !best_doh.is_empty() && !best_dot.is_empty() {
        let doh_avg: i32 = best_doh.iter().map(|r| r.score).sum::<i32>() / best_doh.len() as i32;
        let dot_avg: i32 = best_dot.iter().map(|r| r.score).sum::<i32>() / best_dot.len() as i32;
        if dot_avg + 15 < doh_avg {
            (DnsProtocol::Dot, best_dot)
        } else {
            (DnsProtocol::Doh, best_doh)
        }
    } else if !best_doh.is_empty() {
        (DnsProtocol::Doh, best_doh)
    } else if !best_dot.is_empty() {
        (DnsProtocol::Dot, best_dot)
    } else {
        (DnsProtocol::Udp, Vec::new())
    };

    if !pick_enc.1.is_empty() {
        let servers: Vec<String> = pick_enc.1.iter().map(|r| r.address.clone()).collect();
        let summary: Vec<String> = pick_enc
            .1
            .iter()
            .map(|r| format!("{} ({} мс)", r.provider, r.latency_ms))
            .collect();
        let summary_en: Vec<String> = pick_enc
            .1
            .iter()
            .map(|r| format!("{} ({} ms)", r.provider, r.latency_ms))
            .collect();
        return DnsRecommendation {
            protocol: pick_enc.0,
            upstream_mode: DnsUpstreamMode::Parallel,
            servers,
            bootstrap_servers,
            fallback_servers,
            reason_ru: format!(
                "Выбраны 2 независимых шифрованных {} узла: {}",
                pick_enc.0.label_ru(),
                summary.join(", ")
            ),
            reason_en: format!(
                "Selected 2 independent encrypted {} servers: {}",
                pick_enc.0.label_en(),
                summary_en.join(", ")
            ),
        };
    }

    if !working_udp.is_empty() {
        let top_udp = select_diverse_rows(&working_udp, 2);
        let servers: Vec<String> = top_udp.iter().map(|r| r.address.clone()).collect();
        return DnsRecommendation {
            protocol: DnsProtocol::Udp,
            upstream_mode: DnsUpstreamMode::Parallel,
            servers,
            bootstrap_servers,
            fallback_servers,
            reason_ru:
                "Зашифрованные DoH/DoT серверы недоступны — выбраны самые быстрые UDP-серверы"
                    .to_string(),
            reason_en: "Encrypted DoH/DoT endpoints unreachable — selected fastest UDP servers"
                .to_string(),
        };
    }

    let def = DnsSettings::default();
    DnsRecommendation {
        protocol: def.protocol,
        upstream_mode: def.upstream_mode,
        servers: def.servers,
        bootstrap_servers: def.bootstrap_servers,
        fallback_servers: def.fallback_servers,
        reason_ru: "Все проверенные узлы не ответили — применены безопасные значения по умолчанию"
            .to_string(),
        reason_en: "All probed endpoints timed out — applied safe default configuration"
            .to_string(),
    }
}

#[derive(Clone)]
struct BenchCandidate {
    id: String,
    provider: String,
    protocol: DnsProtocol,
    address: String,
    bootstrap_ip: String,
    tag: String,
}

fn build_bench_candidates() -> Vec<BenchCandidate> {
    let mut out = Vec::new();
    for proto in [DnsProtocol::Udp, DnsProtocol::Dot, DnsProtocol::Doh] {
        for item in presets_for_protocol(proto) {
            if let Some(addr) = item.servers.first() {
                out.push(BenchCandidate {
                    id: format!(
                        "{}_{}",
                        proto.as_str(),
                        item.provider.to_ascii_lowercase().replace([' ', '.'], "_")
                    ),
                    provider: item.provider.to_string(),
                    protocol: proto,
                    address: (*addr).to_string(),
                    bootstrap_ip: item.bootstrap_ip.to_string(),
                    tag: item.tag.to_string(),
                });
            }
        }
    }
    out
}

async fn probe_bench_candidate(
    cand: &BenchCandidate,
    bootstrap_servers: &[String],
    allow_desync: bool,
) -> DnsBenchRow {
    const DOMAINS: &[&str] = &["google.com", "yandex.ru", "cloudflare.com"];
    let timeout = Duration::from_millis(2200);
    let mut used_desync = false;
    let mut latencies = Vec::new();
    let mut failed = 0usize;

    match cand.protocol {
        DnsProtocol::Udp => {
            for (idx, domain) in DOMAINS.iter().enumerate() {
                let Ok(q) = build_dns_query(domain, 1, 0x7000 + idx as u16) else {
                    failed += 1;
                    continue;
                };
                let t0 = Instant::now();
                match query_single_server(&cand.address, DnsProtocol::Udp, &q, &[], false, timeout)
                    .await
                {
                    Ok(resp)
                        if parse_dns_answer_ips(&resp, true).is_some_and(|p| !p.ips.is_empty()) =>
                    {
                        latencies.push(t0.elapsed().as_millis() as i32);
                    }
                    _ => failed += 1,
                }
            }
        }
        DnsProtocol::Dot | DnsProtocol::Doh => {
            let mut eff_boot = bootstrap_servers.to_vec();
            if !cand.bootstrap_ip.is_empty() && !eff_boot.contains(&cand.bootstrap_ip) {
                eff_boot.push(cand.bootstrap_ip.clone());
            }

            let (host, port, ep_opt) = if cand.protocol == DnsProtocol::Doh {
                match parse_doh_url(&cand.address) {
                    Ok(ep) => (ep.host.clone(), ep.port, Some(ep)),
                    Err(_) => {
                        return DnsBenchRow {
                            id: cand.id.clone(),
                            provider: cand.provider.clone(),
                            protocol: cand.protocol,
                            address: cand.address.clone(),
                            tag: cand.tag.clone(),
                            latency_ms: -1,
                            loss_pct: 100,
                            score: 99_999,
                            rating: "failed".to_string(),
                            used_desync: false,
                        };
                    }
                }
            } else {
                let clean = cand.address.strip_prefix("tls://").unwrap_or(&cand.address);
                match parse_host_port_parts(clean, 853) {
                    Ok((h, p)) => (h, p, None),
                    Err(_) => {
                        return DnsBenchRow {
                            id: cand.id.clone(),
                            provider: cand.provider.clone(),
                            protocol: cand.protocol,
                            address: cand.address.clone(),
                            tag: cand.tag.clone(),
                            latency_ms: -1,
                            loss_pct: 100,
                            score: 99_999,
                            rating: "failed".to_string(),
                            used_desync: false,
                        };
                    }
                }
            };

            let ips = match resolve_server_host_ips(&host, &eff_boot, timeout).await {
                Ok(v) if !v.is_empty() => v,
                _ => {
                    return DnsBenchRow {
                        id: cand.id.clone(),
                        provider: cand.provider.clone(),
                        protocol: cand.protocol,
                        address: cand.address.clone(),
                        tag: cand.tag.clone(),
                        latency_ms: -1,
                        loss_pct: 100,
                        score: 99_999,
                        rating: "failed".to_string(),
                        used_desync: false,
                    };
                }
            };
            let dst = SocketAddr::new(ips[0], port);
            let sni = if host.parse::<IpAddr>().is_ok() {
                ""
            } else {
                host.as_str()
            };
            let alpn: &[u8] = if cand.protocol == DnsProtocol::Doh {
                b"http/1.1"
            } else {
                b"dot"
            };

            let mut conn =
                match connect_tls13_stream(dst, sni, alpn, None, Duration::from_millis(1600)).await
                {
                    Ok(s) => Some(s),
                    Err(_) if allow_desync => {
                        match connect_dns_tls_with_policy(dst, sni, alpn, true, timeout).await {
                            Ok((s, used)) => {
                                used_desync = used;
                                Some(s)
                            }
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                };

            if let Some(ref mut stream) = conn {
                // 1 прогревочный + 2 замерных запроса на одном переиспользуемом соединении
                for (step, domain) in ["cloudflare.com", "google.com", "yandex.ru"]
                    .iter()
                    .enumerate()
                {
                    let Ok(q) = build_dns_query(domain, 1, 0x7100 + step as u16) else {
                        if step > 0 {
                            failed += 1;
                        }
                        continue;
                    };
                    let t0 = Instant::now();
                    let ok = if let Some(ref ep) = ep_opt {
                        matches!(
                            exchange_doh_on_stream(stream, ep, &q, timeout).await,
                            Ok((resp, _)) if parse_dns_answer_ips(&resp, true).is_some_and(|p| !p.ips.is_empty())
                        )
                    } else {
                        matches!(
                            exchange_dot_on_stream(stream, &q, timeout).await,
                            Ok(resp) if parse_dns_answer_ips(&resp, true).is_some_and(|p| !p.ips.is_empty())
                        )
                    };
                    if step == 0 {
                        if !ok
                            && allow_desync
                            && !used_desync
                            && let Ok((s2, u2)) =
                                connect_dns_tls_with_policy(dst, sni, alpn, true, timeout).await
                        {
                            // Переподключение если прогрев сбросил сокет (например с TLS Split)
                            *stream = s2;
                            used_desync = u2;
                        }
                    } else if ok {
                        latencies.push(t0.elapsed().as_millis() as i32);
                    } else {
                        failed += 1;
                    }
                }
            } else {
                failed = 2;
            }
        }
    }

    let total_samples = latencies.len() + failed;
    let loss_pct = (failed * 100).checked_div(total_samples).unwrap_or(100) as u8;
    let latency_ms = if latencies.is_empty() {
        -1
    } else {
        latencies.iter().sum::<i32>() / latencies.len() as i32
    };
    let rating = rate_latency(latency_ms, loss_pct);
    let score = if latency_ms < 0 {
        99_999
    } else {
        latency_ms + (loss_pct as i32) * 5
    };

    DnsBenchRow {
        id: cand.id.clone(),
        provider: cand.provider.clone(),
        protocol: cand.protocol,
        address: cand.address.clone(),
        tag: cand.tag.clone(),
        latency_ms,
        loss_pct,
        score,
        rating,
        used_desync,
    }
}

pub async fn run_dns_benchmark(
    shared_state: Arc<Mutex<DnsBenchmarkState>>,
    cancel: Arc<AtomicBool>,
    desync_cfg: DesyncConfig,
) -> Option<DnsRecommendation> {
    let all = build_bench_candidates();
    let total = all.len().max(1);
    let udp_cands: Vec<BenchCandidate> = all
        .iter()
        .filter(|c| c.protocol == DnsProtocol::Udp)
        .cloned()
        .collect();
    let enc_cands: Vec<BenchCandidate> = all
        .iter()
        .filter(|c| c.protocol != DnsProtocol::Udp)
        .cloned()
        .collect();

    if let Ok(mut st) = shared_state.lock() {
        *st = DnsBenchmarkState {
            running: true,
            progress_pct: 0,
            current_target: "Фаза 1: проверка UDP-серверов".to_string(),
            results: Vec::new(),
            recommendation: None,
            error: None,
        };
    }

    let mut completed = 0usize;
    let mut results = Vec::with_capacity(all.len());

    // Фаза 1: UDP до 6 параллельно
    let sem_udp = Arc::new(Semaphore::new(6));
    let mut udp_set = JoinSet::new();
    for cand in udp_cands {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let sem = Arc::clone(&sem_udp);
        udp_set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            probe_bench_candidate(&cand, &[], false).await
        });
    }
    let mut udp_results = Vec::new();
    while let Some(res) = udp_set.join_next().await {
        if cancel.load(Ordering::Relaxed) {
            udp_set.abort_all();
            break;
        }
        if let Ok(row) = res {
            completed += 1;
            udp_results.push(row.clone());
            results.push(row.clone());
            if let Ok(mut st) = shared_state.lock() {
                st.progress_pct = ((completed * 100) / total).min(99) as u8;
                st.current_target = format!("{} ({})", row.provider, row.protocol.label_en());
                st.results = results.clone();
                st.results.sort_by_key(|r| r.score);
            }
        }
    }

    // Выбор топ-2 независимых UDP Bootstrap-узлов для Фазы 2
    udp_results.sort_by_key(|r| r.score);
    let working_udp_refs: Vec<&DnsBenchRow> = udp_results
        .iter()
        .filter(|r| r.latency_ms >= 0 && r.rating != "failed")
        .collect();
    let boot_rows = select_diverse_rows(&working_udp_refs, 2);
    let bootstrap_servers: Vec<String> = if boot_rows.is_empty() {
        DnsSettings::default().bootstrap_servers
    } else {
        boot_rows.iter().map(|r| r.address.clone()).collect()
    };

    // Фаза 2: DoT и DoH до 5 параллельно
    let sem_enc = Arc::new(Semaphore::new(5));
    let mut enc_set = JoinSet::new();
    let allow_desync = desync_cfg.enabled;
    for cand in enc_cands {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let sem = Arc::clone(&sem_enc);
        let boot = bootstrap_servers.clone();
        enc_set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            probe_bench_candidate(&cand, &boot, allow_desync).await
        });
    }
    while let Some(res) = enc_set.join_next().await {
        if cancel.load(Ordering::Relaxed) {
            enc_set.abort_all();
            break;
        }
        if let Ok(row) = res {
            completed += 1;
            results.push(row.clone());
            if let Ok(mut st) = shared_state.lock() {
                st.progress_pct = ((completed * 100) / total).min(99) as u8;
                st.current_target = format!("{} ({})", row.provider, row.protocol.label_en());
                st.results = results.clone();
                st.results.sort_by_key(|r| r.score);
            }
        }
    }

    results.sort_by_key(|r| r.score);
    let was_cancelled = cancel.load(Ordering::Relaxed);
    let rec = if results.is_empty() {
        None
    } else {
        Some(compute_dns_recommendation(&results))
    };

    if let Ok(mut st) = shared_state.lock() {
        st.running = false;
        st.progress_pct = if was_cancelled { st.progress_pct } else { 100 };
        st.current_target = if was_cancelled {
            "Остановлено".to_string()
        } else {
            "Готово".to_string()
        };
        st.results = results;
        st.recommendation = rec.clone();
        if was_cancelled {
            st.error = Some("Бенчмарк остановлен пользователем".to_string());
        }
    }
    rec
}

fn summarize_speed_samples(
    server: String,
    protocol: DnsProtocol,
    role: String,
    samples: Vec<DnsDomainSample>,
) -> DnsSpeedServerReport {
    let total_count = samples.len();
    let success_count = samples.iter().filter(|s| s.ok).count();
    let mut all_ms: Vec<i32> = samples
        .iter()
        .map(|s| if s.ok { s.ms.max(0) } else { 5000 })
        .collect();
    let mut ok_ms: Vec<i32> = samples
        .iter()
        .filter(|s| s.ok)
        .map(|s| s.ms.max(0))
        .collect();
    all_ms.sort_unstable();
    ok_ms.sort_unstable();

    let (min_ms, median_ms, avg_ms, max_ms) = if all_ms.is_empty() {
        (-1, -1, -1, -1)
    } else {
        let min_v = ok_ms.first().copied().unwrap_or(5000);
        let max_v = *all_ms.last().unwrap_or(&5000);
        let med_v = all_ms[all_ms.len() / 2];
        let avg_v = (all_ms.iter().map(|&x| x as i64).sum::<i64>() / all_ms.len() as i64) as i32;
        (min_v, med_v, avg_v, max_v)
    };

    DnsSpeedServerReport {
        server,
        protocol,
        role,
        min_ms,
        median_ms,
        avg_ms,
        max_ms,
        success_count,
        total_count,
        samples,
    }
}

pub async fn run_dns_speed_test(
    mut settings: DnsSettings,
    shared_state: Arc<Mutex<DnsSpeedTestState>>,
    cancel: Arc<AtomicBool>,
    desync_cfg: DesyncConfig,
) {
    sanitize_dns_settings(&mut settings);
    let domains = if settings.speed_test_domains.is_empty() {
        default_speed_test_domains()
    } else {
        settings.speed_test_domains.clone()
    };

    let mut targets: Vec<(String, DnsProtocol, &'static str)> = Vec::new();
    for srv in &settings.servers {
        targets.push((srv.clone(), settings.protocol, "main"));
    }
    for srv in &settings.bootstrap_servers {
        if !targets
            .iter()
            .any(|t| t.0 == *srv && t.1 == DnsProtocol::Udp)
        {
            targets.push((srv.clone(), DnsProtocol::Udp, "bootstrap"));
        }
    }
    for srv in &settings.fallback_servers {
        if !targets
            .iter()
            .any(|t| t.0 == *srv && t.1 == DnsProtocol::Udp)
        {
            targets.push((srv.clone(), DnsProtocol::Udp, "fallback"));
        }
    }

    if let Ok(mut st) = shared_state.lock() {
        *st = DnsSpeedTestState {
            running: true,
            progress_pct: 0,
            current_target: String::new(),
            reports: Vec::new(),
            error: None,
        };
    }

    let total_steps = (targets.len() * domains.len()).max(1);
    let mut step_done = 0usize;
    let mut reports = Vec::with_capacity(targets.len());
    let timeout = Duration::from_millis(settings.check_timeout_ms.clamp(300, 10_000) as u64);
    let use_desync = settings.desync_doh_dot && desync_cfg.enabled;

    for (srv, proto, role) in targets {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // Прогрев соединения / кэша маршрута
        if let Ok(wq) = build_dns_query("example.com", 1, 0x8100) {
            let _ = query_single_server(
                &srv,
                proto,
                &wq,
                &settings.bootstrap_servers,
                use_desync,
                Duration::from_millis(1500),
            )
            .await;
        }

        let mut samples = Vec::with_capacity(domains.len());
        for (idx, domain) in domains.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(mut st) = shared_state.lock() {
                st.current_target = format!("{srv} -> {domain}");
            }
            let sample = match build_dns_query(domain, 1, 0x8200 + idx as u16) {
                Ok(q) => {
                    let t0 = Instant::now();
                    match query_single_server(
                        &srv,
                        proto,
                        &q,
                        &settings.bootstrap_servers,
                        use_desync,
                        timeout,
                    )
                    .await
                    {
                        Ok(resp) => {
                            let ms = t0.elapsed().as_millis() as i32;
                            if let Some(parsed) =
                                parse_dns_answer_ips(&resp, settings.reject_fake_ip)
                            {
                                if !parsed.ips.is_empty() {
                                    DnsDomainSample {
                                        domain: domain.clone(),
                                        ok: true,
                                        ms,
                                        detail: parsed.ips[0].to_string(),
                                    }
                                } else {
                                    DnsDomainSample {
                                        domain: domain.clone(),
                                        ok: false,
                                        ms: 5000,
                                        detail: "no valid records".to_string(),
                                    }
                                }
                            } else {
                                DnsDomainSample {
                                    domain: domain.clone(),
                                    ok: false,
                                    ms: 5000,
                                    detail: "malformed DNS packet".to_string(),
                                }
                            }
                        }
                        Err(e) => DnsDomainSample {
                            domain: domain.clone(),
                            ok: false,
                            ms: 5000,
                            detail: e.to_string(),
                        },
                    }
                }
                Err(e) => DnsDomainSample {
                    domain: domain.clone(),
                    ok: false,
                    ms: 5000,
                    detail: e.to_string(),
                },
            };
            samples.push(sample);
            step_done += 1;
            if let Ok(mut st) = shared_state.lock() {
                st.progress_pct = ((step_done * 100) / total_steps).min(99) as u8;
            }
        }
        reports.push(summarize_speed_samples(
            srv,
            proto,
            role.to_string(),
            samples,
        ));
        if let Ok(mut st) = shared_state.lock() {
            st.reports = reports.clone();
        }
    }

    let cancelled = cancel.load(Ordering::Relaxed);
    if let Ok(mut st) = shared_state.lock() {
        st.running = false;
        if !cancelled {
            st.progress_pct = 100;
            st.current_target = "Готово".to_string();
        } else {
            st.error = Some("Тест скорости остановлен пользователем".to_string());
        }
        st.reports = reports;
    }
}

// ---------------------------------------------------------------------------
// Фоновые задачи health/recovery (Sequential) и turbo_cache
// ---------------------------------------------------------------------------

pub fn spawn_dns_background_tasks(
    stop: Arc<AtomicBool>,
    lists: Vec<ListProfile>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    let settings = current_dns_settings();

    if settings.enabled
        && settings.upstream_mode == DnsUpstreamMode::Sequential
        && settings.servers.len() > 1
    {
        let stop_hc = Arc::clone(&stop);
        handles.push(tokio::spawn(async move {
            loop {
                let s = current_dns_settings();
                if stop_hc.load(Ordering::Relaxed)
                    || !s.enabled
                    || s.upstream_mode != DnsUpstreamMode::Sequential
                    || s.servers.len() <= 1
                {
                    break;
                }
                let idx = global_state().failover.active_index.load(Ordering::Relaxed) % s.servers.len();
                let interval = if idx > 0 {
                    s.recovery_check_interval_secs.clamp(10, 1800)
                } else {
                    s.check_interval_secs.clamp(5, 600)
                };
                for _ in 0..interval {
                    if stop_hc.load(Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                let timeout = Duration::from_millis(s.check_timeout_ms.clamp(300, 10_000) as u64);
                let Ok(q) = build_dns_query("cloudflare.com", 1, 0x9100) else {
                    continue;
                };
                if idx > 0 {
                    let ok = matches!(
                        query_single_server(&s.servers[0], s.protocol, &q, &s.bootstrap_servers, s.desync_doh_dot, timeout).await,
                        Ok(resp) if parse_dns_answer_ips(&resp, s.reject_fake_ip).is_some_and(|p| !p.ips.is_empty())
                    );
                    if ok {
                        let succ = global_state().failover.recovery_successes.fetch_add(1, Ordering::Relaxed) + 1;
                        if succ >= s.recovery_threshold {
                            global_state().failover.active_index.store(0, Ordering::Relaxed);
                            global_state().failover.consecutive_failures.store(0, Ordering::Relaxed);
                            global_state().failover.recovery_successes.store(0, Ordering::Relaxed);
                            global_state().failover.failover_switches.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        global_state().failover.recovery_successes.store(0, Ordering::Relaxed);
                    }
                } else {
                    let ok = matches!(
                        query_single_server(&s.servers[0], s.protocol, &q, &s.bootstrap_servers, s.desync_doh_dot, timeout).await,
                        Ok(resp) if parse_dns_answer_ips(&resp, s.reject_fake_ip).is_some_and(|p| !p.ips.is_empty())
                    );
                    if ok {
                        global_state().failover.consecutive_failures.store(0, Ordering::Relaxed);
                    } else {
                        let fails = global_state().failover.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                        if fails >= s.failure_threshold {
                            global_state().failover.active_index.store(1 % s.servers.len(), Ordering::Relaxed);
                            global_state().failover.consecutive_failures.store(0, Ordering::Relaxed);
                            global_state().failover.recovery_successes.store(0, Ordering::Relaxed);
                            global_state().failover.failover_switches.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    if settings.enabled && settings.local_cache && settings.turbo_cache {
        let stop_tc = stop;
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(800)).await;
            if stop_tc.load(Ordering::Relaxed) {
                return;
            }
            let mut domains = Vec::new();
            let mut seen = HashSet::new();
            for list in lists.into_iter().filter(|l| l.enabled) {
                for raw in list.entries {
                    let candidate = raw
                        .trim()
                        .trim_start_matches("*.")
                        .trim_start_matches('.')
                        .to_ascii_lowercase();
                    if candidate.is_empty()
                        || candidate.contains('/')
                        || candidate.contains(':')
                        || candidate.parse::<IpAddr>().is_ok()
                        || !is_valid_hostname(&candidate)
                    {
                        continue;
                    }
                    if seen.insert(candidate.clone()) {
                        domains.push(candidate);
                        if domains.len() >= 48 {
                            break;
                        }
                    }
                }
                if domains.len() >= 48 {
                    break;
                }
            }
            for chunk in domains.chunks(4) {
                if stop_tc.load(Ordering::Relaxed) {
                    break;
                }
                let mut batch = JoinSet::new();
                for dom in chunk {
                    let d = dom.clone();
                    batch.spawn(async move {
                        let _ = resolve_hostname(&d, 443).await;
                    });
                }
                while batch.join_next().await.is_some() {}
            }
        }));
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1035_codec_build_parse_rewrite_and_fake_ip_filter() {
        let query = build_dns_query("api.discord.com", 1, 0xABCD).expect("valid query");
        let (qname, qtype, qclass, qend) =
            parse_dns_question_section(&query).expect("parse question");
        assert_eq!(qname, "api.discord.com");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
        assert_eq!(qend, query.len());

        // Синтетический ответ с двумя A-записями: FakeIP (198.18.0.10) и реальный IP (162.159.135.232)
        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);
        resp.extend_from_slice(&query[12..]);
        // Answer 1: pointer 0xC00C, A, IN, TTL=300, 198.18.0.10
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 198, 18, 0, 10,
        ]);
        // Answer 2: pointer 0xC00C, A, IN, TTL=300, 162.159.135.232
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 162, 159, 135,
            232,
        ]);

        let parsed = parse_dns_answer_ips(&resp, true).expect("parse answer");
        assert_eq!(parsed.total_addr_records, 2);
        assert_eq!(
            parsed.ips,
            vec![IpAddr::V4(Ipv4Addr::new(162, 159, 135, 232))]
        );

        let (rewritten, ttl) =
            rewrite_dns_response_packet(&resp, 0xABCD, 45, true).expect("rewritten");
        assert_eq!(u16::from_be_bytes([rewritten[0], rewritten[1]]), 0xABCD);
        assert_eq!(ttl, 45);
        let parsed2 = parse_dns_answer_ips(&rewritten, true).expect("parse rewritten");
        assert_eq!(parsed2.min_ttl, 45);

        // Если в ответе только FakeIP — ответ отклоняется при reject_fake_ip = true
        let mut only_fake = Vec::new();
        only_fake.extend_from_slice(&[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        only_fake.extend_from_slice(&query[12..]);
        only_fake.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 198, 18, 0, 5,
        ]);
        assert!(rewrite_dns_response_packet(&only_fake, 0xABCD, 60, true).is_none());
    }

    #[test]
    fn compute_dns_recommendation_prefers_two_distinct_encrypted_providers_and_falls_back_to_udp() {
        let rows = vec![
            DnsBenchRow {
                id: "udp_cf".into(),
                provider: "Cloudflare".into(),
                protocol: DnsProtocol::Udp,
                address: "1.1.1.1".into(),
                tag: "Fast".into(),
                latency_ms: 12,
                loss_pct: 0,
                score: 12,
                rating: "excellent".into(),
                used_desync: false,
            },
            DnsBenchRow {
                id: "udp_g".into(),
                provider: "Google".into(),
                protocol: DnsProtocol::Udp,
                address: "8.8.8.8".into(),
                tag: "Fast".into(),
                latency_ms: 18,
                loss_pct: 0,
                score: 18,
                rating: "excellent".into(),
                used_desync: false,
            },
            DnsBenchRow {
                id: "doh_cf1".into(),
                provider: "Cloudflare".into(),
                protocol: DnsProtocol::Doh,
                address: "https://cloudflare-dns.com/dns-query".into(),
                tag: "DoH Encrypted".into(),
                latency_ms: 25,
                loss_pct: 0,
                score: 25,
                rating: "excellent".into(),
                used_desync: true,
            },
            DnsBenchRow {
                id: "doh_cf2".into(),
                provider: "Cloudflare".into(),
                protocol: DnsProtocol::Doh,
                address: "https://1.0.0.1/dns-query".into(),
                tag: "DoH Encrypted".into(),
                latency_ms: 26,
                loss_pct: 0,
                score: 26,
                rating: "excellent".into(),
                used_desync: true,
            },
            DnsBenchRow {
                id: "doh_adg".into(),
                provider: "AdGuard".into(),
                protocol: DnsProtocol::Doh,
                address: "https://dns.adguard-dns.com/dns-query".into(),
                tag: "DoH Filter".into(),
                latency_ms: 35,
                loss_pct: 0,
                score: 35,
                rating: "excellent".into(),
                used_desync: false,
            },
        ];

        let rec = compute_dns_recommendation(&rows);
        assert_eq!(rec.protocol, DnsProtocol::Doh);
        assert_eq!(rec.upstream_mode, DnsUpstreamMode::Parallel);
        assert_eq!(
            rec.servers,
            vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.adguard-dns.com/dns-query".to_string()
            ]
        );
        assert_eq!(rec.bootstrap_servers, vec!["1.1.1.1", "8.8.8.8"]);

        // При недоступности DoH/DoT выбирает топ-2 UDP
        let udp_only: Vec<DnsBenchRow> = rows
            .into_iter()
            .filter(|r| r.protocol == DnsProtocol::Udp)
            .collect();
        let rec_udp = compute_dns_recommendation(&udp_only);
        assert_eq!(rec_udp.protocol, DnsProtocol::Udp);
        assert_eq!(rec_udp.servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn speed_test_report_math_uses_5000ms_penalty_for_failures() {
        let samples = vec![
            DnsDomainSample {
                domain: "a.com".into(),
                ok: true,
                ms: 10,
                detail: "1.1.1.1".into(),
            },
            DnsDomainSample {
                domain: "b.com".into(),
                ok: true,
                ms: 30,
                detail: "8.8.8.8".into(),
            },
            DnsDomainSample {
                domain: "c.com".into(),
                ok: false,
                ms: 5000,
                detail: "timeout".into(),
            },
        ];
        let rep =
            summarize_speed_samples("1.1.1.1".into(), DnsProtocol::Udp, "main".into(), samples);
        assert_eq!(rep.success_count, 2);
        assert_eq!(rep.total_count, 3);
        assert_eq!(rep.min_ms, 10);
        assert_eq!(rep.median_ms, 30);
        assert_eq!(rep.max_ms, 5000);
        assert_eq!(rep.avg_ms, (10 + 30 + 5000) / 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_udp_dns_tests_cache_ttl_rewrite_and_sequential_failover() {
        let _guard = test_dns_state_lock().lock().await;
        let bad_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = bad_sock.local_addr().unwrap();
        drop(bad_sock); // закрыт — вызовы будут отклоняться/падать сразу

        let good_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_sock.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);

        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = good_sock.recv_from(&mut buf).await else {
                    break;
                };
                if n < 12 {
                    continue;
                }
                hits_srv.fetch_add(1, Ordering::Relaxed);
                let Some((_qn, qtype, _qc, qend)) = parse_dns_question_section(&buf[..n]) else {
                    continue;
                };
                let ip = if qtype == 28 {
                    Some(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()))
                } else {
                    Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                };
                let resp = build_synthetic_dns_response(&buf[..n], qend, ip, 300);
                let _ = good_sock.send_to(&resp, peer).await;
            }
        });

        flush_dns_caches();
        let s = DnsSettings {
            enabled: true,
            protocol: DnsProtocol::Udp,
            upstream_mode: DnsUpstreamMode::Sequential,
            servers: vec![dead_addr.to_string(), good_addr.to_string()],
            bootstrap_servers: vec![good_addr.to_string()],
            fallback_servers: Vec::new(),
            split_local_ru: false,
            failure_threshold: 1,
            rewrite_ttl_secs: 77,
            local_cache: true,
            strategy: DnsIpStrategy::Ipv4Only,
            ..Default::default()
        };
        apply_dns_settings(&s);

        let q = build_dns_query("unit-cache-failover.example", 1, 0xCAFE).unwrap();
        let r1 = forward_tun_dns_packet(&q, dead_addr)
            .await
            .expect("failover to second sequential server");
        let parsed1 = parse_dns_answer_ips(&r1, true).expect("parsed reply");
        assert_eq!(parsed1.min_ttl, 77);
        assert_eq!(
            parsed1.ips,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        assert_eq!(current_dns_status().active_index, 1);
        assert!(current_dns_status().failover_switches >= 1);

        // Повторный запрос с другим TXID должен прийти из локального кэша (hits == 1)
        let q2 = build_dns_query("unit-cache-failover.example", 1, 0xBEEF).unwrap();
        let r2 = forward_tun_dns_packet(&q2, dead_addr)
            .await
            .expect("cached reply");
        assert_eq!(u16::from_be_bytes([r2[0], r2[1]]), 0xBEEF);
        assert_eq!(hits.load(Ordering::Relaxed), 1);

        srv_task.abort();
        flush_dns_caches();
        apply_dns_settings(&DnsSettings::default());
    }

    #[test]
    fn ptr_arpa_soa_nodata_and_https_svcb_hint_stripping() {
        assert_eq!(
            parse_ptr_arpa("4.3.2.1.in-addr.arpa."),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            parse_ptr_arpa(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa"
            ),
            Some("fc00::1".parse().unwrap())
        );
        assert_eq!(parse_ptr_arpa("bad.ip6.arpa"), None);

        // PTR synthetic response + SOA on NXDOMAIN
        let ptr_q = build_dns_query("4.3.2.1.in-addr.arpa", 12, 0x1122).unwrap();
        let (_, _, _, qend) = parse_dns_question_section(&ptr_q).unwrap();
        let ptr_ok = build_synthetic_ptr_response(&ptr_q, qend, Some("svc.example.com"), 90);
        assert_eq!(ptr_ok[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([ptr_ok[6], ptr_ok[7]]), 1);
        let ptr_nx = build_synthetic_ptr_response(&ptr_q, qend, None, 90);
        assert_eq!(ptr_nx[3] & 0x0F, 3);
        assert_eq!(u16::from_be_bytes([ptr_nx[8], ptr_nx[9]]), 1);

        // NODATA + SOA for filtered AAAA under Ipv4Only
        let aaaa_q = build_dns_query("svc.example.com", 28, 0x2233).unwrap();
        let (_, _, _, qend_a) = parse_dns_question_section(&aaaa_q).unwrap();
        let nodata = build_synthetic_dns_response(&aaaa_q, qend_a, None, 60);
        assert_eq!(u16::from_be_bytes([nodata[6], nodata[7]]), 0);
        assert_eq!(u16::from_be_bytes([nodata[8], nodata[9]]), 1);

        // TYPE 65 HTTPS RDATA: priority=1, target=".", params: Mandatory(4,6), ALPN("h2"), ipv4hint(1.1.1.1), ipv6hint(2606:4700::1)
        let https_q = build_dns_query("svc.example.com", 65, 0x3344).unwrap();
        let mut resp = https_q.clone();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[7] = 0x01;
        let mut rdata = vec![0x00, 0x01, 0x00]; // prio 1, root target "."
        // Mandatory [4, 6]
        rdata.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x06]);
        // ALPN "h2" (key 1)
        rdata.extend_from_slice(&[0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2']);
        // ipv4hint (key 4)
        rdata.extend_from_slice(&[0x00, 0x04, 0x00, 0x04, 1, 1, 1, 1]);
        // ipv6hint (key 6)
        let v6: Ipv6Addr = "2606:4700::1".parse().unwrap();
        rdata.extend_from_slice(&[0x00, 0x06, 0x00, 0x10]);
        rdata.extend_from_slice(&v6.octets());
        resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 65, 0x00, 0x01, 0, 0, 0, 60]);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        let stripped = rewrite_svcb_https_hints(&resp, false, true);
        // ipv6hint 16-byte bytes must be absent while ipv4hint (1.1.1.1) and ALPN remain
        assert!(!stripped.windows(16).any(|w| w == v6.octets()));
        assert!(stripped.windows(4).any(|w| w == [1, 1, 1, 1]));
        assert!(stripped.windows(3).any(|w| w == [0x02, b'h', b'2']));
    }
}
