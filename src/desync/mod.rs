//! Мост между графической оболочкой / маршрутизатором списков `tachyon-desync`
//! и апстримным движком `crate::outbound::desync` из `tachyon-core` (компилируемым через `OUT_DIR`).

use crate::outbound::desync as upstream;
use crate::outbound::desync::packet::{
    TlsReplyClass, classify_tls_reply, compute_seven_point_offsets, find_http_host, find_sni,
};
use crate::outbound::desync::payload::build_fake_tls_client_hello;
pub use crate::upstream_compat::{WIN_OUTBOUND_IF_INDEX, bind_outbound_socket};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Порог верифицированной передачи данных после рукопожатия (32 КиБ) из апстрима.
pub const MIN_VERIFIED_TRANSFER_BYTES: u64 = upstream::DPI_CAP_WINDOW_BYTES;

/// Описание каждого из 16 рецептов апстримного `ADAPTIVE_RECIPES` для отображения в GUI.
pub const RECIPE_TITLES: [(&str, &str); 16] = [
    (
        "r0_fakesplit_md5_midsld",
        "#0 FakeSplit (midsld, MD5 клон ClientHello)",
    ),
    (
        "r1_tlsrec_sni",
        "#1 TlsRec + Split (разрез TLS-записи по SNI без фейка)",
    ),
    (
        "r2_fakesplit_ts_tlsrec",
        "#2 FakeSplit + TlsRec (midsld, PAWS Timestamp, max.ru)",
    ),
    (
        "r3_fakedisorder_md5_vk",
        "#3 FakeDisorder (midsld, MD5, vk.com)",
    ),
    (
        "r4_fakedisorder_badseq_tlsrec",
        "#4 FakeDisorder + TlsRec (midsld, BadSeq -10000, rzd.ru)",
    ),
    (
        "r5_fakesplit_hopbyhop",
        "#5 IPv6 HopByHop2 + FakeSplit (midsld, fonts.google.com)",
    ),
    (
        "r6_multisplit_tlsrec",
        "#6 MultiSplit [2, sni_ext, host, midsld] + TlsRec",
    ),
    (
        "r7_fakesplit_autottl",
        "#7 FakeSplit AutoTTL (по границе SNI, gosuslugi.ru)",
    ),
    (
        "r8_multidisorder_md5",
        "#8 MultiDisorder [2, sni_ext, host, midsld] (MD5, vk.com)",
    ),
    (
        "r9_disorder_byte1_autottl",
        "#9 Disorder (1-й байт TTL=1 + ретрансмит)",
    ),
    (
        "r10_7pt_multidisorder_md5badack",
        "#10 7-Point MultiDisorder (Md5BadAck + rndsni)",
    ),
    (
        "r11_hostfakesplit_md5badack",
        "#11 HostFakeSplit Disorder (in-band срез хоста, Md5BadAck, rzd.ru)",
    ),
    (
        "r12_fakedisorder_badack_padencap",
        "#12 FakeDisorder (BadAck -66000 + PadEncap + seqovl=8)",
    ),
    (
        "r13_7pt_multidisorder_triple",
        "#13 7-Point MultiDisorder (BadSeq+BadAck+BadSum, ozon.ru)",
    ),
    (
        "r14_fakesplit_datanoack_seqovl12",
        "#14 FakeSplit DataNoAck (PSH без ACK + TlsRec + seqovl=12)",
    ),
    (
        "r15_hostfakesplit_autottl",
        "#15 HostFakeSplit Disorder (AutoTTL, шаблон max.ru)",
    ),
];

/// Справочная структура рецепта для GUI.
#[derive(Debug, Clone, Copy)]
pub struct RecipeSummary {
    pub id: u8,
    pub code: &'static str,
    pub title: &'static str,
}

pub fn all_recipe_summaries() -> [RecipeSummary; 16] {
    std::array::from_fn(|i| RecipeSummary {
        id: i as u8,
        code: RECIPE_TITLES[i].0,
        title: RECIPE_TITLES[i].1,
    })
}

/// Именованные пресеты для выбора в списках и профилях GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesyncPreset {
    None,
    Split,
    Disorder,
    Fake,
    FakeSplit,
    FakeDisorder,
    TlsRec,
    MultiSplit,
    MultiDisorder,
    SevenPointDisorder,
    HostFakeSplit,
    PadEncap,
    Oob,
    Auto,
}

impl DesyncPreset {
    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" | "disabled" | "direct" => Some(Self::None),
            "split" => Some(Self::Split),
            "disorder" => Some(Self::Disorder),
            "fake" => Some(Self::Fake),
            "fake_split" | "fakesplit" => Some(Self::FakeSplit),
            "fake_disorder" | "fakedisorder" => Some(Self::FakeDisorder),
            "tlsrec" | "tls_rec" => Some(Self::TlsRec),
            "multi_split" | "multisplit" => Some(Self::MultiSplit),
            "multi_disorder" | "multidisorder" => Some(Self::MultiDisorder),
            "seven_point_disorder" | "7point" => Some(Self::SevenPointDisorder),
            "host_fake_split" | "hostfakesplit" => Some(Self::HostFakeSplit),
            "pad_encap" | "padencap" => Some(Self::PadEncap),
            "oob" => Some(Self::Oob),
            "auto" | "adaptive" => Some(Self::Auto),
            _ => None,
        }
    }
}

/// Сериализуемая конфигурация десинхронизатора для GUI и профилей списков,
/// транслируемая напрямую в апстримный `upstream::DesyncConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DesyncConfig {
    pub enabled: bool,
    pub auto: bool,
    /// Строковый код режима (`fake_split`, `fake_disorder`, `multi_disorder`, `multi_split`, `tlsrec`, `split`, `disorder`, `fake`, `oob`).
    pub mode: String,
    /// Метод инвалидации фейка (`md5`, `badsum`, `badseq`, `timestamp`, `badack`, `md5_badack`, `autottl`, `hopbyhop`, `badseq_badack_badsum`, `datanoack`).
    pub fooling: String,
    /// Точка разреза (`midsld`, `sni`, `sniext+1`, `host+1`, `endhost-1`, либо число байт).
    pub split_pos: String,
    pub multi_seven_point: bool,
    pub host_fake: bool,
    pub tlsrec_first: bool,
    pub fake_sni: String,
    pub fake_ttl: u8,
    pub repeats: u32,
    pub split_delay_ms: u64,
    pub seqovl: usize,
    #[serde(alias = "window_clamp")]
    pub wsize: u32,
    pub syndata: bool,
    pub ipfrag: bool,
    pub udp_fake: bool,
    #[serde(alias = "udp_fake_repeats")]
    pub udp_repeats: u32,
    pub udp_fake_ttl: u8,
    pub udplen: usize,
    pub block_quic: bool,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto: true,
            mode: "fake_split".to_string(),
            fooling: "md5".to_string(),
            split_pos: "midsld".to_string(),
            multi_seven_point: false,
            host_fake: false,
            tlsrec_first: true,
            fake_sni: "www.google.com".to_string(),
            fake_ttl: 6,
            repeats: 1,
            split_delay_ms: 1,
            seqovl: 0,
            wsize: 0,
            syndata: false,
            ipfrag: false,
            udp_fake: true,
            udp_repeats: 3,
            udp_fake_ttl: 6,
            udplen: 0,
            block_quic: true,
        }
    }
}

impl DesyncConfig {
    /// Построить полную конфигурацию GUI из одного из 16 рецептов апстримного `ADAPTIVE_RECIPES`.
    pub fn from_recipe_id(id: u8) -> Self {
        let idx = (id as usize).min(upstream::ADAPTIVE_RECIPES.len() - 1);
        let r = upstream::ADAPTIVE_RECIPES[idx];
        let mode_str = match r.mode {
            upstream::DesyncMode::FakeSplit => "fake_split",
            upstream::DesyncMode::FakeDisorder => "fake_disorder",
            upstream::DesyncMode::MultiSplit => "multi_split",
            upstream::DesyncMode::Split => "split",
            upstream::DesyncMode::Disorder => "disorder",
            upstream::DesyncMode::TlsRec => "tlsrec",
            upstream::DesyncMode::Fake => "fake",
            upstream::DesyncMode::Oob => "oob",
            upstream::DesyncMode::MultiDisorder => "multi_disorder",
            upstream::DesyncMode::None => "none",
        };
        let fooling_str = match r.fooling {
            upstream::DesyncFooling::Md5 => "md5",
            upstream::DesyncFooling::Timestamp => "timestamp",
            upstream::DesyncFooling::BadSeq => "badseq",
            upstream::DesyncFooling::BadAck => "badack",
            upstream::DesyncFooling::BadSum => "badsum",
            upstream::DesyncFooling::AutoTtl => "autottl",
            upstream::DesyncFooling::HopByHop => "hopbyhop",
            upstream::DesyncFooling::BadSeqBadAckBadSum => "badseq_badack_badsum",
            upstream::DesyncFooling::Md5BadAck => "md5_badack",
            upstream::DesyncFooling::DataNoAck => "datanoack",
        };
        let split_pos_str = match r.split_pos {
            upstream::SplitPos::Byte(n) => n.to_string(),
            upstream::SplitPos::Sni => "sni".to_string(),
            upstream::SplitPos::SniExtPlus1 => "sniext+1".to_string(),
            upstream::SplitPos::HostPlus1 => "host+1".to_string(),
            upstream::SplitPos::MidSldMinus2 => "midsld-2".to_string(),
            upstream::SplitPos::MidSld => "midsld".to_string(),
            upstream::SplitPos::MidSldPlus2 => "midsld+2".to_string(),
            upstream::SplitPos::EndHostMinus1 => "endhost-1".to_string(),
            upstream::SplitPos::ExtLen => "extlen".to_string(),
        };
        let fake_sni = r
            .white_sni_idx
            .and_then(|w| upstream::payload::WHITE_SNI_POOL.get(w as usize).copied())
            .unwrap_or("www.google.com")
            .to_string();

        Self {
            enabled: true,
            auto: false,
            mode: mode_str.to_string(),
            fooling: fooling_str.to_string(),
            split_pos: split_pos_str,
            multi_seven_point: r.seven_point,
            host_fake: r.host_fake,
            tlsrec_first: r.tlsrec_first,
            fake_sni,
            fake_ttl: 6,
            repeats: 1,
            split_delay_ms: 1,
            seqovl: usize::from(r.seqovl),
            wsize: 0,
            syndata: false,
            ipfrag: false,
            udp_fake: true,
            udp_repeats: 3,
            udp_fake_ttl: 6,
            udplen: 0,
            block_quic: true,
        }
    }

    /// Сформировать JSON-объект outbound `"type": "desync"` для конфигурации `tachyon-core`.
    pub fn to_core_outbound_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("type".to_string(), serde_json::json!("desync"));
        obj.insert("tag".to_string(), serde_json::json!("desync-out"));
        if self.auto {
            obj.insert("preset".to_string(), serde_json::json!("auto"));
        } else {
            obj.insert("mode".to_string(), serde_json::json!(self.mode));
            obj.insert("fooling".to_string(), serde_json::json!(self.fooling));
            obj.insert("split_pos".to_string(), serde_json::json!(self.split_pos));
            obj.insert(
                "tlsrec_first".to_string(),
                serde_json::json!(self.tlsrec_first),
            );
            if self.multi_seven_point {
                obj.insert(
                    "split_positions".to_string(),
                    serde_json::json!([
                        1,
                        "sniext+1",
                        "host+1",
                        "midsld-2",
                        "midsld",
                        "midsld+2",
                        "endhost-1"
                    ]),
                );
            } else if self.host_fake {
                obj.insert(
                    "split_positions".to_string(),
                    serde_json::json!(["sni", "endhost-1"]),
                );
            }
        }
        obj.insert("fake_sni".to_string(), serde_json::json!(self.fake_sni));
        obj.insert("fake_ttl".to_string(), serde_json::json!(self.fake_ttl));
        if self.repeats > 1 {
            obj.insert("repeats".to_string(), serde_json::json!(self.repeats));
        }
        if self.split_delay_ms != 1 {
            obj.insert(
                "split_delay_ms".to_string(),
                serde_json::json!(self.split_delay_ms),
            );
        }
        if self.seqovl > 0 {
            obj.insert("seqovl".to_string(), serde_json::json!(self.seqovl));
        }
        if self.wsize > 0 {
            obj.insert("wsize".to_string(), serde_json::json!(self.wsize));
        }
        if self.syndata {
            obj.insert("syndata".to_string(), serde_json::json!(true));
        }
        if self.ipfrag {
            obj.insert("ipfrag".to_string(), serde_json::json!(true));
        }
        obj.insert("udp_fake".to_string(), serde_json::json!(self.udp_fake));
        obj.insert(
            "udp_repeats".to_string(),
            serde_json::json!(self.udp_repeats),
        );
        obj.insert(
            "udp_fake_ttl".to_string(),
            serde_json::json!(self.udp_fake_ttl),
        );
        if self.udplen > 0 {
            obj.insert("udplen".to_string(), serde_json::json!(self.udplen));
        }
        serde_json::Value::Object(obj)
    }
    pub fn from_preset(preset: DesyncPreset) -> Self {
        let mut c = Self {
            enabled: preset != DesyncPreset::None,
            auto: preset == DesyncPreset::Auto,
            ..Self::default()
        };
        match preset {
            DesyncPreset::None => {
                c.enabled = false;
                c.auto = false;
                c.block_quic = false;
                c.udp_fake = false;
            }
            DesyncPreset::Auto => {
                c.auto = true;
                c.mode = "fake_split".to_string();
                c.fooling = "md5".to_string();
            }
            DesyncPreset::FakeSplit => {
                c.auto = false;
                c.mode = "fake_split".to_string();
                c.fooling = "md5".to_string();
                c.split_pos = "midsld".to_string();
                c.tlsrec_first = true;
            }
            DesyncPreset::FakeDisorder => {
                c.auto = false;
                c.mode = "fake_disorder".to_string();
                c.fooling = "md5".to_string();
                c.split_pos = "midsld".to_string();
                c.tlsrec_first = true;
            }
            DesyncPreset::TlsRec => {
                c.auto = false;
                c.mode = "tlsrec".to_string();
                c.split_pos = "sni".to_string();
                c.tlsrec_first = true;
            }
            DesyncPreset::MultiSplit => {
                c.auto = false;
                c.mode = "multi_split".to_string();
                c.split_pos = "midsld".to_string();
                c.tlsrec_first = true;
            }
            DesyncPreset::MultiDisorder => {
                c.auto = false;
                c.mode = "multi_disorder".to_string();
                c.fooling = "md5".to_string();
                c.split_pos = "midsld".to_string();
                c.tlsrec_first = false;
            }
            DesyncPreset::SevenPointDisorder => {
                c.auto = false;
                c.mode = "multi_disorder".to_string();
                c.fooling = "md5_badack".to_string();
                c.multi_seven_point = true;
                c.fake_sni = "rndsni".to_string();
            }
            DesyncPreset::HostFakeSplit => {
                c.auto = false;
                c.mode = "fake_disorder".to_string();
                c.fooling = "md5_badack".to_string();
                c.host_fake = true;
                c.fake_sni = "rzd.ru".to_string();
            }
            DesyncPreset::PadEncap => {
                c.auto = false;
                c.mode = "fake_disorder".to_string();
                c.fooling = "badack".to_string();
                c.fake_sni = "padencap".to_string();
                c.seqovl = 8;
            }
            DesyncPreset::Split => {
                c.auto = false;
                c.mode = "split".to_string();
                c.split_pos = "midsld".to_string();
                c.tlsrec_first = true;
            }
            DesyncPreset::Disorder => {
                c.auto = false;
                c.mode = "disorder".to_string();
                c.split_pos = "1".to_string();
                c.fooling = "autottl".to_string();
            }
            DesyncPreset::Fake => {
                c.auto = false;
                c.mode = "fake".to_string();
                c.fooling = "md5".to_string();
            }
            DesyncPreset::Oob => {
                c.auto = false;
                c.mode = "oob".to_string();
                c.split_pos = "midsld".to_string();
            }
        }
        c
    }

    /// Преобразовать настройки GUI в нативный `upstream::DesyncConfig` из `tachyon-core`.
    pub fn to_upstream(&self) -> upstream::DesyncConfig {
        use std::str::FromStr;

        let mut u = upstream::DesyncConfig::default();
        if !self.enabled {
            u.mode = upstream::DesyncMode::None;
            u.auto_tune = false;
            u.udp_fake = false;
            return u;
        }

        u.auto_tune = self.auto;
        u.mode =
            upstream::DesyncMode::from_str(&self.mode).unwrap_or(upstream::DesyncMode::FakeSplit);
        u.preset = if self.auto {
            Some(upstream::DesyncPreset::Auto)
        } else {
            upstream::DesyncPreset::from_str(&self.mode).ok()
        };
        u.fooling = upstream::DesyncFooling::from_str(&self.fooling)
            .unwrap_or(upstream::DesyncFooling::Md5);
        u.explicit_fooling = !self.auto;
        let parse_one_pos = |s: &str| -> Option<upstream::SplitPos> {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            serde_json::from_value(serde_json::Value::String(trimmed.to_string()))
                .ok()
                .or_else(|| {
                    trimmed
                        .parse::<usize>()
                        .ok()
                        .map(|n| upstream::SplitPos::Byte(n.max(1)))
                })
        };
        if self.split_pos.contains(',') {
            let list: Vec<upstream::SplitPos> = self
                .split_pos
                .split(',')
                .filter_map(parse_one_pos)
                .collect();
            if !list.is_empty() {
                u.split_pos = list[0];
                u.split_positions = list;
            } else {
                u.split_pos = upstream::SplitPos::MidSld;
            }
        } else {
            u.split_pos = parse_one_pos(&self.split_pos).unwrap_or(upstream::SplitPos::MidSld);
        }
        u.explicit_split_pos = !self.auto;
        if self.multi_seven_point {
            u.split_positions = vec![
                upstream::SplitPos::Byte(1),
                upstream::SplitPos::SniExtPlus1,
                upstream::SplitPos::HostPlus1,
                upstream::SplitPos::MidSldMinus2,
                upstream::SplitPos::MidSld,
                upstream::SplitPos::MidSldPlus2,
                upstream::SplitPos::EndHostMinus1,
            ];
        } else if self.host_fake {
            u.split_positions = vec![upstream::SplitPos::Sni, upstream::SplitPos::EndHostMinus1];
        }
        u.tlsrec_first = self.tlsrec_first;
        u.explicit_tlsrec_first = !self.auto;
        u.fake_sni = if self.fake_sni.trim().is_empty() {
            "www.google.com".to_string()
        } else {
            self.fake_sni.trim().to_string()
        };
        u.explicit_fake_sni = !self.auto;
        u.fake_payload = Arc::from(build_fake_tls_client_hello(&u.fake_sni));
        u.fake_ttl = self.fake_ttl.clamp(1, 64);
        u.explicit_fake_ttl = !self.auto;
        u.repeats = self.repeats.clamp(1, 10);
        u.split_delay_ms = self.split_delay_ms.min(50);
        u.seqovl = self.seqovl;
        u.wsize = self.wsize;
        u.syndata = self.syndata;
        u.ipfrag = self.ipfrag;
        u.udp_fake = self.udp_fake;
        u.udp_repeats = self.udp_repeats.clamp(1, 10);
        u.udp_fake_ttl = self.udp_fake_ttl.clamp(1, 64);
        u.udplen = self.udplen;
        u
    }
}

/// Проверка принадлежности IP-адреса подсети `net_ip/prefix`.
pub fn ip_in_subnet(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let p = prefix.min(32);
            if p == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - p);
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let p = prefix.min(128);
            if p == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - p);
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

/// Извлечь строковое имя хоста из TLS SNI или HTTP `Host` с помощью апстримного парсера `packet.rs`.
pub fn extract_hostname(data: &[u8]) -> Option<String> {
    if let Some(m) = find_sni(data) {
        return Some(m.host.trim().to_ascii_lowercase());
    }
    if let Some(h) = find_http_host(data) {
        let host_only = h.host.split(':').next().unwrap_or(h.host);
        return Some(host_only.trim().to_ascii_lowercase());
    }
    None
}

/// Установить исходящее TCP-соединение через `crate::outbound::dial::connect_tcp_addr`.
pub async fn connect_outbound_tcp(dst: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let dial = crate::outbound::dial::DialOptions {
        connect_timeout_ms: Some(timeout.as_millis() as u64),
    };
    crate::outbound::dial::connect_tcp_addr(dst, &dial).await
}

/// Установить соединение через внешний `SOCKS5` или `HTTP CONNECT` прокси (для гибридного режима списков).
pub async fn connect_via_upstream_proxy(
    proxy_spec: &str,
    dst: SocketAddr,
    target_host: Option<&str>,
    first_pkt: &[u8],
) -> io::Result<TcpStream> {
    let raw = proxy_spec.trim();
    if raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Внешний прокси не задан",
        ));
    }
    let is_http = raw.starts_with("http://") || raw.starts_with("https://");
    let clean_addr = raw
        .trim_start_matches("socks5://")
        .trim_start_matches("socks5h://")
        .trim_start_matches("socks://")
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim();

    let proxy_sock: SocketAddr = if let Ok(sa) = clean_addr.parse::<SocketAddr>() {
        sa
    } else if let Some((h, p_str)) = clean_addr.rsplit_once(':')
        && let Ok(port) = p_str.parse::<u16>()
    {
        let addrs = crate::outbound::dial::resolve(h, port).await?;
        addrs
            .first()
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Upstream proxy IP not found"))?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Некорректный адрес внешнего прокси: {raw}"),
        ));
    };

    let mut stream = connect_outbound_tcp(proxy_sock, Duration::from_millis(5000)).await?;
    let host_label = target_host
        .map(|s| s.trim().trim_end_matches('.'))
        .filter(|s| !s.is_empty() && s.len() <= 253);

    if is_http {
        let authority = if let Some(h) = host_label {
            format!("{h}:{}", dst.port())
        } else {
            dst.to_string()
        };
        let req = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        let mut hdr = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while hdr.len() < 4096 {
            let n = tokio::time::timeout(Duration::from_millis(4500), stream.read(&mut byte))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP proxy timeout"))??;
            if n == 0 {
                break;
            }
            hdr.push(byte[0]);
            if hdr.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let status_line = String::from_utf8_lossy(&hdr);
        if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "HTTP proxy rejected CONNECT: {}",
                    status_line.lines().next().unwrap_or("EOF")
                ),
            ));
        }
    } else {
        // SOCKS5 (RFC 1928)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greet = [0u8; 2];
        tokio::time::timeout(Duration::from_millis(4000), stream.read_exact(&mut greet))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 greeting timeout"))??;
        if greet[0] != 0x05 || greet[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy requires auth or invalid version",
            ));
        }
        let mut req = Vec::with_capacity(264);
        req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER=5, CMD=CONNECT, RSV=0
        if let Some(h) = host_label {
            req.push(0x03); // ATYP = DOMAINNAME
            req.push(h.len() as u8);
            req.extend_from_slice(h.as_bytes());
        } else {
            match dst.ip() {
                IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        }
        req.extend_from_slice(&dst.port().to_be_bytes());
        stream.write_all(&req).await?;

        let mut rep_hdr = [0u8; 4];
        tokio::time::timeout(Duration::from_millis(5000), stream.read_exact(&mut rep_hdr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 connect timeout"))??;
        if rep_hdr[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 connect error code 0x{:02x}", rep_hdr[1]),
            ));
        }
        let skip_len = match rep_hdr[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                dlen[0] as usize + 2
            }
            _ => 6,
        };
        let mut discard = vec![0u8; skip_len];
        stream.read_exact(&mut discard).await?;
    }

    if !first_pkt.is_empty() {
        stream.write_all(first_pkt).await?;
    }
    Ok(stream)
}

/// Глобальный флаг автоматического фонового переобучения домена при серии сбоев (`TCP RST` / таймаут).
pub static AUTO_RELEARN_ENABLED: AtomicBool = AtomicBool::new(true);

type RelearnLogFn = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

fn relearn_log_slot() -> &'static Mutex<Option<RelearnLogFn>> {
    static SLOT: OnceLock<Mutex<Option<RelearnLogFn>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

pub fn set_relearn_log_callback(cb: RelearnLogFn) {
    if let Ok(mut g) = relearn_log_slot().lock() {
        *g = Some(cb);
    }
}

fn domain_fail_tracker() -> &'static Mutex<HashMap<String, (u8, Instant)>> {
    static TRACKER: OnceLock<Mutex<HashMap<String, (u8, Instant)>>> = OnceLock::new();
    TRACKER.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn notify_domain_connection_result(host: &str, ok: bool) {
    if !AUTO_RELEARN_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let clean = sanitize_domain_input(host).to_ascii_lowercase();
    if clean.is_empty() || clean.parse::<IpAddr>().is_ok() {
        return;
    }
    let should_relearn = if let Ok(mut map) = domain_fail_tracker().lock() {
        if map.len() > 1024 {
            map.clear();
        }
        let entry = map
            .entry(clean.clone())
            .or_insert_with(|| (0, Instant::now() - Duration::from_secs(120)));
        if ok {
            entry.0 = 0;
            false
        } else {
            entry.0 = entry.0.saturating_add(1);
            if entry.0 >= 2 && entry.1.elapsed() >= Duration::from_secs(45) {
                entry.0 = 0;
                entry.1 = Instant::now();
                true
            } else {
                false
            }
        }
    } else {
        false
    };

    if should_relearn && let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let banned = upstream::engine::gui_get_banned_mask(&clean);
            if let Ok(report) =
                generate_domain_strategy_with_mask(&clean, 443, false, 1600, banned, false).await
                && let Some(best_id) = report.best_recipe_id
            {
                let idx = (best_id as usize).min(15);
                let title = RECIPE_TITLES[idx].1;
                if let Ok(guard) = relearn_log_slot().lock()
                    && let Some(ref log_cb) = *guard
                {
                    log_cb(
                        "info",
                        "relearn",
                        &format!(
                            "Авто-переобучение: для {clean} после сбоя подобран кандидат {title} (ожидает проверки 32 KiB, исключено маской: {})",
                            banned.count_ones()
                        ),
                    );
                }
            }
        });
    }
}

/// Выполнить подключение и применить апстримный десинхронизатор (`apply_desync_tcp_auto`)
/// с автоматическим переключением на резервные IP-адреса из анти-спуфинг DNS при недоступности узла.
/// Возвращает `(TcpStream, префикс ответа сервера, применённый рецепт, имя хоста)`.
pub async fn connect_and_apply_desync_auto(
    dst: SocketAddr,
    first_pkt: &[u8],
    cfg: &DesyncConfig,
    known_host: Option<&str>,
) -> io::Result<(TcpStream, Vec<u8>, Option<u8>, Option<String>)> {
    let host_opt =
        extract_hostname(first_pkt).or_else(|| known_host.map(|s| s.to_ascii_lowercase()));

    let mut candidate_addrs = vec![dst];
    if let Some(ref h) = host_opt
        && h.parse::<IpAddr>().is_err()
        && let Ok(resolved) = crate::outbound::dial::resolve(h, dst.port()).await
    {
        for addr in resolved {
            if addr != dst && addr.is_ipv4() == dst.is_ipv4() && candidate_addrs.len() < 3 {
                candidate_addrs.push(addr);
            }
        }
    }

    let upstream_cfg = cfg.to_upstream();
    let mut last_err: Option<io::Error> = None;

    for (attempt_idx, &target_addr) in candidate_addrs.iter().enumerate() {
        let connect_timeout = if attempt_idx == 0 {
            Duration::from_millis(4200)
        } else {
            Duration::from_millis(2800)
        };
        let stream = match connect_outbound_tcp(target_addr, connect_timeout).await {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        if !cfg.enabled || first_pkt.is_empty() {
            return Ok((stream, Vec::new(), None, host_opt));
        }

        match upstream::apply_desync_tcp_auto(Box::new(stream), first_pkt, &upstream_cfg).await {
            Ok((boxed_stream, initial_reply)) => {
                let used_recipe = host_opt.as_deref().and_then(|h| {
                    upstream::engine::gui_snapshot_learned_domains()
                        .into_iter()
                        .find(|d| d.host.eq_ignore_ascii_case(h))
                        .map(|d| d.recipe_id)
                });
                return Ok((*boxed_stream, initial_reply, used_recipe, host_opt));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(ref h) = host_opt {
        notify_domain_connection_result(h, false);
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TCP desync failed")))
}

/// Отправить адаптивные UDP-фейки с того же самого сокета (`sock.send_to`), сохраняя точный 5-tuple потока
/// без вызова `sock.connect(dst)`, и немедленно восстановить штатный TTL/HopLimit (`64`).
pub async fn send_udp_fakes_same_tuple(
    sock: &UdpSocket,
    dst: SocketAddr,
    cfg: &DesyncConfig,
) -> io::Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    let repeats = cfg.udp_repeats.clamp(1, 10);
    let fake_ttl = cfg.udp_fake_ttl.clamp(1, 15) as u32;
    let sref = socket2::SockRef::from(sock);
    if dst.is_ipv6() {
        let _ = sref.set_unicast_hops_v6(fake_ttl);
    } else {
        let _ = sock.set_ttl(fake_ttl);
    }

    let port = dst.port();
    let is_discord_voice = (50000..=65535).contains(&port) || (19294..=19344).contains(&port);
    let is_stun = port == 3478 || port == 19302 || port == 5349;

    for i in 0..repeats {
        if port == 443 || port == 8443 {
            let quic_fake = if (i & 1) == 0 {
                upstream::payload::build_fake_quic_initial()
            } else {
                upstream::payload::build_fake_quic_v2_initial()
            };
            let _ = sock.send_to(&quic_fake, dst).await;
        } else if is_discord_voice {
            if (i & 1) == 0 {
                let _ = sock
                    .send_to(&upstream::payload::FAKE_DISCORD_IP_DISCOVERY, dst)
                    .await;
            } else {
                let _ = sock
                    .send_to(&upstream::payload::FAKE_STUN_BINDING_REQUEST, dst)
                    .await;
            }
        } else if is_stun {
            let _ = sock
                .send_to(&upstream::payload::FAKE_STUN_BINDING_REQUEST, dst)
                .await;
        } else {
            let zero_fake = [0u8; 64];
            let _ = sock.send_to(&zero_fake, dst).await;
        }
    }

    if dst.is_ipv6() {
        let _ = sref.set_unicast_hops_v6(64);
    } else {
        let _ = sock.set_ttl(64);
    }
    Ok(())
}

/// Применить UDP-десинхронизацию на том же 5-tuple и отправить датаграмму.
pub async fn apply_desync_udp_datagram(
    sock: &UdpSocket,
    dst: SocketAddr,
    payload: &[u8],
    cfg: &DesyncConfig,
) -> io::Result<usize> {
    if !cfg.enabled {
        return sock.send_to(payload, dst).await;
    }
    if cfg.block_quic && dst.port() == 443 && payload.len() >= 120 && (payload[0] & 0x80) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "QUIC UDP/443 blocked by profile",
        ));
    }
    let _ = send_udp_fakes_same_tuple(sock, dst, cfg).await;
    if payload.is_empty() {
        return Ok(0);
    }
    sock.send_to(payload, dst).await
}

/// Передать обратную связь по UDP/QUIC-потоку в апстримный `AdaptiveBrain`.
pub fn report_udp_quic_outcome(peer: SocketAddr, got_reply: bool) {
    upstream::report_udp_quic_outcome(peer, got_reply);
}

/// Передать обратную связь о передаче потока в апстримный `AdaptiveBrain` (проверка 32 KiB гейта и шейпера).
pub fn report_transfer_outcome(
    host: Option<&str>,
    peer: Option<SocketAddr>,
    down_bytes: u64,
    elapsed_ms: u64,
    io_ok: bool,
) {
    let Some(h) = host else {
        return;
    };
    if h.is_empty() {
        return;
    }
    let transfer_healthy = io_ok && down_bytes >= 64;
    notify_domain_connection_result(h, transfer_healthy);
    // Если поток оборвался или завис до прохождения порога 32 KiB (например, тихий blackhole на 16 KB cap,
    // который браузер держит открытым >4 секунд), нормализуем время для гарантированной отбраковки рецепта.
    let effective_ms = if down_bytes < 32 * 1024 && (!io_ok || down_bytes < 64) {
        elapsed_ms.min(3500)
    } else {
        elapsed_ms
    };
    upstream::report_transfer_outcome(
        h,
        peer,
        down_bytes,
        Duration::from_millis(effective_ms),
        io_ok,
    );
}

// ============================================================================
// Структуры и функции инспекции AdaptiveBrain для GUI
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedDomainView {
    pub host: String,
    pub tier: String,
    pub recipe_id: u8,
    pub recipe_code: String,
    pub recipe_title: String,
    pub verified: bool,
    pub failures: u8,
    pub banned_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeScoreView {
    pub id: u8,
    pub code: String,
    pub title: String,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeProbeResult {
    pub recipe_id: u8,
    pub recipe_code: String,
    pub recipe_title: String,
    pub ok: bool,
    pub rtt_ms: u32,
    pub block_reason: String,
    pub detail: String,
    pub config: DesyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSlicePreview {
    pub domain: String,
    pub packet_len: usize,
    pub ext_len_offset: usize,
    pub sni_ext_offset: usize,
    pub host_offset: usize,
    pub host_len: usize,
    pub midsld_offset: usize,
    pub endhost_offset: usize,
    pub seven_points: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyGeneratorReport {
    pub domain: String,
    pub resolved_ip: String,
    pub packet_preview: PacketSlicePreview,
    pub results: Vec<RecipeProbeResult>,
    pub passed_count: usize,
    pub total_tested: usize,
    pub best_recipe_id: Option<u8>,
    pub recommended_config: DesyncConfig,
    pub diagnosis: String,
    pub core_outbound_json: serde_json::Value,
}

pub fn inspect_client_hello_slices(domain: &str) -> PacketSlicePreview {
    let clean = sanitize_domain_input(domain);
    let target = if clean.is_empty() {
        "www.youtube.com"
    } else {
        clean
    };
    let ch = build_fake_tls_client_hello(target);
    let (pts, cnt) = compute_seven_point_offsets(&ch);
    if let Some(m) = find_sni(&ch) {
        let endhost = (m.host_offset + m.host_len).saturating_sub(1);
        PacketSlicePreview {
            domain: target.to_string(),
            packet_len: ch.len(),
            ext_len_offset: m.ext_len_offset,
            sni_ext_offset: m.sni_ext_offset,
            host_offset: m.host_offset,
            host_len: m.host_len,
            midsld_offset: m.midsld_offset,
            endhost_offset: endhost,
            seven_points: pts[..cnt].to_vec(),
        }
    } else {
        PacketSlicePreview {
            domain: target.to_string(),
            packet_len: ch.len(),
            ext_len_offset: 80,
            sni_ext_offset: 86,
            host_offset: 95,
            host_len: target.len(),
            midsld_offset: 95 + target.len() / 2,
            endhost_offset: 95 + target.len().saturating_sub(1),
            seven_points: pts[..cnt].to_vec(),
        }
    }
}

pub fn get_learned_domains_snapshot() -> Vec<LearnedDomainView> {
    upstream::engine::gui_snapshot_learned_domains()
        .into_iter()
        .map(|d| {
            let idx = (d.recipe_id as usize).min(15);
            let (code, title) = RECIPE_TITLES[idx];
            LearnedDomainView {
                host: d.host,
                tier: d.tier,
                recipe_id: d.recipe_id,
                recipe_code: code.to_string(),
                recipe_title: title.to_string(),
                verified: d.verified_32k,
                failures: d.consecutive_fails,
                banned_count: d.banned_mask.count_ones(),
            }
        })
        .collect()
}

pub fn get_isp_scoreboard() -> Vec<RecipeScoreView> {
    let scores = upstream::engine::gui_snapshot_l3_scores();
    (0..16)
        .map(|i| RecipeScoreView {
            id: i as u8,
            code: RECIPE_TITLES[i].0.to_string(),
            title: RECIPE_TITLES[i].1.to_string(),
            score: scores[i],
        })
        .collect()
}

pub fn pin_domain_recipe(host: &str, recipe_id: u8) {
    upstream::engine::gui_pin_domain_recipe(host, recipe_id);
}

pub fn remove_learned_domain(host: &str) {
    upstream::engine::gui_remove_learned_domain(host);
}

pub fn clear_brain_cache() {
    upstream::reset_adaptive_state();
}

static STORE_HANDLE: OnceLock<crate::cache_file::SharedCacheFile> = OnceLock::new();

pub fn attach_persistent_cache(path: &Path) {
    let handle = STORE_HANDLE
        .get_or_init(|| crate::cache_file::CacheFile::open_shared(path.to_path_buf()))
        .clone();
    upstream::attach_store(Some(handle));
}

pub fn flush_persistent_cache() {
    if let Some(handle) = STORE_HANDLE.get()
        && let Ok(c) = handle.lock()
    {
        c.flush_to_disk();
    }
}

fn sanitize_domain_input(domain: &str) -> &str {
    domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
}

async fn execute_single_probe(
    dst: SocketAddr,
    ch: Arc<[u8]>,
    rid: u8,
    code: String,
    title: String,
    gui_cfg: DesyncConfig,
    wait: Duration,
) -> RecipeProbeResult {
    let upstream_cfg = gui_cfg.to_upstream();
    let t0 = Instant::now();

    let outcome: Result<(String, &'static str), (String, &'static str)> = async {
        let mut stream = connect_outbound_tcp(dst, wait)
            .await
            .map_err(|e| (format!("Ошибка TCP SYN: {e}"), "connect_err"))?;
        upstream::apply_desync_tcp(&stream, &ch, &upstream_cfg)
            .await
            .map_err(|e| (format!("Ошибка отправки: {e}"), "connect_err"))?;
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(wait, stream.read(&mut buf))
            .await
            .map_err(|_| {
                (
                    "Таймаут ожидания ServerHello (Blackhole)".to_string(),
                    "timeout",
                )
            })?
            .map_err(|e| (format!("Сброс соединения (RST): {e}"), "rst_eof"))?;
        if n == 0 {
            return Err(("Соединение закрыто узлом (EOF)".to_string(), "rst_eof"));
        }
        match classify_tls_reply(&buf[..n]) {
            TlsReplyClass::ServerHello => {
                // Проверяем отсутствие отложенного RST (Delayed RST injection) в течение 35 мс после ServerHello
                let mut trail = [0u8; 512];
                match tokio::time::timeout(Duration::from_millis(35), stream.read(&mut trail)).await
                {
                    Ok(Err(e)) => Err((
                        format!("Сброс после ServerHello (Delayed RST): {e}"),
                        "rst_eof",
                    )),
                    Ok(Ok(0)) => Err((
                        "Обрыв потока сразу после ServerHello (EOF)".to_string(),
                        "rst_eof",
                    )),
                    Ok(Ok(m)) => {
                        if matches!(
                            classify_tls_reply(&trail[..m]),
                            TlsReplyClass::ForeignInjection
                        ) {
                            Err((
                                "Подмена ответа после ServerHello (ForeignInjection)".to_string(),
                                "hijack",
                            ))
                        } else {
                            Ok((format!("ServerHello получен ({} Б)", n + m), "ok"))
                        }
                    }
                    Err(_) => Ok((format!("ServerHello получен ({n} Б)"), "ok")),
                }
            }
            TlsReplyClass::TlsAlert { level, description } => {
                if description == 50 || description == 47 || description == 22 {
                    Err((
                        format!("TLS Alert (desc={description} — фейк дошёл до сервера)"),
                        "tls_alert",
                    ))
                } else {
                    Ok((
                        format!("TLS Alert (level={level}, desc={description} — сервер ответил)"),
                        "ok",
                    ))
                }
            }
            TlsReplyClass::ForeignInjection => Err((
                "Подмена ответа на маршруте (HTTP Redirect / Blockpage)".to_string(),
                "hijack",
            )),
        }
    }
    .await;

    let rtt = t0.elapsed().as_millis() as u32;
    match outcome {
        Ok((detail, reason)) => RecipeProbeResult {
            recipe_id: rid,
            recipe_code: code,
            recipe_title: title,
            ok: true,
            rtt_ms: rtt,
            block_reason: reason.to_string(),
            detail,
            config: gui_cfg,
        },
        Err((detail, reason)) => RecipeProbeResult {
            recipe_id: rid,
            recipe_code: code,
            recipe_title: title,
            ok: false,
            rtt_ms: rtt,
            block_reason: reason.to_string(),
            detail,
            config: gui_cfg,
        },
    }
}

/// Полный генератор и сканер стратегий по домену: тестирует 8 или все 16 рецептов параллельными волнами,
/// классифицирует ответы и синтезирует оптимальную конфигурацию `DesyncConfig` + JSON `tachyon-core`.
pub async fn generate_domain_strategy(
    domain: &str,
    port: u16,
    scan_all: bool,
    timeout_ms: u64,
) -> io::Result<StrategyGeneratorReport> {
    let clean_domain = sanitize_domain_input(domain);
    let banned = upstream::engine::gui_get_banned_mask(clean_domain);
    generate_domain_strategy_with_mask(domain, port, scan_all, timeout_ms, banned, true).await
}

async fn generate_domain_strategy_with_mask(
    domain: &str,
    port: u16,
    scan_all: bool,
    timeout_ms: u64,
    banned_mask: u16,
    pin_verified: bool,
) -> io::Result<StrategyGeneratorReport> {
    let clean_domain = sanitize_domain_input(domain);
    if clean_domain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Укажите доменное имя для генерации стратегии",
        ));
    }

    let addrs = crate::outbound::dial::resolve(clean_domain, port).await?;
    let dst = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "IP не найден"))?;

    let packet_preview = inspect_client_hello_slices(clean_domain);
    let ch: Arc<[u8]> = Arc::from(build_fake_tls_client_hello(clean_domain));
    let test_ids: Vec<u8> = if scan_all {
        (0..16).collect()
    } else {
        let mut base = vec![0u8, 1, 2, 3, 6, 10, 11, 14];
        // Если часть базовых рецептов уже забанена на 32 KiB гейте, добираем незабаненные из полного пула
        for alt in 0..16u8 {
            if base.len() >= 10 {
                break;
            }
            if !base.contains(&alt) && (banned_mask & (1u16 << alt)) == 0 {
                base.push(alt);
            }
        }
        base
    };

    let wait = Duration::from_millis(timeout_ms.clamp(600, 4000));
    let mut results = Vec::with_capacity(test_ids.len());

    // Выполняем проверку волнами по 4 рецепта параллельно для быстрого отклика (~1.2 с на все 16)
    for chunk in test_ids.chunks(4) {
        let mut handles = Vec::with_capacity(chunk.len());
        for &rid in chunk {
            let idx = (rid as usize).min(15);
            let (code, title) = RECIPE_TITLES[idx];
            let gui_cfg = DesyncConfig::from_recipe_id(rid);
            let ch_clone = ch.clone();
            handles.push(tokio::spawn(async move {
                execute_single_probe(
                    dst,
                    ch_clone,
                    rid,
                    code.to_string(),
                    title.to_string(),
                    gui_cfg,
                    wait,
                )
                .await
            }));
        }
        for h in handles {
            if let Ok(r) = h.await {
                results.push(r);
            }
        }
    }

    let passed: Vec<&RecipeProbeResult> = results.iter().filter(|r| r.ok).collect();
    let passed_count = passed.len();
    let total_tested = results.len();

    // Приоритет отдаём рецептам, которые не находятся в маске отбраковки 32 KiB гейта (`banned_mask`)
    let best = passed
        .iter()
        .copied()
        .filter(|r| (banned_mask & (1u16 << r.recipe_id)) == 0)
        .min_by_key(|r| r.rtt_ms)
        .or_else(|| passed.iter().copied().min_by_key(|r| r.rtt_ms));

    let (best_recipe_id, recommended_config, diagnosis) = if let Some(win) = best {
        upstream::engine::gui_set_learned_candidate(
            clean_domain,
            win.recipe_id,
            banned_mask,
            pin_verified,
        );
        let leaked_alerts = results
            .iter()
            .filter(|r| r.block_reason == "tls_alert")
            .count();
        let rst_count = results
            .iter()
            .filter(|r| r.block_reason == "rst_eof")
            .count();
        let timeout_count = results
            .iter()
            .filter(|r| r.block_reason == "timeout")
            .count();

        let diag = format!(
            "Оптимальный рецепт #{:02} ({} мс). Прошло {passed_count}/{total_tested} рецептов (RST: {rst_count}, Blackhole: {timeout_count}, Alert: {leaked_alerts}). Рецепт закреплён в AdaptiveBrain.",
            win.recipe_id, win.rtt_ms
        );
        (Some(win.recipe_id), win.config.clone(), diag)
    } else {
        let fallback = DesyncConfig::from_preset(DesyncPreset::SevenPointDisorder);
        let diag = format!(
            "Ни один из {total_tested} базовых рецептов не получил ServerHello от {clean_domain} ({dst}). Рекомендуется комбинированный 7-Point MultiDisorder или режим TUN."
        );
        (None, fallback, diag)
    };

    let core_outbound_json = recommended_config.to_core_outbound_json();

    Ok(StrategyGeneratorReport {
        domain: clean_domain.to_string(),
        resolved_ip: dst.to_string(),
        packet_preview,
        results,
        passed_count,
        total_tested,
        best_recipe_id,
        recommended_config,
        diagnosis,
        core_outbound_json,
    })
}

/// Проверить произвольную пользовательскую конфигурацию из Конструктора стратегий на указанном домене.
pub async fn probe_custom_strategy(
    domain: &str,
    port: u16,
    custom_cfg: &DesyncConfig,
    timeout_ms: u64,
) -> io::Result<StrategyGeneratorReport> {
    let clean_domain = sanitize_domain_input(domain);
    if clean_domain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Укажите доменное имя для проверки конструктора",
        ));
    }

    let addrs = crate::outbound::dial::resolve(clean_domain, port).await?;
    let dst = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "IP не найден"))?;

    let packet_preview = inspect_client_hello_slices(clean_domain);
    let ch: Arc<[u8]> = Arc::from(build_fake_tls_client_hello(clean_domain));
    let wait = Duration::from_millis(timeout_ms.clamp(600, 4000));

    let mut cfg = custom_cfg.clone();
    cfg.enabled = true;
    cfg.auto = false;
    let title = format!(
        "Конструктор: {} + {} (split={}{}{}{})",
        cfg.mode,
        cfg.fooling,
        cfg.split_pos,
        if cfg.tlsrec_first { ", tlsrec" } else { "" },
        if cfg.multi_seven_point { ", 7-pt" } else { "" },
        if cfg.host_fake { ", hostfake" } else { "" },
    );

    let res = execute_single_probe(
        dst,
        ch,
        99,
        "custom_builder".to_string(),
        title,
        cfg.clone(),
        wait,
    )
    .await;

    let passed_count = usize::from(res.ok);
    let diagnosis = if res.ok {
        format!(
            "Пользовательская стратегия успешно прошла проверку на {clean_domain} ({dst}) за {} мс: {}",
            res.rtt_ms, res.detail
        )
    } else {
        format!(
            "Пользовательская стратегия не прошла проверку на {clean_domain} ({dst}): {}",
            res.detail
        )
    };
    let core_outbound_json = cfg.to_core_outbound_json();

    Ok(StrategyGeneratorReport {
        domain: clean_domain.to_string(),
        resolved_ip: dst.to_string(),
        packet_preview,
        results: vec![res],
        passed_count,
        total_tested: 1,
        best_recipe_id: None,
        recommended_config: cfg,
        diagnosis,
        core_outbound_json,
    })
}

/// Обратная совместимость для быстрого вызова `probe_domain_recipes`.
pub async fn probe_domain_recipes(
    domain: &str,
    port: u16,
    timeout_ms: u64,
) -> io::Result<Vec<RecipeProbeResult>> {
    let report = generate_domain_strategy(domain, port, false, timeout_ms).await?;
    Ok(report.results)
}

/// Результат экспресс-диагностики одного ключевого сервиса.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthItem {
    pub name: String,
    pub domain: String,
    pub ok: bool,
    pub rtt_ms: u32,
    pub recipe_id: Option<u8>,
    pub detail: String,
}

/// Параллельная экспресс-диагностика 6 ключевых сервисов через активный десинхронизатор.
pub async fn run_services_health_check(active_cfg: &DesyncConfig) -> Vec<ServiceHealthItem> {
    let targets: &[(&str, &str)] = &[
        ("YouTube", "www.youtube.com"),
        ("GoogleVideo", "manifest.googlevideo.com"),
        ("Discord", "discord.com"),
        ("Telegram", "web.telegram.org"),
        ("X / Twitter", "x.com"),
        ("GitHub", "github.com"),
    ];

    let mut handles = Vec::with_capacity(targets.len());
    for &(svc_name, domain) in targets {
        let mut cfg = active_cfg.clone();
        cfg.enabled = true;
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let res: Result<(u32, Option<u8>, String), String> = async {
                let addrs = crate::outbound::dial::resolve(domain, 443)
                    .await
                    .map_err(|e| format!("DNS: {e}"))?;
                let dst = addrs
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| addrs.first())
                    .copied()
                    .ok_or_else(|| "IP not found".to_string())?;

                let ch = build_fake_tls_client_hello(domain);
                let (mut stream, pre_read, used_recipe, _) = tokio::time::timeout(
                    Duration::from_millis(2600),
                    connect_and_apply_desync_auto(dst, &ch, &cfg, Some(domain)),
                )
                .await
                .map_err(|_| "Timeout".to_string())?
                .map_err(|e| format!("{e}"))?;

                let reply = if !pre_read.is_empty() {
                    pre_read
                } else {
                    let mut buf = [0u8; 1024];
                    let n =
                        tokio::time::timeout(Duration::from_millis(2000), stream.read(&mut buf))
                            .await
                            .map_err(|_| "ServerHello timeout".to_string())?
                            .map_err(|e| format!("RST: {e}"))?;
                    if n == 0 {
                        return Err("EOF".to_string());
                    }
                    buf[..n].to_vec()
                };

                match classify_tls_reply(&reply) {
                    TlsReplyClass::ServerHello => {
                        let rtt = t0.elapsed().as_millis() as u32;
                        Ok((rtt, used_recipe, format!("TLS 1.3 OK ({dst})")))
                    }
                    TlsReplyClass::TlsAlert { description, .. } => {
                        if description == 50 || description == 47 || description == 22 {
                            Err(format!("TLS Alert ({description})"))
                        } else {
                            let rtt = t0.elapsed().as_millis() as u32;
                            Ok((
                                rtt,
                                used_recipe,
                                format!("TLS Alert #{description} ({dst})"),
                            ))
                        }
                    }
                    TlsReplyClass::ForeignInjection => Err("Injection / Redirect".to_string()),
                }
            }
            .await;

            match res {
                Ok((rtt_ms, recipe_id, detail)) => ServiceHealthItem {
                    name: svc_name.to_string(),
                    domain: domain.to_string(),
                    ok: true,
                    rtt_ms,
                    recipe_id,
                    detail,
                },
                Err(err) => ServiceHealthItem {
                    name: svc_name.to_string(),
                    domain: domain.to_string(),
                    ok: false,
                    rtt_ms: t0.elapsed().as_millis() as u32,
                    recipe_id: None,
                    detail: err,
                },
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(item) = h.await {
            out.push(item);
        }
    }
    out
}

/// Результат проверки одного значения `TTL` при авто-калибровке дистанции до транзитного узла.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlHopProbe {
    pub ttl: u8,
    pub ok: bool,
    pub rtt_ms: u32,
    pub status: String,
}

/// Сводный отчёт авто-калибровки `TTL` (`fake_ttl` / `udp_fake_ttl`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTtlReport {
    pub domain: String,
    pub resolved_ip: String,
    pub optimal_ttl: u8,
    pub min_working_ttl: Option<u8>,
    pub max_working_ttl: Option<u8>,
    pub probes: Vec<TtlHopProbe>,
    pub summary: String,
}

/// Авто-калибровка оптимального `TTL` для фейковых пакетов (`fake_ttl` / `udp_fake_ttl`):
/// выполняет серию проб с `fooling = "ttl"` на дистанциях `TTL = 2..=11`, находит окно хопов,
/// где фейковый пакет проходит транзитный узел, но сгорает до целевого сервера, и возвращает оптимальный `TTL`.
pub async fn calibrate_optimal_ttl(domain: &str, port: u16) -> io::Result<AutoTtlReport> {
    let clean = sanitize_domain_input(domain);
    let target = if clean.is_empty() {
        "www.youtube.com"
    } else {
        clean
    };
    let addrs = crate::outbound::dial::resolve(target, port).await?;
    let dst = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "IP не найден"))?;

    let ch: Arc<[u8]> = Arc::from(build_fake_tls_client_hello(target));
    let wait = Duration::from_millis(1600);
    let ttl_candidates: Vec<u8> = (2..=10).collect();
    let mut probes = Vec::with_capacity(ttl_candidates.len());

    for chunk in ttl_candidates.chunks(5) {
        let mut handles = Vec::with_capacity(chunk.len());
        for &ttl in chunk {
            let ch_c = ch.clone();
            let mut cfg = DesyncConfig::from_preset(DesyncPreset::FakeDisorder);
            cfg.enabled = true;
            cfg.auto = false;
            cfg.mode = "fake_disorder".to_string();
            cfg.fooling = "ttl".to_string();
            cfg.split_pos = "midsld".to_string();
            cfg.tlsrec_first = true;
            cfg.fake_ttl = ttl;
            handles.push(tokio::spawn(async move {
                let r = execute_single_probe(
                    dst,
                    ch_c,
                    ttl,
                    format!("ttl_{ttl}"),
                    format!("TTL={ttl}"),
                    cfg,
                    wait,
                )
                .await;
                TtlHopProbe {
                    ttl,
                    ok: r.ok,
                    rtt_ms: r.rtt_ms,
                    status: r.block_reason,
                }
            }));
        }
        for h in handles {
            if let Ok(p) = h.await {
                probes.push(p);
            }
        }
    }

    probes.sort_by_key(|p| p.ttl);
    let working: Vec<&TtlHopProbe> = probes.iter().filter(|p| p.ok).collect();
    let min_working_ttl = working.first().map(|p| p.ttl);
    let max_working_ttl = working.last().map(|p| p.ttl);

    // Ищем первый TTL, где сервер вернул tls_alert (значит фейк долетел до самого сервера)
    let first_server_alert_ttl = probes
        .iter()
        .find(|p| p.status == "tls_alert")
        .map(|p| p.ttl);

    let optimal_ttl = if let (Some(min_t), Some(max_t)) = (min_working_ttl, max_working_ttl) {
        if let Some(alert_t) = first_server_alert_ttl {
            alert_t.saturating_sub(1).clamp(min_t, max_t)
        } else if max_t > min_t {
            min_t + 1
        } else {
            min_t
        }
    } else if let Some(alert_t) = first_server_alert_ttl {
        alert_t.saturating_sub(1).clamp(2, 9)
    } else {
        5
    };

    let summary = match (min_working_ttl, max_working_ttl) {
        (Some(min_t), Some(max_t)) => format!(
            "Оптимальный TTL = {optimal_ttl} (рабочее окно: {min_t}..{max_t} хопов до {target} [{dst}])"
        ),
        _ => format!(
            "Установлен базовый TTL = {optimal_ttl} для {target} ({dst}); на этом маршруте рекомендуется Fooling = md5 / badseq"
        ),
    };

    Ok(AutoTtlReport {
        domain: target.to_string(),
        resolved_ip: dst.to_string(),
        optimal_ttl,
        min_working_ttl,
        max_working_ttl,
        probes,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learned_candidate_preserves_banned_mask_and_demotes_stalled_32k_cap() {
        let host = "shard-test.googlevideo.com";
        remove_learned_domain(host);
        remove_learned_domain("googlevideo.com");

        // Симулируем кандидата от авто-переобучения с сохранённой маской забаненных рецептов (#0 и #1)
        let initial_mask: u16 = (1 << 0) | (1 << 1);
        upstream::engine::gui_set_learned_candidate(host, 3, initial_mask, false);
        assert_eq!(upstream::engine::gui_get_banned_mask(host), initial_mask);

        let snap = get_learned_domains_snapshot();
        let entry = snap.iter().find(|d| d.host == host).expect("host in L1");
        assert_eq!(entry.recipe_id, 3);
        assert!(!entry.verified);
        assert_eq!(entry.banned_count, 2);

        // Симулируем тихий обрыв на 16 KB cap спустя 12 секунд (больше старого лимита 4 с)
        report_transfer_outcome(Some(host), None, 14_000, 12_000, false);
        let updated_mask = upstream::engine::gui_get_banned_mask(host);
        assert_ne!(
            updated_mask & (1 << 3),
            0,
            "recipe #3 must be added to banned_mask after <32 KiB stall even at 12s elapsed"
        );

        remove_learned_domain(host);
        remove_learned_domain("googlevideo.com");
    }

    #[tokio::test]
    async fn udp_fakes_share_exact_5_tuple_and_restore_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let cfg = DesyncConfig {
            enabled: true,
            udp_repeats: 2,
            udp_fake_ttl: 3,
            ..Default::default()
        };

        let sent = apply_desync_udp_datagram(&client, server_addr, b"real-payload", &cfg)
            .await
            .unwrap();
        assert_eq!(sent, b"real-payload".len());
        assert_eq!(client.ttl().unwrap(), 64);

        let mut buf = [0u8; 1500];
        let mut received_real = false;
        for _ in 0..6 {
            if let Ok(Ok((n, peer))) =
                tokio::time::timeout(Duration::from_millis(200), server.recv_from(&mut buf)).await
            {
                // Все пакеты (и фейки, и реальная датаграмма) обязаны приходить с одного и того же source port
                assert_eq!(peer, client_addr);
                if &buf[..n] == b"real-payload" {
                    received_real = true;
                    break;
                }
            }
        }
        assert!(received_real);
    }
}
