//! Мост между графической оболочкой / маршрутизатором списков `tachyon-desync`
//! и апстримным движком `crate::outbound::desync` из `tachyon-core` (компилируемым через `OUT_DIR`).

use crate::outbound::desync as upstream;
use crate::outbound::desync::packet::{compute_seven_point_offsets, find_http_host, find_sni};
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
pub use upstream::{AutoTtlReport, DesyncWatchdog, TtlHopProbe};

/// Порог верифицированной передачи данных после рукопожатия (32 КиБ) из апстрима.
pub const MIN_VERIFIED_TRANSFER_BYTES: u64 = upstream::DPI_CAP_WINDOW_BYTES;

/// Порог живого продвижения активного потока на лету (256 КиБ) из апстрима `0.5.0`.
pub const DESYNC_LIVE_PROMOTE_BYTES: u64 = upstream::DESYNC_LIVE_PROMOTE_BYTES;

/// Описание каждого из 24 рецептов апстримного `ADAPTIVE_RECIPES` для отображения в GUI.
pub const RECIPE_TITLES: [(&str, &str); 24] = [
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
        "#9 Disorder (1-й байт AutoTTL + ретрансмит)",
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
        "#14 FakeSplit DataNoAck (PSH без ACK + sniext+1 + seqovl=12, aws.amazon.com)",
    ),
    (
        "r15_hostfakesplit_autottl",
        "#15 HostFakeSplit Disorder (AutoTTL, шаблон max.ru)",
    ),
    (
        "r16_oob_midsld",
        "#16 OOB Urgent (MSG_OOB + срочный указатель на midsld без фейка)",
    ),
    (
        "r17_disoob_tlsrec_wsize64",
        "#17 Disoob + TlsRec (внеочередной MSG_OOB на host+1 + окно wsize=64)",
    ),
    (
        "r18_multisplit_seqovl210",
        "#18 MultiSplit + SeqOvl=210 (чистое перекрытие сегментов без фейков)",
    ),
    (
        "r19_fakesplit_snidel_datanoack",
        "#19 FakeSplit sni_del (клон без SNI + DataNoAck + sniext+1 + seqovl=16)",
    ),
    (
        "r20_multidisorder_binnoise",
        "#20 MultiDisorder bin_noise (бинарный декой 0x0F0F0F0F + BadSeq+BadAck+BadSum)",
    ),
    (
        "r21_fakedisorder_syndata_padencap",
        "#21 FakeDisorder SYNData (декой в SYN + Md5BadAck + PadEncap + seqovl=10)",
    ),
    (
        "r22_fakesplit_badsum_tlsrec_wsize64",
        "#22 FakeSplit + TlsRec + wsize=64 (host+1, BadSum, ya.ru)",
    ),
    (
        "r23_multidisorder_wsize1_scale1",
        "#23 MultiDisorder + wsize=1:scale=1 (midsld, AutoTTL + sni_del, googlevideo)",
    ),
];

/// Справочная структура рецепта для GUI.
#[derive(Debug, Clone, Copy)]
pub struct RecipeSummary {
    pub id: u8,
    pub code: &'static str,
    pub title: &'static str,
}

pub fn all_recipe_summaries() -> [RecipeSummary; 24] {
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
    Disoob,
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
            "disoob" | "dis_oob" | "disorder_oob" => Some(Self::Disoob),
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
    #[serde(default, alias = "scale")]
    pub wscale: Option<u8>,
    pub syndata: bool,
    pub ipfrag: bool,
    pub udp_fake: bool,
    #[serde(alias = "udp_fake_repeats")]
    pub udp_repeats: u32,
    pub udp_fake_ttl: u8,
    #[serde(default)]
    pub explicit_udp_fake_ttl: bool,
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
            wscale: None,
            syndata: false,
            ipfrag: false,
            udp_fake: true,
            udp_repeats: 3,
            udp_fake_ttl: 6,
            explicit_udp_fake_ttl: false,
            udplen: 0,
            block_quic: true,
        }
    }
}

impl DesyncConfig {
    /// Построить полную конфигурацию GUI из одного из 24 рецептов апстримного `ADAPTIVE_RECIPES`.
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
            upstream::DesyncMode::Disoob => "disoob",
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
            wsize: u32::from(r.wsize),
            wscale: r.wscale,
            syndata: r.syndata,
            ipfrag: false,
            udp_fake: true,
            udp_repeats: 3,
            udp_fake_ttl: 6,
            explicit_udp_fake_ttl: false,
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
            obj.insert("auto_tune".to_string(), serde_json::json!(false));
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
        if let Some(ws) = self.wscale {
            obj.insert("wscale".to_string(), serde_json::json!(ws.min(14)));
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
            DesyncPreset::Disoob => {
                c.auto = false;
                c.mode = "disoob".to_string();
                c.split_pos = "host+1".to_string();
                c.tlsrec_first = true;
                c.wsize = 64;
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
            u.explicit_auto_tune = true;
            u.udp_fake = false;
            return u;
        }

        u.auto_tune = self.auto;
        u.explicit_auto_tune = true;
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
        u.host_fake = !self.auto && self.host_fake;
        u.tlsrec_first = self.tlsrec_first;
        u.explicit_tlsrec_first = !self.auto;
        u.fake_sni = if self.fake_sni.trim().is_empty() {
            "www.google.com".to_string()
        } else {
            self.fake_sni.trim().to_string()
        };
        u.explicit_fake_sni = !self.auto;
        u.fake_payload = None;
        u.fake_ttl = self.fake_ttl.clamp(1, 64);
        u.explicit_fake_ttl = !self.auto;
        u.repeats = self.repeats.clamp(1, 10);
        u.split_delay_ms = self.split_delay_ms.min(50);
        u.seqovl = self.seqovl;
        u.wsize = self.wsize;
        u.wscale = self.wscale.map(|s| s.min(14));
        u.syndata = self.syndata;
        u.ipfrag = self.ipfrag;
        u.udp_fake = self.udp_fake;
        u.udp_repeats = self.udp_repeats.clamp(1, 10);
        u.udp_fake_ttl = self.udp_fake_ttl.clamp(1, 64);
        u.explicit_udp_fake_ttl = self.explicit_udp_fake_ttl || !self.auto;
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
    connect_outbound_tcp_with_window(dst, timeout, 0, None).await
}

/// Установить исходящее TCP-соединение с предконнектным зажимом приёмного окна (`wsize`, `wscale`) до отправки `SYN`.
pub async fn connect_outbound_tcp_with_window(
    dst: SocketAddr,
    timeout: Duration,
    wsize: u32,
    wscale: Option<u8>,
) -> io::Result<TcpStream> {
    let dial = crate::outbound::dial::DialOptions {
        connect_timeout: Some(timeout),
        connect_timeout_ms: Some(timeout.as_millis() as u64),
        ..Default::default()
    };
    crate::outbound::dial::connect_tcp_addr_with_window(dst, &dial, wsize, wscale).await
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
            map.shrink_to(256);
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
                let idx = (best_id as usize).min(RECIPE_TITLES.len() - 1);
                let title = RECIPE_TITLES[idx].1;
                if let Ok(guard) = relearn_log_slot().lock()
                    && let Some(ref log_cb) = *guard
                {
                    log_cb(
                        "info",
                        "relearn",
                        &format!(
                            "Авто-переобучение: для {clean} после сбоя подобран кандидат {title} (ожидает проверки 32 KiB, исключено маской: {})",
                            (banned & 0xFF_FFFF).count_ones()
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
        && let Ok(mut resolved) = crate::outbound::dial::resolve(h, dst.port()).await
    {
        resolved.sort_by_key(|a| upstream::peer_ip_failures(a.ip()));
        for addr in resolved {
            if addr != dst && addr.is_ipv4() == dst.is_ipv4() && candidate_addrs.len() < 4 {
                candidate_addrs.push(addr);
            }
        }
        if candidate_addrs.len() > 1 && upstream::peer_ip_failures(dst.ip()) > 0 {
            candidate_addrs.sort_by_key(|a| upstream::peer_ip_failures(a.ip()));
        }
    }

    let upstream_cfg = cfg.to_upstream();
    let (pre_wsize, pre_wscale) = if cfg.enabled && !first_pkt.is_empty() {
        upstream::preferred_preconnect_window(host_opt.as_deref(), &upstream_cfg)
    } else {
        (0, None)
    };
    let mut last_err: Option<io::Error> = None;

    for (attempt_idx, &target_addr) in candidate_addrs.iter().enumerate() {
        let connect_timeout = if attempt_idx == 0 {
            Duration::from_millis(4200)
        } else {
            Duration::from_millis(2800)
        };
        let stream = match connect_outbound_tcp_with_window(
            target_addr,
            connect_timeout,
            pre_wsize,
            pre_wscale,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                upstream::record_peer_ip_failure(target_addr.ip());
                last_err = Some(e);
                continue;
            }
        };
        if !cfg.enabled || first_pkt.is_empty() {
            return Ok((stream, Vec::new(), None, host_opt));
        }

        match upstream::apply_desync_tcp_auto(Box::new(stream), first_pkt, &upstream_cfg).await {
            Ok((boxed_stream, initial_reply)) => {
                let used_recipe = if cfg.auto {
                    host_opt.as_deref().and_then(|h| {
                        let snap = upstream::engine::gui_snapshot_learned_domains();
                        snap.iter()
                            .find(|d| d.host.eq_ignore_ascii_case(h))
                            .or_else(|| {
                                let etld = upstream::packet::extract_etld_plus_one(h);
                                (!etld.is_empty())
                                    .then(|| {
                                        snap.iter().find(|d| d.host.eq_ignore_ascii_case(etld))
                                    })
                                    .flatten()
                            })
                            .map(|d| d.recipe_id)
                    })
                } else {
                    None
                };
                return Ok((*boxed_stream, initial_reply, used_recipe, host_opt));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if cfg.auto
        && let Some(ref h) = host_opt
    {
        notify_domain_connection_result(h, false);
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TCP desync failed")))
}

/// Проверить, помечен ли целевой узел `UDP 443` как недоступный по QUIC в `AdaptiveBrain`
/// для мгновенного отката клиента на `TCP 443`.
#[inline]
pub fn is_quic_endpoint_dead(peer: SocketAddr) -> bool {
    upstream::is_quic_endpoint_dead(peer)
}

/// Отправить адаптивные UDP-фейки с того же самого сокета (`sock.send_to`), сохраняя точный 5-tuple потока
/// без вызова `sock.connect(dst)`, с ротацией по 6 UDP-рецептам `0.5.0` и восстановлением исходного TTL/HopLimit.
pub async fn send_udp_fakes_same_tuple(
    sock: &UdpSocket,
    dst: SocketAddr,
    cfg: &DesyncConfig,
) -> io::Result<()> {
    if !cfg.enabled || !cfg.udp_fake || cfg.udp_repeats == 0 {
        return Ok(());
    }
    let sref = socket2::SockRef::from(sock);
    let is_ipv6 = dst.is_ipv6();
    let orig_ttl = upstream::engine::get_socket_ttl_ref(&sref, is_ipv6);

    let adaptive = cfg.auto && !dst.ip().is_loopback();
    let udp_recipe = if adaptive {
        upstream::current_udp_recipe(dst)
    } else {
        0
    };

    let port = dst.port();
    let up_cfg = cfg.to_upstream();
    let (base_fake_ttl, max_step_ttl, is_discord_voice, is_stun) =
        upstream::engine::compute_udp_fake_ttl(port, adaptive, None, None, &up_cfg);

    let repeats = if adaptive {
        match udp_recipe {
            5 => cfg.udp_repeats.max(8),
            1 | 3 | 4 => cfg.udp_repeats.max(6),
            2 => cfg.udp_repeats.max(4),
            _ if is_stun => cfg.udp_repeats.max(4),
            _ => cfg.udp_repeats,
        }
    } else {
        cfg.udp_repeats
    }
    .clamp(1, 10);

    let use_opaque_blob = adaptive && matches!(udp_recipe, 1 | 4 | 5);
    let stepped_ttl = adaptive && udp_recipe == 4 && !up_cfg.explicit_udp_fake_ttl;
    let eff_udplen = if cfg.udplen > 0 {
        cfg.udplen
    } else if adaptive {
        match udp_recipe {
            5 => 24,
            1 | 3 => 16,
            _ => 0,
        }
    } else {
        0
    };

    let _ = upstream::engine::set_socket_ttl_ref(&sref, base_fake_ttl, is_ipv6);

    let mut pad_buf = [0u8; 1328];
    for i in 0..repeats {
        if stepped_ttl {
            let step_ttl = if is_stun {
                (2 + (i as u8 % 3)).min(max_step_ttl).max(2)
            } else {
                (2 + (i as u8 % 4)).min(max_step_ttl).max(2)
            };
            let _ = upstream::engine::set_socket_ttl_ref(&sref, step_ttl, is_ipv6);
        }

        if use_opaque_blob && i % 2 == 0 {
            let blob = upstream::payload::build_fake_udp_opaque_blob();
            let raw_pad = if eff_udplen > 0 {
                (((i as usize) + 1) * 4).min(eff_udplen).min(96)
            } else {
                0
            };
            if raw_pad > 0 {
                let total_len = blob.len() + raw_pad;
                pad_buf[..blob.len()].copy_from_slice(&blob);
                let _ = getrandom::fill(&mut pad_buf[blob.len()..total_len]);
                let _ = sock.send_to(&pad_buf[..total_len], dst).await;
            } else {
                let _ = sock.send_to(&blob, dst).await;
            }
        } else if is_stun {
            let disc_pkt;
            let stun_pkt;
            let is_disc = (adaptive || is_discord_voice) && i % 2 == 1;
            let base: &[u8] = if is_disc {
                disc_pkt = upstream::payload::build_fake_discord_ip_discovery();
                &disc_pkt
            } else {
                stun_pkt = upstream::payload::build_fake_stun_binding_request();
                &stun_pkt
            };
            if eff_udplen > 0 {
                let raw_pad = (((i as usize) + 1) * 4).min(eff_udplen).min(120);
                if !is_disc && base.len() == 20 {
                    let val_len = (raw_pad & !3).max(4);
                    let attr_total = 4 + val_len;
                    let total_len = 20 + attr_total;
                    pad_buf[..20].copy_from_slice(base);
                    pad_buf[2..4].copy_from_slice(&(attr_total as u16).to_be_bytes());
                    pad_buf[20..22].copy_from_slice(&[0x00, 0x26]);
                    pad_buf[22..24].copy_from_slice(&(val_len as u16).to_be_bytes());
                    let _ = getrandom::fill(&mut pad_buf[24..total_len]);
                    let _ = sock.send_to(&pad_buf[..total_len], dst).await;
                } else {
                    let total_len = base.len() + raw_pad;
                    pad_buf[..base.len()].copy_from_slice(base);
                    let _ = getrandom::fill(&mut pad_buf[base.len()..total_len]);
                    let _ = sock.send_to(&pad_buf[..total_len], dst).await;
                }
            } else {
                let _ = sock.send_to(base, dst).await;
            }
        } else if port == 443 || port == 8443 || adaptive {
            let quic_fake = if (adaptive && i >= 2 && i % 2 == 1) || (!adaptive && (i & 1) == 1) {
                upstream::payload::build_fake_quic_v2_initial()
            } else {
                upstream::payload::build_fake_quic_initial()
            };
            if eff_udplen > 0 {
                let pad_len = (((i as usize) + 1) * 4).min(eff_udplen).min(128);
                let total_len = quic_fake.len() + pad_len;
                pad_buf[..quic_fake.len()].copy_from_slice(&quic_fake);
                let quic_body_len = (1182 + pad_len) as u16;
                pad_buf[16..18].copy_from_slice(&(0x4000u16 | quic_body_len).to_be_bytes());
                let _ = getrandom::fill(&mut pad_buf[quic_fake.len()..total_len]);
                let _ = sock.send_to(&pad_buf[..total_len], dst).await;
            } else {
                let _ = sock.send_to(&quic_fake, dst).await;
            }
        } else {
            let blob = upstream::payload::build_fake_udp_opaque_blob();
            let _ = sock.send_to(&blob, dst).await;
        }
    }

    let _ = upstream::engine::set_socket_ttl_ref(&sref, orig_ttl, is_ipv6);
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
    if cfg.auto && dst.port() == 443 && !dst.ip().is_loopback() && is_quic_endpoint_dead(dst) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "QUIC UDP/443 marked dead by AdaptiveBrain",
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
    relayed_up: u64,
    relayed_down: u64,
    elapsed_ms: u64,
    io_ok: bool,
) {
    let Some(h) = host else {
        return;
    };
    if h.is_empty() {
        return;
    }

    // Пост-рукопожатный 0-байтовый блок после ServerHello: клиент отправил TLS Finished + запрос,
    // но сервер не прислал ни одного байта прикладных данных после начального ServerHello.
    let post_hs_zero_app_freeze =
        down_bytes < MIN_VERIFIED_TRANSFER_BYTES && relayed_down == 0 && relayed_up > 0;

    // Тихое удержание потока в окне 14..32 КиБ (типичный CloudFront/CDN 16 KB cap + 2.5 KB сертификатов)
    // свыше 15 с до штатного закрытия сервером по таймауту.
    let silent_16k_cap_window = io_ok
        && (14 * 1024..MIN_VERIFIED_TRANSFER_BYTES).contains(&down_bytes)
        && elapsed_ms >= 15_000;

    // Чисто завершившийся короткий JSON API-запрос или штатно закрытый WebSocket / HTTP/2 keep-alive
    // поток (< 32 КиБ, прикладной ответ доставлен без ошибок ввода-вывода и без 16 KB cap-таймаута):
    // обновляем свежесть записи в AdaptiveBrain без ложной отбраковки рабочего рецепта!
    if io_ok
        && (64..MIN_VERIFIED_TRANSFER_BYTES).contains(&down_bytes)
        && relayed_down >= 96
        && !post_hs_zero_app_freeze
        && !silent_16k_cap_window
    {
        notify_domain_connection_result(h, true);
        upstream::engine::gui_refresh_clean_short_transfer(h, peer);
        upstream::report_transfer_outcome_with_reply(
            h,
            peer,
            down_bytes,
            relayed_down,
            Duration::from_millis(elapsed_ms),
            true,
        );
        return;
    }

    let transfer_healthy = io_ok
        && down_bytes >= MIN_VERIFIED_TRANSFER_BYTES
        && !post_hs_zero_app_freeze
        && !silent_16k_cap_window;
    notify_domain_connection_result(h, transfer_healthy);

    let effective_ok = io_ok && !post_hs_zero_app_freeze && !silent_16k_cap_window;
    let effective_ms =
        if down_bytes < MIN_VERIFIED_TRANSFER_BYTES && (!effective_ok || down_bytes < 64) {
            elapsed_ms.clamp(2600, 3500)
        } else {
            elapsed_ms
        };
    let post_req_down = if relayed_up > 0 {
        relayed_down
    } else if down_bytes >= MIN_VERIFIED_TRANSFER_BYTES {
        down_bytes
    } else {
        0
    };
    upstream::report_transfer_outcome_with_reply(
        h,
        peer,
        down_bytes,
        post_req_down,
        Duration::from_millis(effective_ms),
        effective_ok,
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
            let idx = (d.recipe_id as usize).min(RECIPE_TITLES.len() - 1);
            let (code, title) = RECIPE_TITLES[idx];
            LearnedDomainView {
                host: d.host,
                tier: d.tier,
                recipe_id: d.recipe_id,
                recipe_code: code.to_string(),
                recipe_title: title.to_string(),
                verified: d.verified_32k,
                failures: d.consecutive_fails,
                banned_count: (d.banned_mask & 0xFF_FFFF).count_ones(),
            }
        })
        .collect()
}

pub fn get_isp_scoreboard() -> Vec<RecipeScoreView> {
    let scores = upstream::engine::gui_snapshot_l3_scores();
    (0..RECIPE_TITLES.len())
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
    let clean = sanitize_domain_input(host).to_ascii_lowercase();
    if !clean.is_empty()
        && let Ok(mut map) = domain_fail_tracker().lock()
    {
        map.remove(&clean);
        let etld = upstream::packet::extract_etld_plus_one(&clean);
        if !etld.is_empty() {
            map.remove(etld);
        }
    }
    upstream::engine::gui_remove_learned_domain(host);
    flush_persistent_cache();
}

pub(crate) fn clear_domain_fail_tracker() {
    if let Ok(mut map) = domain_fail_tracker().lock() {
        map.clear();
        map.shrink_to(64);
    }
}

pub fn clear_brain_cache() {
    clear_domain_fail_tracker();
    upstream::reset_adaptive_state();
    flush_persistent_cache();
}

static STORE_HANDLE: OnceLock<crate::cache_file::SharedCacheFile> = OnceLock::new();

pub fn attach_persistent_cache(path: &Path) {
    let handle = STORE_HANDLE
        .get_or_init(|| crate::cache_file::CacheFile::open_shared(path.to_path_buf()))
        .clone();
    upstream::attach_store(Some(handle));
    upstream::engine::gui_sanitize_poisoned_cap_entries();
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
    host: &str,
    rid: u8,
    code: String,
    title: String,
    gui_cfg: DesyncConfig,
    wait: Duration,
) -> RecipeProbeResult {
    let upstream_cfg = gui_cfg.to_upstream();
    let recipe_opt = if (rid as usize) < upstream::ADAPTIVE_RECIPES.len() {
        Some(upstream::ADAPTIVE_RECIPES[rid as usize])
    } else {
        None
    };
    let out = upstream::probe_desync_https_32k(dst, host, recipe_opt, &upstream_cfg, wait).await;
    RecipeProbeResult {
        recipe_id: rid,
        recipe_code: code,
        recipe_title: title,
        ok: out.ok && out.verified_32k,
        rtt_ms: out.rtt_ms,
        block_reason: out.block_reason,
        detail: out.detail,
        config: gui_cfg,
    }
}

/// Полный генератор и сканер стратегий по домену: тестирует 12 или все 24 рецепта параллельными волнами,
/// проверяет полное чтение `> 32 КиБ` по TLS 1.3 и синтезирует оптимальную конфигурацию `DesyncConfig` + JSON `tachyon-core`.
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
    banned_mask: u32,
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
    let host_arc: Arc<str> = Arc::from(clean_domain);
    let total_recipes = RECIPE_TITLES.len() as u8;
    let test_ids: Vec<u8> = if scan_all {
        (0..total_recipes).collect()
    } else {
        let mut base = vec![0u8, 1, 2, 3, 6, 10, 11, 14, 18, 19, 21, 23];
        // Если часть базовых рецептов уже забанена на 32 KiB гейте, добираем незабаненные из полного пула
        for alt in 0..total_recipes {
            if base.len() >= 14 {
                break;
            }
            if !base.contains(&alt) && (banned_mask & (1u32 << alt)) == 0 {
                base.push(alt);
            }
        }
        base
    };

    let wait = Duration::from_millis(timeout_ms.clamp(600, 4000));
    let mut results = Vec::with_capacity(test_ids.len());

    // Выполняем проверку волнами по 6 рецептов параллельно для быстрого отклика
    for chunk in test_ids.chunks(6) {
        let mut handles = Vec::with_capacity(chunk.len());
        for &rid in chunk {
            let idx = (rid as usize).min(RECIPE_TITLES.len() - 1);
            let (code, title) = RECIPE_TITLES[idx];
            let gui_cfg = DesyncConfig::from_recipe_id(rid);
            let host_c = host_arc.clone();
            handles.push(tokio::spawn(async move {
                execute_single_probe(
                    dst,
                    &host_c,
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

    let mut cap_mask = 0u32;
    for r in &results {
        if r.block_reason == "cap_16k" && (r.recipe_id as usize) < 24 {
            cap_mask |= 1u32 << r.recipe_id;
        }
    }
    let effective_banned = (banned_mask | cap_mask) & 0xFF_FFFF;

    let passed: Vec<&RecipeProbeResult> = results.iter().filter(|r| r.ok).collect();
    let passed_count = passed.len();
    let total_tested = results.len();

    // Приоритет отдаём рецептам, которые не находятся в маске отбраковки 32 KiB гейта (`effective_banned`)
    let best = passed
        .iter()
        .copied()
        .filter(|r| (effective_banned & (1u32 << r.recipe_id)) == 0)
        .min_by_key(|r| r.rtt_ms)
        .or_else(|| passed.iter().copied().min_by_key(|r| r.rtt_ms));

    let cap_count = results
        .iter()
        .filter(|r| r.block_reason == "cap_16k")
        .count();
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

    let (best_recipe_id, recommended_config, diagnosis) = if let Some(win) = best {
        let saved_mask = if pin_verified {
            effective_banned & !(1u32 << win.recipe_id)
        } else {
            effective_banned
        };
        upstream::engine::gui_set_learned_candidate(
            clean_domain,
            win.recipe_id,
            saved_mask,
            pin_verified,
        );

        let diag = format!(
            "Оптимальный рецепт #{:02} ({} мс, >32 КиБ проверено). Прошло {passed_count}/{total_tested} рецептов (Cap <32K: {cap_count}, RST: {rst_count}, Blackhole: {timeout_count}, Alert: {leaked_alerts}). Рецепт закреплён в AdaptiveBrain.",
            win.recipe_id, win.rtt_ms
        );
        (Some(win.recipe_id), win.config.clone(), diag)
    } else {
        let fallback = DesyncConfig::from_preset(DesyncPreset::SevenPointDisorder);
        let diag = format!(
            "Ни один из {total_tested} проверенных рецептов не прошёл контроль чтения >32 КиБ для {clean_domain} ({dst}) (Cap <32K: {cap_count}, RST: {rst_count}, Blackhole: {timeout_count}). Рекомендуется полное сканирование 24 рецептов или режим TUN."
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
    let wait = Duration::from_millis(timeout_ms.clamp(600, 4000));

    let mut cfg = custom_cfg.clone();
    cfg.enabled = true;
    cfg.auto = false;
    let win_suffix = if cfg.wsize > 0 {
        if let Some(ws) = cfg.wscale {
            format!(", wsize={}:scale={ws}", cfg.wsize)
        } else {
            format!(", wsize={}", cfg.wsize)
        }
    } else {
        String::new()
    };
    let title = format!(
        "Конструктор: {} + {} (split={}{}{}{}{})",
        cfg.mode,
        cfg.fooling,
        cfg.split_pos,
        if cfg.tlsrec_first { ", tlsrec" } else { "" },
        if cfg.multi_seven_point { ", 7-pt" } else { "" },
        if cfg.host_fake { ", hostfake" } else { "" },
        win_suffix,
    );

    let res = execute_single_probe(
        dst,
        clean_domain,
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
            "Пользовательская стратегия успешно прошла проверку чтения >32 КиБ на {clean_domain} ({dst}) за {} мс: {}",
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

/// Параллельная экспресс-диагностика 6 ключевых сервисов через активный десинхронизатор с контролем `> 32 КиБ`.
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

                let up_cfg = cfg.to_upstream();
                let learned_rid = if cfg.auto {
                    let snap = upstream::engine::gui_snapshot_learned_domains();
                    snap.iter()
                        .find(|d| d.host.eq_ignore_ascii_case(domain))
                        .or_else(|| {
                            let etld = upstream::packet::extract_etld_plus_one(domain);
                            (!etld.is_empty())
                                .then(|| snap.iter().find(|d| d.host.eq_ignore_ascii_case(etld)))
                                .flatten()
                        })
                        .map(|d| d.recipe_id)
                } else {
                    None
                };
                let recipe_opt = learned_rid
                    .and_then(|rid| upstream::ADAPTIVE_RECIPES.get(rid as usize).copied());

                let out = upstream::probe_desync_https_32k(
                    dst,
                    domain,
                    recipe_opt,
                    &up_cfg,
                    Duration::from_millis(2600),
                )
                .await;

                let used_recipe = if cfg.auto {
                    learned_rid.or_else(|| {
                        let snap = upstream::engine::gui_snapshot_learned_domains();
                        snap.iter()
                            .find(|d| d.host.eq_ignore_ascii_case(domain))
                            .or_else(|| {
                                let etld = upstream::packet::extract_etld_plus_one(domain);
                                (!etld.is_empty())
                                    .then(|| {
                                        snap.iter().find(|d| d.host.eq_ignore_ascii_case(etld))
                                    })
                                    .flatten()
                            })
                            .map(|d| d.recipe_id)
                    })
                } else {
                    None
                };

                if out.ok && out.verified_32k {
                    if cfg.auto {
                        report_transfer_outcome(
                            Some(domain),
                            Some(dst),
                            out.rx_wire_bytes as u64,
                            512,
                            out.rx_app_bytes as u64,
                            u64::from(out.rtt_ms),
                            true,
                        );
                    }
                    Ok((out.rtt_ms, used_recipe, format!("{} ({dst})", out.detail)))
                } else {
                    if cfg.auto && out.block_reason != "connect_err" {
                        report_transfer_outcome(
                            Some(domain),
                            Some(dst),
                            out.rx_wire_bytes as u64,
                            512,
                            out.rx_app_bytes as u64,
                            u64::from(out.rtt_ms).max(2600),
                            false,
                        );
                    }
                    Err(out.detail)
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

/// Авто-калибровка оптимального `TTL` для фейковых пакетов (`fake_ttl` / `udp_fake_ttl`) через апстримный зонд `tachyon-core`.
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

    Ok(upstream::calibrate_ttl_hops(
        dst,
        target,
        &DesyncConfig::default().to_upstream(),
        Duration::from_millis(1600),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;

    static FAIL_TRACKER_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn learned_candidate_preserves_banned_mask_and_demotes_stalled_32k_cap() {
        let _guard = FAIL_TRACKER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let host = "shard-test.googlevideo-desync-unit.com";
        remove_learned_domain(host);
        remove_learned_domain("googlevideo-desync-unit.com");

        // Симулируем кандидата от авто-переобучения с сохранённой маской забаненных рецептов (#0 и #1)
        let initial_mask: u32 = (1 << 0) | (1 << 1);
        upstream::engine::gui_set_learned_candidate(host, 3, initial_mask, false);
        assert_eq!(upstream::engine::gui_get_banned_mask(host), initial_mask);

        let snap = get_learned_domains_snapshot();
        let entry = snap.iter().find(|d| d.host == host).expect("host in L1");
        assert_eq!(entry.recipe_id, 3);
        assert!(!entry.verified);
        assert_eq!(entry.banned_count, 2);

        // Симулируем тихий обрыв на 16 KB cap спустя 12 секунд (больше старого лимита 4 с)
        report_transfer_outcome(Some(host), None, 14_000, 512, 10_500, 12_000, false);
        let updated_mask = upstream::engine::gui_get_banned_mask(host);
        assert_ne!(
            updated_mask & (1 << 3),
            0,
            "recipe #3 must be added to banned_mask after <32 KiB stall even at 12s elapsed"
        );

        remove_learned_domain(host);
        remove_learned_domain("googlevideo-desync-unit.com");
    }

    #[test]
    fn manual_presets_and_custom_profiles_disable_adaptive_brain_override() {
        let public_peer: SocketAddr = "162.159.135.232:443".parse().unwrap();
        for preset in [
            DesyncPreset::TlsRec,
            DesyncPreset::FakeSplit,
            DesyncPreset::FakeDisorder,
            DesyncPreset::HostFakeSplit,
            DesyncPreset::SevenPointDisorder,
        ] {
            let cfg = DesyncConfig::from_preset(preset);
            assert!(!cfg.auto);
            let up = cfg.to_upstream();
            assert!(
                !up.is_adaptive_enabled(Some(public_peer)),
                "manual preset {preset:?} must not be hijacked by AdaptiveBrain"
            );
        }

        let auto_cfg = DesyncConfig::from_preset(DesyncPreset::Auto);
        assert!(
            auto_cfg
                .to_upstream()
                .is_adaptive_enabled(Some(public_peer))
        );
    }

    #[test]
    fn clean_short_json_and_websocket_sessions_do_not_ban_working_recipe() {
        let _guard = FAIL_TRACKER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let host = "gateway-test.discord-desync-unit.gg";
        remove_learned_domain(host);
        remove_learned_domain("discord-desync-unit.gg");

        upstream::engine::gui_set_learned_candidate(host, 1, 0, false);

        // 1. Короткий JSON API-ответ (4.2 КиБ за 180 мс, прикладные байты доставлены, чистое закрытие)
        report_transfer_outcome(Some(host), None, 4_200, 620, 1_800, 180, true);
        let mask_after_api = upstream::engine::gui_get_banned_mask(host);
        assert_eq!(
            mask_after_api, 0,
            "clean short JSON API response must never ban the working recipe"
        );

        // 2. Штатная сессия Discord Gateway WebSocket (11 КиБ за 9 секунд, без ошибок ввода-вывода)
        report_transfer_outcome(Some(host), None, 11_200, 950, 8_400, 9_000, true);
        let mask_after_ws = upstream::engine::gui_get_banned_mask(host);
        assert_eq!(
            mask_after_ws, 0,
            "clean <32 KiB WebSocket session must never ban or set POST_HS_CAP_DETECTED_BIT"
        );

        // 3. Реальный пост-ServerHello 0-байтовый блок (клиент послал 600 Б после ServerHello, сервер отдал 0 Б)
        report_transfer_outcome(Some(host), None, 3_400, 600, 0, 2_600, true);
        let mask_after_freeze = upstream::engine::gui_get_banned_mask(host);
        assert_ne!(
            mask_after_freeze & (1 << 1),
            0,
            "genuine 0-byte post-ServerHello freeze must ban the stalled recipe"
        );

        remove_learned_domain(host);
        remove_learned_domain("discord-desync-unit.gg");
    }

    #[tokio::test]
    async fn execute_single_probe_rejects_post_handshake_truncation_below_32k() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 2048];
            let _ = s.read(&mut req).await.unwrap();
            // Валидный заголовок ServerHello без завершения TLS 1.3 и без 32 КиБ данных (имитация 16 KiB cap)
            let mut sh = vec![0u8; 96];
            sh[0] = 0x16;
            sh[1] = 0x03;
            sh[2] = 0x03;
            sh[3] = 0x00;
            sh[4] = 91;
            sh[5] = 0x02;
            sh[6] = 0x00;
            sh[7] = 0x00;
            sh[8] = 87;
            sh[9] = 0x03;
            sh[10] = 0x03;
            let _ = s.write_all(&sh).await;
            drop(s);
        });

        let res = execute_single_probe(
            addr,
            "discord.com",
            17,
            "r17_disoob_tlsrec_wsize64".to_string(),
            "#17 Disoob".to_string(),
            DesyncConfig::from_recipe_id(17),
            Duration::from_millis(900),
        )
        .await;
        assert!(
            !res.ok,
            "truncated stream below 32 KiB must never return ok=true in Strategy Generator: {:?}",
            res
        );
        let _ = srv.await;
    }

    #[test]
    fn recipe_23_wsize_1_wscale_1_and_core_outbound_json() {
        let cfg = DesyncConfig::from_recipe_id(23);
        assert_eq!(cfg.mode, "multi_disorder");
        assert_eq!(cfg.split_pos, "midsld");
        assert_eq!(cfg.wsize, 1);
        assert_eq!(cfg.wscale, Some(1));

        let json = cfg.to_core_outbound_json();
        assert_eq!(json.get("wsize").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(json.get("wscale").and_then(|v| v.as_u64()), Some(1));

        let up = cfg.to_upstream();
        assert_eq!(up.wsize, 1);
        assert_eq!(up.wscale, Some(1));
    }

    #[test]
    fn remove_learned_domain_and_clear_brain_reset_fail_tracker() {
        let _guard = FAIL_TRACKER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let host = "stuck-cache-test.discord-desync-unit.gg";
        notify_domain_connection_result(host, false);
        upstream::engine::gui_set_learned_candidate(host, 15, 1 << 17, false);

        assert!(
            domain_fail_tracker()
                .lock()
                .unwrap()
                .contains_key("stuck-cache-test.discord-desync-unit.gg")
        );
        remove_learned_domain(host);
        assert!(
            !domain_fail_tracker()
                .lock()
                .unwrap()
                .contains_key("stuck-cache-test.discord-desync-unit.gg")
        );
        assert!(
            get_learned_domains_snapshot()
                .iter()
                .all(|d| d.host != host && d.host != "discord-desync-unit.gg")
        );

        notify_domain_connection_result("another-test.googlevideo-desync-unit.com", false);
        clear_domain_fail_tracker();
        assert!(domain_fail_tracker().lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn udp_fakes_share_exact_5_tuple_and_restore_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let orig_ttl = client.ttl().unwrap();

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
        assert_eq!(client.ttl().unwrap(), orig_ttl);

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
