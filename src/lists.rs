//! Категории списков доменов и подсетей (`tachyon-lists`), пользовательские списки,
//! компилятор правил маршрутизации/десинка и DNS-кэш обратного отображения `IP -> Домен`.

use crate::desync::{DesyncConfig, DesyncPreset, ip_in_subnet};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Действие, назначаемое списку доменов/подсетей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListStrategy {
    /// Адаптивный автоподбор из 16 рецептов (`AdaptiveBrain`).
    Auto,
    /// Конкретный именованный пресет (`fake_split`, `fake_disorder`, `tlsrec`, `multi_disorder`, `seven_point_disorder`, `host_fake_split`, `pad_encap`, `multi_split`, `split`, `disorder`, `oob`).
    Preset(String),
    /// Глобальные пользовательские параметры из вкладки «Параметры десинка».
    CustomGlobal,
    /// Перенаправление через внешний прокси (`SOCKS5` / `HTTP CONNECT`, например для списков с гео-ограничениями).
    UpstreamProxy,
    /// Прямое соединение без модификаций пакетов (исключение).
    Direct,
    /// Полная блокировка соединения.
    Block,
}

impl Serialize for ListStrategy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_code())
    }
}

impl<'de> Deserialize<'de> for ListStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;
        if let Some(s) = v.as_str() {
            return Ok(Self::from_code(s));
        }
        if let Some(obj) = v.as_object()
            && let Some(p) = obj.get("preset").and_then(|x| x.as_str())
        {
            return Ok(Self::from_code(p));
        }
        Ok(Self::Auto)
    }
}

impl ListStrategy {
    pub fn as_code(&self) -> String {
        match self {
            Self::Auto => "auto".to_string(),
            Self::Preset(p) => p.clone(),
            Self::CustomGlobal => "custom".to_string(),
            Self::UpstreamProxy => "upstream".to_string(),
            Self::Direct => "direct".to_string(),
            Self::Block => "block".to_string(),
        }
    }

    pub fn from_code(code: &str) -> Self {
        let c = code.trim().to_ascii_lowercase();
        match c.as_str() {
            "auto" | "adaptive" => Self::Auto,
            "direct" | "none" | "bypass" => Self::Direct,
            "block" | "reject" => Self::Block,
            "custom" | "custom_global" => Self::CustomGlobal,
            "upstream" | "proxy" | "socks5" | "http_proxy" => Self::UpstreamProxy,
            other => Self::Preset(other.to_string()),
        }
    }
}

/// Профиль категории или пользовательского списка.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub builtin: bool,
    pub enabled: bool,
    pub strategy: ListStrategy,
    pub block_quic: bool,
    pub udp_fake: bool,
    /// Строки правил: домены (`youtube.com`), ключевые слова (`kw:googlevideo`), подсети (`149.154.160.0/20`).
    pub entries: Vec<String>,
}

/// Решение диспетчера списков для конкретного соединения.
#[derive(Debug, Clone)]
pub enum MatchDecision {
    /// Прямая передача без десинхронизации.
    Direct { matched_list: Option<String> },
    /// Сбросить соединение (блокировка по списку или блокировка QUIC).
    Block { reason: String },
    /// Перенаправить соединение через внешний `SOCKS5` / `HTTP CONNECT` прокси.
    UpstreamProxy {
        proxy_url: String,
        matched_list: String,
    },
    /// Применить конфигурацию десинхронизации.
    Desync {
        config: DesyncConfig,
        matched_list: String,
    },
}

/// Скомпилированный без-аллокационный матчер списков.
#[derive(Debug, Clone)]
pub struct CompiledListRule {
    pub id: String,
    pub name: String,
    pub strategy: ListStrategy,
    pub block_quic: bool,
    pub udp_fake: bool,
    pub exact_domains: HashSet<String>,
    pub domain_suffixes: Vec<String>,
    pub keywords: Vec<String>,
    pub subnets: Vec<(IpAddr, u8)>,
}

impl CompiledListRule {
    pub fn compile(profile: &ListProfile) -> Self {
        let mut exact_domains = HashSet::new();
        let mut domain_suffixes = Vec::new();
        let mut keywords = Vec::new();
        let mut subnets = Vec::new();

        for raw in &profile.entries {
            let line = raw
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if line.is_empty() {
                continue;
            }
            if let Some((dom_part, _ip_part)) = line.split_once('=') {
                let clean_dom = dom_part
                    .trim()
                    .trim_start_matches("*.")
                    .trim_start_matches("domain:")
                    .trim_matches('.');
                if !clean_dom.is_empty() {
                    exact_domains.insert(clean_dom.to_string());
                    domain_suffixes.push(format!(".{clean_dom}"));
                }
                continue;
            }
            if let Some(kw) = line
                .strip_prefix("kw:")
                .or_else(|| line.strip_prefix("keyword:"))
            {
                let kw = kw.trim();
                if !kw.is_empty() {
                    keywords.push(kw.to_string());
                }
                continue;
            }
            if let Some(exact) = line
                .strip_prefix("full:")
                .or_else(|| line.strip_prefix("exact:"))
            {
                let exact = exact.trim().trim_matches('.');
                if !exact.is_empty() {
                    exact_domains.insert(exact.to_string());
                }
                continue;
            }
            if let Some((ip_net, prefix)) = parse_cidr_or_ip(&line) {
                subnets.push((ip_net, prefix));
                continue;
            }
            let clean_dom = line
                .trim_start_matches("*.")
                .trim_start_matches("domain:")
                .trim_matches('.');
            if !clean_dom.is_empty() {
                exact_domains.insert(clean_dom.to_string());
                domain_suffixes.push(format!(".{clean_dom}"));
            }
        }

        Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            strategy: profile.strategy.clone(),
            block_quic: profile.block_quic,
            udp_fake: profile.udp_fake,
            exact_domains,
            domain_suffixes,
            keywords,
            subnets,
        }
    }

    pub fn matches(&self, host: Option<&str>, dst_ip: IpAddr) -> bool {
        for &(net, prefix) in &self.subnets {
            if ip_in_subnet(dst_ip, net, prefix) {
                return true;
            }
        }
        if let Some(h) = host {
            let h_lc = h.trim().trim_end_matches('.').to_ascii_lowercase();
            if h_lc.is_empty() {
                return false;
            }
            if self.exact_domains.contains(&h_lc) {
                return true;
            }
            for suf in &self.domain_suffixes {
                if h_lc.ends_with(suf.as_str()) {
                    return true;
                }
            }
            for kw in &self.keywords {
                if h_lc.contains(kw.as_str()) {
                    return true;
                }
            }
        }
        false
    }
}

/// Режим фильтрации трафика по приложениям (`.exe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppFilterMode {
    /// Все приложения обрабатываются по правилам списков доменов.
    #[default]
    All,
    /// Белый список: через десинк идут только выбранные приложения (`selected_apps`), остальные — напрямую.
    Include,
    /// Чёрный список (обход): выбранные приложения (`selected_apps`) всегда идут напрямую, остальные — через десинк.
    Exclude,
}

impl AppFilterMode {
    pub fn from_code(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "include" | "whitelist" | "only" => Self::Include,
            "exclude" | "bypass" | "except" => Self::Exclude,
            _ => Self::All,
        }
    }
}

/// Полный скомпилированный набор правил для быстрого чтения из всех потоков.
#[derive(Debug, Clone)]
pub struct CompiledMatcher {
    pub rules: Vec<CompiledListRule>,
    pub default_strategy: ListStrategy,
    pub custom_global_config: DesyncConfig,
    pub app_filter_mode: AppFilterMode,
    pub selected_apps: Vec<String>,
    pub force_desync_selected_apps: bool,
    pub upstream_proxy: String,
    pub app_strategies: Vec<(String, ListStrategy)>,
}

impl CompiledMatcher {
    pub fn build(
        lists: &[ListProfile],
        default_strategy: ListStrategy,
        custom_global_config: DesyncConfig,
    ) -> Self {
        Self::build_with_apps(
            lists,
            default_strategy,
            custom_global_config,
            AppFilterMode::All,
            Vec::new(),
            true,
        )
    }

    pub fn build_with_apps(
        lists: &[ListProfile],
        default_strategy: ListStrategy,
        custom_global_config: DesyncConfig,
        app_filter_mode: AppFilterMode,
        selected_apps: Vec<String>,
        force_desync_selected_apps: bool,
    ) -> Self {
        Self::build_full(
            lists,
            default_strategy,
            custom_global_config,
            app_filter_mode,
            selected_apps,
            force_desync_selected_apps,
            String::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_full(
        lists: &[ListProfile],
        default_strategy: ListStrategy,
        custom_global_config: DesyncConfig,
        app_filter_mode: AppFilterMode,
        selected_apps: Vec<String>,
        force_desync_selected_apps: bool,
        upstream_proxy: String,
        app_strategies_map: &std::collections::BTreeMap<String, String>,
        explicit_dns_overrides: &std::collections::BTreeMap<String, String>,
    ) -> Self {
        // Пользовательские списки проверяются первыми, затем встроенные категории
        let mut rules = Vec::new();
        for p in lists.iter().filter(|p| p.enabled && !p.builtin) {
            rules.push(CompiledListRule::compile(p));
        }
        for p in lists.iter().filter(|p| p.enabled && p.builtin) {
            rules.push(CompiledListRule::compile(p));
        }
        let normalized_apps: Vec<String> = selected_apps
            .into_iter()
            .map(|s| crate::apps::normalize_app_name(&s))
            .filter(|s| !s.is_empty())
            .collect();
        let app_strategies: Vec<(String, ListStrategy)> = app_strategies_map
            .iter()
            .filter_map(|(k, v)| {
                let norm = crate::apps::normalize_app_name(k);
                let code = v.trim();
                if norm.is_empty() || code.is_empty() || code.eq_ignore_ascii_case("default") {
                    None
                } else {
                    Some((norm, ListStrategy::from_code(code)))
                }
            })
            .collect();

        // Обновляем глобальную таблицу DNS-переопределений (домен=IP из настроек и активных списков)
        refresh_dns_overrides_from_config(lists, explicit_dns_overrides);

        Self {
            rules,
            default_strategy,
            custom_global_config,
            app_filter_mode,
            selected_apps: normalized_apps,
            force_desync_selected_apps,
            upstream_proxy: upstream_proxy.trim().to_string(),
            app_strategies,
        }
    }

    fn find_app_strategy<'a>(
        &'a self,
        app_name: Option<&'a str>,
    ) -> Option<(&'a str, &'a ListStrategy)> {
        let app = app_name?;
        for (rule, strat) in &self.app_strategies {
            if crate::apps::app_matches_rule(app, rule) {
                return Some((app, strat));
            }
        }
        None
    }

    fn matches_selected_app(&self, app_name: Option<&str>) -> bool {
        let Some(app) = app_name else {
            return false;
        };
        self.selected_apps
            .iter()
            .any(|rule| crate::apps::app_matches_rule(app, rule))
    }

    /// Определить политику обработки пакета/потока по `(host, dst_ip, dst_port, is_udp)`.
    pub fn evaluate(
        &self,
        host: Option<&str>,
        dst_ip: IpAddr,
        dst_port: u16,
        is_udp: bool,
    ) -> MatchDecision {
        self.evaluate_with_app(host, dst_ip, dst_port, is_udp, None)
    }

    /// Определить политику обработки пакета/потока с учётом имени приложения `app_name`.
    pub fn evaluate_with_app(
        &self,
        host: Option<&str>,
        dst_ip: IpAddr,
        dst_port: u16,
        is_udp: bool,
        app_name: Option<&str>,
    ) -> MatchDecision {
        // Локальные и приватные адреса всегда идут напрямую
        if is_private_or_loopback(dst_ip) {
            return MatchDecision::Direct {
                matched_list: Some("local".to_string()),
            };
        }

        // 1. Индивидуальная стратегия для конкретного .exe (Per-App Strategy Override)
        if let Some((app_label, app_strat)) = self.find_app_strategy(app_name) {
            return self.strategy_to_decision(
                app_strat,
                self.custom_global_config.block_quic,
                true, // для выделенных .exe (Discord.exe, игры) включаем UDP Fake по умолчанию
                &format!("Профиль .exe ({app_label})"),
                dst_port,
                is_udp,
            );
        }

        // 2. Автоматическое прямое соединение (Direct Bypass) для процессов ядерных античитов
        // и защищённых мультиплеерных игр (RICOCHET / Call of Duty, EasyAntiCheat, BattlEye,
        // Riot Vanguard, FACEIT, EA AntiCheat, Battle.net), если пользователь явно не задал
        // индивидуальный профиль для этого .exe выше.
        if is_anticheat_or_protected_game_process(app_name) {
            let app_label = app_name.unwrap_or("anticheat");
            return MatchDecision::Direct {
                matched_list: Some(format!("Античит / Игра ({app_label})")),
            };
        }

        // 3. Общая фильтрация по приложениям (.exe), если список выбранных приложений не пуст
        if !self.selected_apps.is_empty() {
            match self.app_filter_mode {
                AppFilterMode::All => {}
                AppFilterMode::Exclude => {
                    if self.matches_selected_app(app_name) {
                        let app_label = app_name.unwrap_or("app");
                        return MatchDecision::Direct {
                            matched_list: Some(format!("Исключено ({app_label})")),
                        };
                    }
                }
                AppFilterMode::Include => {
                    if !self.matches_selected_app(app_name) {
                        return MatchDecision::Direct {
                            matched_list: Some("Вне списка приложений".to_string()),
                        };
                    }
                }
            }
        }

        // Если имя хоста не передано явно (например, UDP/QUIC или TCP без SNI), проверяем DNS-кэш
        let snooped = if host.is_none() {
            lookup_dns_mapping(dst_ip)
        } else {
            None
        };
        let effective_host = host.or(snooped.as_deref());

        // Домены авторизации античитов и игрового матчмейкинга (Demonware / RICOCHET / Battle.net / EAC / BattlEye)
        // всегда идут напрямую без модификации пакетов.
        if is_anticheat_or_game_auth_domain(effective_host) {
            return MatchDecision::Direct {
                matched_list: Some("Античит / Игровой шлюз".to_string()),
            };
        }

        for rule in &self.rules {
            if rule.matches(effective_host, dst_ip) {
                return self.strategy_to_decision(
                    &rule.strategy,
                    rule.block_quic,
                    rule.udp_fake,
                    &rule.name,
                    dst_port,
                    is_udp,
                );
            }
        }

        // Если включён режим «Только выбранные приложения» с принудительным десинком всего их трафика
        if self.app_filter_mode == AppFilterMode::Include
            && !self.selected_apps.is_empty()
            && self.force_desync_selected_apps
            && self.matches_selected_app(app_name)
        {
            let app_label = app_name.unwrap_or("приложение");
            return self.strategy_to_decision(
                &ListStrategy::Auto,
                self.custom_global_config.block_quic,
                true,
                &format!("Приложение {app_label}"),
                dst_port,
                is_udp,
            );
        }

        // Для произвольных UDP-портов вне списков (например, игровые UDP-порты 3074, 27015..27050, STUN)
        // никогда не инжектируем фейковые UDP-пакеты по умолчанию, если пакет не попал в целевой список
        // (Discord / YouTube) и пользователь явно не выбрал CustomGlobal.
        if is_udp && dst_port != 443 && !matches!(self.default_strategy, ListStrategy::CustomGlobal)
        {
            return MatchDecision::Direct {
                matched_list: Some("UDP вне списков (Прямое)".to_string()),
            };
        }

        // Правило по умолчанию для трафика вне списков
        let default_block_quic = self.custom_global_config.block_quic;
        let default_udp_fake = self.custom_global_config.udp_fake;
        self.strategy_to_decision(
            &self.default_strategy,
            default_block_quic,
            default_udp_fake,
            "По умолчанию",
            dst_port,
            is_udp,
        )
    }

    fn strategy_to_decision(
        &self,
        strategy: &ListStrategy,
        block_quic: bool,
        udp_fake: bool,
        list_name: &str,
        dst_port: u16,
        is_udp: bool,
    ) -> MatchDecision {
        match strategy {
            ListStrategy::Direct => MatchDecision::Direct {
                matched_list: Some(list_name.to_string()),
            },
            ListStrategy::Block => MatchDecision::Block {
                reason: format!("Заблокировано правилом «{list_name}»"),
            },
            ListStrategy::UpstreamProxy => {
                if !is_udp && !self.upstream_proxy.is_empty() {
                    return MatchDecision::UpstreamProxy {
                        proxy_url: self.upstream_proxy.clone(),
                        matched_list: list_name.to_string(),
                    };
                }
                if is_udp && block_quic && dst_port == 443 {
                    return MatchDecision::Block {
                        reason: format!(
                            "QUIC UDP/443 отключён профилем «{list_name}» (переход на TCP)"
                        ),
                    };
                }
                let mut cfg = DesyncConfig::from_preset(DesyncPreset::Auto);
                cfg.block_quic = block_quic;
                cfg.udp_fake = udp_fake;
                cfg.fake_sni = self.custom_global_config.fake_sni.clone();
                cfg.fake_ttl = self.custom_global_config.fake_ttl;
                cfg.repeats = self.custom_global_config.repeats;
                MatchDecision::Desync {
                    config: cfg,
                    matched_list: list_name.to_string(),
                }
            }
            ListStrategy::Auto => {
                if is_udp && block_quic && dst_port == 443 {
                    return MatchDecision::Block {
                        reason: format!(
                            "QUIC UDP/443 отключён профилем «{list_name}» (переход на TCP)"
                        ),
                    };
                }
                let mut cfg = DesyncConfig::from_preset(DesyncPreset::Auto);
                cfg.block_quic = block_quic;
                cfg.udp_fake = udp_fake;
                cfg.fake_sni = self.custom_global_config.fake_sni.clone();
                cfg.fake_ttl = self.custom_global_config.fake_ttl;
                cfg.repeats = self.custom_global_config.repeats;
                MatchDecision::Desync {
                    config: cfg,
                    matched_list: list_name.to_string(),
                }
            }
            ListStrategy::Preset(code) => {
                if is_udp && block_quic && dst_port == 443 {
                    return MatchDecision::Block {
                        reason: format!(
                            "QUIC UDP/443 отключён профилем «{list_name}» (переход на TCP)"
                        ),
                    };
                }
                let preset = DesyncPreset::from_name(code).unwrap_or(DesyncPreset::FakeSplit);
                if preset == DesyncPreset::None {
                    return MatchDecision::Direct {
                        matched_list: Some(list_name.to_string()),
                    };
                }
                let mut cfg = DesyncConfig::from_preset(preset);
                cfg.block_quic = block_quic;
                cfg.udp_fake = udp_fake;
                cfg.fake_sni = self.custom_global_config.fake_sni.clone();
                cfg.fake_ttl = self.custom_global_config.fake_ttl;
                MatchDecision::Desync {
                    config: cfg,
                    matched_list: list_name.to_string(),
                }
            }
            ListStrategy::CustomGlobal => {
                if is_udp && block_quic && dst_port == 443 {
                    return MatchDecision::Block {
                        reason: format!(
                            "QUIC UDP/443 отключён профилем «{list_name}» (переход на TCP)"
                        ),
                    };
                }
                let mut cfg = self.custom_global_config.clone();
                cfg.enabled = true;
                cfg.block_quic = block_quic;
                cfg.udp_fake = udp_fake;
                MatchDecision::Desync {
                    config: cfg,
                    matched_list: list_name.to_string(),
                }
            }
        }
    }
}

pub fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Является ли процесс ядерным античитом или защищённым игровым клиентом
/// (RICOCHET / Call of Duty, EasyAntiCheat, BattlEye, Riot Vanguard, FACEIT, EA AntiCheat),
/// чей трафик должен идти напрямую без модификации пакетов.
pub fn is_anticheat_or_protected_game_process(app_name: Option<&str>) -> bool {
    let Some(raw) = app_name else {
        return false;
    };
    let name = crate::apps::normalize_app_name(raw);
    if name.is_empty() {
        return false;
    }
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    if stem.starts_with("easyanticheat")
        || stem.starts_with("beservice")
        || stem.starts_with("eaanticheat")
        || stem.starts_with("faceit")
        || stem.starts_with("cod2")
        || stem.ends_with("-cod")
    {
        return true;
    }
    matches!(
        stem,
        // Call of Duty / RICOCHET / Battle.net
        "cod"
            | "sp22-cod"
            | "mp22-cod"
            | "sp23-cod"
            | "mp23-cod"
            | "sp24-cod"
            | "mp24-cod"
            | "modernwarfare"
            | "blackops6"
            | "blackopscoldwar"
            | "vanguard"
            | "bootstrapper"
            | "bootstrappercrashhandler"
            | "randgrid"
            | "battle.net"
            | "agent"
            | "blizzarderror"
            // EasyAntiCheat / BattlEye / Riot Vanguard / Valve / Anti-Cheat Protected Games
            | "start_protected_game"
            | "belauncher"
            | "vgc"
            | "vgtray"
            | "valorant"
            | "valorant-win64-shipping"
            | "riotclientservices"
            | "riotclientux"
            | "cs2"
            | "dota2"
            | "r5apex"
            | "fortniteclient-win64-shipping"
            | "fortniteclient-win64-shipping_eac"
            | "fortniteclient-win64-shipping_be"
            | " fortlauncher"
            | "tslgame"
            | "pubg-win64-shipping"
            | "rainbowsix"
            | "rainbowsix_be"
            | "escapefromtarkov"
            | "escapefromtarkov_be"
            | "rustclient"
            | "dayz_x64"
            | "dayz_be"
            | "deadbydaylight-win64-shipping"
            | "overwatch"
            | "destiny2"
            | "helldivers2"
            | "thefinals"
            | "discovery"
    )
}

/// Является ли целевой домен сервером авторизации античита или игрового матчмейкинга
/// (Demonware / RICOCHET / Activision / Battle.net / EasyAntiCheat / BattlEye / FACEIT).
pub fn is_anticheat_or_game_auth_domain(host: Option<&str>) -> bool {
    let Some(h) = host else {
        return false;
    };
    let clean = h.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    const DIRECT_DOMAINS: &[&str] = &[
        "demonware.net",
        "callofduty.com",
        "activision.com",
        "battle.net",
        "blizzard.com",
        "bnet.com",
        "easyanticheat.net",
        "eac-cdn.com",
        "battleye.com",
        "faceit.com",
        "pvp.net",
    ];
    for &dom in DIRECT_DOMAINS {
        if clean == dom
            || (clean.len() > dom.len()
                && clean.ends_with(dom)
                && clean.as_bytes()[clean.len() - dom.len() - 1] == b'.')
        {
            return true;
        }
    }
    false
}

pub fn parse_cidr_or_ip(s: &str) -> Option<(IpAddr, u8)> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let ip: IpAddr = ip_part.trim().parse().ok()?;
        let max_p = if ip.is_ipv4() { 32 } else { 128 };
        let p: u8 = prefix_part.trim().parse().ok()?;
        if p <= max_p {
            return Some((ip, p));
        }
        return None;
    }
    let ip: IpAddr = s.trim().parse().ok()?;
    let p = if ip.is_ipv4() { 32 } else { 128 };
    Some((ip, p))
}

// ============================================================================
// Глобальный ограниченный DNS-кэш обратного сопоставления IP -> Домен (4096 записей)
// и таблица пользовательских DNS-переопределений (домен=IP / локальный аналог hosts)
// ============================================================================

type DnsOverrideList = Vec<(String, IpAddr)>;

fn custom_dns_overrides_store() -> &'static Mutex<DnsOverrideList> {
    static OVERRIDES: OnceLock<Mutex<DnsOverrideList>> = OnceLock::new();
    OVERRIDES.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn refresh_dns_overrides_from_config(
    lists: &[ListProfile],
    explicit_map: &std::collections::BTreeMap<String, String>,
) {
    let mut vec = Vec::new();
    for (dom, ip_str) in explicit_map {
        let d = dom
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches("domain:")
            .trim_matches('.')
            .to_ascii_lowercase();
        if !d.is_empty()
            && let Ok(ip) = ip_str.trim().parse::<IpAddr>()
        {
            vec.push((d, ip));
        }
    }
    for p in lists.iter().filter(|p| p.enabled) {
        for raw in &p.entries {
            let line = raw.split('#').next().unwrap_or("").trim();
            if let Some((dom_part, ip_part)) = line.split_once('=') {
                let d = dom_part
                    .trim()
                    .trim_start_matches("*.")
                    .trim_start_matches("domain:")
                    .trim_matches('.')
                    .to_ascii_lowercase();
                if !d.is_empty()
                    && let Ok(ip) = ip_part.trim().parse::<IpAddr>()
                {
                    vec.push((d, ip));
                }
            }
        }
    }
    if let Ok(mut guard) = custom_dns_overrides_store().lock() {
        *guard = vec;
    }
}

/// Найти переопределённый IP-адрес для домена (`домен=IP` или суффикс поддомена).
pub fn lookup_custom_dns_override(host: &str) -> Option<IpAddr> {
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return None;
    }
    let guard = custom_dns_overrides_store().lock().ok()?;
    for (pattern, ip) in guard.iter() {
        if &clean == pattern {
            return Some(*ip);
        }
        if clean.len() > pattern.len()
            && clean.ends_with(pattern.as_str())
            && clean.as_bytes()[clean.len() - pattern.len() - 1] == b'.'
        {
            return Some(*ip);
        }
    }
    None
}

fn dns_ip_cache() -> &'static Mutex<LruCache<IpAddr, String>> {
    static DNS_CACHE: OnceLock<Mutex<LruCache<IpAddr, String>>> = OnceLock::new();
    DNS_CACHE.get_or_init(|| Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())))
}

/// Записать соответствие `IP -> домен` в DNS-кэш.
pub fn record_dns_mapping(ip: IpAddr, domain: &str) {
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return;
    }
    if let Ok(mut c) = dns_ip_cache().lock() {
        c.put(ip, clean);
    }
}

/// Найти имя домена по целевому IP-адресу из перехваченных DNS-ответов.
pub fn lookup_dns_mapping(ip: IpAddr) -> Option<String> {
    if let Ok(mut c) = dns_ip_cache().lock() {
        return c.get(&ip).cloned();
    }
    None
}

/// Разобрать UDP-пакет DNS-ответа (RFC 1035) и сохранить все записи `A` и `AAAA` в кэш `IP -> QNAME`.
pub fn snoop_dns_response_packet(udp_payload: &[u8]) -> usize {
    if udp_payload.len() < 12 {
        return 0;
    }
    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
    // Бит QR (0x8000) должен быть 1 (ответ), RCODE (младшие 4 бита) == 0 (NOERROR)
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return 0;
    }
    let qdcount = u16::from_be_bytes([udp_payload[4], udp_payload[5]]) as usize;
    let ancount = u16::from_be_bytes([udp_payload[6], udp_payload[7]]) as usize;
    if qdcount == 0 || ancount == 0 || qdcount > 16 || ancount > 64 {
        return 0;
    }

    let mut pos = 12;
    let mut qname = String::new();
    for q_idx in 0..qdcount {
        let Some((name, next_pos)) = read_dns_name(udp_payload, pos) else {
            return 0;
        };
        if q_idx == 0 {
            qname = name;
        }
        pos = next_pos;
        if pos + 4 > udp_payload.len() {
            return 0;
        }
        pos += 4; // QTYPE + QCLASS
    }

    if qname.is_empty() {
        return 0;
    }

    let mut inserted = 0usize;
    for _ in 0..ancount {
        let Some((_rr_name, next_pos)) = read_dns_name(udp_payload, pos) else {
            break;
        };
        pos = next_pos;
        if pos + 10 > udp_payload.len() {
            break;
        }
        let rtype = u16::from_be_bytes([udp_payload[pos], udp_payload[pos + 1]]);
        let rdlen = u16::from_be_bytes([udp_payload[pos + 8], udp_payload[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > udp_payload.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            let ip = IpAddr::V4(Ipv4Addr::new(
                udp_payload[pos],
                udp_payload[pos + 1],
                udp_payload[pos + 2],
                udp_payload[pos + 3],
            ));
            record_dns_mapping(ip, &qname);
            inserted += 1;
        } else if rtype == 28 && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&udp_payload[pos..pos + 16]);
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            record_dns_mapping(ip, &qname);
            inserted += 1;
        }
        pos += rdlen;
    }
    inserted
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
        let label_len = b as usize;
        pos += 1;
        if pos + label_len > pkt.len() {
            return None;
        }
        if let Ok(s) = std::str::from_utf8(&pkt[pos..pos + label_len]) {
            labels.push(s.to_ascii_lowercase());
        }
        pos += label_len;
    }
}

/// Сформировать стартовый набор встроенных списков `tachyon-lists` (с подгрузкой расширенных списков из локального каталога `tachyon-lists`, если он присутствует рядом).
pub fn default_builtin_lists() -> Vec<ListProfile> {
    let mut profiles = vec![
        ListProfile {
            id: "youtube".to_string(),
            name: "YouTube и Google Video".to_string(),
            description:
                "Видеопотоки googlevideo.com, интерфейс YouTube, YouTube Music и статика ytimg"
                    .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: true,
            udp_fake: true,
            entries: vec![
                "youtube.com",
                "googlevideo.com",
                "ytimg.com",
                "youtu.be",
                "ggpht.com",
                "youtubei.googleapis.com",
                "youtube-nocookie.com",
                "youtubekids.com",
                "withyoutube.com",
                "widevine.com",
                "kw:googlevideo",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "discord".to_string(),
            name: "Discord и Голосовые каналы".to_string(),
            description:
                "Клиент Discord, CDN вложений, WebSocket-шлюзы и UDP/WebRTC голосовые серверы"
                    .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: false,
            udp_fake: true,
            entries: vec![
                "discord.com",
                "discordapp.com",
                "discordapp.net",
                "discord.gg",
                "discord.media",
                "discordcdn.com",
                "discordstatus.com",
                "dis.gd",
                "discord.co",
                "airhorn.solutions",
                "kw:discord",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "telegram".to_string(),
            name: "Telegram и Медиа-серверы".to_string(),
            description: "Домены Telegram Web/Desktop и подсети дата-центров Telegram".to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: false,
            udp_fake: true,
            entries: vec![
                "telegram.org",
                "t.me",
                "tdesktop.com",
                "telegra.ph",
                "telesco.pe",
                "cdn-telegram.org",
                "telegram.me",
                "149.154.160.0/20",
                "91.108.4.0/22",
                "91.108.8.0/22",
                "91.108.12.0/22",
                "91.108.16.0/22",
                "91.108.56.0/22",
                "91.105.192.0/23",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "ai_all".to_string(),
            name: "ИИ-платформы (OpenAI, Claude, Gemini, xAI)".to_string(),
            description:
                "ChatGPT, Claude, Google AI Studio, Perplexity, HuggingFace, Grok и GitHub Copilot"
                    .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: true,
            udp_fake: false,
            entries: vec![
                "openai.com",
                "chatgpt.com",
                "oaistatic.com",
                "oaiusercontent.com",
                "anthropic.com",
                "claude.ai",
                "gemini.google.com",
                "aistudio.google.com",
                "perplexity.ai",
                "huggingface.co",
                "hf.co",
                "x.ai",
                "grok.com",
                "midjourney.com",
                "githubcopilot.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "social_media".to_string(),
            name: "Социальные сети и блоги".to_string(),
            description:
                "X (Twitter), Instagram, Facebook, Threads, Reddit, Patreon, Medium, Quora"
                    .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: true,
            udp_fake: false,
            entries: vec![
                "x.com",
                "twitter.com",
                "twimg.com",
                "t.co",
                "instagram.com",
                "cdninstagram.com",
                "facebook.com",
                "fbcdn.net",
                "threads.net",
                "reddit.com",
                "redd.it",
                "redditmedia.com",
                "patreon.com",
                "medium.com",
                "quora.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "streaming".to_string(),
            name: "Стриминг и аудио (Twitch, Spotify, SoundCloud)".to_string(),
            description: "Видеопотоки Twitch, аудиопотоки Spotify и SoundCloud".to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: true,
            udp_fake: true,
            entries: vec![
                "twitch.tv",
                "ttvnw.net",
                "jtvnw.net",
                "spotify.com",
                "scdn.co",
                "spotifycdn.com",
                "soundcloud.com",
                "sndcdn.com",
                "netflix.com",
                "nflxvideo.net",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "gaming".to_string(),
            name: "Игровые сервисы (Steam, Roblox, Epic, Riot)".to_string(),
            description: "Игровые лаунчеры, CDN обновлений и голосовые/игровые UDP-шлюзы"
                .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: false,
            udp_fake: true,
            entries: vec![
                "roblox.com",
                "rbxcdn.com",
                "steampowered.com",
                "steamcommunity.com",
                "steamstatic.com",
                "steamcontent.com",
                "epicgames.com",
                "unrealengine.com",
                "riotgames.com",
                "ea.com",
                "ubisoft.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "dev_cloud".to_string(),
            name: "Разработка, репозитории и Cloudflare".to_string(),
            description:
                "GitHub, GitLab, Docker Hub, Crates.io, npm, PyPI и Cloudflare Workers/Pages"
                    .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Auto,
            block_quic: true,
            udp_fake: false,
            entries: vec![
                "github.com",
                "githubusercontent.com",
                "githubassets.com",
                "gitlab.com",
                "docker.com",
                "docker.io",
                "crates.io",
                "npmjs.org",
                "pypi.org",
                "workers.dev",
                "pages.dev",
                "cloudflare-ech.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
        ListProfile {
            id: "ru_direct".to_string(),
            name: "Внутренние ресурсы и банки (Прямое соединение)".to_string(),
            description:
                "Домены .ru / .рф, Госуслуги, банки и маркетплейсы — всегда без десинхронизации"
                    .to_string(),
            builtin: true,
            enabled: true,
            strategy: ListStrategy::Direct,
            block_quic: false,
            udp_fake: false,
            entries: vec![
                "ru",
                "su",
                "xn--p1ai",
                "yandex.com",
                "yandex.net",
                "userapi.com",
                "vkuseraudio.net",
                "vkuservideo.net",
                "mycdn.me",
                "2gis.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        },
    ];

    // Если рядом на диске есть локальный каталог `tachyon-lists/release/domains`, обогащаем списки
    enrich_from_local_tachyon_lists(&mut profiles);
    profiles
}

/// Синхронизировать профили из локального каталога `tachyon-lists` (если он доступен на машине).
pub fn enrich_from_local_tachyon_lists(profiles: &mut [ListProfile]) -> usize {
    let candidate_dirs = [
        Path::new(r"..\tachyon-lists\release\domains"),
        Path::new(r"tachyon-lists\release\domains"),
    ];
    let Some(dir) = candidate_dirs.into_iter().find(|p| p.is_dir()) else {
        return 0;
    };

    let mapping: &[(&str, &[&str])] = &[
        ("youtube", &["youtube.lst"]),
        ("discord", &["discord.lst"]),
        ("telegram", &["telegram.lst"]),
        (
            "ai_all",
            &[
                "ai_all.lst",
                "openai.lst",
                "anthropic.lst",
                "gemini.lst",
                "perplexity.lst",
                "xai.lst",
            ],
        ),
        (
            "social_media",
            &[
                "x.lst",
                "meta.lst",
                "tiktok.lst",
                "patreon.lst",
                "medium.lst",
                "quora.lst",
            ],
        ),
        (
            "streaming",
            &["twitch.lst", "spotify.lst", "soundcloud.lst", "netflix.lst"],
        ),
        (
            "gaming",
            &[
                "roblox.lst",
                "steam.lst",
                "epicgames.lst",
                "ea.lst",
                "ubisoft.lst",
                "riot.lst",
            ],
        ),
        ("dev_cloud", &["github.lst", "docker.lst", "cloudflare.lst"]),
    ];

    let mut total_added = 0usize;
    for (profile_id, files) in mapping {
        let Some(prof) = profiles.iter_mut().find(|p| p.id == *profile_id) else {
            continue;
        };
        let mut existing: HashSet<String> = prof
            .entries
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        for fname in *files {
            let p = dir.join(fname);
            if let Ok(content) = std::fs::read_to_string(&p) {
                for line in content.lines() {
                    let dom = line
                        .split('#')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    if !dom.is_empty() && existing.len() < 1500 && existing.insert(dom.clone()) {
                        prof.entries.push(dom);
                        total_added += 1;
                    }
                }
            }
        }
    }
    total_added
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiled_matcher_and_dns_snooping() {
        let lists = default_builtin_lists();
        let matcher = CompiledMatcher::build(&lists, ListStrategy::Auto, DesyncConfig::default());

        // 1. YouTube по SNI должен матчиться в профиль YouTube и блокировать QUIC UDP/443
        let d_quic = matcher.evaluate(
            Some("rr1---sn-abc.googlevideo.com"),
            "142.250.74.110".parse().unwrap(),
            443,
            true,
        );
        assert!(matches!(d_quic, MatchDecision::Block { .. }));

        // 2. YouTube по TCP/443 должен получать Desync
        let d_tcp = matcher.evaluate(
            Some("www.youtube.com"),
            "142.250.74.110".parse().unwrap(),
            443,
            false,
        );
        assert!(matches!(d_tcp, MatchDecision::Desync { .. }));

        // 3. Домены .ru должны идти напрямую (Direct)
        let d_ru = matcher.evaluate(
            Some("gosuslugi.ru"),
            "213.59.254.8".parse().unwrap(),
            443,
            false,
        );
        assert!(matches!(d_ru, MatchDecision::Direct { .. }));

        // 4. Проверим DNS snooping: сохраняем IP для discord.media и матчим без SNI
        let voice_ip: IpAddr = "66.22.196.10".parse().unwrap();
        record_dns_mapping(voice_ip, "rotterdam1234.discord.media");
        let d_voice = matcher.evaluate(None, voice_ip, 50001, true);
        match d_voice {
            MatchDecision::Desync {
                matched_list,
                config,
            } => {
                assert!(matched_list.contains("Discord"));
                assert!(config.udp_fake);
            }
            other => panic!("Expected Desync for Discord Voice IP, got {other:?}"),
        }
    }

    #[test]
    fn test_snoop_dns_response_packet() {
        // Минимальный валидный DNS-ответ для `youtube.com` -> A `142.250.185.78`
        let pkt: [u8; 45] = [
            0x12, 0x34, 0x81, 0x80, // ID, Flags (QR=1, RCODE=0)
            0x00, 0x01, 0x00, 0x01, // QD=1, AN=1
            0x00, 0x00, 0x00, 0x00, // NS=0, AR=0
            // QNAME: 7youtube3com0
            0x07, b'y', b'o', b'u', b't', b'u', b'b', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
            // Answer: ptr to offset 12 (0xc00c)
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, // TYPE=A, CLASS=IN
            0x00, 0x00, 0x00, 0x3c, // TTL=60
            0x00, 0x04, // RDLENGTH=4
            142, 250, 185, 78, // RDATA
        ];
        let count = snoop_dns_response_packet(&pkt);
        assert_eq!(count, 1);
        let mapped = lookup_dns_mapping("142.250.185.78".parse().unwrap());
        assert_eq!(mapped.as_deref(), Some("youtube.com"));
    }

    #[test]
    fn test_per_application_filtering_include_and_exclude() {
        let lists = default_builtin_lists();

        // 1. Whitelist (Include): только discord.exe
        let matcher_inc = CompiledMatcher::build_with_apps(
            &lists,
            ListStrategy::Direct,
            DesyncConfig::default(),
            AppFilterMode::Include,
            vec!["discord.exe".to_string()],
            true,
        );

        // Любой процесс не из списка (например, chrome.exe) идёт напрямую даже на youtube.com
        let d_chrome = matcher_inc.evaluate_with_app(
            Some("www.youtube.com"),
            "142.250.74.110".parse().unwrap(),
            443,
            false,
            Some("chrome.exe"),
        );
        assert!(matches!(d_chrome, MatchDecision::Direct { .. }));

        // А выбранный процесс discord.exe с force_desync_selected_apps = true десинхронизируется даже вне списков
        let d_discord = matcher_inc.evaluate_with_app(
            Some("unknown-voice-edge.example.net"),
            "162.159.130.233".parse().unwrap(),
            443,
            false,
            Some("Discord.exe"),
        );
        assert!(matches!(d_discord, MatchDecision::Desync { .. }));

        // 2. Bypass (Exclude): исключаем steam.exe
        let matcher_exc = CompiledMatcher::build_with_apps(
            &lists,
            ListStrategy::Auto,
            DesyncConfig::default(),
            AppFilterMode::Exclude,
            vec!["steam.exe".to_string()],
            true,
        );

        let d_steam = matcher_exc.evaluate_with_app(
            Some("steamcommunity.com"),
            "23.52.74.10".parse().unwrap(),
            443,
            false,
            Some("steam.exe"),
        );
        assert!(matches!(d_steam, MatchDecision::Direct { .. }));

        let d_firefox = matcher_exc.evaluate_with_app(
            Some("steamcommunity.com"),
            "23.52.74.10".parse().unwrap(),
            443,
            false,
            Some("firefox.exe"),
        );
        assert!(matches!(d_firefox, MatchDecision::Desync { .. }));
    }

    #[test]
    fn test_per_app_strategy_upstream_proxy_and_dns_overrides() {
        let mut lists = default_builtin_lists();
        if let Some(ai) = lists.iter_mut().find(|l| l.id == "ai_all") {
            ai.strategy = ListStrategy::UpstreamProxy;
        }
        let mut app_strats = std::collections::BTreeMap::new();
        app_strats.insert("discord.exe".to_string(), "fake_disorder".to_string());
        app_strats.insert("steam.exe".to_string(), "direct".to_string());

        let mut dns_ov = std::collections::BTreeMap::new();
        dns_ov.insert("chatgpt.com".to_string(), "172.64.155.209".to_string());

        let matcher = CompiledMatcher::build_full(
            &lists,
            ListStrategy::Auto,
            DesyncConfig::default(),
            AppFilterMode::All,
            vec!["discord.exe".to_string(), "steam.exe".to_string()],
            true,
            "127.0.0.1:1080".to_string(),
            &app_strats,
            &dns_ov,
        );

        // 1. DNS override lookup (exact + subdomain)
        assert_eq!(
            lookup_custom_dns_override("chatgpt.com"),
            Some("172.64.155.209".parse().unwrap())
        );
        assert_eq!(
            lookup_custom_dns_override("api.chatgpt.com"),
            Some("172.64.155.209".parse().unwrap())
        );

        // 2. AI list with UpstreamProxy -> MatchDecision::UpstreamProxy
        let d_ai = matcher.evaluate_with_app(
            Some("chatgpt.com"),
            "172.64.155.209".parse().unwrap(),
            443,
            false,
            Some("chrome.exe"),
        );
        match d_ai {
            MatchDecision::UpstreamProxy { proxy_url, .. } => {
                assert_eq!(proxy_url, "127.0.0.1:1080");
            }
            other => panic!("Expected UpstreamProxy for chatgpt.com, got {other:?}"),
        }

        // 3. Per-app override for discord.exe -> Desync (fake_disorder + udp_fake=true) even for unknown raw IP UDP
        let d_disc_udp = matcher.evaluate_with_app(
            None,
            "66.22.244.77".parse().unwrap(),
            50005,
            true,
            Some("Discord.exe"),
        );
        match d_disc_udp {
            MatchDecision::Desync {
                config,
                matched_list,
            } => {
                assert_eq!(config.mode, "fake_disorder");
                assert!(config.udp_fake);
                assert!(matched_list.contains("Discord.exe"));
            }
            other => panic!("Expected per-app Desync for Discord.exe, got {other:?}"),
        }

        // 4. Per-app override for steam.exe -> Direct
        let d_steam = matcher.evaluate_with_app(
            Some("www.youtube.com"),
            "142.250.74.110".parse().unwrap(),
            443,
            false,
            Some("steam.exe"),
        );
        assert!(matches!(d_steam, MatchDecision::Direct { .. }));
    }

    #[test]
    fn test_anticheat_and_game_udp_direct_bypass() {
        let lists = default_builtin_lists();
        let matcher = CompiledMatcher::build(&lists, ListStrategy::Auto, DesyncConfig::default());

        // 1. RICOCHET / Call of Duty processes (`bootstrapper.exe`, `cod.exe`) -> Direct
        let d_ricochet = matcher.evaluate_with_app(
            Some("prod.umbrella.demonware.net"),
            "185.34.107.129".parse().unwrap(),
            443,
            false,
            Some("bootstrapper.exe"),
        );
        assert!(matches!(d_ricochet, MatchDecision::Direct { .. }));

        let d_cod = matcher.evaluate_with_app(
            None,
            "185.34.107.129".parse().unwrap(),
            3074,
            true,
            Some("cod.exe"),
        );
        assert!(matches!(d_cod, MatchDecision::Direct { .. }));

        // 2. Demonware / Activision / Battle.net domains -> Direct even if process name is unknown
        let d_demonware = matcher.evaluate_with_app(
            Some("auth.demonware.net"),
            "185.34.107.130".parse().unwrap(),
            443,
            false,
            None,
        );
        assert!(matches!(d_demonware, MatchDecision::Direct { .. }));

        // 3. Unmatched game UDP port (e.g. 3074 / 27015) -> Direct without UDP fake injection
        let d_game_udp =
            matcher.evaluate_with_app(None, "155.133.248.34".parse().unwrap(), 27015, true, None);
        assert!(matches!(d_game_udp, MatchDecision::Direct { .. }));
    }
}
