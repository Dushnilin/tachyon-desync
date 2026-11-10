//! Центральный менеджер состояния, конфигурации, фоновых задач перехвата (`TUN` / `Proxy`)
//! и IPC-команд для графического интерфейса `tachyon-desync`.

use crate::apps::{RunningAppInfo, list_running_apps, normalize_app_name};
use crate::desync::{
    DesyncConfig, DesyncPreset, LearnedDomainView, RecipeProbeResult, RecipeScoreView,
    all_recipe_summaries, attach_persistent_cache, clear_brain_cache, flush_persistent_cache,
    generate_domain_strategy, get_isp_scoreboard, get_learned_domains_snapshot,
    inspect_client_hello_slices, pin_domain_recipe, probe_custom_strategy, remove_learned_domain,
};
use crate::lists::{
    AppFilterMode, CompiledMatcher, ListProfile, ListStrategy, NamedCustomProfile,
    default_builtin_lists, enrich_from_local_tachyon_lists,
};
use crate::proxy::{LogCallback, TrafficCounters, run_local_proxy_server, set_os_system_proxy};
use crate::tun::run_tun_capture;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

const MAX_LOG_ENTRIES: usize = 300;
const MAX_CUSTOM_PROFILES: usize = 64;

/// Режим перехвата сетевого трафика.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Системный виртуальный адаптер TUN (`Wintun` / `/dev/net/tun`) + локальный прокси.
    #[default]
    Tun,
    /// Системный прокси ОС (`127.0.0.1:7897`) без создания сетевого адаптера.
    SystemProxy,
    /// Только локальный прокси `SOCKS5 + HTTP/CONNECT` на `127.0.0.1:7897`.
    LocalProxy,
}

/// Сохраняемая на диск конфигурация приложения (`state.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppStateConfig {
    pub language: String,
    pub minimize_to_tray: bool,
    pub dns_mode: String,
    pub auto_relearn: bool,
    pub upstream_proxy: String,
    pub app_strategies: std::collections::BTreeMap<String, String>,
    pub dns_overrides: std::collections::BTreeMap<String, String>,
    pub capture_mode: CaptureMode,
    pub listen_port: u16,
    pub tun_interface_name: String,
    pub default_strategy: ListStrategy,
    pub custom_global_config: DesyncConfig,
    pub custom_profiles: Vec<NamedCustomProfile>,
    pub app_filter_mode: AppFilterMode,
    pub selected_apps: Vec<String>,
    pub force_desync_selected_apps: bool,
    pub lists: Vec<ListProfile>,
}

impl Default for AppStateConfig {
    fn default() -> Self {
        Self {
            language: "ru".to_string(),
            minimize_to_tray: true,
            dns_mode: "auto".to_string(),
            auto_relearn: true,
            upstream_proxy: String::new(),
            app_strategies: std::collections::BTreeMap::new(),
            dns_overrides: std::collections::BTreeMap::new(),
            capture_mode: CaptureMode::SystemProxy,
            listen_port: 7897,
            tun_interface_name: "TachyonDesync".to_string(),
            default_strategy: ListStrategy::Auto,
            custom_global_config: DesyncConfig::from_preset(DesyncPreset::Auto),
            custom_profiles: Vec::new(),
            app_filter_mode: AppFilterMode::All,
            selected_apps: Vec::new(),
            force_desync_selected_apps: true,
            lists: default_builtin_lists(),
        }
    }
}

/// Запись журнала событий для интерфейса.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts_ms: u64,
    pub level: String,
    pub category: String,
    pub message: String,
}

/// Справочная карточка рецепта для выпадающих списков и генератора стратегий GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeCatalogItem {
    pub id: u8,
    pub code: String,
    pub title: String,
    pub config: DesyncConfig,
}

/// Полный снимок состояния для рендера в GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSnapshot {
    pub running: bool,
    pub is_admin: bool,
    pub active_mode: String,
    pub uptime_sec: u64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub desynced_connections: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub config: AppStateConfig,
    pub running_apps: Vec<RunningAppInfo>,
    pub live_flows: Vec<crate::flows::LiveFlowSnapshot>,
    pub learned_domains: Vec<LearnedDomainView>,
    pub scoreboard: Vec<RecipeScoreView>,
    pub recipes_catalog: Vec<RecipeCatalogItem>,
    pub logs: Vec<LogEntry>,
}

/// Рабочая среда `tachyon-desync`.
pub struct DesyncRuntime {
    data_dir: PathBuf,
    running: AtomicBool,
    stop_flag: Mutex<Arc<AtomicBool>>,
    active_mode_label: RwLock<String>,
    started_at: Mutex<Option<Instant>>,
    config: RwLock<AppStateConfig>,
    matcher: Arc<RwLock<Arc<CompiledMatcher>>>,
    counters: Arc<TrafficCounters>,
    logs: Arc<Mutex<VecDeque<LogEntry>>>,
    cached_running_apps: Mutex<Vec<RunningAppInfo>>,
}

impl DesyncRuntime {
    pub fn new() -> Arc<Self> {
        Self::new_internal(true)
    }

    pub fn new_for_test() -> Arc<Self> {
        Self::new_internal(false)
    }

    fn new_internal(use_persistent_files: bool) -> Arc<Self> {
        let data_dir = if use_persistent_files {
            resolve_app_data_dir()
        } else {
            std::env::temp_dir().join("tachyon-desync-test")
        };
        let _ = std::fs::create_dir_all(&data_dir);

        let state_path = data_dir.join("state.json");
        if use_persistent_files {
            let brain_path = data_dir.join("adaptive_cache.json");
            if let Ok(raw) = std::fs::read_to_string(&brain_path)
                && (raw.contains("googlevideo-fastpath-test.com")
                    || raw.contains("example-circular.org"))
            {
                let _ = std::fs::remove_file(&brain_path);
            }
            attach_persistent_cache(&brain_path);
        }

        let mut cfg: AppStateConfig = if use_persistent_files {
            std::fs::read_to_string(&state_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            AppStateConfig::default()
        };

        // Repair builtin list names/descriptions if an older state.json had broken encoding
        let defaults = default_builtin_lists();
        for item in &mut cfg.lists {
            if item.builtin
                && (item.description.contains("???") || item.name.contains("???"))
                && let Some(def) = defaults.iter().find(|d| d.id == item.id)
            {
                item.name = def.name.clone();
                item.description = def.description.clone();
            }
        }

        crate::upstream_compat::set_clean_dns_mode_from_str(&cfg.dns_mode);
        crate::desync::AUTO_RELEARN_ENABLED.store(cfg.auto_relearn, Ordering::Relaxed);

        let compiled = Arc::new(
            CompiledMatcher::build_full(
                &cfg.lists,
                cfg.default_strategy.clone(),
                cfg.custom_global_config.clone(),
                cfg.app_filter_mode,
                cfg.selected_apps.clone(),
                cfg.force_desync_selected_apps,
                cfg.upstream_proxy.clone(),
                &cfg.app_strategies,
                &cfg.dns_overrides,
            )
            .with_custom_profiles(&cfg.custom_profiles),
        );

        let initial_apps = if use_persistent_files {
            list_running_apps()
        } else {
            Vec::new()
        };

        let rt = Arc::new(Self {
            data_dir,
            running: AtomicBool::new(false),
            stop_flag: Mutex::new(Arc::new(AtomicBool::new(false))),
            active_mode_label: RwLock::new("Остановлен".to_string()),
            started_at: Mutex::new(None),
            config: RwLock::new(cfg),
            matcher: Arc::new(RwLock::new(compiled)),
            counters: Arc::new(TrafficCounters::default()),
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES))),
            cached_running_apps: Mutex::new(initial_apps),
        });

        crate::desync::set_relearn_log_callback(rt.make_log_callback());

        rt.push_log(
            "info",
            "system",
            "Движок десинхронизации Tachyon Desync инициализирован (апстрим tachyon-core, 16 адаптивных рецептов)",
        );
        rt
    }

    /// Быстрое чтение атомарных счётчиков трафика `(rx_bytes, tx_bytes)` для тултипа системного трея.
    pub fn traffic_bytes(&self) -> (u64, u64) {
        (
            self.counters.rx_bytes.load(Ordering::Relaxed),
            self.counters.tx_bytes.load(Ordering::Relaxed),
        )
    }

    pub fn push_log(&self, level: &str, category: &str, message: &str) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut q) = self.logs.lock() {
            if q.len() >= MAX_LOG_ENTRIES {
                q.pop_front();
            }
            q.push_back(LogEntry {
                ts_ms,
                level: level.to_string(),
                category: category.to_string(),
                message: message.to_string(),
            });
        }
    }

    fn make_log_callback(self: &Arc<Self>) -> LogCallback {
        let logs = self.logs.clone();
        Arc::new(move |level: &str, category: &str, message: &str| {
            let ts_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Ok(mut q) = logs.lock() {
                if q.len() >= MAX_LOG_ENTRIES {
                    q.pop_front();
                }
                q.push_back(LogEntry {
                    ts_ms,
                    level: level.to_string(),
                    category: category.to_string(),
                    message: message.to_string(),
                });
            }
        })
    }

    /// Сохранить `state.json` и `adaptive_cache.json` и пересобрать `CompiledMatcher`.
    pub async fn persist_and_recompile(&self) {
        let cfg = self.config.read().await.clone();
        crate::upstream_compat::set_clean_dns_mode_from_str(&cfg.dns_mode);
        crate::desync::AUTO_RELEARN_ENABLED.store(cfg.auto_relearn, Ordering::Relaxed);

        let compiled = Arc::new(
            CompiledMatcher::build_full(
                &cfg.lists,
                cfg.default_strategy.clone(),
                cfg.custom_global_config.clone(),
                cfg.app_filter_mode,
                cfg.selected_apps.clone(),
                cfg.force_desync_selected_apps,
                cfg.upstream_proxy.clone(),
                &cfg.app_strategies,
                &cfg.dns_overrides,
            )
            .with_custom_profiles(&cfg.custom_profiles),
        );
        *self.matcher.write().await = compiled;

        if let Ok(json) = serde_json::to_string_pretty(&cfg) {
            let _ = std::fs::write(self.data_dir.join("state.json"), json);
        }
        flush_persistent_cache();
    }

    /// Запустить перехват и десинхронизацию трафика.
    pub async fn start(self: &Arc<Self>) -> io::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        if let Ok(mut g) = self.stop_flag.lock() {
            *g = stop.clone();
        }
        if let Ok(mut st) = self.started_at.lock() {
            *st = Some(Instant::now());
        }

        let cfg = self.config.read().await.clone();
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), cfg.listen_port);
        let matcher_proxy = self.matcher.clone();
        let counters_proxy = self.counters.clone();
        let log_proxy = self.make_log_callback();
        let stop_proxy = stop.clone();

        tokio::spawn(async move {
            if let Err(e) = run_local_proxy_server(
                listen_addr,
                matcher_proxy,
                counters_proxy,
                log_proxy.clone(),
                stop_proxy,
            )
            .await
            {
                (log_proxy)(
                    "error",
                    "proxy",
                    &format!("Ошибка локального прокси {listen_addr}: {e}"),
                );
            }
        });

        match cfg.capture_mode {
            CaptureMode::Tun => {
                *self.active_mode_label.write().await = format!(
                    "TUN ({}) + SOCKS5/HTTP :{}",
                    cfg.tun_interface_name, cfg.listen_port
                );
                let iface_name = cfg.tun_interface_name.clone();
                let matcher_tun = self.matcher.clone();
                let counters_tun = self.counters.clone();
                let log_tun = self.make_log_callback();
                let stop_tun = stop.clone();
                let rt_clone = self.clone();
                let port = cfg.listen_port;

                tokio::spawn(async move {
                    if let Err(e) = run_tun_capture(
                        &iface_name,
                        matcher_tun,
                        counters_tun,
                        log_tun.clone(),
                        stop_tun,
                    )
                    .await
                    {
                        (log_tun)(
                            "warn",
                            "tun",
                            &format!(
                                "Не удалось поднять TUN «{iface_name}» ({e}). Активирован системный прокси 127.0.0.1:{port}"
                            ),
                        );
                        let _ = set_os_system_proxy(true, port);
                        *rt_clone.active_mode_label.write().await =
                            format!("Системный прокси 127.0.0.1:{port} (фоллбэк без прав админа)");
                    }
                });
            }
            CaptureMode::SystemProxy => {
                let _ = set_os_system_proxy(true, cfg.listen_port);
                *self.active_mode_label.write().await =
                    format!("Системный прокси 127.0.0.1:{}", cfg.listen_port);
                self.push_log(
                    "info",
                    "system",
                    &format!(
                        "Системный прокси ОС направлен на 127.0.0.1:{}",
                        cfg.listen_port
                    ),
                );
            }
            CaptureMode::LocalProxy => {
                *self.active_mode_label.write().await =
                    format!("Локальный прокси 127.0.0.1:{}", cfg.listen_port);
                self.push_log(
                    "info",
                    "system",
                    &format!(
                        "Активен локальный прокси SOCKS5/HTTP на 127.0.0.1:{}",
                        cfg.listen_port
                    ),
                );
            }
        }

        Ok(())
    }

    /// Остановить перехват трафика и очистить системные настройки прокси/TUN.
    pub async fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Ok(g) = self.stop_flag.lock() {
            g.store(true, Ordering::SeqCst);
        }
        if let Ok(mut st) = self.started_at.lock() {
            *st = None;
        }
        let port = self.config.read().await.listen_port;
        let _ = set_os_system_proxy(false, port);
        *self.active_mode_label.write().await = "Остановлен".to_string();
        flush_persistent_cache();
        self.push_log("info", "system", "Десинхронизация остановлена");
    }

    /// Синхронная очистка при закрытии окна / выходе из программы.
    pub fn shutdown_sync(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(g) = self.stop_flag.lock() {
            g.store(true, Ordering::SeqCst);
        }
        let _ = set_os_system_proxy(false, 7897);
        flush_persistent_cache();
    }

    /// Собрать полный снимок состояния для GUI.
    pub async fn snapshot(&self) -> UiSnapshot {
        let running = self.running.load(Ordering::Relaxed);
        let active_mode = self.active_mode_label.read().await.clone();
        let uptime_sec = self
            .started_at
            .lock()
            .ok()
            .and_then(|g| g.map(|t| t.elapsed().as_secs()))
            .unwrap_or(0);
        let config = self.config.read().await.clone();
        let logs = self
            .logs
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default();
        let recipes_catalog = all_recipe_summaries()
            .iter()
            .map(|r| RecipeCatalogItem {
                id: r.id,
                code: r.code.to_string(),
                title: r.title.to_string(),
                config: DesyncConfig::from_recipe_id(r.id),
            })
            .collect();

        let running_apps = self
            .cached_running_apps
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();

        UiSnapshot {
            running,
            is_admin: crate::tray::is_running_as_admin(),
            active_mode,
            uptime_sec,
            active_connections: self.counters.active_connections.load(Ordering::Relaxed),
            total_connections: self.counters.total_connections.load(Ordering::Relaxed),
            desynced_connections: self.counters.desynced_connections.load(Ordering::Relaxed),
            tx_bytes: self.counters.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.counters.rx_bytes.load(Ordering::Relaxed),
            config,
            running_apps,
            live_flows: crate::flows::snapshot_flows(),
            learned_domains: get_learned_domains_snapshot(),
            scoreboard: get_isp_scoreboard(),
            recipes_catalog,
            logs,
        }
    }

    /// Обработать JSON-команду из GUI и вернуть JSON-ответ.
    pub async fn handle_ipc_action(
        self: &Arc<Self>,
        action: &str,
        payload: serde_json::Value,
    ) -> serde_json::Value {
        match action {
            "get_state" | "get_snapshot" => {
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_language" => {
                if let Some(lang) = payload.get("language").and_then(|v| v.as_str()) {
                    let normalized = if lang.eq_ignore_ascii_case("en") {
                        "en"
                    } else {
                        "ru"
                    };
                    self.config.write().await.language = normalized.to_string();
                    self.persist_and_recompile().await;
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_minimize_to_tray" => {
                if let Some(val) = payload.get("minimize_to_tray").and_then(|v| v.as_bool()) {
                    self.config.write().await.minimize_to_tray = val;
                    self.persist_and_recompile().await;
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_dns_mode" => {
                if let Some(m) = payload.get("dns_mode").and_then(|v| v.as_str()) {
                    let norm = m.trim().to_ascii_lowercase();
                    crate::upstream_compat::set_clean_dns_mode_from_str(&norm);
                    self.config.write().await.dns_mode = norm.clone();
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "dns",
                        &format!("Режим чистого DNS-резолвера переключён на «{norm}»"),
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_auto_relearn" => {
                if let Some(en) = payload.get("enabled").and_then(|v| v.as_bool()) {
                    crate::desync::AUTO_RELEARN_ENABLED.store(en, Ordering::Relaxed);
                    self.config.write().await.auto_relearn = en;
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "adaptive",
                        if en {
                            "Авто-переобучение доменов при сбоях (TCP RST / таймаут) включено"
                        } else {
                            "Авто-переобучение доменов при сбоях отключено"
                        },
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_upstream_proxy" => {
                if let Some(p) = payload.get("upstream_proxy").and_then(|v| v.as_str()) {
                    let clean = p.trim().to_string();
                    self.config.write().await.upstream_proxy = clean.clone();
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "proxy",
                        if clean.is_empty() {
                            "Внешний прокси для списков отключён"
                        } else {
                            "Адрес внешнего прокси для списков обновлён"
                        },
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_app_strategy" => {
                if let (Some(raw_app), Some(strat)) = (
                    payload.get("app").and_then(|v| v.as_str()),
                    payload.get("strategy").and_then(|v| v.as_str()),
                ) {
                    let norm_app = normalize_app_name(raw_app);
                    if !norm_app.is_empty() {
                        let s_clean = strat.trim().to_ascii_lowercase();
                        let mut cfg = self.config.write().await;
                        if s_clean.is_empty() || s_clean == "default" {
                            cfg.app_strategies.remove(&norm_app);
                        } else {
                            cfg.app_strategies.insert(norm_app.clone(), s_clean.clone());
                        }
                        drop(cfg);
                        self.persist_and_recompile().await;
                        self.push_log(
                            "info",
                            "apps",
                            &format!("Индивидуальная стратегия для {norm_app}: {s_clean}"),
                        );
                    }
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_dns_overrides_text" => {
                if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
                    let mut map = std::collections::BTreeMap::new();
                    for raw_line in text.lines() {
                        let line = raw_line.split('#').next().unwrap_or("").trim();
                        if line.is_empty() {
                            continue;
                        }
                        let pair = line
                            .split_once('=')
                            .or_else(|| line.split_once(char::is_whitespace));
                        if let Some((a, b)) = pair {
                            let a_t = a.trim().to_ascii_lowercase();
                            let b_t = b.trim().to_ascii_lowercase();
                            // Поддержка как "домен=IP", так и стандартного hosts-формата "IP домен"
                            if a_t.parse::<IpAddr>().is_ok() && !b_t.is_empty() {
                                map.insert(b_t, a_t);
                            } else if b_t.parse::<IpAddr>().is_ok() && !a_t.is_empty() {
                                map.insert(a_t, b_t);
                            }
                        }
                    }
                    let count = map.len();
                    self.config.write().await.dns_overrides = map;
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "dns",
                        &format!("Сохранено пользовательских DNS-переопределений (hosts): {count}"),
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "apply_calibrated_ttl" => {
                if let Some(ttl_u64) = payload.get("ttl").and_then(|v| v.as_u64()) {
                    let ttl = (ttl_u64 as u8).clamp(1, 64);
                    {
                        let mut cfg = self.config.write().await;
                        cfg.custom_global_config.fake_ttl = ttl;
                        cfg.custom_global_config.udp_fake_ttl = ttl;
                    }
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "config",
                        &format!("Применён откалиброванный TTL = {ttl} для TCP/UDP фейков"),
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "toggle_domain_bypass" => {
                if let Some(raw_host) = payload.get("host").and_then(|v| v.as_str()) {
                    let host = raw_host
                        .trim()
                        .trim_end_matches('.')
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if !host.is_empty() && host != "-" {
                        let mut cfg = self.config.write().await;
                        let bypass_idx = if let Some(idx) =
                            cfg.lists.iter().position(|l| l.id == "direct_bypass")
                        {
                            idx
                        } else {
                            cfg.lists.insert(
                                0,
                                ListProfile {
                                    id: "direct_bypass".to_string(),
                                    name: "Исключения (Прямое)".to_string(),
                                    description: "Домены и IP, идущие напрямую без десинхронизации"
                                        .to_string(),
                                    builtin: false,
                                    enabled: true,
                                    strategy: ListStrategy::Direct,
                                    block_quic: false,
                                    udp_fake: false,
                                    entries: Vec::new(),
                                },
                            );
                            0
                        };
                        cfg.lists[bypass_idx].enabled = true;
                        cfg.lists[bypass_idx].strategy = ListStrategy::Direct;
                        let added = if let Some(pos) = cfg.lists[bypass_idx]
                            .entries
                            .iter()
                            .position(|e| e.eq_ignore_ascii_case(&host))
                        {
                            cfg.lists[bypass_idx].entries.remove(pos);
                            false
                        } else {
                            cfg.lists[bypass_idx].entries.push(host.clone());
                            true
                        };
                        drop(cfg);
                        self.persist_and_recompile().await;
                        if added {
                            self.push_log(
                                "info",
                                "lists",
                                &format!("Домен {host} добавлен в исключения (Прямое)"),
                            );
                        } else {
                            self.push_log(
                                "info",
                                "lists",
                                &format!("Домен {host} удалён из исключений"),
                            );
                        }
                    }
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "import_backup_json" => {
                if let Some(raw) = payload.get("json").and_then(|v| v.as_str())
                    && let Ok(imported) = serde_json::from_str::<AppStateConfig>(raw)
                {
                    crate::upstream_compat::set_clean_dns_mode_from_str(&imported.dns_mode);
                    *self.config.write().await = imported;
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "config",
                        "Профиль настроек успешно импортирован из JSON",
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "clear_flows" => {
                crate::flows::clear_finished_flows();
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "toggle_running" => {
                if self.running.load(Ordering::Relaxed) {
                    self.stop().await;
                } else {
                    let _ = self.start().await;
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "start_service" => {
                let _ = self.start().await;
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "stop_service" => {
                self.stop().await;
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_capture_mode" => {
                if let Some(m) = payload
                    .get("capture_mode")
                    .or_else(|| payload.get("mode"))
                    .and_then(|v| v.as_str())
                {
                    let mode = match m {
                        "tun" => CaptureMode::Tun,
                        "local_proxy" => CaptureMode::LocalProxy,
                        _ => CaptureMode::SystemProxy,
                    };
                    let was_running = self.running.load(Ordering::Relaxed);
                    if was_running {
                        self.stop().await;
                    }
                    self.config.write().await.capture_mode = mode;
                    if let Some(p) = payload.get("listen_port").and_then(|v| v.as_u64())
                        && (1024..=65535).contains(&p)
                    {
                        self.config.write().await.listen_port = p as u16;
                    }
                    self.persist_and_recompile().await;
                    if was_running {
                        let _ = self.start().await;
                    }
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "set_default_strategy" => {
                if let Some(code) = payload.get("strategy").and_then(|v| v.as_str()) {
                    self.config.write().await.default_strategy = ListStrategy::from_code(code);
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "config",
                        &format!("Политика по умолчанию изменена на «{code}»"),
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "update_list" => {
                if let Some(id) = payload.get("id").and_then(|v| v.as_str()) {
                    let mut cfg = self.config.write().await;
                    if let Some(list) = cfg.lists.iter_mut().find(|l| l.id == id) {
                        if let Some(en) = payload.get("enabled").and_then(|v| v.as_bool()) {
                            list.enabled = en;
                        }
                        if let Some(st) = payload.get("strategy").and_then(|v| v.as_str()) {
                            list.strategy = ListStrategy::from_code(st);
                        }
                        if let Some(bq) = payload.get("block_quic").and_then(|v| v.as_bool()) {
                            list.block_quic = bq;
                        }
                        if let Some(uf) = payload.get("udp_fake").and_then(|v| v.as_bool()) {
                            list.udp_fake = uf;
                        }
                        if let Some(name) = payload.get("name").and_then(|v| v.as_str())
                            && !name.trim().is_empty()
                        {
                            list.name = name.trim().to_string();
                        }
                        if let Some(entries_text) =
                            payload.get("entries_text").and_then(|v| v.as_str())
                        {
                            list.entries = entries_text
                                .lines()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                        }
                    }
                    drop(cfg);
                    self.persist_and_recompile().await;
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "create_custom_list" => {
                let name = payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Пользовательский список")
                    .trim()
                    .to_string();
                let description = payload
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Пользовательские домены и подсети")
                    .trim()
                    .to_string();
                let strategy_str = payload
                    .get("strategy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto");
                let entries_text = payload
                    .get("entries_text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let entries: Vec<String> = entries_text
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();

                let id = format!(
                    "custom_{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(1)
                );
                self.config.write().await.lists.insert(
                    0,
                    ListProfile {
                        id,
                        name: name.clone(),
                        description,
                        builtin: false,
                        enabled: true,
                        strategy: ListStrategy::from_code(strategy_str),
                        block_quic: true,
                        udp_fake: true,
                        entries,
                    },
                );
                self.persist_and_recompile().await;
                self.push_log("info", "lists", &format!("Создан список «{name}»"));
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "delete_custom_list" => {
                if let Some(id) = payload.get("id").and_then(|v| v.as_str()) {
                    self.config
                        .write()
                        .await
                        .lists
                        .retain(|l| l.builtin || l.id != id);
                    self.persist_and_recompile().await;
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "sync_tachyon_lists" => {
                let mut cfg = self.config.write().await;
                let added = enrich_from_local_tachyon_lists(&mut cfg.lists);
                drop(cfg);
                self.persist_and_recompile().await;
                self.push_log(
                    "info",
                    "lists",
                    &format!(
                        "Синхронизация со списками tachyon-lists завершена (+{added} доменов)"
                    ),
                );
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "update_app_filter" => {
                let mut cfg = self.config.write().await;
                if let Some(mode_str) = payload.get("app_filter_mode").and_then(|v| v.as_str()) {
                    cfg.app_filter_mode = AppFilterMode::from_code(mode_str);
                }
                if let Some(force) = payload
                    .get("force_desync_selected_apps")
                    .and_then(|v| v.as_bool())
                {
                    cfg.force_desync_selected_apps = force;
                }
                if let Some(arr) = payload.get("selected_apps").and_then(|v| v.as_array()) {
                    let mut clean = Vec::new();
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let norm = normalize_app_name(s);
                            if !norm.is_empty() && !clean.contains(&norm) {
                                clean.push(norm);
                            }
                        }
                    }
                    cfg.selected_apps = clean;
                } else if let Some(text) =
                    payload.get("selected_apps_text").and_then(|v| v.as_str())
                {
                    let mut clean = Vec::new();
                    for part in text.split(['\n', ',', ';']) {
                        let norm = normalize_app_name(part);
                        if !norm.is_empty() && !clean.contains(&norm) {
                            clean.push(norm);
                        }
                    }
                    cfg.selected_apps = clean;
                }
                let mode_label = match cfg.app_filter_mode {
                    AppFilterMode::All => "Все приложения",
                    AppFilterMode::Include => "Только выбранные приложения",
                    AppFilterMode::Exclude => "Исключить выбранные приложения",
                };
                let count = cfg.selected_apps.len();
                drop(cfg);
                self.persist_and_recompile().await;
                self.push_log(
                    "info",
                    "apps",
                    &format!("Фильтр приложений: {mode_label} (выбрано: {count})"),
                );
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "toggle_app" => {
                if let Some(raw_app) = payload.get("app").and_then(|v| v.as_str()) {
                    let add_only = payload
                        .get("add_only")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let norm = normalize_app_name(raw_app);
                    if !norm.is_empty() {
                        let mut cfg = self.config.write().await;
                        if let Some(pos) = cfg.selected_apps.iter().position(|x| x == &norm) {
                            if !add_only {
                                cfg.selected_apps.remove(pos);
                                if cfg.selected_apps.is_empty()
                                    && cfg.app_filter_mode == AppFilterMode::Include
                                {
                                    cfg.app_filter_mode = AppFilterMode::All;
                                }
                            }
                        } else {
                            cfg.selected_apps.push(norm.clone());
                            if cfg.app_filter_mode == AppFilterMode::All {
                                cfg.app_filter_mode = AppFilterMode::Include;
                            }
                        }
                        drop(cfg);
                        self.persist_and_recompile().await;
                        self.push_log(
                            "info",
                            "apps",
                            &format!("Обновлён выбор приложения: {norm}"),
                        );
                    }
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "scan_running_apps" => {
                let apps = list_running_apps();
                if let Ok(mut guard) = self.cached_running_apps.lock() {
                    *guard = apps;
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "update_global_desync" => {
                if let Ok(new_desync) = serde_json::from_value::<DesyncConfig>(payload) {
                    self.config.write().await.custom_global_config = new_desync;
                    self.persist_and_recompile().await;
                    self.push_log(
                        "info",
                        "config",
                        "Глобальные параметры десинхронизатора сохранены",
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "save_custom_profile" => {
                let custom_cfg = payload
                    .get("config")
                    .cloned()
                    .and_then(|v| serde_json::from_value::<DesyncConfig>(v).ok());
                if let Some(config) = custom_cfg {
                    let mut cfg = self.config.write().await;
                    let req_id = payload
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_lowercase())
                        .unwrap_or_default();
                    let raw_name = payload
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .unwrap_or_default();
                    let next_num = cfg.custom_profiles.len() + 1;
                    let name = if raw_name.is_empty() {
                        format!("Профиль #{next_num}")
                    } else {
                        raw_name.chars().take(48).collect::<String>()
                    };

                    let existing_idx = cfg.custom_profiles.iter().position(|p| {
                        (!req_id.is_empty() && p.id.eq_ignore_ascii_case(&req_id))
                            || p.name.to_lowercase() == name.to_lowercase()
                    });

                    let mut saved_ok = true;
                    if let Some(idx) = existing_idx {
                        cfg.custom_profiles[idx].name = name.clone();
                        cfg.custom_profiles[idx].config = config;
                    } else if cfg.custom_profiles.len() >= MAX_CUSTOM_PROFILES {
                        saved_ok = false;
                    } else {
                        let base_ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(1);
                        let mut id = if !req_id.is_empty() {
                            req_id
                        } else {
                            format!("p_{base_ts}")
                        };
                        while cfg
                            .custom_profiles
                            .iter()
                            .any(|p| p.id.eq_ignore_ascii_case(&id))
                        {
                            id.push('x');
                        }
                        cfg.custom_profiles.push(NamedCustomProfile {
                            id,
                            name: name.clone(),
                            config,
                        });
                    }
                    drop(cfg);
                    if saved_ok {
                        self.persist_and_recompile().await;
                        self.push_log(
                            "info",
                            "config",
                            &format!("Сохранён профиль стратегии «{name}»"),
                        );
                    } else {
                        self.push_log(
                            "warn",
                            "config",
                            "Достигнут предел сохранённых профилей (64)",
                        );
                    }
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "delete_custom_profile" => {
                if let Some(raw_id) = payload.get("id").and_then(|v| v.as_str()) {
                    let norm_id = raw_id.trim().to_lowercase();
                    if !norm_id.is_empty() {
                        let mut cfg = self.config.write().await;
                        let mut removed_name = None;
                        cfg.custom_profiles.retain(|p| {
                            if p.id.to_lowercase() == norm_id {
                                removed_name = Some(p.name.clone());
                                false
                            } else {
                                true
                            }
                        });
                        if let ListStrategy::CustomProfile(ref pid) = cfg.default_strategy
                            && pid == &norm_id
                        {
                            cfg.default_strategy = ListStrategy::Auto;
                        }
                        for list in &mut cfg.lists {
                            if let ListStrategy::CustomProfile(ref pid) = list.strategy
                                && pid == &norm_id
                            {
                                list.strategy = ListStrategy::Auto;
                            }
                        }
                        for strat_val in cfg.app_strategies.values_mut() {
                            if let ListStrategy::CustomProfile(pid) =
                                ListStrategy::from_code(strat_val)
                                && pid == norm_id
                            {
                                *strat_val = "auto".to_string();
                            }
                        }
                        drop(cfg);
                        if let Some(name) = removed_name {
                            self.persist_and_recompile().await;
                            self.push_log(
                                "info",
                                "config",
                                &format!("Удалён профиль стратегии «{name}»"),
                            );
                        }
                    }
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "pin_domain_recipe" => {
                if let (Some(host), Some(rid)) = (
                    payload.get("host").and_then(|v| v.as_str()),
                    payload.get("recipe_id").and_then(|v| v.as_u64()),
                ) {
                    pin_domain_recipe(host, rid as u8);
                    flush_persistent_cache();
                    self.push_log(
                        "info",
                        "adaptive",
                        &format!("Для домена {host} закреплён рецепт #{rid}"),
                    );
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "remove_learned_domain" => {
                if let Some(host) = payload.get("host").and_then(|v| v.as_str()) {
                    remove_learned_domain(host);
                    flush_persistent_cache();
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "clear_brain" | "clear_brain_cache" | "clear_learned" => {
                clear_brain_cache();
                flush_persistent_cache();
                self.push_log("info", "adaptive", "Кэш адаптивного подбора очищен");
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "clear_logs" => {
                if let Ok(mut q) = self.logs.lock() {
                    q.clear();
                }
                serde_json::to_value(self.snapshot().await).unwrap_or_default()
            }
            "probe_domain" | "generate_strategy" => {
                let domain = payload
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("www.youtube.com");
                let port = payload.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
                let scan_all = payload
                    .get("scan_all")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(action == "generate_strategy");
                let apply_global = payload
                    .get("apply_global")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.push_log(
                    "info",
                    "probe",
                    &format!(
                        "Запущена генерация стратегии ({} рецептов) для {domain}:{port}...",
                        if scan_all { 16 } else { 8 }
                    ),
                );
                match generate_domain_strategy(domain, port, scan_all, 1800).await {
                    Ok(report) => {
                        if apply_global {
                            self.config.write().await.custom_global_config =
                                report.recommended_config.clone();
                            self.persist_and_recompile().await;
                        } else {
                            flush_persistent_cache();
                        }
                        self.push_log("info", "probe", &report.diagnosis);
                        serde_json::json!({
                            "ok": true,
                            "domain": report.domain,
                            "resolved_ip": report.resolved_ip,
                            "packet_preview": report.packet_preview,
                            "results": report.results,
                            "passed_count": report.passed_count,
                            "total_tested": report.total_tested,
                            "best_recipe_id": report.best_recipe_id,
                            "recommended_config": report.recommended_config,
                            "diagnosis": report.diagnosis,
                            "core_outbound_json": report.core_outbound_json,
                            "state": self.snapshot().await,
                        })
                    }
                    Err(e) => {
                        self.push_log("warn", "probe", &format!("Ошибка генератора {domain}: {e}"));
                        serde_json::json!({
                            "ok": false,
                            "error": e.to_string(),
                            "results": Vec::<RecipeProbeResult>::new(),
                        })
                    }
                }
            }
            "probe_custom_strategy" => {
                let domain = payload
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("www.youtube.com");
                let port = payload.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
                let custom_cfg = payload
                    .get("config")
                    .cloned()
                    .and_then(|v| serde_json::from_value::<DesyncConfig>(v).ok())
                    .unwrap_or_else(|| {
                        serde_json::from_value::<DesyncConfig>(payload.clone()).unwrap_or_default()
                    });
                self.push_log(
                    "info",
                    "probe",
                    &format!(
                        "Тест конструктора ({} + {}, split={}) на {domain}:{port}...",
                        custom_cfg.mode, custom_cfg.fooling, custom_cfg.split_pos
                    ),
                );
                match probe_custom_strategy(domain, port, &custom_cfg, 1800).await {
                    Ok(report) => {
                        self.push_log("info", "probe", &report.diagnosis);
                        serde_json::json!({
                            "ok": report.passed_count > 0,
                            "domain": report.domain,
                            "resolved_ip": report.resolved_ip,
                            "packet_preview": report.packet_preview,
                            "results": report.results,
                            "recommended_config": report.recommended_config,
                            "diagnosis": report.diagnosis,
                            "core_outbound_json": report.core_outbound_json,
                            "state": self.snapshot().await,
                        })
                    }
                    Err(e) => {
                        self.push_log("warn", "probe", &format!("Ошибка теста конструктора: {e}"));
                        serde_json::json!({
                            "ok": false,
                            "error": e.to_string(),
                            "results": Vec::<RecipeProbeResult>::new(),
                        })
                    }
                }
            }
            "inspect_packet" => {
                let domain = payload
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("www.youtube.com");
                let custom_cfg = payload
                    .get("config")
                    .cloned()
                    .and_then(|v| serde_json::from_value::<DesyncConfig>(v).ok());
                let preview = inspect_client_hello_slices(domain);
                let outbound_json = custom_cfg.map(|c| c.to_core_outbound_json());
                serde_json::json!({
                    "ok": true,
                    "packet_preview": preview,
                    "core_outbound_json": outbound_json,
                })
            }
            _ => serde_json::json!({ "error": format!("Неизвестная команда: {action}") }),
        }
    }
}

impl Drop for DesyncRuntime {
    fn drop(&mut self) {
        if self.running.swap(false, Ordering::Relaxed) {
            if let Ok(flag) = self.stop_flag.lock() {
                flag.store(true, Ordering::Relaxed);
            }
            let _ = set_os_system_proxy(false, 7897);
            flush_persistent_cache();
        }
    }
}

fn resolve_app_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA").or_else(|_| std::env::var("APPDATA")) {
            return PathBuf::from(appdata).join("TachyonDesync");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("tachyon-desync");
    }
    std::env::temp_dir().join("tachyon-desync")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_start_stop_and_serialization() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let app = DesyncRuntime::new_for_test();
            let s0 = app
                .handle_ipc_action("get_state", serde_json::json!({}))
                .await;
            assert_eq!(s0.get("running").and_then(|v| v.as_bool()), Some(false));
            // Проверяем, что стратегия списка сериализуется в плоскую строку
            let first_strat = s0
                .pointer("/config/lists/0/strategy")
                .and_then(|v| v.as_str());
            assert!(first_strat.is_some());

            // Переключаем в LocalProxy, чтобы тест не менял системный прокси машины
            let s_mode = app
                .handle_ipc_action(
                    "set_capture_mode",
                    serde_json::json!({ "mode": "local_proxy", "listen_port": 17899 }),
                )
                .await;
            assert_eq!(
                s_mode
                    .pointer("/config/capture_mode")
                    .and_then(|v| v.as_str()),
                Some("local_proxy")
            );

            // Запускаем через toggle_running
            let s1 = app
                .handle_ipc_action("toggle_running", serde_json::json!({}))
                .await;
            assert_eq!(s1.get("running").and_then(|v| v.as_bool()), Some(true));

            // Останавливаем через stop_service и возвращаем штатный режим system_proxy:7897
            let s2 = app
                .handle_ipc_action("stop_service", serde_json::json!({}))
                .await;
            assert_eq!(s2.get("running").and_then(|v| v.as_bool()), Some(false));
            let _ = app
                .handle_ipc_action(
                    "set_capture_mode",
                    serde_json::json!({ "mode": "system_proxy", "listen_port": 7897 }),
                )
                .await;
        });
    }

    #[test]
    fn test_ipc_save_and_delete_custom_profiles_with_fallback() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let app = DesyncRuntime::new_for_test();
            let mut c1 = DesyncConfig::from_preset(DesyncPreset::FakeSplit);
            c1.fake_ttl = 5;
            let mut c2 = DesyncConfig::from_preset(DesyncPreset::FakeDisorder);
            c2.fake_ttl = 4;

            let _ = app
                .handle_ipc_action(
                    "save_custom_profile",
                    serde_json::json!({ "id": "p_yt", "name": "YT Custom", "config": c1 }),
                )
                .await;
            let s = app
                .handle_ipc_action(
                    "save_custom_profile",
                    serde_json::json!({ "id": "p_dc", "name": "Discord TTL4", "config": c2 }),
                )
                .await;
            assert_eq!(
                s.pointer("/config/custom_profiles")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len()),
                Some(2)
            );

            // Назначаем p_yt списку youtube и p_dc маршруту по умолчанию
            let _ = app
                .handle_ipc_action(
                    "update_list",
                    serde_json::json!({ "id": "youtube", "strategy": "profile:p_yt" }),
                )
                .await;
            let _ = app
                .handle_ipc_action(
                    "set_default_strategy",
                    serde_json::json!({ "strategy": "profile:p_dc" }),
                )
                .await;

            // Удаляем p_dc -> default_strategy сбрасывается обратно на auto, а p_yt остаётся
            let s_del = app
                .handle_ipc_action("delete_custom_profile", serde_json::json!({ "id": "p_dc" }))
                .await;
            assert_eq!(
                s_del
                    .pointer("/config/default_strategy")
                    .and_then(|v| v.as_str()),
                Some("auto")
            );
            let yt_strat = s_del
                .pointer("/config/lists")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find(|x| x.get("id").and_then(|i| i.as_str()) == Some("youtube"))
                })
                .and_then(|x| x.get("strategy"))
                .and_then(|v| v.as_str());
            assert_eq!(yt_strat, Some("profile:p_yt"));
        });
    }
}
