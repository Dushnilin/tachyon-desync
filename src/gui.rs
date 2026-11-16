//! Нативный аппаратно-ускоренный графический интерфейс `Tachyon Desync` (GPU / `eframe` + `egui`).
//!
//! Работает напрямую поверх видеокарты (OpenGL / `glow`) в строгой миниатюрной теме GPUI / Zed Dark
//! без использования WebView2, браузерных процессов и локального HTTP-сервера.

use crate::desync::{
    AutoTtlReport, DesyncConfig, PacketSlicePreview, ServiceHealthItem, StrategyGeneratorReport,
    calibrate_optimal_ttl, generate_domain_strategy_with_options, inspect_client_hello_slices,
    probe_custom_strategy_with_options, run_services_health_check, white_sni_pool,
};
use crate::dns_resolver::{
    DnsBenchmarkState, DnsIpStrategy, DnsProtocol, DnsRecommendation, DnsSettings,
    DnsSpeedTestState, DnsUpstreamMode, bootstrap_presets, default_speed_test_domains,
    estimate_cache_ram_kb, presets_for_protocol, run_dns_benchmark, run_dns_speed_test,
    validate_dns_server_entry,
};
use crate::lists::AppFilterMode;
use crate::runtime::{CaptureMode, DesyncRuntime, UiSnapshot};
use crate::upstream_compat::{NetworkTuningConfig, TcpCongestionMode, TunBufferMode, hardware};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontFamily, FontId, Frame, Id, Key, Layout, Margin, Pos2,
    Rect, RichText, ScrollArea, Sense, Stroke, StrokeKind, TextEdit, TextStyle, Vec2,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HISTORY_LEN: usize = 60;

// Строгая графитовая шкала нейтралей (Graphite Dark Ramp — без цветного тумана на поверхностях)
const BG_DEEPEST: Color32 = Color32::from_rgb(15, 15, 16);
const BG_CANVAS: Color32 = Color32::from_rgb(20, 20, 21);
const BG_PANEL: Color32 = Color32::from_rgb(25, 25, 27);
const BG_ELEVATED: Color32 = Color32::from_rgb(35, 35, 37);
const BG_HOVER: Color32 = Color32::from_rgb(45, 45, 48);
const BORDER_SUBTLE: Color32 = Color32::from_rgb(38, 38, 41);
const BORDER_STRONG: Color32 = Color32::from_rgb(62, 62, 68);

// Три роли текста (Primary / Secondary / Muted)
const TEXT_PRIMARY: Color32 = Color32::from_rgb(237, 237, 237);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(161, 161, 166);
const TEXT_MUTED: Color32 = Color32::from_rgb(133, 133, 139);

// Единый инструментальный акцент и приглушённые семантические статусы
const ACCENT: Color32 = Color32::from_rgb(56, 189, 248);
const SEMANTIC_OK: Color32 = Color32::from_rgb(76, 195, 138);
const SEMANTIC_WARN: Color32 = Color32::from_rgb(217, 155, 38);
const SEMANTIC_ERR: Color32 = Color32::from_rgb(229, 72, 77);

static ACTIVE_THEME_ID: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuiThemePreset {
    Graphite = 0,
    AyuDark = 1,
    TokyoNight = 2,
    Catppuccin = 3,
    Gruvbox = 4,
}

#[derive(Debug, Clone, Copy)]
struct ThemeTokens {
    bg_deepest: Color32,
    bg_canvas: Color32,
    bg_panel: Color32,
    bg_elevated: Color32,
    bg_hover: Color32,
    border_subtle: Color32,
    border_strong: Color32,
    accent: Color32,
}

impl GpuiThemePreset {
    pub const ALL: [Self; 5] = [
        Self::Graphite,
        Self::AyuDark,
        Self::TokyoNight,
        Self::Catppuccin,
        Self::Gruvbox,
    ];

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::AyuDark,
            2 => Self::TokyoNight,
            3 => Self::Catppuccin,
            4 => Self::Gruvbox,
            _ => Self::Graphite,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Graphite => "Graphite",
            Self::AyuDark => "Ayu Dark",
            Self::TokyoNight => "TokyoNight",
            Self::Catppuccin => "Catppuccin",
            Self::Gruvbox => "Gruvbox",
        }
    }

    fn tokens(self) -> ThemeTokens {
        match self {
            Self::Graphite => ThemeTokens {
                bg_deepest: BG_DEEPEST,
                bg_canvas: BG_CANVAS,
                bg_panel: BG_PANEL,
                bg_elevated: BG_ELEVATED,
                bg_hover: BG_HOVER,
                border_subtle: BORDER_SUBTLE,
                border_strong: BORDER_STRONG,
                accent: ACCENT,
            },
            Self::AyuDark => ThemeTokens {
                bg_deepest: Color32::from_rgb(11, 14, 20),
                bg_canvas: Color32::from_rgb(15, 19, 26),
                bg_panel: Color32::from_rgb(19, 23, 33),
                bg_elevated: Color32::from_rgb(26, 31, 44),
                bg_hover: Color32::from_rgb(35, 42, 58),
                border_subtle: Color32::from_rgb(30, 36, 50),
                border_strong: Color32::from_rgb(52, 62, 82),
                accent: Color32::from_rgb(57, 186, 230),
            },
            Self::TokyoNight => ThemeTokens {
                bg_deepest: Color32::from_rgb(22, 22, 30),
                bg_canvas: Color32::from_rgb(26, 27, 38),
                bg_panel: Color32::from_rgb(31, 35, 53),
                bg_elevated: Color32::from_rgb(36, 40, 59),
                bg_hover: Color32::from_rgb(47, 53, 77),
                border_subtle: Color32::from_rgb(41, 46, 66),
                border_strong: Color32::from_rgb(65, 72, 104),
                accent: Color32::from_rgb(122, 162, 247),
            },
            Self::Catppuccin => ThemeTokens {
                bg_deepest: Color32::from_rgb(17, 17, 27),
                bg_canvas: Color32::from_rgb(24, 24, 37),
                bg_panel: Color32::from_rgb(30, 30, 46),
                bg_elevated: Color32::from_rgb(49, 50, 68),
                bg_hover: Color32::from_rgb(69, 71, 90),
                border_subtle: Color32::from_rgb(49, 50, 68),
                border_strong: Color32::from_rgb(88, 91, 112),
                accent: Color32::from_rgb(137, 180, 250),
            },
            Self::Gruvbox => ThemeTokens {
                bg_deepest: Color32::from_rgb(29, 32, 33),
                bg_canvas: Color32::from_rgb(40, 40, 40),
                bg_panel: Color32::from_rgb(50, 48, 47),
                bg_elevated: Color32::from_rgb(60, 56, 54),
                bg_hover: Color32::from_rgb(80, 73, 69),
                border_subtle: Color32::from_rgb(60, 56, 54),
                border_strong: Color32::from_rgb(102, 92, 84),
                accent: Color32::from_rgb(131, 165, 152),
            },
        }
    }
}

fn active_tokens() -> ThemeTokens {
    GpuiThemePreset::from_u8(ACTIVE_THEME_ID.load(std::sync::atomic::Ordering::Relaxed)).tokens()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowSortColumn {
    Time,
    Traffic,
    App,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToastKind {
    Info,
    Success,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
struct GuiToast {
    title: String,
    detail: String,
    kind: ToastKind,
    created: Instant,
    duration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Overview,
    Flows,
    Generator,
    Lists,
    Dns,
    Logs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChartMode {
    Traffic,
    Flows,
}

#[derive(Debug, Clone, Copy, Default)]
struct TelemetryPoint {
    rx_bps: f64,
    tx_bps: f64,
    active_flows: u64,
    desync_delta: u64,
}

struct ListEditorModal {
    open: bool,
    list_id: Option<String>,
    name: String,
    strategy: String,
    udp_ports: String,
    udp_fake_ttl: u8,
    entries_text: String,
    quick_entry: String,
}

impl Default for ListEditorModal {
    fn default() -> Self {
        Self {
            open: false,
            list_id: None,
            name: String::new(),
            strategy: "auto".to_string(),
            udp_ports: String::new(),
            udp_fake_ttl: 0,
            entries_text: String::new(),
            quick_entry: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
enum GuiUpdateState {
    Idle,
    Checking,
    UpToDate(String),
    Available(crate::updater::UpdateCheckResult),
    Downloading(crate::updater::UpdateCheckResult),
    ReadyToRestart(std::path::PathBuf),
    Error(String),
}

struct BusyFlagGuard(Arc<Mutex<bool>>);

impl Drop for BusyFlagGuard {
    fn drop(&mut self) {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *g = false;
    }
}

fn try_acquire_busy(flag: &Arc<Mutex<bool>>) -> Option<BusyFlagGuard> {
    let mut g = flag.lock().unwrap_or_else(|e| e.into_inner());
    if *g {
        return None;
    }
    *g = true;
    Some(BusyFlagGuard(flag.clone()))
}

pub struct TachyonGuiApp {
    rt: Arc<DesyncRuntime>,
    tokio_handle: tokio::runtime::Handle,
    snap: UiSnapshot,
    last_refresh: Instant,
    active_tab: ActiveTab,
    chart_mode: ChartMode,
    telemetry: VecDeque<TelemetryPoint>,
    prev_rx_bytes: Option<u64>,
    prev_tx_bytes: Option<u64>,
    prev_desync_count: Option<u64>,
    prev_sample_ts: Option<Instant>,
    cur_rx_bps: f64,
    cur_tx_bps: f64,

    // Состояние автозапуска ОС
    autostart_enabled: bool,

    // Вкладка Авто (закрепление домена + экспресс-диагностика + hosts)
    pin_host_input: String,
    pin_recipe_id: u8,
    health_in_progress: Arc<Mutex<bool>>,
    health_results: Arc<Mutex<Vec<ServiceHealthItem>>>,
    backup_toast_until: Option<Instant>,
    show_dns_overrides_panel: bool,
    show_services_on_overview: bool,
    dns_overrides_input: String,
    dns_overrides_dirty: bool,

    // Вкладка DNS (резолвер, бенчмарк, автонастройка, тест скорости)
    dns_draft: DnsSettings,
    dns_dirty: bool,
    dns_server_input: String,
    dns_bootstrap_input: String,
    dns_fallback_input: String,
    dns_speed_domains_input: String,
    dns_bench_state: Arc<Mutex<DnsBenchmarkState>>,
    dns_bench_cancel: Arc<AtomicBool>,
    dns_speed_state: Arc<Mutex<DnsSpeedTestState>>,
    dns_speed_cancel: Arc<AtomicBool>,
    dns_auto_apply_on_finish: Arc<AtomicBool>,
    selected_speed_server_idx: Option<usize>,

    // Сетевой стек и производительность (BBR / TUN / IPv6)
    net_draft: NetworkTuningConfig,
    net_dirty: bool,
    show_net_tuning_panel: bool,

    // Вкладка Потоки (Live Flows + DataTable сортировка)
    flow_filter: String,
    flows_only_active: bool,
    flow_sort_col: FlowSortColumn,
    flow_sort_asc: bool,

    // Вкладка Генератор и Конструктор
    probe_domain: String,
    probe_port: u16,
    probe_stream_192k: bool,
    probe_in_progress: Arc<Mutex<bool>>,
    probe_report: Arc<Mutex<Option<StrategyGeneratorReport>>>,
    ttl_calib_in_progress: Arc<Mutex<bool>>,
    ttl_calib_report: Arc<Mutex<Option<AutoTtlReport>>>,
    packet_preview: PacketSlicePreview,
    builder_cfg: DesyncConfig,
    builder_dirty: bool,
    builder_preset_id: u8,
    builder_profile_name: String,
    selected_profile_id: Option<String>,
    copied_toast_until: Option<Instant>,

    // Вкладка Списки и .exe
    add_app_input: String,
    upstream_proxy_input: String,
    upstream_proxy_dirty: bool,
    list_search_filter: String,
    list_modal: ListEditorModal,

    // Вкладка Журнал
    log_category_filter: String,
    log_search_query: String,
    show_scoreboard_in_logs: bool,
    log_copied_toast_until: Option<Instant>,

    // Компоненты gpui-kit: темы, Command Palette (Ctrl+K), стек Toast-уведомлений
    theme_preset: GpuiThemePreset,
    theme_configured: bool,
    cmd_palette_open: bool,
    cmd_palette_query: String,
    cmd_palette_selected: usize,
    cmd_palette_just_opened: bool,
    toasts: VecDeque<GuiToast>,

    // Окно «О программе» и автообновление
    about_modal_open: bool,
    start_minimized_done: bool,
    start_minimized: bool,
    update_state: Arc<Mutex<GuiUpdateState>>,
}

impl TachyonGuiApp {
    pub fn new(
        rt: Arc<DesyncRuntime>,
        tokio_handle: tokio::runtime::Handle,
        start_minimized: bool,
    ) -> Self {
        let initial_snap = tokio_handle.block_on(rt.snapshot());
        let builder_cfg = initial_snap.config.custom_global_config.clone();
        let upstream_proxy_input = initial_snap.config.upstream_proxy.clone();
        let dns_overrides_input = initial_snap
            .config
            .dns_overrides
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let dns_draft = initial_snap.config.dns.clone();
        let dns_speed_domains_input = dns_draft.speed_test_domains.join("\n");
        let net_draft = initial_snap.config.network.clone();
        let probe_stream_192k = net_draft.stream_verify_192k;
        let probe_domain = "www.youtube.com".to_string();
        let packet_preview = inspect_client_hello_slices(&probe_domain);
        let mut telemetry = VecDeque::with_capacity(HISTORY_LEN);
        for _ in 0..HISTORY_LEN {
            telemetry.push_back(TelemetryPoint::default());
        }

        let update_state = Arc::new(Mutex::new(GuiUpdateState::Idle));
        let update_state_bg = update_state.clone();
        let initial_proxy_port = if initial_snap.running {
            Some(initial_snap.config.listen_port)
        } else {
            None
        };
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2500));
            if let Ok(res) = crate::updater::check_for_updates(initial_proxy_port)
                && res.update_available
                && let Ok(mut guard) = update_state_bg.lock()
            {
                *guard = GuiUpdateState::Available(res);
            }
        });

        Self {
            rt,
            tokio_handle,
            snap: initial_snap,
            last_refresh: Instant::now() - Duration::from_secs(2),
            active_tab: ActiveTab::Overview,
            chart_mode: ChartMode::Traffic,
            telemetry,
            prev_rx_bytes: None,
            prev_tx_bytes: None,
            prev_desync_count: None,
            prev_sample_ts: None,
            cur_rx_bps: 0.0,
            cur_tx_bps: 0.0,
            autostart_enabled: crate::tray::is_autostart_enabled(),
            pin_host_input: String::new(),
            pin_recipe_id: 0,
            health_in_progress: Arc::new(Mutex::new(false)),
            health_results: Arc::new(Mutex::new(Vec::new())),
            backup_toast_until: None,
            show_dns_overrides_panel: false,
            show_services_on_overview: false,
            dns_overrides_input,
            dns_overrides_dirty: false,
            dns_draft,
            dns_dirty: false,
            dns_server_input: String::new(),
            dns_bootstrap_input: String::new(),
            dns_fallback_input: String::new(),
            dns_speed_domains_input,
            dns_bench_state: Arc::new(Mutex::new(DnsBenchmarkState::default())),
            dns_bench_cancel: Arc::new(AtomicBool::new(false)),
            dns_speed_state: Arc::new(Mutex::new(DnsSpeedTestState::default())),
            dns_speed_cancel: Arc::new(AtomicBool::new(false)),
            dns_auto_apply_on_finish: Arc::new(AtomicBool::new(false)),
            selected_speed_server_idx: None,
            net_draft,
            net_dirty: false,
            show_net_tuning_panel: false,
            flow_filter: String::new(),
            flows_only_active: false,
            flow_sort_col: FlowSortColumn::Time,
            flow_sort_asc: false,
            probe_domain,
            probe_port: 443,
            probe_stream_192k,
            probe_in_progress: Arc::new(Mutex::new(false)),
            probe_report: Arc::new(Mutex::new(None)),
            ttl_calib_in_progress: Arc::new(Mutex::new(false)),
            ttl_calib_report: Arc::new(Mutex::new(None)),
            packet_preview,
            builder_cfg,
            builder_dirty: false,
            builder_preset_id: 0,
            builder_profile_name: String::new(),
            selected_profile_id: None,
            copied_toast_until: None,
            add_app_input: String::new(),
            upstream_proxy_input,
            upstream_proxy_dirty: false,
            list_search_filter: String::new(),
            list_modal: ListEditorModal::default(),
            log_category_filter: "all".to_string(),
            log_search_query: String::new(),
            show_scoreboard_in_logs: true,
            log_copied_toast_until: None,
            theme_preset: GpuiThemePreset::Graphite,
            theme_configured: false,
            cmd_palette_open: false,
            cmd_palette_query: String::new(),
            cmd_palette_selected: 0,
            cmd_palette_just_opened: false,
            toasts: VecDeque::new(),
            about_modal_open: false,
            start_minimized_done: false,
            start_minimized,
            update_state,
        }
    }

    fn push_toast(&mut self, kind: ToastKind, title: impl Into<String>, detail: impl Into<String>) {
        if self.toasts.len() >= 4 {
            self.toasts.pop_front();
        }
        self.toasts.push_back(GuiToast {
            title: title.into(),
            detail: detail.into(),
            kind,
            created: Instant::now(),
            duration: Duration::from_millis(3200),
        });
    }

    fn set_theme_preset(&mut self, preset: GpuiThemePreset) {
        self.theme_preset = preset;
        ACTIVE_THEME_ID.store(preset as u8, std::sync::atomic::Ordering::Relaxed);
        self.theme_configured = false;
        let is_en = self.is_en();
        self.push_toast(
            ToastKind::Info,
            if is_en {
                format!("Theme: {}", preset.label())
            } else {
                format!("Тема: {}", preset.label())
            },
            if is_en {
                "Applied gpui-kit color tokens"
            } else {
                "Применена цветовая палитра gpui-kit"
            },
        );
    }

    fn trigger_update_check(&self) {
        if let Ok(mut guard) = self.update_state.lock() {
            if matches!(
                *guard,
                GuiUpdateState::Checking | GuiUpdateState::Downloading(_)
            ) {
                return;
            }
            *guard = GuiUpdateState::Checking;
        }
        let state = self.update_state.clone();
        let proxy_port = if self.snap.running {
            Some(self.snap.config.listen_port)
        } else {
            None
        };
        std::thread::spawn(move || {
            let next = match crate::updater::check_for_updates(proxy_port) {
                Ok(res) if res.update_available => GuiUpdateState::Available(res),
                Ok(res) => GuiUpdateState::UpToDate(res.latest_version),
                Err(e) => GuiUpdateState::Error(e),
            };
            if let Ok(mut guard) = state.lock() {
                *guard = next;
            }
        });
    }

    fn trigger_update_install(&self, info: crate::updater::UpdateCheckResult) {
        if let Ok(mut guard) = self.update_state.lock() {
            if matches!(*guard, GuiUpdateState::Downloading(_)) {
                return;
            }
            *guard = GuiUpdateState::Downloading(info.clone());
        }
        let state = self.update_state.clone();
        let proxy_port = if self.snap.running {
            Some(self.snap.config.listen_port)
        } else {
            None
        };
        std::thread::spawn(move || {
            let next = match crate::updater::download_and_apply_update(&info, proxy_port) {
                Ok(exe_path) => GuiUpdateState::ReadyToRestart(exe_path),
                Err(e) => GuiUpdateState::Error(e),
            };
            if let Ok(mut guard) = state.lock() {
                *guard = next;
            }
        });
    }

    fn is_en(&self) -> bool {
        self.snap.config.language.eq_ignore_ascii_case("en")
    }

    fn all_strategy_options(&self, is_en: bool) -> Vec<(String, String)> {
        let base = strategy_options(is_en);
        let mut out = Vec::with_capacity(base.len() + self.snap.config.custom_profiles.len());
        for (code, lbl) in base {
            out.push((code.to_string(), lbl.to_string()));
            if code == "custom" {
                for p in &self.snap.config.custom_profiles {
                    let p_code = format!("profile:{}", p.id);
                    let p_lbl = if is_en {
                        format!("[Profile] {}", p.name)
                    } else {
                        format!("[Профиль] {}", p.name)
                    };
                    out.push((p_code, p_lbl));
                }
            }
        }
        out
    }

    fn strategy_label(&self, code: &str, is_en: bool) -> String {
        let trimmed = code.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(pid) = lower.strip_prefix("profile:") {
            let norm = pid.trim();
            if let Some(p) = self
                .snap
                .config
                .custom_profiles
                .iter()
                .find(|p| p.id.eq_ignore_ascii_case(norm))
            {
                return if is_en {
                    format!("[Profile] {}", p.name)
                } else {
                    format!("[Профиль] {}", p.name)
                };
            }
        }
        strategy_short_label(code, is_en).to_string()
    }

    fn sync_editable_fields_from_snap(&mut self) {
        if !self.builder_dirty {
            self.builder_cfg = self.snap.config.custom_global_config.clone();
        }
        if !self.upstream_proxy_dirty {
            self.upstream_proxy_input = self.snap.config.upstream_proxy.clone();
        }
        if !self.dns_overrides_dirty {
            self.dns_overrides_input = self
                .snap
                .config
                .dns_overrides
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n");
        }
        if !self.dns_dirty {
            self.dns_draft = self.snap.config.dns.clone();
            self.dns_speed_domains_input = self.dns_draft.speed_test_domains.join("\n");
        }
        if !self.net_dirty {
            self.net_draft = self.snap.config.network.clone();
        }
    }

    fn dispatch_ipc(&mut self, action: &str, payload: serde_json::Value) {
        let rt = self.rt.clone();
        let _ = self
            .tokio_handle
            .block_on(rt.handle_ipc_action(action, payload));
        self.snap = self.tokio_handle.block_on(self.rt.snapshot());
        self.sync_editable_fields_from_snap();
    }

    fn poll_snapshot_if_due(&mut self) {
        if self.last_refresh.elapsed() < Duration::from_millis(500) {
            return;
        }
        self.last_refresh = Instant::now();
        self.snap = self.tokio_handle.block_on(self.rt.snapshot());
        self.sync_editable_fields_from_snap();

        let now = Instant::now();
        let rx = self.snap.rx_bytes;
        let tx = self.snap.tx_bytes;
        let desynced = self.snap.desynced_connections;
        let active = self.snap.active_connections;

        if let Some(prev_ts) = self.prev_sample_ts {
            let dt = now.duration_since(prev_ts).as_secs_f64().max(0.15);
            if dt >= 0.85 {
                let rx_bps = (rx.saturating_sub(self.prev_rx_bytes.unwrap_or(rx))) as f64 / dt;
                let tx_bps = (tx.saturating_sub(self.prev_tx_bytes.unwrap_or(tx))) as f64 / dt;
                let desync_delta =
                    desynced.saturating_sub(self.prev_desync_count.unwrap_or(desynced));

                self.cur_rx_bps = rx_bps;
                self.cur_tx_bps = tx_bps;
                self.prev_rx_bytes = Some(rx);
                self.prev_tx_bytes = Some(tx);
                self.prev_desync_count = Some(desynced);
                self.prev_sample_ts = Some(now);

                if self.telemetry.len() >= HISTORY_LEN {
                    self.telemetry.pop_front();
                }
                self.telemetry.push_back(TelemetryPoint {
                    rx_bps,
                    tx_bps,
                    active_flows: active,
                    desync_delta,
                });
            }
        } else {
            self.prev_rx_bytes = Some(rx);
            self.prev_tx_bytes = Some(tx);
            self.prev_desync_count = Some(desynced);
            self.prev_sample_ts = Some(now);
        }
    }

    fn configure_gpui_theme(&mut self, ctx: &egui::Context) {
        if self.theme_configured {
            return;
        }
        self.theme_configured = true;
        let tk = active_tokens();

        // Строгая сетка 4px (Spacing Pass) и чистая 5-ступенчатая типографика (Type Pass)
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(8.0, 4.0);
        style.spacing.window_margin = Margin::same(12);
        style.spacing.button_padding = Vec2::new(8.0, 4.0);
        style.spacing.interact_size = Vec2::new(28.0, 24.0);
        style.spacing.scroll.bar_width = 4.0;

        style.text_styles.insert(
            TextStyle::Heading,
            FontId::new(12.0, FontFamily::Proportional),
        );
        style
            .text_styles
            .insert(TextStyle::Body, FontId::new(11.0, FontFamily::Proportional));
        style.text_styles.insert(
            TextStyle::Button,
            FontId::new(11.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Small,
            FontId::new(10.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Monospace,
            FontId::new(10.0, FontFamily::Monospace),
        );

        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = tk.bg_canvas;
        visuals.window_fill = tk.bg_panel;
        visuals.extreme_bg_color = tk.bg_deepest;
        visuals.faint_bg_color = tk.bg_elevated;
        visuals.code_bg_color = tk.bg_deepest;

        visuals.widgets.noninteractive.bg_fill = tk.bg_panel;
        visuals.widgets.noninteractive.weak_bg_fill = tk.bg_panel;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, tk.border_subtle);
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.noninteractive.corner_radius = CornerRadius::same(4);

        visuals.widgets.inactive.bg_fill = tk.bg_elevated;
        visuals.widgets.inactive.weak_bg_fill = tk.bg_elevated;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, tk.border_strong);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.inactive.corner_radius = CornerRadius::same(4);

        // Спокойный шаг поверхности при наведении без неоновой обводки
        visuals.widgets.hovered.bg_fill = tk.bg_hover;
        visuals.widgets.hovered.weak_bg_fill = tk.bg_hover;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, tk.border_strong);
        visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.hovered.corner_radius = CornerRadius::same(4);

        visuals.widgets.active.bg_fill = tk.bg_hover;
        visuals.widgets.active.weak_bg_fill = tk.bg_hover;
        visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, TEXT_SECONDARY);
        visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.active.corner_radius = CornerRadius::same(4);

        visuals.selection.bg_fill =
            Color32::from_rgba_unmultiplied(tk.accent.r(), tk.accent.g(), tk.accent.b(), 44);
        visuals.selection.stroke = Stroke::new(1.0_f32, tk.accent);

        style.visuals = visuals;
        ctx.set_style(style);
    }

    // Внешняя панель: радиус 8px, внутренний отступ 8px -> вложенные карточки имеют радиус 4px (8 - 4 = 4)
    fn panel_frame() -> Frame {
        let tk = active_tokens();
        Frame::new()
            .fill(tk.bg_panel)
            .stroke(Stroke::new(1.0_f32, tk.border_subtle))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(8, 8))
    }

    fn card_frame(active_border: bool) -> Frame {
        let tk = active_tokens();
        Frame::new()
            .fill(tk.bg_elevated)
            .stroke(Stroke::new(
                1.0_f32,
                if active_border {
                    tk.border_strong
                } else {
                    tk.border_subtle
                },
            ))
            .corner_radius(CornerRadius::same(4))
            .inner_margin(Margin::symmetric(8, 8))
    }

    // Основная кнопка на тёмной теме: светлая поверхность из нейтральной шкалы с тёмным текстом
    fn primary_button(label: &str) -> egui::Button<'static> {
        let tk = active_tokens();
        egui::Button::new(
            RichText::new(label.to_string())
                .strong()
                .size(11.0)
                .color(tk.bg_deepest),
        )
        .fill(TEXT_PRIMARY)
        .corner_radius(CornerRadius::same(4))
    }

    // Фирменная деталь (Signature): моноширинный кейкап 4px с тонкой рамкой 1px
    fn keycap(ui: &mut egui::Ui, text: &str) {
        let tk = active_tokens();
        Frame::new()
            .fill(tk.bg_deepest)
            .stroke(Stroke::new(1.0_f32, tk.border_subtle))
            .corner_radius(CornerRadius::same(4))
            .inner_margin(Margin::symmetric(4, 2))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(text)
                        .monospace()
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
            });
    }

    // Компонент `kbd.rs` из gpui-kit: компактная плашка горячей клавиши (Ctrl+K, Esc, Enter)
    fn kbd_badge(ui: &mut egui::Ui, shortcut: &str) {
        let tk = active_tokens();
        Frame::new()
            .fill(tk.bg_deepest)
            .stroke(Stroke::new(1.0_f32, tk.border_strong))
            .corner_radius(CornerRadius::same(3))
            .inner_margin(Margin::symmetric(4, 1))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(shortcut)
                        .monospace()
                        .size(9.0)
                        .color(TEXT_SECONDARY),
                );
            });
    }

    // Компонент `tag.rs` из gpui-kit: семантический тег с приглушённой заливкой и рамкой 1px
    fn semantic_tag(ui: &mut egui::Ui, text: &str, fg: Color32) {
        let bg = Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 26);
        let border = Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 88);
        Frame::new()
            .fill(bg)
            .stroke(Stroke::new(1.0_f32, border))
            .corner_radius(CornerRadius::same(3))
            .inner_margin(Margin::symmetric(4, 1))
            .show(ui, |ui| {
                ui.label(RichText::new(text).monospace().strong().size(9.0).color(fg));
            });
    }

    // Компонент `switch.rs` из gpui-kit: капсульный тумблер 26x14px с ползунком
    fn gpui_switch(ui: &mut egui::Ui, on: &mut bool, label: &str) -> egui::Response {
        let tk = active_tokens();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let (rect, mut switch_resp) =
                ui.allocate_exact_size(Vec2::new(26.0, 14.0), Sense::click());
            if switch_resp.clicked() {
                *on = !*on;
                switch_resp.mark_changed();
            }
            let bg = if *on {
                tk.accent
            } else if switch_resp.hovered() {
                tk.bg_hover
            } else {
                tk.bg_deepest
            };
            let stroke_col = if *on { tk.accent } else { tk.border_strong };
            ui.painter().rect_filled(rect, CornerRadius::same(7), bg);
            ui.painter().rect_stroke(
                rect,
                CornerRadius::same(7),
                Stroke::new(1.0_f32, stroke_col),
                StrokeKind::Inside,
            );
            let knob_x = if *on {
                rect.max.x - 7.0
            } else {
                rect.min.x + 7.0
            };
            let knob_col = if *on { tk.bg_deepest } else { TEXT_SECONDARY };
            ui.painter()
                .circle_filled(Pos2::new(knob_x, rect.center().y), 4.5, knob_col);

            let lbl_resp = ui.add(
                egui::Label::new(RichText::new(label).size(10.0).color(if *on {
                    TEXT_PRIMARY
                } else {
                    TEXT_SECONDARY
                }))
                .sense(Sense::click()),
            );
            if lbl_resp.clicked() {
                *on = !*on;
                switch_resp.mark_changed();
            }
            switch_resp | lbl_resp
        })
        .inner
    }

    fn handle_custom_window_resize(ctx: &egui::Context) {
        let is_maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
        if is_maximized {
            return;
        }
        let screen = ctx.screen_rect();
        let border = 4.0_f32;
        let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) else {
            return;
        };

        let left = pos.x - screen.min.x <= border;
        let right = screen.max.x - pos.x <= border;
        let top = pos.y - screen.min.y <= border;
        let bottom = screen.max.y - pos.y <= border;

        let dir_and_cursor = match (left, right, top, bottom) {
            (true, _, true, _) => Some((
                egui::ResizeDirection::NorthWest,
                egui::CursorIcon::ResizeNorthWest,
            )),
            (_, true, true, _) => Some((
                egui::ResizeDirection::NorthEast,
                egui::CursorIcon::ResizeNorthEast,
            )),
            (true, _, _, true) => Some((
                egui::ResizeDirection::SouthWest,
                egui::CursorIcon::ResizeSouthWest,
            )),
            (_, true, _, true) => Some((
                egui::ResizeDirection::SouthEast,
                egui::CursorIcon::ResizeSouthEast,
            )),
            (true, _, _, _) => Some((egui::ResizeDirection::West, egui::CursorIcon::ResizeWest)),
            (_, true, _, _) => Some((egui::ResizeDirection::East, egui::CursorIcon::ResizeEast)),
            (_, _, true, _) => Some((egui::ResizeDirection::North, egui::CursorIcon::ResizeNorth)),
            (_, _, _, true) => Some((egui::ResizeDirection::South, egui::CursorIcon::ResizeSouth)),
            _ => None,
        };

        if let Some((dir, cursor)) = dir_and_cursor {
            ctx.set_cursor_icon(cursor);
            if ctx.input(|i| i.pointer.button_pressed(egui::PointerButton::Primary)) {
                ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
            }
        }
    }

    fn render_custom_titlebar(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let is_en = self.is_en();
        let is_maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));

        ui.horizontal(|ui| {
            ui.set_height(24.0);

            // 1. Слева: монограммный знак [T] (20x20px, радиус 4px)
            let (logo_rect, logo_resp) =
                ui.allocate_exact_size(Vec2::new(20.0, 20.0), Sense::click());
            ui.painter()
                .rect_filled(logo_rect, CornerRadius::same(4), BG_ELEVATED);
            ui.painter().rect_stroke(
                logo_rect,
                CornerRadius::same(4),
                Stroke::new(1.0_f32, BORDER_STRONG),
                StrokeKind::Inside,
            );
            ui.painter().text(
                logo_rect.center(),
                egui::Align2::CENTER_CENTER,
                "T",
                FontId::new(11.0, FontFamily::Monospace),
                ACCENT,
            );
            if logo_resp
                .on_hover_text(if is_en {
                    "About Tachyon Desync"
                } else {
                    "О программе Tachyon Desync"
                })
                .clicked()
            {
                self.about_modal_open = true;
            }

            // 2. Справа налево: кнопки [✕] [□] [—] + [Выход] [RU/EN] [О программе],
            //    а всё оставшееся пространство между [T] и [О программе] — зона перетаскивания.
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                // Кнопка Закрыть [✕] (сворачивает в трей, если включено «В трей», иначе останавливает и закрывает)
                let (close_rect, close_resp) =
                    ui.allocate_exact_size(Vec2::new(28.0, 22.0), Sense::click());
                if close_resp.hovered() {
                    ui.painter()
                        .rect_filled(close_rect, CornerRadius::same(4), SEMANTIC_ERR);
                }
                let close_fg = if close_resp.hovered() {
                    Color32::WHITE
                } else {
                    TEXT_SECONDARY
                };
                let c = close_rect.center();
                let d = 4.0_f32;
                ui.painter().line_segment(
                    [Pos2::new(c.x - d, c.y - d), Pos2::new(c.x + d, c.y + d)],
                    Stroke::new(1.4_f32, close_fg),
                );
                ui.painter().line_segment(
                    [Pos2::new(c.x + d, c.y - d), Pos2::new(c.x - d, c.y + d)],
                    Stroke::new(1.4_f32, close_fg),
                );
                let close_tip = if self.snap.config.minimize_to_tray {
                    if is_en {
                        "Minimize to system tray"
                    } else {
                        "Свернуть в системный трей"
                    }
                } else if is_en {
                    "Close window"
                } else {
                    "Закрыть окно"
                };
                if close_resp.on_hover_text(close_tip).clicked() {
                    if self.snap.config.minimize_to_tray {
                        crate::tray::hide_main_window_to_tray();
                    } else {
                        crate::tray::request_app_exit();
                        self.tokio_handle.block_on(self.rt.stop());
                        std::process::exit(0);
                    }
                }

                // Кнопка Развернуть / Восстановить [□]
                let (max_rect, max_resp) =
                    ui.allocate_exact_size(Vec2::new(28.0, 22.0), Sense::click());
                if max_resp.hovered() {
                    ui.painter()
                        .rect_filled(max_rect, CornerRadius::same(4), BG_HOVER);
                }
                let max_fg = if max_resp.hovered() {
                    TEXT_PRIMARY
                } else {
                    TEXT_SECONDARY
                };
                let mc = max_rect.center();
                if is_maximized {
                    let back_r =
                        Rect::from_center_size(Pos2::new(mc.x + 1.5, mc.y - 1.5), Vec2::splat(6.5));
                    let front_r =
                        Rect::from_center_size(Pos2::new(mc.x - 1.0, mc.y + 1.0), Vec2::splat(6.5));
                    ui.painter().rect_stroke(
                        back_r,
                        CornerRadius::ZERO,
                        Stroke::new(1.2_f32, max_fg),
                        StrokeKind::Inside,
                    );
                    ui.painter().rect_filled(
                        front_r,
                        CornerRadius::ZERO,
                        if max_resp.hovered() {
                            BG_HOVER
                        } else {
                            BG_DEEPEST
                        },
                    );
                    ui.painter().rect_stroke(
                        front_r,
                        CornerRadius::ZERO,
                        Stroke::new(1.2_f32, max_fg),
                        StrokeKind::Inside,
                    );
                } else {
                    let sq = Rect::from_center_size(mc, Vec2::splat(8.0));
                    ui.painter().rect_stroke(
                        sq,
                        CornerRadius::same(1),
                        Stroke::new(1.2_f32, max_fg),
                        StrokeKind::Inside,
                    );
                }
                let max_tip = if is_maximized {
                    if is_en {
                        "Restore"
                    } else {
                        "Восстановить"
                    }
                } else if is_en {
                    "Maximize"
                } else {
                    "Развернуть"
                };
                if max_resp.on_hover_text(max_tip).clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!is_maximized));
                }

                // Кнопка Свернуть на панель задач [—]
                let (min_rect, min_resp) =
                    ui.allocate_exact_size(Vec2::new(28.0, 22.0), Sense::click());
                if min_resp.hovered() {
                    ui.painter()
                        .rect_filled(min_rect, CornerRadius::same(4), BG_HOVER);
                }
                let min_fg = if min_resp.hovered() {
                    TEXT_PRIMARY
                } else {
                    TEXT_SECONDARY
                };
                let mnc = min_rect.center();
                ui.painter().line_segment(
                    [Pos2::new(mnc.x - 4.5, mnc.y), Pos2::new(mnc.x + 4.5, mnc.y)],
                    Stroke::new(1.4_f32, min_fg),
                );
                let min_tip = if is_en {
                    "Minimize"
                } else {
                    "Свернуть"
                };
                if min_resp.on_hover_text(min_tip).clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    crate::tray::minimize_main_window_to_taskbar();
                }

                // Тонкий вертикальный разделитель 1px
                let (sep_rect, _) = ui.allocate_exact_size(Vec2::new(4.0, 16.0), Sense::hover());
                ui.painter().line_segment(
                    [
                        Pos2::new(sep_rect.center().x, sep_rect.top()),
                        Pos2::new(sep_rect.center().x, sep_rect.bottom()),
                    ],
                    Stroke::new(1.0_f32, BORDER_SUBTLE),
                );

                // Переключатель языка RU / EN
                let tk = active_tokens();
                let lang_label = if is_en { "EN" } else { "RU" };
                let lang_tip = if is_en {
                    "Switch interface language to Russian (RU)"
                } else {
                    "Переключить язык интерфейса на английский (EN)"
                };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(lang_label)
                                .monospace()
                                .size(10.0)
                                .color(TEXT_PRIMARY),
                        )
                        .fill(tk.bg_elevated),
                    )
                    .on_hover_text(lang_tip)
                    .clicked()
                {
                    let next_lang = if is_en { "ru" } else { "en" };
                    self.dispatch_ipc("set_language", serde_json::json!({ "language": next_lang }));
                }

                // Селектор темы оформления gpui-kit (Graphite / Ayu Dark / TokyoNight / Catppuccin / Gruvbox)
                let theme_tip = if is_en {
                    "Cycle gpui-kit theme preset (Graphite / Ayu Dark / TokyoNight / Catppuccin / Gruvbox)"
                } else {
                    "Сменить цветовую тему gpui-kit (Graphite / Ayu Dark / TokyoNight / Catppuccin / Gruvbox)"
                };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(self.theme_preset.label())
                                .monospace()
                                .size(10.0)
                                .color(tk.accent),
                        )
                        .fill(tk.bg_elevated),
                    )
                    .on_hover_text(theme_tip)
                    .clicked()
                {
                    let next_idx = ((self.theme_preset as u8) + 1) % 5;
                    self.set_theme_preset(GpuiThemePreset::from_u8(next_idx));
                }

                // Кнопка вызова Command Palette (Ctrl+K) из gpui-kit
                let cmd_tip = if is_en {
                    "Open Command Palette (Ctrl+K / F1)"
                } else {
                    "Открыть палитру быстрых команд и рецептов (Ctrl+K / F1)"
                };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Ctrl+K")
                                .monospace()
                                .size(10.0)
                                .color(TEXT_PRIMARY),
                        )
                        .fill(tk.bg_elevated)
                        .stroke(Stroke::new(1.0_f32, tk.border_strong)),
                    )
                    .on_hover_text(cmd_tip)
                    .clicked()
                {
                    self.cmd_palette_open = true;
                    self.cmd_palette_just_opened = true;
                    self.cmd_palette_selected = 0;
                }

                // Кнопка «О программе» / «About»
                let about_lbl = if is_en {
                    "About"
                } else {
                    "О программе"
                };
                let about_tip = if is_en {
                    "Version info, software updates, and GitHub repository link"
                } else {
                    "Сведения о версии, обновление программы и ссылка на репозиторий GitHub"
                };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(about_lbl).size(10.0).color(TEXT_SECONDARY),
                        )
                        .fill(tk.bg_elevated),
                    )
                    .on_hover_text(about_tip)
                    .clicked()
                {
                    self.about_modal_open = true;
                }

                // Индикатор доступного обновления в заголовке окна
                let upd_snapshot = self.update_state.lock().ok().map(|g| g.clone());
                if let Some(GuiUpdateState::Available(ref info)) = upd_snapshot {
                    let upd_lbl = if is_en {
                        format!("Update v{}", info.latest_version)
                    } else {
                        format!("Обновить v{}", info.latest_version)
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(upd_lbl)
                                    .monospace()
                                    .strong()
                                    .size(10.0)
                                    .color(SEMANTIC_OK),
                            )
                            .fill(BG_ELEVATED)
                            .stroke(Stroke::new(1.0_f32, SEMANTIC_OK)),
                        )
                        .on_hover_text(if is_en {
                            "New version available — click to review and install"
                        } else {
                            "Доступна новая версия — нажмите для просмотра изменений и установки"
                        })
                        .clicked()
                    {
                        self.about_modal_open = true;
                    }
                } else if let Some(GuiUpdateState::Downloading(ref info)) = upd_snapshot {
                    let dl_lbl = if is_en {
                        format!("Updating v{}...", info.latest_version)
                    } else {
                        format!("Загрузка v{}...", info.latest_version)
                    };
                    ui.add(
                        egui::Button::new(
                            RichText::new(dl_lbl).monospace().size(10.0).color(ACCENT),
                        )
                        .fill(BG_ELEVATED),
                    );
                }

                // 3. Вся свободная область заголовка между [T] и [О программе] (без перекрытия кнопок):
                //    перетаскивание окна и двойной клик для разворачивания / восстановления.
                let drag_rect = ui.available_rect_before_wrap();
                let drag_resp = ui.interact(
                    drag_rect,
                    Id::new("tachyon_custom_titlebar_drag_zone"),
                    Sense::click_and_drag(),
                );

                let title_galley = ui.painter().layout_no_wrap(
                    "Tachyon Desync".to_string(),
                    FontId::new(12.0, FontFamily::Proportional),
                    TEXT_PRIMARY,
                );
                let title_pos = Pos2::new(
                    drag_rect.min.x + 4.0,
                    drag_rect.center().y - title_galley.size().y * 0.5,
                );
                ui.painter()
                    .galley(title_pos, title_galley.clone(), TEXT_PRIMARY);

                let ver_galley = ui.painter().layout_no_wrap(
                    concat!("v", env!("CARGO_PKG_VERSION")).to_string(),
                    FontId::new(10.0, FontFamily::Monospace),
                    TEXT_SECONDARY,
                );
                let pill_w = ver_galley.size().x + 8.0;
                let pill_rect = Rect::from_min_size(
                    Pos2::new(
                        title_pos.x + title_galley.size().x + 6.0,
                        drag_rect.center().y - 8.0,
                    ),
                    Vec2::new(pill_w, 16.0),
                );
                if pill_rect.max.x <= drag_rect.max.x {
                    ui.painter()
                        .rect_filled(pill_rect, CornerRadius::same(4), BG_ELEVATED);
                    ui.painter().rect_stroke(
                        pill_rect,
                        CornerRadius::same(4),
                        Stroke::new(1.0_f32, BORDER_STRONG),
                        StrokeKind::Inside,
                    );
                    ui.painter().galley(
                        Pos2::new(
                            pill_rect.center().x - ver_galley.size().x * 0.5,
                            pill_rect.center().y - ver_galley.size().y * 0.5,
                        ),
                        ver_galley,
                        TEXT_SECONDARY,
                    );
                }

                if drag_resp.double_clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!is_maximized));
                } else if drag_resp.drag_started_by(egui::PointerButton::Primary)
                    || drag_resp.dragged_by(egui::PointerButton::Primary)
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
            });
        });
    }

    fn render_top_header(&mut self, ui: &mut egui::Ui) {
        let is_en = self.is_en();

        Self::panel_frame().show(ui, |ui| {
            // Строка 1: Индикатор статуса и текущий режим слева | Автозапуск + В трей + UAC + Старт/Стоп справа
            ui.horizontal(|ui| {
                let dot_color = if self.snap.running {
                    SEMANTIC_OK
                } else {
                    TEXT_MUTED
                };
                let (dot_rect, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                ui.painter()
                    .circle_filled(dot_rect.center(), 3.5, dot_color);

                let status_txt = if self.snap.running {
                    if is_en { "Active" } else { "Активен" }
                } else if is_en {
                    "Stopped"
                } else {
                    "Остановлен"
                };
                ui.label(
                    RichText::new(status_txt)
                        .strong()
                        .size(11.0)
                        .color(if self.snap.running {
                            SEMANTIC_OK
                        } else {
                            TEXT_SECONDARY
                        }),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (btn_txt, btn_fill, btn_fg) = if self.snap.running {
                        (
                            if is_en { "Stop" } else { "Стоп" },
                            SEMANTIC_ERR,
                            Color32::WHITE,
                        )
                    } else {
                        (
                            if is_en { "Start" } else { "Запустить" },
                            TEXT_PRIMARY,
                            BG_DEEPEST,
                        )
                    };
                    if ui
                        .add_sized(
                            Vec2::new(84.0, 24.0),
                            egui::Button::new(
                                RichText::new(btn_txt).strong().size(11.0).color(btn_fg),
                            )
                            .fill(btn_fill),
                        )
                        .clicked()
                    {
                        self.dispatch_ipc("toggle_running", serde_json::json!({}));
                    }

                    if !self.snap.is_admin
                        && (self.snap.config.capture_mode == CaptureMode::Tun
                            || self.snap.active_mode.contains("фоллбэк"))
                    {
                        let uac_lbl = "UAC";
                        let uac_tip = if is_en {
                            "Relaunch Tachyon Desync as Administrator to activate Wintun L3 TUN adapter"
                        } else {
                            "Перезапустить Tachyon Desync от имени Администратора для работы адаптера Wintun L3 TUN"
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(uac_lbl)
                                        .strong()
                                        .size(10.0)
                                        .color(BG_DEEPEST),
                                )
                                .fill(SEMANTIC_WARN),
                            )
                            .on_hover_text(uac_tip)
                            .clicked()
                            && crate::tray::relaunch_as_admin()
                        {
                            crate::tray::request_app_exit();
                            self.tokio_handle.block_on(self.rt.stop());
                            std::process::exit(0);
                        }
                    }

                    let mut min_tray = self.snap.config.minimize_to_tray;
                    let tray_lbl = if is_en { "Tray" } else { "В трей" };
                    let tray_tip = if is_en {
                        "Minimize to system tray on window close [X]"
                    } else {
                        "При нажатии на крестик [X] сворачивать окно в системный трей без остановки десинка"
                    };
                    if Self::gpui_switch(ui, &mut min_tray, tray_lbl)
                        .on_hover_text(tray_tip)
                        .changed()
                    {
                        self.dispatch_ipc(
                            "set_minimize_to_tray",
                            serde_json::json!({ "minimize_to_tray": min_tray }),
                        );
                    }

                    let mut auto_on = self.autostart_enabled;
                    let auto_lbl = if is_en { "Autostart" } else { "Автозапуск" };
                    let auto_tip = if is_en {
                        "Start Tachyon Desync automatically with OS (minimized to tray)"
                    } else {
                        "Запускать Tachyon Desync автоматически при старте ОС (в трее)"
                    };
                    if Self::gpui_switch(ui, &mut auto_on, auto_lbl)
                        .on_hover_text(auto_tip)
                        .changed()
                    {
                        crate::tray::set_autostart_enabled(auto_on);
                        self.autostart_enabled = crate::tray::is_autostart_enabled();
                    }

                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        let mode_full = format!(
                            "— {}",
                            localize_active_mode(&self.snap.active_mode, is_en)
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(&mode_full).size(10.0).color(TEXT_SECONDARY),
                            )
                            .truncate(),
                        )
                        .on_hover_text(mode_full);
                    });
                });
            });

            ui.add_space(4.0);

            // Строка 3: Два ровных столбца (Режим перехвата | Стратегия вне списков)
            let cur_mode = self.snap.config.capture_mode;
            let cur_strat = self.snap.config.default_strategy.as_code();
            let mut next_capture_mode: Option<&'static str> = None;
            let mut next_def_strat: Option<String> = None;
            let header_custom_profiles: Vec<(String, String)> = self
                .snap
                .config
                .custom_profiles
                .iter()
                .map(|p| {
                    (
                        format!("profile:{}", p.id),
                        if is_en {
                            format!("[Profile] {}", p.name)
                        } else {
                            format!("[Профиль] {}", p.name)
                        },
                    )
                })
                .collect();
            let cur_strat_display = match cur_strat.as_str() {
                "auto" => {
                    if is_en {
                        "Auto (24 recipes)".to_string()
                    } else {
                        "Авто (24 рецепта)".to_string()
                    }
                }
                "direct" => {
                    if is_en {
                        "Direct (lists only)".to_string()
                    } else {
                        "Только списки".to_string()
                    }
                }
                "tlsrec" => "TlsRec Split".to_string(),
                "custom" => {
                    if is_en {
                        "Generator Profile".to_string()
                    } else {
                        "Профиль Генератора".to_string()
                    }
                }
                other => self.strategy_label(other, is_en),
            };

            ui.columns(2, |cols| {
                cols[0].horizontal(|ui| {
                    ui.label(
                        RichText::new(if is_en { "Capture:" } else { "Перехват:" })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                    );
                    let mode_text = match cur_mode {
                        CaptureMode::SystemProxy => {
                            if is_en {
                                "System Proxy (:7897)".to_string()
                            } else {
                                "Системный прокси (:7897)".to_string()
                            }
                        }
                        CaptureMode::Tun => {
                            #[cfg(target_os = "windows")]
                            let drv = "Wintun";
                            #[cfg(target_os = "macos")]
                            let drv = "utun";
                            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
                            let drv = "tun L3";
                            if is_en {
                                format!("TUN Adapter ({drv})")
                            } else {
                                format!("Адаптер TUN ({drv})")
                            }
                        }
                        CaptureMode::LocalProxy => {
                            if is_en {
                                "SOCKS5 / HTTP Only".to_string()
                            } else {
                                "Только SOCKS5 / HTTP".to_string()
                            }
                        }
                    };
                    let w = (ui.available_width() - 4.0).max(88.0);
                    egui::ComboBox::from_id_salt("combo_capture_mode")
                        .width(w)
                        .selected_text(RichText::new(mode_text).size(10.0))
                        .show_ui(ui, |ui| {
                            let modes = [
                                (
                                    "system_proxy",
                                    CaptureMode::SystemProxy,
                                    if is_en {
                                        "System Proxy (:7897)"
                                    } else {
                                        "Системный прокси (:7897)"
                                    },
                                ),
                                (
                                    "tun",
                                    CaptureMode::Tun,
                                    if is_en {
                                        "TUN Adapter (Wintun L3)"
                                    } else {
                                        "Адаптер TUN (Wintun L3)"
                                    },
                                ),
                                (
                                    "local_proxy",
                                    CaptureMode::LocalProxy,
                                    if is_en {
                                        "SOCKS5 / HTTP Only"
                                    } else {
                                        "Только SOCKS5 / HTTP"
                                    },
                                ),
                            ];
                            for (code, m_enum, label) in modes {
                                if ui.selectable_label(cur_mode == m_enum, label).clicked() {
                                    next_capture_mode = Some(code);
                                }
                            }
                        });
                });

                cols[1].horizontal(|ui| {
                    ui.label(
                        RichText::new(if is_en { "Default:" } else { "Вне списков:" })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                    );
                    let w = (ui.available_width() - 4.0).max(88.0);
                    egui::ComboBox::from_id_salt("combo_default_strategy")
                        .width(w)
                        .selected_text(RichText::new(cur_strat_display).size(10.0))
                        .show_ui(ui, |ui| {
                            let opts = [
                                (
                                    "auto",
                                    if is_en {
                                        "Auto (24 recipes)"
                                    } else {
                                        "Авто (24 рецепта)"
                                    },
                                ),
                                (
                                    "direct",
                                    if is_en {
                                        "Direct (lists only)"
                                    } else {
                                        "Прямое (только списки)"
                                    },
                                ),
                                ("tlsrec", "TlsRec (TLS Split)"),
                                (
                                    "custom",
                                    if is_en {
                                        "Generator Profile"
                                    } else {
                                        "Профиль Генератора"
                                    },
                                ),
                            ];
                            for (code, label) in opts {
                                if ui.selectable_label(cur_strat == code, label).clicked() {
                                    next_def_strat = Some(code.to_string());
                                }
                            }
                            for (p_code, p_lbl) in &header_custom_profiles {
                                if ui.selectable_label(&cur_strat == p_code, p_lbl).clicked() {
                                    next_def_strat = Some(p_code.clone());
                                }
                            }
                        });
                });
            });

            if let Some(code) = next_capture_mode {
                self.dispatch_ipc(
                    "set_capture_mode",
                    serde_json::json!({ "capture_mode": code }),
                );
            }
            if let Some(code) = next_def_strat {
                self.dispatch_ipc(
                    "set_default_strategy",
                    serde_json::json!({ "strategy": code }),
                );
            }

            ui.add_space(4.0);

            // Строка 4: Навигационные вкладки (активное состояние — спокойный шаг поверхности + рамка без цветной заливки)
            let live_cnt = self.snap.live_flows.iter().filter(|f| f.active).count();
            let lists_cnt = self.snap.config.lists.iter().filter(|l| l.enabled).count();
            let apps_cnt = self.snap.config.selected_apps.len();
            let logs_cnt = self.snap.logs.len();

            let tabs = [
                (
                    ActiveTab::Overview,
                    (if is_en { "Auto" } else { "Авто" }).to_string(),
                ),
                (
                    ActiveTab::Flows,
                    format!("{} ({})", if is_en { "Flows" } else { "Потоки" }, live_cnt),
                ),
                (
                    ActiveTab::Generator,
                    (if is_en { "Generator" } else { "Генератор" }).to_string(),
                ),
                (
                    ActiveTab::Lists,
                    if apps_cnt > 0 {
                        format!(
                            "{} ({}+{})",
                            if is_en { "Lists" } else { "Списки" },
                            lists_cnt,
                            apps_cnt
                        )
                    } else {
                        format!(
                            "{} ({})",
                            if is_en { "Lists" } else { "Списки" },
                            lists_cnt
                        )
                    },
                ),
                (ActiveTab::Dns, "DNS".to_string()),
                (
                    ActiveTab::Logs,
                    format!("{} ({})", if is_en { "Logs" } else { "Журнал" }, logs_cnt),
                ),
            ];

            let tk = active_tokens();
            Frame::new()
                .fill(tk.bg_deepest)
                .stroke(Stroke::new(1.0_f32, tk.border_subtle))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(Margin::same(2))
                .show(ui, |ui| {
                    ui.columns(tabs.len(), |cols| {
                        for (i, (tab_id, label)) in tabs.into_iter().enumerate() {
                            let is_active = self.active_tab == tab_id;
                            let fill = if is_active {
                                tk.bg_elevated
                            } else {
                                Color32::TRANSPARENT
                            };
                            let stroke = if is_active {
                                Stroke::new(1.0_f32, tk.border_strong)
                            } else {
                                Stroke::NONE
                            };
                            let text_col = if is_active {
                                TEXT_PRIMARY
                            } else {
                                TEXT_SECONDARY
                            };
                            let col_w = cols[i].available_width();
                            if cols[i]
                                .add_sized(
                                    Vec2::new(col_w, 22.0),
                                    egui::Button::new(
                                        RichText::new(label)
                                            .strong()
                                            .size(10.0)
                                            .color(text_col),
                                    )
                                    .fill(fill)
                                    .stroke(stroke)
                                    .corner_radius(CornerRadius::same(4)),
                                )
                                .clicked()
                            {
                                self.active_tab = tab_id;
                            }
                        }
                    });
                });
        });
    }

    fn render_tab_overview(&mut self, ui: &mut egui::Ui) {
        let is_en = self.is_en();

        // 1. Четыре карточки ключевых показателей (один акцент на главной метрике десинхронизации)
        ui.columns(4, |cols| {
            Self::card_frame(false).show(&mut cols[0], |ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Active flows"
                    } else {
                        "Активные потоки"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
                ui.label(
                    RichText::new(self.snap.active_connections.to_string())
                        .monospace()
                        .strong()
                        .size(16.0)
                        .color(TEXT_PRIMARY),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{} {}",
                            if is_en { "Total:" } else { "Всего:" },
                            self.snap.total_connections
                        ))
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    )
                    .truncate(),
                );
            });

            Self::card_frame(false).show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Desynced"
                    } else {
                        "После десинка"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
                ui.label(
                    RichText::new(self.snap.desynced_connections.to_string())
                        .monospace()
                        .strong()
                        .size(16.0)
                        .color(ACCENT),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(if is_en {
                            "Gate: 32 KB"
                        } else {
                            "Гейт: 32 КБ"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    )
                    .truncate(),
                );
            });

            Self::card_frame(false).show(&mut cols[2], |ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Traffic RX / TX"
                    } else {
                        "Трафик RX / TX"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{} / {}",
                            format_bytes(self.snap.rx_bytes, is_en),
                            format_bytes(self.snap.tx_bytes, is_en)
                        ))
                        .monospace()
                        .strong()
                        .size(11.0)
                        .color(TEXT_PRIMARY),
                    )
                    .truncate(),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "↓{} ↑{}",
                            format_rate_bps(self.cur_rx_bps, is_en),
                            format_rate_bps(self.cur_tx_bps, is_en)
                        ))
                        .monospace()
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    )
                    .truncate(),
                );
            });

            Self::card_frame(false).show(&mut cols[3], |ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Domain cache"
                    } else {
                        "Кэш доменов"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
                ui.label(
                    RichText::new(self.snap.learned_domains.len().to_string())
                        .monospace()
                        .strong()
                        .size(16.0)
                        .color(TEXT_PRIMARY),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(format_uptime(self.snap.uptime_sec))
                            .monospace()
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                    )
                    .truncate(),
                );
            });
        });

        // 2. 60-секундный график телеметрии (первый визуальный акцент — Moment 1)
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Telemetry (60s)"
                    } else {
                        "Телеметрия (60 с)"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .selectable_label(
                            self.chart_mode == ChartMode::Flows,
                            RichText::new(if is_en { "Flows" } else { "Потоки" }).size(10.0),
                        )
                        .clicked()
                    {
                        self.chart_mode = ChartMode::Flows;
                    }
                    if ui
                        .selectable_label(
                            self.chart_mode == ChartMode::Traffic,
                            RichText::new(if is_en { "Traffic" } else { "Трафик" }).size(10.0),
                        )
                        .clicked()
                    {
                        self.chart_mode = ChartMode::Traffic;
                    }
                });
            });
            self.draw_telemetry_chart(ui);
        });

        // 2.5. Активный DNS (сводка + быстрая автонастройка) и экспресс-проверка 6 ключевых узлов
        Self::panel_frame().show(ui, |ui| {
            let is_checking = self.health_in_progress.lock().map(|g| *g).unwrap_or(false);
            let is_dns_benching = self.dns_bench_state.lock().map(|g| g.running).unwrap_or(false);
            let mut trigger_hc = false;
            let mut trigger_dns_auto = false;
            let mut open_dns_tab = false;

            let dns_st = &self.snap.dns_status;
            let dns_dot_col = if !dns_st.enabled {
                TEXT_MUTED
            } else if dns_st.consecutive_failures > 0 {
                SEMANTIC_WARN
            } else {
                SEMANTIC_OK
            };
            let dns_proto_txt = if dns_st.enabled {
                format!(
                    "{} · {}",
                    dns_st.protocol.as_str().to_ascii_uppercase(),
                    if is_en {
                        dns_st.upstream_mode.label_en()
                    } else {
                        dns_st.upstream_mode.label_ru()
                    }
                )
            } else if is_en {
                "OS System DNS".to_string()
            } else {
                "Системный DNS ОС".to_string()
            };
            let dns_primary = if !dns_st.enabled {
                "-".to_string()
            } else if !dns_st.active_primary.is_empty() {
                dns_st.active_primary.clone()
            } else {
                self.snap
                    .config
                    .dns
                    .servers
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "-".to_string())
            };
            let dns_metrics = format!(
                "{}/{} {} · ~{} {}",
                dns_st.cache_hits,
                dns_st.total_queries,
                if is_en { "hits" } else { "кэш" },
                dns_st.approx_ram_kb,
                if is_en { "KiB" } else { "КиБ" },
            );

            ui.horizontal_wrapped(|ui| {
                let (dot_r, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                ui.painter().circle_filled(dot_r.center(), 3.0, dns_dot_col);
                ui.label(
                    RichText::new("DNS:")
                        .strong()
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                Self::keycap(ui, &dns_proto_txt);
                ui.add(
                    egui::Label::new(
                        RichText::new(&dns_primary)
                            .monospace()
                            .size(10.0)
                            .color(TEXT_PRIMARY),
                    )
                    .truncate(),
                );
                ui.label(
                    RichText::new(dns_metrics)
                        .monospace()
                        .size(9.5)
                        .color(TEXT_MUTED),
                );
            });

            ui.horizontal_wrapped(|ui| {
                let auto_dns_lbl = if is_dns_benching {
                    if is_en {
                        "Auto-tuning DNS..."
                    } else {
                        "Автонастройка DNS..."
                    }
                } else if is_en {
                    "DNS Auto-Tune"
                } else {
                    "Автонастройка DNS"
                };
                if ui
                    .add_enabled(
                        !is_dns_benching,
                        egui::Button::new(RichText::new(auto_dns_lbl).size(10.0).color(ACCENT)),
                    )
                    .on_hover_text(if is_en {
                        "Benchmark public UDP/DoT/DoH resolvers and automatically apply the optimal configuration"
                    } else {
                        "Протестировать публичные UDP/DoT/DoH резолверы, подобрать оптимальный профиль и перейти во вкладку DNS"
                    })
                    .clicked()
                {
                    trigger_dns_auto = true;
                }

                let cfg_dns_lbl = if is_en {
                    "DNS Settings"
                } else {
                    "Настройки DNS"
                };
                if ui
                    .add(egui::Button::new(
                        RichText::new(cfg_dns_lbl).size(10.0).color(TEXT_PRIMARY),
                    ))
                    .clicked()
                {
                    open_dns_tab = true;
                }

                let hc_lbl = if is_checking {
                    if is_en {
                        "Checking..."
                    } else {
                        "Проверка..."
                    }
                } else if is_en {
                    "Check Services (6)"
                } else {
                    "Проверить узлы (6)"
                };
                if ui
                    .add_enabled(!is_checking, Self::primary_button(hc_lbl))
                    .clicked()
                {
                    trigger_hc = true;
                }
            });

            if trigger_hc {
                self.start_health_check();
            }
            if trigger_dns_auto {
                self.active_tab = ActiveTab::Dns;
                self.start_dns_benchmark(true);
            } else if open_dns_tab {
                self.active_tab = ActiveTab::Dns;
            }

            let mut auto_rel = self.snap.config.auto_relearn;
            let mut toggle_rel: Option<bool> = None;
            let hosts_cnt = self.snap.config.dns_overrides.len();
            ui.horizontal_wrapped(|ui| {
                let rel_lbl = if is_en {
                    "Auto-relearn on RST/timeout"
                } else {
                    "Авто-переобучение при сбоях (RST)"
                };
                if Self::gpui_switch(ui, &mut auto_rel, rel_lbl)
                    .on_hover_text(if is_en {
                        "Automatically re-probe 8 recipes in the background when a domain suffers consecutive TCP RST / timeouts"
                    } else {
                        "При серии TCP RST или таймаутов автоматически перебирает рецепты в фоне и закрепляет новый рабочий"
                    })
                    .changed()
                {
                    toggle_rel = Some(auto_rel);
                }

                let hosts_btn_lbl = if is_en {
                    format!("Local hosts ({hosts_cnt})")
                } else {
                    format!("Локальный hosts ({hosts_cnt})")
                };
                if ui
                    .small_button(RichText::new(hosts_btn_lbl).size(10.0).color(TEXT_SECONDARY))
                    .on_hover_text(if is_en {
                        "Custom domain=IP overrides without modifying Windows system hosts file"
                    } else {
                        "Привязка домен=IP без правки системного файла C:\\Windows\\System32\\drivers\\etc\\hosts"
                    })
                    .clicked()
                {
                    self.show_dns_overrides_panel = !self.show_dns_overrides_panel;
                }
            });

            if let Some(en) = toggle_rel {
                self.dispatch_ipc("set_auto_relearn", serde_json::json!({ "enabled": en }));
            }

            if self.show_dns_overrides_panel {
                self.render_dns_overrides_editor(ui, is_en, "overview_dns_overrides");
            }

            let hc_items = self
                .health_results
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            if !hc_items.is_empty() {
                let mut probe_failed_domain: Option<String> = None;
                let hc_cols = if ui.available_width() < 480.0 { 2 } else { 3 };
                for row in hc_items.chunks(hc_cols) {
                    ui.columns(hc_cols, |cols| {
                        for (c_idx, item) in row.iter().enumerate() {
                            Self::card_frame(item.ok).show(&mut cols[c_idx], |ui| {
                                ui.horizontal(|ui| {
                                    let col = if item.ok { SEMANTIC_OK } else { SEMANTIC_ERR };
                                    let (dot_rect, _) =
                                        ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                                    ui.painter().circle_filled(dot_rect.center(), 3.0, col);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&item.name)
                                                .strong()
                                                .size(10.0)
                                                .color(TEXT_PRIMARY),
                                        )
                                        .truncate(),
                                    );
                                });
                                ui.horizontal(|ui| {
                                    if item.ok {
                                        ui.label(
                                            RichText::new(format!("{} ms", item.rtt_ms))
                                                .monospace()
                                                .size(10.0)
                                                .color(SEMANTIC_OK),
                                        );
                                    } else {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&item.detail)
                                                    .size(10.0)
                                                    .color(SEMANTIC_ERR),
                                            )
                                            .truncate(),
                                        );
                                        let fix_lbl = if is_en { "Probe" } else { "Подбор" };
                                        if ui
                                            .small_button(
                                                RichText::new(fix_lbl)
                                                    .size(10.0)
                                                    .color(TEXT_PRIMARY),
                                            )
                                            .on_hover_text(if is_en {
                                                "Open in Strategy Generator"
                                            } else {
                                                "Подобрать рецепт в Генераторе"
                                            })
                                            .clicked()
                                        {
                                            probe_failed_domain = Some(item.domain.clone());
                                        }
                                    }
                                });
                            });
                        }
                    });
                }
                if let Some(dom) = probe_failed_domain {
                    self.probe_domain = dom;
                    self.probe_port = 443;
                    self.packet_preview = inspect_client_hello_slices(&self.probe_domain);
                    self.active_tab = ActiveTab::Generator;
                    self.start_probe_scan(false);
                }
            }
        });

        ui.add_space(4.0);

        // 2.75. Компактная панель сетевого стека и производительности ядра (BBR / smoltcp / Happy Eyeballs)
        Self::panel_frame().show(ui, |ui| {
            let hw = hardware::HardwareProfile::detect();
            let init_kb = hardware::smol_tcp_init_buf() / 1024;
            let max_kb = hardware::smol_tcp_max_buf() / 1024;
            let last_rtt_ms = hardware::last_connect_rtt_us() / 1000;

            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Network Stack & Tuning"
                    } else {
                        "Сетевой стек и производительность"
                    })
                    .strong()
                    .size(12.0),
                );
                Self::keycap(
                    ui,
                    &format!(
                        "{} · {}..{} KiB · MTU {}",
                        self.snap.config.network.tcp_congestion.as_str().to_ascii_uppercase(),
                        init_kb,
                        max_kb,
                        self.snap.config.network.tun_mtu,
                    ),
                );
                let hw_info = if last_rtt_ms > 0 {
                    format!("{} MB · {} CPU · RTT {} ms", hw.total_ram_mb, hw.cpu_count, last_rtt_ms)
                } else {
                    format!("{} MB · {} CPU", hw.total_ram_mb, hw.cpu_count)
                };
                ui.label(RichText::new(hw_info).monospace().size(9.5).color(TEXT_MUTED));

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let adv_lbl = if self.show_net_tuning_panel {
                        if is_en { "Hide" } else { "Скрыть" }
                    } else if is_en {
                        "Tune"
                    } else {
                        "Настроить"
                    };
                    if ui
                        .small_button(RichText::new(adv_lbl).size(10.0).color(TEXT_SECONDARY))
                        .clicked()
                    {
                        self.show_net_tuning_panel = !self.show_net_tuning_panel;
                    }

                    if ui
                        .small_button(
                            RichText::new(if is_en { "Turbo 4K" } else { "Турбо 4K" })
                                .size(10.0)
                                .color(ACCENT),
                        )
                        .on_hover_text(if is_en {
                            "BBR + 2 MiB TUN auto-tune buffers + MSS Clamp + Happy Eyeballs v2 + 192 KiB Verify"
                        } else {
                            "Целочисленный BBR + буфер до 2 MiB + MSS Clamp + Happy Eyeballs v2 + зонд 192 KiB"
                        })
                        .clicked()
                    {
                        let turbo = NetworkTuningConfig {
                            tcp_congestion: TcpCongestionMode::Bbr,
                            tun_buffer_mode: TunBufferMode::Turbo2m,
                            tun_mss_clamp: true,
                            tun_mtu: self.net_draft.tun_mtu,
                            tun_ipv6: self.net_draft.tun_ipv6,
                            happy_eyeballs: true,
                            quic_fast_failover: true,
                            stream_verify_192k: true,
                        };
                        self.net_draft = turbo.clone();
                        self.net_dirty = false;
                        self.probe_stream_192k = true;
                        self.dispatch_ipc("update_network_tuning", serde_json::json!(turbo));
                        self.push_toast(
                            ToastKind::Success,
                            if is_en { "Turbo 4K profile applied" } else { "Профиль Турбо 4K применён" },
                            "BBR + 2 MiB + Happy Eyeballs v2",
                        );
                    }

                    if ui
                        .small_button(
                            RichText::new(if is_en { "Default" } else { "Базовый" })
                                .size(10.0)
                                .color(TEXT_SECONDARY),
                        )
                        .clicked()
                    {
                        let def = NetworkTuningConfig::default();
                        self.net_draft = def.clone();
                        self.net_dirty = false;
                        self.probe_stream_192k = def.stream_verify_192k;
                        self.dispatch_ipc("update_network_tuning", serde_json::json!(def));
                    }
                });
            });

            if self.show_net_tuning_panel {
                ui.add_space(4.0);
                ui.columns(3, |cols| {
                    cols[0].horizontal(|ui| {
                        ui.label(
                            RichText::new(if is_en { "TCP CC:" } else { "TCP перегрузка:" })
                                .size(10.0)
                                .color(TEXT_SECONDARY),
                        );
                        let cur_lbl = if is_en {
                            self.net_draft.tcp_congestion.label_en()
                        } else {
                            self.net_draft.tcp_congestion.label_ru()
                        };
                        egui::ComboBox::from_id_salt("net_tcp_cc_combo")
                            .width(124.0)
                            .selected_text(RichText::new(cur_lbl).size(10.0))
                            .show_ui(ui, |ui| {
                                for m in TcpCongestionMode::ALL {
                                    let lbl = if is_en { m.label_en() } else { m.label_ru() };
                                    if ui
                                        .selectable_label(self.net_draft.tcp_congestion == m, lbl)
                                        .clicked()
                                    {
                                        self.net_draft.tcp_congestion = m;
                                        self.net_dirty = true;
                                    }
                                }
                            });
                    });

                    cols[1].horizontal(|ui| {
                        ui.label(
                            RichText::new(if is_en { "TUN Buffer:" } else { "Буфер TUN:" })
                                .size(10.0)
                                .color(TEXT_SECONDARY),
                        );
                        let cur_lbl = if is_en {
                            self.net_draft.tun_buffer_mode.label_en()
                        } else {
                            self.net_draft.tun_buffer_mode.label_ru()
                        };
                        egui::ComboBox::from_id_salt("net_tun_buf_combo")
                            .width(136.0)
                            .selected_text(RichText::new(cur_lbl).size(10.0))
                            .show_ui(ui, |ui| {
                                for m in TunBufferMode::ALL {
                                    let lbl = if is_en { m.label_en() } else { m.label_ru() };
                                    if ui
                                        .selectable_label(self.net_draft.tun_buffer_mode == m, lbl)
                                        .clicked()
                                    {
                                        self.net_draft.tun_buffer_mode = m;
                                        self.net_dirty = true;
                                    }
                                }
                            });
                    });

                    cols[2].horizontal(|ui| {
                        ui.label(RichText::new("TUN MTU:").size(10.0).color(TEXT_SECONDARY));
                        if ui
                            .add(egui::DragValue::new(&mut self.net_draft.tun_mtu).range(1280..=9000))
                            .changed()
                        {
                            self.net_dirty = true;
                        }
                    });
                });

                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    if Self::gpui_switch(
                        ui,
                        &mut self.net_draft.tun_mss_clamp,
                        if is_en {
                            "MSS Clamp (IPv4 + IPv6 ext headers)"
                        } else {
                            "MSS Clamp (IPv4 + IPv6 заголовки)"
                        },
                    )
                    .changed()
                    {
                        self.net_dirty = true;
                    }
                    if Self::gpui_switch(
                        ui,
                        &mut self.net_draft.happy_eyeballs,
                        "Happy Eyeballs v2 (RFC 8305)",
                    )
                    .changed()
                    {
                        self.net_dirty = true;
                    }
                    if Self::gpui_switch(
                        ui,
                        &mut self.net_draft.quic_fast_failover,
                        if is_en {
                            "QUIC Fast Failover (Host+IP)"
                        } else {
                            "Быстрый откат QUIC (Хост+IP)"
                        },
                    )
                    .changed()
                    {
                        self.net_dirty = true;
                    }
                    if Self::gpui_switch(
                        ui,
                        &mut self.net_draft.tun_ipv6,
                        if is_en {
                            "TUN IPv6 Routing"
                        } else {
                            "IPv6 в TUN (fd00::)"
                        },
                    )
                    .changed()
                    {
                        self.net_dirty = true;
                    }
                    if Self::gpui_switch(
                        ui,
                        &mut self.net_draft.stream_verify_192k,
                        if is_en {
                            "192 KiB Stream Probe"
                        } else {
                            "Зонд 192 KiB (поток)"
                        },
                    )
                    .changed()
                    {
                        self.probe_stream_192k = self.net_draft.stream_verify_192k;
                        self.net_dirty = true;
                    }
                });

                if self.net_dirty {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(Self::primary_button(if is_en {
                                "Apply Stack Tuning"
                            } else {
                                "Применить настройки стека"
                            }))
                            .clicked()
                        {
                            let payload = self.net_draft.clone();
                            self.net_dirty = false;
                            self.dispatch_ipc("update_network_tuning", serde_json::json!(payload));
                            self.push_toast(
                                ToastKind::Success,
                                if is_en { "Stack tuning saved" } else { "Настройки стека сохранены" },
                                format!(
                                    "CC={}, MTU={}",
                                    self.net_draft.tcp_congestion.as_str(),
                                    self.net_draft.tun_mtu
                                ),
                            );
                        }
                        if ui.button(if is_en { "Discard" } else { "Отменить" }).clicked() {
                            self.net_draft = self.snap.config.network.clone();
                            self.net_dirty = false;
                        }
                    });
                }
            }
        });

        ui.add_space(4.0);

        // 3. Карточки сервисов и категорий (по умолчанию свёрнуты)
        Self::panel_frame().show(ui, |ui| {
            let total_lists = self.snap.config.lists.len();
            let enabled_lists = self.snap.config.lists.iter().filter(|l| l.enabled).count();

            ui.horizontal(|ui| {
                // Векторный шеврон состояния развёрнутости (без Unicode-квадратиков)
                let (chev_rect, chev_resp) =
                    ui.allocate_exact_size(Vec2::new(14.0, 14.0), Sense::click());
                let c = chev_rect.center();
                let chev_stroke = Stroke::new(1.4_f32, TEXT_SECONDARY);
                if self.show_services_on_overview {
                    ui.painter().line_segment(
                        [Pos2::new(c.x - 4.0, c.y - 1.5), Pos2::new(c.x, c.y + 2.5)],
                        chev_stroke,
                    );
                    ui.painter().line_segment(
                        [Pos2::new(c.x, c.y + 2.5), Pos2::new(c.x + 4.0, c.y - 1.5)],
                        chev_stroke,
                    );
                } else {
                    ui.painter().line_segment(
                        [Pos2::new(c.x - 1.5, c.y - 4.0), Pos2::new(c.x + 2.5, c.y)],
                        chev_stroke,
                    );
                    ui.painter().line_segment(
                        [Pos2::new(c.x + 2.5, c.y), Pos2::new(c.x - 1.5, c.y + 4.0)],
                        chev_stroke,
                    );
                }

                let hdr_text = if is_en {
                    format!("Services & Categories ({enabled_lists}/{total_lists})")
                } else {
                    format!("Сервисы и категории ({enabled_lists}/{total_lists})")
                };
                let title_resp = ui.add(
                    egui::Label::new(
                        RichText::new(hdr_text)
                            .strong()
                            .size(12.0)
                            .color(TEXT_PRIMARY),
                    )
                    .sense(Sense::click()),
                );
                if chev_resp.clicked() || title_resp.clicked() {
                    self.show_services_on_overview = !self.show_services_on_overview;
                }

                let toggle_lbl = if self.show_services_on_overview {
                    if is_en {
                        "Collapse"
                    } else {
                        "Свернуть"
                    }
                } else if is_en {
                    "Expand"
                } else {
                    "Развернуть"
                };
                if ui
                    .small_button(RichText::new(toggle_lbl).size(10.0).color(TEXT_SECONDARY))
                    .clicked()
                {
                    self.show_services_on_overview = !self.show_services_on_overview;
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .small_button(
                            RichText::new(if is_en {
                                "Lists & .exe"
                            } else {
                                "Списки и .exe"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        )
                        .clicked()
                    {
                        self.active_tab = ActiveTab::Lists;
                    }
                    if ui
                        .small_button(
                            RichText::new(if is_en {
                                "Generator"
                            } else {
                                "Генератор"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        )
                        .clicked()
                    {
                        self.active_tab = ActiveTab::Generator;
                    }
                });
            });

            if self.show_services_on_overview {
                ui.add_space(4.0);
                let lists_snapshot = self.snap.config.lists.clone();
                let all_strat_opts = self.all_strategy_options(is_en);
                let mut toggle_action: Option<(String, bool)> = None;
                let mut strat_action: Option<(String, String)> = None;
                let mut edit_action: Option<String> = None;

                let service_cols = if ui.available_width() >= 560.0 { 2 } else { 1 };
                for pair in lists_snapshot.chunks(service_cols) {
                    ui.columns(service_cols, |cols| {
                        for (col_idx, item) in pair.iter().enumerate() {
                            Self::card_frame(item.enabled).show(&mut cols[col_idx], |ui| {
                                ui.horizontal(|ui| {
                                    let mut en = item.enabled;
                                    if ui.checkbox(&mut en, "").changed() {
                                        toggle_action = Some((item.id.clone(), en));
                                    }
                                    let loc_name = localize_list_name(&item.id, &item.name, is_en);
                                    let loc_desc =
                                        localize_list_desc(&item.id, &item.description, is_en);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&loc_name)
                                                .strong()
                                                .size(11.0)
                                                .color(TEXT_PRIMARY),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(format!("{loc_name}\n{loc_desc}"));
                                });

                                ui.horizontal(|ui| {
                                    let cur_s = item.strategy.as_code();
                                    let combo_w = (ui.available_width() - 40.0).max(76.0);
                                    egui::ComboBox::from_id_salt(format!("q_strat_{}", item.id))
                                        .width(combo_w)
                                        .selected_text(
                                            RichText::new(resolve_strategy_label(
                                                &cur_s,
                                                &all_strat_opts,
                                                is_en,
                                            ))
                                            .size(10.0),
                                        )
                                        .show_ui(ui, |ui| {
                                            for (code, lbl) in &all_strat_opts {
                                                if ui
                                                    .selectable_label(&cur_s == code, lbl)
                                                    .clicked()
                                                {
                                                    strat_action =
                                                        Some((item.id.clone(), code.clone()));
                                                }
                                            }
                                        });

                                    let tip = if is_en {
                                        "Edit domain & subnet rules"
                                    } else {
                                        "Редактировать список доменов и подсетей"
                                    };
                                    if ui
                                        .small_button(
                                            RichText::new(format!("{}", item.entries.len()))
                                                .monospace()
                                                .size(10.0)
                                                .color(TEXT_MUTED),
                                        )
                                        .on_hover_text(tip)
                                        .clicked()
                                    {
                                        edit_action = Some(item.id.clone());
                                    }
                                });
                            });
                        }
                    });
                }

                if let Some((id, en)) = toggle_action {
                    self.dispatch_ipc(
                        "update_list",
                        serde_json::json!({ "id": id, "enabled": en }),
                    );
                }
                if let Some((id, st)) = strat_action {
                    self.dispatch_ipc(
                        "update_list",
                        serde_json::json!({ "id": id, "strategy": st }),
                    );
                }
                if let Some(id) = edit_action {
                    self.open_list_modal(Some(&id));
                }
            }
        });

        // 4. Закреплённые домены (без маркетингового штампа AdaptiveBrain)
        let learned = self.snap.learned_domains.clone();
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                let hdr_lbl = if is_en {
                    format!("Pinned Domains ({})", learned.len())
                } else {
                    format!("Закреплённые домены ({})", learned.len())
                };
                ui.label(RichText::new(hdr_lbl).strong().size(12.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .small_button(
                            RichText::new(if is_en {
                                "Reset All Cache"
                            } else {
                                "Сбросить весь кэш"
                            })
                            .size(10.0),
                        )
                        .clicked()
                    {
                        self.dispatch_ipc("clear_brain", serde_json::json!({}));
                        self.push_toast(
                            ToastKind::Info,
                            if is_en {
                                "Adaptive cache cleared"
                            } else {
                                "Кэш адаптивного подбора очищен"
                            },
                            "adaptive_cache.json",
                        );
                    }
                });
            });

            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let rst_dom_lbl = if is_en {
                        "Reset Domain"
                    } else {
                        "Сбросить домен"
                    };
                    if ui
                        .add_enabled(
                            !self.pin_host_input.trim().is_empty(),
                            egui::Button::new(RichText::new(rst_dom_lbl).size(10.0)),
                        )
                        .clicked()
                    {
                        let host = self.pin_host_input.trim().to_string();
                        self.pin_host_input.clear();
                        self.dispatch_ipc(
                            "remove_learned_domain",
                            serde_json::json!({ "host": host }),
                        );
                        self.push_toast(
                            ToastKind::Info,
                            if is_en {
                                "Domain cache reset"
                            } else {
                                "Кэш домена сброшен"
                            },
                            host,
                        );
                    }

                    let pin_btn_lbl = if is_en { "Pin" } else { "Закрепить" };
                    if ui.button(RichText::new(pin_btn_lbl).size(10.0)).clicked() {
                        let host = self.pin_host_input.trim().to_string();
                        if !host.is_empty() {
                            self.pin_host_input.clear();
                            self.dispatch_ipc(
                                "pin_domain_recipe",
                                serde_json::json!({
                                    "host": host,
                                    "recipe_id": self.pin_recipe_id
                                }),
                            );
                        }
                    }

                    let selected_recipe_title = self
                        .snap
                        .recipes_catalog
                        .iter()
                        .find(|r| r.id == self.pin_recipe_id)
                        .map(|r| format!("#{} {}", r.id, r.code))
                        .unwrap_or_else(|| format!("#{}", self.pin_recipe_id));

                    let catalog_clone = self.snap.recipes_catalog.clone();
                    egui::ComboBox::from_id_salt("combo_pin_recipe")
                        .width(148.0)
                        .selected_text(RichText::new(selected_recipe_title).size(10.0))
                        .show_ui(ui, |ui| {
                            for r in &catalog_clone {
                                let r_title = localize_recipe_title(r.id, &r.title, is_en);
                                if ui
                                    .selectable_label(
                                        self.pin_recipe_id == r.id,
                                        format!("#{:02} — {}", r.id, r_title),
                                    )
                                    .clicked()
                                {
                                    self.pin_recipe_id = r.id;
                                }
                            }
                        });

                    let hint = if is_en {
                        "Domain (googlevideo.com)"
                    } else {
                        "Домен (googlevideo.com)"
                    };
                    ui.add(
                        TextEdit::singleline(&mut self.pin_host_input)
                            .hint_text(hint)
                            .desired_width(ui.available_width().max(80.0)),
                    );
                });
            });

            if learned.is_empty() {
                ui.label(
                    RichText::new(if is_en {
                        "No pinned domains yet — open a service or run the generator"
                    } else {
                        "Нет закреплённых доменов — откройте сервис или запустите генератор"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
            } else {
                let mut remove_host: Option<String> = None;
                ScrollArea::vertical()
                    .id_salt("scroll_learned_domains")
                    .max_height(320.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for d in &learned {
                            Frame::new()
                                .fill(BG_ELEVATED)
                                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                                .corner_radius(CornerRadius::same(4))
                                .inner_margin(Margin::symmetric(8, 5))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                if ui
                                                    .small_button(RichText::new("×").size(10.0))
                                                    .clicked()
                                                {
                                                    remove_host = Some(d.host.clone());
                                                }

                                                Self::keycap(
                                                    ui,
                                                    &format!(
                                                        "#{:02} {}",
                                                        d.recipe_id, d.recipe_code
                                                    ),
                                                );

                                                let (badge_txt, badge_col) = if d.verified {
                                                    ("32K OK", SEMANTIC_OK)
                                                } else {
                                                    (
                                                        if is_en { "Probe" } else { "Тест" },
                                                        SEMANTIC_WARN,
                                                    )
                                                };
                                                ui.label(
                                                    RichText::new(badge_txt)
                                                        .monospace()
                                                        .size(10.0)
                                                        .color(badge_col),
                                                );

                                                let tier_short = if d.tier.starts_with("L1") {
                                                    "L1"
                                                } else {
                                                    "L2"
                                                };
                                                ui.label(
                                                    RichText::new(tier_short)
                                                        .monospace()
                                                        .size(9.5)
                                                        .color(TEXT_MUTED),
                                                );

                                                ui.with_layout(
                                                    Layout::left_to_right(Align::Center),
                                                    |ui| {
                                                        ui.add(
                                                            egui::Label::new(
                                                                RichText::new(&d.host)
                                                                    .monospace()
                                                                    .strong()
                                                                    .size(11.0)
                                                                    .color(TEXT_PRIMARY),
                                                            )
                                                            .truncate(),
                                                        )
                                                        .on_hover_text(format!(
                                                            "{} — {} ({})",
                                                            d.host, d.recipe_title, d.tier
                                                        ));
                                                    },
                                                );
                                            },
                                        );
                                    });
                                });
                            ui.add_space(3.0);
                        }
                    });

                if let Some(h) = remove_host {
                    self.dispatch_ipc(
                        "remove_learned_domain",
                        serde_json::json!({ "host": h.clone() }),
                    );
                    self.push_toast(
                        ToastKind::Info,
                        if is_en {
                            "Domain cache reset"
                        } else {
                            "Кэш домена сброшен"
                        },
                        h,
                    );
                }
            }
        });
    }

    fn draw_telemetry_chart(&self, ui: &mut egui::Ui) {
        let desired = Vec2::new(ui.available_width(), 80.0);
        let (rect, response) = ui.allocate_exact_size(desired, Sense::hover());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, CornerRadius::same(4), BG_DEEPEST);
        painter.rect_stroke(
            rect,
            CornerRadius::same(4),
            Stroke::new(1.0_f32, BORDER_SUBTLE),
            StrokeKind::Inside,
        );

        for i in 1..=2 {
            let y = rect.top() + rect.height() * (i as f32 / 3.0);
            painter.line_segment(
                [Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)],
                Stroke::new(1.0_f32, Color32::from_rgb(26, 26, 29)),
            );
        }

        let pad_top = 8.0;
        let pad_bot = 8.0;
        let plot_h = (rect.height() - pad_top - pad_bot).max(12.0);
        let step_x = rect.width() / (HISTORY_LEN.saturating_sub(1).max(1) as f32);

        // Один акцент на график (unslop Details Pass): ведущая серия в ACCENT, вторая — в нейтральном шаге
        if self.chart_mode == ChartMode::Traffic {
            let mut max_val = 1024.0_f64;
            for pt in &self.telemetry {
                max_val = max_val.max(pt.rx_bps).max(pt.tx_bps);
            }
            max_val *= 1.15;

            let mut rx_pts = Vec::with_capacity(HISTORY_LEN);
            let mut tx_pts = Vec::with_capacity(HISTORY_LEN);
            for (i, pt) in self.telemetry.iter().enumerate() {
                let x = rect.left() + (i as f32) * step_x;
                let ry = rect.top()
                    + pad_top
                    + plot_h * (1.0 - (pt.rx_bps / max_val).clamp(0.0, 1.0) as f32);
                let ty = rect.top()
                    + pad_top
                    + plot_h * (1.0 - (pt.tx_bps / max_val).clamp(0.0, 1.0) as f32);
                rx_pts.push(Pos2::new(x, ry));
                tx_pts.push(Pos2::new(x, ty));
            }

            if tx_pts.len() >= 2 {
                painter.add(egui::Shape::line(tx_pts, Stroke::new(1.2_f32, TEXT_MUTED)));
            }
            if rx_pts.len() >= 2 {
                painter.add(egui::Shape::line(rx_pts, Stroke::new(1.6_f32, ACCENT)));
            }
        } else {
            let mut max_flows = 4.0_f64;
            for pt in &self.telemetry {
                max_flows = max_flows
                    .max(pt.active_flows as f64)
                    .max(pt.desync_delta as f64);
            }
            max_flows *= 1.2;

            let bar_w = (step_x * 0.55).max(2.0);
            let mut flow_pts = Vec::with_capacity(HISTORY_LEN);
            for (i, pt) in self.telemetry.iter().enumerate() {
                let x = rect.left() + (i as f32) * step_x;
                if pt.desync_delta > 0 {
                    let bh = (plot_h
                        * ((pt.desync_delta as f64 / max_flows).clamp(0.0, 1.0) as f32))
                        .max(4.0);
                    let bar_rect = Rect::from_min_max(
                        Pos2::new(x - bar_w * 0.5, rect.bottom() - pad_bot - bh),
                        Pos2::new(x + bar_w * 0.5, rect.bottom() - pad_bot),
                    );
                    painter.rect_filled(
                        bar_rect,
                        CornerRadius::same(2),
                        Color32::from_rgba_unmultiplied(161, 161, 166, 52),
                    );
                }
                let fy = rect.top()
                    + pad_top
                    + plot_h * (1.0 - (pt.active_flows as f64 / max_flows).clamp(0.0, 1.0) as f32);
                flow_pts.push(Pos2::new(x, fy));
            }
            if flow_pts.len() >= 2 {
                painter.add(egui::Shape::line(flow_pts, Stroke::new(1.6_f32, ACCENT)));
            }
        }

        if let Some(pointer) = response.hover_pos()
            && rect.contains(pointer)
        {
            let rel_x = (pointer.x - rect.left()).clamp(0.0, rect.width());
            let idx = ((rel_x / rect.width()) * ((HISTORY_LEN - 1) as f32)).round() as usize;
            let idx = idx.min(self.telemetry.len().saturating_sub(1));
            if let Some(pt) = self.telemetry.get(idx) {
                let hx = rect.left() + (idx as f32) * step_x;
                painter.line_segment(
                    [Pos2::new(hx, rect.top()), Pos2::new(hx, rect.bottom())],
                    Stroke::new(1.0_f32, BORDER_STRONG),
                );
                let sec_ago = HISTORY_LEN.saturating_sub(1 + idx);
                let tip = format!(
                    "-{}s | RX: {} | TX: {} | Flows: {}",
                    sec_ago,
                    format_rate_bps(pt.rx_bps, self.is_en()),
                    format_rate_bps(pt.tx_bps, self.is_en()),
                    pt.active_flows
                );
                painter.text(
                    Pos2::new(rect.left() + 8.0, rect.top() + 8.0),
                    egui::Align2::LEFT_TOP,
                    tip,
                    FontId::new(10.0, FontFamily::Monospace),
                    TEXT_PRIMARY,
                );
            }
        }
    }

    fn render_tab_flows(&mut self, ui: &mut egui::Ui) {
        let is_en = self.is_en();

        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Live Connections"
                    } else {
                        "Активные соединения"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let clr_lbl = if is_en {
                        "Clear closed"
                    } else {
                        "Очистить закрытые"
                    };
                    if ui
                        .small_button(RichText::new(clr_lbl).size(10.0))
                        .clicked()
                    {
                        self.dispatch_ipc("clear_flows", serde_json::json!({}));
                    }
                    let act_lbl = if is_en {
                        "Active only"
                    } else {
                        "Только активные"
                    };
                    Self::gpui_switch(ui, &mut self.flows_only_active, act_lbl);
                });
            });

            // Шапка сортировки колонок DataTable (из gpui-kit/src/table/data_table.rs) + поиск
            ui.horizontal(|ui| {
                let hint = if is_en {
                    "Filter by .exe, domain or IP"
                } else {
                    "Поиск по .exe, домену или IP"
                };
                let search_w = (ui.available_width() - 252.0).max(96.0);
                ui.add(
                    TextEdit::singleline(&mut self.flow_filter)
                        .hint_text(hint)
                        .desired_width(search_w),
                );

                let sort_cols = [
                    (FlowSortColumn::Time, if is_en { "Time" } else { "Время" }),
                    (
                        FlowSortColumn::Traffic,
                        if is_en { "Traffic" } else { "Трафик" },
                    ),
                    (FlowSortColumn::App, ".exe"),
                    (FlowSortColumn::Host, if is_en { "Host" } else { "Хост" }),
                ];
                let tk = active_tokens();
                for (col, title) in sort_cols {
                    let is_cur = self.flow_sort_col == col;
                    let arrow = if is_cur {
                        if self.flow_sort_asc { " ▲" } else { " ▼" }
                    } else {
                        ""
                    };
                    let txt = format!("{title}{arrow}");
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(txt).monospace().size(9.5).color(if is_cur {
                                    tk.accent
                                } else {
                                    TEXT_SECONDARY
                                }),
                            )
                            .fill(if is_cur { tk.bg_elevated } else { tk.bg_deepest })
                            .small(),
                        )
                        .clicked()
                    {
                        if is_cur {
                            self.flow_sort_asc = !self.flow_sort_asc;
                        } else {
                            self.flow_sort_col = col;
                            self.flow_sort_asc = false;
                        }
                    }
                }
            });

            let query = self.flow_filter.trim().to_ascii_lowercase();
            let selected_apps_set: Vec<String> = self
                .snap
                .config
                .selected_apps
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();

            let mut filtered: Vec<_> = self
                .snap
                .live_flows
                .iter()
                .filter(|f| {
                    if self.flows_only_active && !f.active {
                        return false;
                    }
                    if query.is_empty() {
                        return true;
                    }
                    f.app_name.to_ascii_lowercase().contains(&query)
                        || f.host.to_ascii_lowercase().contains(&query)
                        || f.dst_addr.to_ascii_lowercase().contains(&query)
                        || f.action.to_ascii_lowercase().contains(&query)
                })
                .cloned()
                .collect();

            filtered.sort_by(|a, b| {
                let ord = match self.flow_sort_col {
                    FlowSortColumn::Time => a.started_ms.cmp(&b.started_ms),
                    FlowSortColumn::Traffic => {
                        (a.rx_bytes + a.tx_bytes).cmp(&(b.rx_bytes + b.tx_bytes))
                    }
                    FlowSortColumn::App => a
                        .app_name
                        .to_ascii_lowercase()
                        .cmp(&b.app_name.to_ascii_lowercase()),
                    FlowSortColumn::Host => a
                        .host
                        .to_ascii_lowercase()
                        .cmp(&b.host.to_ascii_lowercase()),
                };
                if self.flow_sort_asc {
                    ord
                } else {
                    ord.reverse()
                }
            });

            if filtered.is_empty() {
                ui.add_space(16.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "No matching flows — start capture and open an application"
                        } else {
                            "Нет активных потоков — запустите перехват и откройте приложение"
                        })
                        .size(11.0)
                        .color(TEXT_MUTED),
                    );
                });
                ui.add_space(16.0);
                return;
            }

            let mut toggle_app_action: Option<String> = None;
            let mut probe_domain_action: Option<(String, u16)> = None;
            let mut bypass_domain_action: Option<String> = None;

            let bypass_entries: Vec<String> = self
                .snap
                .config
                .lists
                .iter()
                .find(|l| l.id == "direct_bypass")
                .map(|l| l.entries.iter().map(|s| s.to_ascii_lowercase()).collect())
                .unwrap_or_default();

            let toggle_tip = if is_en {
                "Toggle .exe in Application Filter"
            } else {
                "Добавить / убрать .exe в фильтр приложений"
            };

            let flows_h = ui.available_height().max(320.0);
            ScrollArea::vertical()
                .id_salt("scroll_live_flows")
                .max_height(flows_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for f in &filtered {
                        Self::card_frame(f.active).show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                let dot_col = if f.active { SEMANTIC_OK } else { TEXT_MUTED };
                                let (dot_rect, _) =
                                    ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                                ui.painter().circle_filled(dot_rect.center(), 3.0, dot_col);
                                ui.label(
                                    RichText::new(format_hms(f.started_ms))
                                        .monospace()
                                        .size(10.0)
                                        .color(TEXT_MUTED),
                                );
                                ui.label(
                                    RichText::new(&f.proto)
                                        .monospace()
                                        .size(10.0)
                                        .color(TEXT_SECONDARY),
                                );

                                let is_known_app = f.app_name != "-" && !f.app_name.is_empty();
                                let in_filter = is_known_app
                                    && selected_apps_set
                                        .iter()
                                        .any(|a| a.eq_ignore_ascii_case(&f.app_name));
                                Self::keycap(ui, &f.app_name);
                                if is_known_app {
                                    let btn_lbl = if in_filter {
                                        if is_en { "In filter" } else { "В фильтре" }
                                    } else if is_en {
                                        "+ Filter"
                                    } else {
                                        "+ В фильтр"
                                    };
                                    if ui
                                        .small_button(RichText::new(btn_lbl).size(10.0))
                                        .on_hover_text(toggle_tip)
                                        .clicked()
                                    {
                                        toggle_app_action = Some(f.app_name.clone());
                                    }
                                }

                                let act_col = if f.desynced {
                                    SEMANTIC_OK
                                } else if f.action.contains("Block") {
                                    SEMANTIC_WARN
                                } else {
                                    TEXT_SECONDARY
                                };
                                ui.label(
                                    RichText::new(localize_runtime_text(&f.action, is_en))
                                        .monospace()
                                        .size(10.0)
                                        .color(act_col),
                                );

                                ui.label(
                                    RichText::new(format!(
                                        "↓{} ↑{}",
                                        format_bytes(f.rx_bytes, is_en),
                                        format_bytes(f.tx_bytes, is_en)
                                    ))
                                    .monospace()
                                    .size(10.0)
                                    .color(TEXT_SECONDARY),
                                );

                                let host_clean = f.host.split(':').next().unwrap_or(&f.host).trim();
                                let is_domain = !host_clean.is_empty()
                                    && host_clean != "-"
                                    && host_clean.contains('.')
                                    && host_clean.parse::<std::net::IpAddr>().is_err();
                                if is_domain {
                                    let dst_port = f
                                        .dst_addr
                                        .rsplit(':')
                                        .next()
                                        .and_then(|p| p.parse::<u16>().ok())
                                        .unwrap_or(443);
                                    let probe_lbl = if is_en { "Probe" } else { "В генератор" };
                                    if ui
                                        .small_button(
                                            RichText::new(probe_lbl)
                                                .size(10.0)
                                                .color(TEXT_PRIMARY),
                                        )
                                        .on_hover_text(if is_en {
                                            "Probe and generate optimal recipe for this domain"
                                        } else {
                                            "Открыть домен в генераторе стратегий и подобрать рецепт"
                                        })
                                        .clicked()
                                    {
                                        probe_domain_action =
                                            Some((host_clean.to_string(), dst_port));
                                    }

                                    let is_bypassed = bypass_entries
                                        .iter()
                                        .any(|b| b.eq_ignore_ascii_case(host_clean));
                                    let byp_lbl = if is_bypassed {
                                        if is_en { "Bypassed" } else { "Исключён" }
                                    } else if is_en {
                                        "Bypass"
                                    } else {
                                        "Исключить"
                                    };
                                    if ui
                                        .small_button(RichText::new(byp_lbl).size(10.0))
                                        .on_hover_text(if is_en {
                                            "Add / remove domain in Direct (Bypass) list"
                                        } else {
                                            "Добавить / убрать домен в список прямого соединения (без десинка)"
                                        })
                                        .clicked()
                                    {
                                        bypass_domain_action = Some(host_clean.to_string());
                                    }
                                }
                            });

                            let target_line = if f.host == f.dst_addr
                                || f.dst_addr.starts_with(&f.host)
                            {
                                f.dst_addr.clone()
                            } else {
                                format!("{}  ->  {}", f.host, f.dst_addr)
                            };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(target_line)
                                        .monospace()
                                        .size(10.0)
                                        .color(TEXT_PRIMARY),
                                )
                                .wrap(),
                            );
                        });
                    }
                });

            if let Some(app) = toggle_app_action {
                self.dispatch_ipc("toggle_app", serde_json::json!({ "app": app }));
            }
            if let Some(host) = bypass_domain_action {
                self.dispatch_ipc(
                    "toggle_domain_bypass",
                    serde_json::json!({ "host": host }),
                );
            }
            if let Some((dom, port)) = probe_domain_action {
                self.probe_domain = dom;
                self.probe_port = port;
                self.packet_preview = inspect_client_hello_slices(&self.probe_domain);
                self.active_tab = ActiveTab::Generator;
                self.start_probe_scan(false);
            }
        });
    }

    fn effective_probe_domain(&self) -> String {
        let domain = self.probe_domain.trim();
        if domain.is_empty() {
            "www.youtube.com".to_string()
        } else {
            domain.to_string()
        }
    }

    fn start_health_check(&mut self) {
        let Some(busy_guard) = try_acquire_busy(&self.health_in_progress) else {
            return;
        };
        let cfg = self.snap.config.custom_global_config.clone();
        let rt = self.rt.clone();
        let results_slot = self.health_results.clone();

        self.tokio_handle.spawn(async move {
            let _busy_guard = busy_guard;
            let items = run_services_health_check(&cfg).await;
            let ok_cnt = items.iter().filter(|i| i.ok).count();
            rt.push_log(
                "info",
                "probe",
                &format!(
                    "Экспресс-диагностика сервисов завершена: доступно {ok_cnt}/{} узлов",
                    items.len()
                ),
            );
            if let Ok(mut g) = results_slot.lock() {
                *g = items;
            }
        });
    }

    fn start_probe_scan(&mut self, scan_all: bool) {
        let Some(busy_guard) = try_acquire_busy(&self.probe_in_progress) else {
            return;
        };
        let domain = self.effective_probe_domain();
        self.packet_preview = inspect_client_hello_slices(&domain);

        let port = self.probe_port;
        let stream_verify = self.probe_stream_192k;
        let rt = self.rt.clone();
        let report_slot = self.probe_report.clone();

        self.tokio_handle.spawn(async move {
            let _busy_guard = busy_guard;
            if let Ok(rep) =
                generate_domain_strategy_with_options(&domain, port, scan_all, 2500, stream_verify)
                    .await
            {
                rt.push_log(
                    "info",
                    "probe",
                    &format!("Генератор стратегий ({domain}:{port}): {}", rep.diagnosis),
                );
                if let Ok(mut guard) = report_slot.lock() {
                    *guard = Some(rep);
                }
            }
        });
    }

    fn start_custom_builder_probe(&mut self) {
        let Some(busy_guard) = try_acquire_busy(&self.probe_in_progress) else {
            return;
        };
        let domain = self.effective_probe_domain();
        let port = self.probe_port;
        let stream_verify = self.probe_stream_192k;
        let cfg = self.builder_cfg.clone();
        let rt = self.rt.clone();
        let report_slot = self.probe_report.clone();

        self.tokio_handle.spawn(async move {
            let _busy_guard = busy_guard;
            if let Ok(rep) =
                probe_custom_strategy_with_options(&domain, port, &cfg, 2500, stream_verify).await
            {
                rt.push_log(
                    if rep.passed_count > 0 { "info" } else { "warn" },
                    "probe",
                    &rep.diagnosis,
                );
                if let Ok(mut guard) = report_slot.lock() {
                    *guard = Some(rep);
                }
            }
        });
    }

    fn start_ttl_calibration(&mut self) {
        let Some(busy_guard) = try_acquire_busy(&self.ttl_calib_in_progress) else {
            return;
        };
        let domain = self.effective_probe_domain();
        let port = self.probe_port;
        let rt = self.rt.clone();
        let report_slot = self.ttl_calib_report.clone();

        self.tokio_handle.spawn(async move {
            let _busy_guard = busy_guard;
            if let Ok(rep) = calibrate_optimal_ttl(&domain, port).await {
                let _ = rt
                    .handle_ipc_action(
                        "apply_calibrated_ttl",
                        serde_json::json!({ "ttl": rep.optimal_ttl }),
                    )
                    .await;
                rt.push_log("info", "ttl", &rep.summary);
                if let Ok(mut guard) = report_slot.lock() {
                    *guard = Some(rep);
                }
            }
        });
    }

    fn render_tab_generator(&mut self, ui: &mut egui::Ui) {
        let is_en = self.is_en();
        let is_probing = self.probe_in_progress.lock().map(|g| *g).unwrap_or(false);
        let is_calib_ttl = self
            .ttl_calib_in_progress
            .lock()
            .map(|g| *g)
            .unwrap_or(false);

        // 1. Панель генератора стратегий (24 рецепта)
        Self::panel_frame().show(ui, |ui| {
            ui.label(
                RichText::new(if is_en {
                    "Strategy Generator (24 recipes)"
                } else {
                    "Генератор стратегий (24 рецепта)"
                })
                .strong()
                .size(12.0),
            );
            ui.add(
                egui::Label::new(
                    RichText::new(if is_en {
                        "Parallel TLS 1.3 probing, route classification and strategy synthesis"
                    } else {
                        "Параллельное зондирование TLS 1.3, диагностика фильтрации и синтез стратегии"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                )
                .wrap(),
            );

            ui.horizontal(|ui| {
                let dom_w = (ui.available_width() - 296.0).max(84.0);
                let resp = ui.add(
                    TextEdit::singleline(&mut self.probe_domain)
                        .hint_text("www.youtube.com")
                        .desired_width(dom_w),
                );
                if resp.changed() {
                    self.packet_preview = inspect_client_hello_slices(&self.probe_domain);
                }

                ui.add(
                    egui::DragValue::new(&mut self.probe_port)
                        .range(1..=65535)
                        .prefix(":"),
                );

                ui.add_enabled_ui(!is_probing && !is_calib_ttl, |ui| {
                    let full_lbl = if is_probing {
                        if is_en { "Scan..." } else { "Скан..." }
                    } else if is_en {
                        "Generate (24)"
                    } else {
                        "Подобрать (24)"
                    };
                    if ui.add(Self::primary_button(full_lbl)).clicked() {
                        self.start_probe_scan(true);
                    }

                    let quick_lbl = if is_en { "Quick (12)" } else { "Быстрый (12)" };
                    if ui.button(quick_lbl).clicked() {
                        self.start_probe_scan(false);
                    }

                    let ttl_lbl = if is_calib_ttl {
                        "TTL..."
                    } else if is_en {
                        "Auto-TTL"
                    } else {
                        "Авто-TTL"
                    };
                    let ttl_tip = if is_en {
                        "Probe hops (TTL 2..10) to find exact distance past transit filter and auto-apply fake_ttl / udp_fake_ttl"
                    } else {
                        "Авто-калибровка дистанции в хопах (TTL 2..10) до транзитного узла с авто-установкой fake_ttl и udp_fake_ttl"
                    };
                    if ui.button(ttl_lbl).on_hover_text(ttl_tip).clicked() {
                        self.start_ttl_calibration();
                    }
                });
            });

            ui.horizontal_wrapped(|ui| {
                let sv_lbl = if is_en {
                    "Stream Verify 192 KiB (detect 64..128 KiB CDN/video caps)"
                } else {
                    "Потоковый зонд 192 KiB (выявление отложенных лимитов видео/CDN)"
                };
                Self::gpui_switch(ui, &mut self.probe_stream_192k, sv_lbl);
            });

            // Если выполнена авто-калибровка TTL — отображаем компактную шкалу хопов 2..10 (один акцент на найденном хопе)
            let ttl_rep_opt = self.ttl_calib_report.lock().ok().and_then(|g| g.clone());
            if let Some(ref tr) = ttl_rep_opt {
                Self::card_frame(true).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(if is_en {
                                format!("Auto-TTL: {}", tr.optimal_ttl)
                            } else {
                                format!("Авто-TTL: {}", tr.optimal_ttl)
                            })
                            .monospace()
                            .strong()
                            .size(11.0)
                            .color(ACCENT),
                        );
                        ui.label(
                            RichText::new(localize_runtime_text(&tr.summary, is_en))
                                .size(10.0)
                                .color(TEXT_PRIMARY),
                        );
                    });
                    ui.horizontal_wrapped(|ui| {
                        for p in &tr.probes {
                            let is_opt = p.ttl == tr.optimal_ttl;
                            let col = if is_opt {
                                ACCENT
                            } else if p.ok {
                                TEXT_PRIMARY
                            } else {
                                TEXT_MUTED
                            };
                            ui.label(
                                RichText::new(format!(
                                    "[TTL={}: {}]",
                                    p.ttl,
                                    if p.ok {
                                        "OK"
                                    } else if p.status == "tls_alert" {
                                        "SRV"
                                    } else {
                                        "DROP"
                                    }
                                ))
                                .monospace()
                                .size(10.0)
                                .color(col),
                            );
                        }
                    });
                });
            }

            // Быстрые чипы целей и управление кэшем AdaptiveBrain
            ui.horizontal_wrapped(|ui| {
                let targets = [
                    ("youtube.com", "www.youtube.com"),
                    ("googlevideo CDN", "rr1---sn-gvnuxaxjvh-n8v6.googlevideo.com"),
                    ("discord.com", "discord.com"),
                    ("discordapp CDN", "cdn.discordapp.com"),
                    ("x.com", "x.com"),
                    ("rutracker.org", "rutracker.org"),
                    ("chatgpt.com", "chatgpt.com"),
                ];
                for (lbl, dom) in targets {
                    if ui
                        .small_button(RichText::new(lbl).monospace().size(10.0))
                        .clicked()
                    {
                        self.probe_domain = dom.to_string();
                        self.packet_preview = inspect_client_hello_slices(&self.probe_domain);
                    }
                }
                ui.separator();
                let rst_dom_lbl = if is_en {
                    "Reset Domain Cache"
                } else {
                    "Сбросить кэш домена"
                };
                if ui
                    .small_button(RichText::new(rst_dom_lbl).size(10.0))
                    .on_hover_text(if is_en {
                        "Remove learned recipe and ban mask for the current domain in adaptive_cache.json"
                    } else {
                        "Удалить сохранённый рецепт и маску отбраковки для текущего домена из adaptive_cache.json"
                    })
                    .clicked()
                {
                    let dom = self.probe_domain.trim().to_string();
                    if !dom.is_empty() {
                        self.dispatch_ipc(
                            "remove_learned_domain",
                            serde_json::json!({ "host": dom.clone() }),
                        );
                        self.push_toast(
                            ToastKind::Info,
                            if is_en {
                                "Domain cache reset"
                            } else {
                                "Кэш домена сброшен"
                            },
                            dom,
                        );
                    }
                }
                let rst_all_lbl = if is_en {
                    "Reset All Cache"
                } else {
                    "Сбросить весь кэш"
                };
                if ui
                    .small_button(RichText::new(rst_all_lbl).size(10.0))
                    .on_hover_text(if is_en {
                        "Clear all AdaptiveBrain entries and flush adaptive_cache.json"
                    } else {
                        "Полностью очистить кэш адаптивного подбора и перезаписать adaptive_cache.json"
                    })
                    .clicked()
                {
                    self.dispatch_ipc("clear_brain", serde_json::json!({}));
                    self.push_toast(
                        ToastKind::Info,
                        if is_en {
                            "Adaptive cache cleared"
                        } else {
                            "Кэш адаптивного подбора очищен"
                        },
                        "adaptive_cache.json",
                    );
                }
            });

            // Карточка синтезированного результата
            let report_opt = self.probe_report.lock().ok().and_then(|g| g.clone());

            if let Some(ref rep) = report_opt {
                self.packet_preview = rep.packet_preview.clone();
                Self::card_frame(true).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let badge_txt = if let Some(id) = rep.best_recipe_id {
                            format!("{} #{:02}", if is_en { "Recipe" } else { "Рецепт" }, id)
                        } else if is_en {
                            "Recommended".to_string()
                        } else {
                            "Рекомендовано".to_string()
                        };
                        Self::keycap(ui, &badge_txt);
                        if !rep.resolved_ip.is_empty() {
                            ui.label(
                                RichText::new(format!("{} ({})", rep.domain, rep.resolved_ip))
                                    .monospace()
                                    .size(10.0)
                                    .color(TEXT_SECONDARY),
                            );
                        }
                    });
                    ui.add(
                        egui::Label::new(
                            RichText::new(localize_runtime_text(&rep.diagnosis, is_en))
                                .size(10.0)
                                .color(TEXT_PRIMARY),
                        )
                        .wrap(),
                    );
                    ui.horizontal_wrapped(|ui| {
                        let apply_lbl = if is_en {
                            "Apply as Global"
                        } else {
                            "Применить как основной"
                        };
                        if ui.add(Self::primary_button(apply_lbl)).clicked() {
                            self.builder_cfg = rep.recommended_config.clone();
                            self.builder_dirty = false;
                            if let Ok(val) = serde_json::to_value(&self.builder_cfg) {
                                self.dispatch_ipc("update_global_desync", val);
                            }
                        }
                        let to_b_lbl = if is_en {
                            "To Builder"
                        } else {
                            "В конструктор"
                        };
                        if ui.small_button(to_b_lbl).clicked() {
                            self.builder_cfg = rep.recommended_config.clone();
                            self.builder_dirty = true;
                            self.selected_profile_id = None;
                            if self.builder_profile_name.trim().is_empty() {
                                self.builder_profile_name = if let Some(id) = rep.best_recipe_id {
                                    format!("{} #{:02}", rep.domain, id)
                                } else {
                                    rep.domain.clone()
                                };
                            }
                        }
                        let save_prof_lbl = if is_en {
                            "+ Save as Profile"
                        } else {
                            "+ В мои профили"
                        };
                        let save_prof_tip = if is_en {
                            "Save synthesized strategy as a named profile assignable to any domain list or .exe"
                        } else {
                            "Сохранить синтезированную стратегию как отдельный именованный профиль для списков доменов и .exe"
                        };
                        if ui
                            .small_button(RichText::new(save_prof_lbl).color(ACCENT))
                            .on_hover_text(save_prof_tip)
                            .clicked()
                        {
                            let prof_name = if !self.builder_profile_name.trim().is_empty() {
                                self.builder_profile_name.trim().to_string()
                            } else if let Some(id) = rep.best_recipe_id {
                                format!("{} #{:02}", rep.domain, id)
                            } else {
                                rep.domain.clone()
                            };
                            self.builder_cfg = rep.recommended_config.clone();
                            self.builder_profile_name = prof_name.clone();
                            self.builder_dirty = false;
                            self.dispatch_ipc(
                                "save_custom_profile",
                                serde_json::json!({
                                    "name": prof_name,
                                    "config": rep.recommended_config
                                }),
                            );
                            if let Some(saved) = self
                                .snap
                                .config
                                .custom_profiles
                                .iter()
                                .find(|p| p.name.eq_ignore_ascii_case(&prof_name))
                            {
                                self.selected_profile_id = Some(saved.id.clone());
                            }
                            self.push_toast(
                                ToastKind::Success,
                                if is_en {
                                    format!("Profile saved: {prof_name}")
                                } else {
                                    format!("Профиль сохранён: {prof_name}")
                                },
                                if is_en {
                                    "Available in all Lists and .exe dropdowns"
                                } else {
                                    "Доступен в выпадающих списках доменов и .exe"
                                },
                            );
                        }
                        let toast_active = self
                            .copied_toast_until
                            .map(|t| Instant::now() < t)
                            .unwrap_or(false);
                        let cp_lbl = if toast_active {
                            if is_en { "Copied ✓" } else { "Скопировано ✓" }
                        } else if is_en {
                            "Copy JSON"
                        } else {
                            "Копировать JSON"
                        };
                        if ui.small_button(cp_lbl).clicked() {
                            let json_str = build_outbound_json_string(&rep.recommended_config);
                            ui.ctx().copy_text(json_str);
                            self.copied_toast_until =
                                Some(Instant::now() + Duration::from_millis(1500));
                        }
                        let rep_lbl = if is_en {
                            "Copy Report"
                        } else {
                            "Копировать отчёт"
                        };
                        if ui.small_button(rep_lbl).clicked() {
                            let mut lines = Vec::new();
                            lines.push(format!(
                                "Tachyon Desync v{} — {} ({})",
                                env!("CARGO_PKG_VERSION"),
                                rep.domain,
                                rep.resolved_ip
                            ));
                            lines.push(localize_runtime_text(&rep.diagnosis, is_en));
                            for r in &rep.results {
                                let st = if r.ok { "OK" } else { r.block_reason.as_str() };
                                let title =
                                    localize_recipe_title(r.recipe_id, &r.recipe_title, is_en);
                                lines.push(format!(
                                    "#{:02} [{}] {} ms — {} ({})",
                                    r.recipe_id,
                                    st,
                                    r.rtt_ms,
                                    title,
                                    localize_runtime_text(&r.detail, is_en)
                                ));
                            }
                            ui.ctx().copy_text(lines.join("\n"));
                            self.copied_toast_until =
                                Some(Instant::now() + Duration::from_millis(1500));
                        }
                    });
                });

                if !rep.results.is_empty() {
                    let use_lbl = if is_en { "Use" } else { "Взять" };
                    ScrollArea::vertical()
                        .id_salt("scroll_probe_results")
                        .max_height(144.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for r in &rep.results {
                                Self::card_frame(r.ok).show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        let (st_txt, st_col) = if r.ok {
                                            ("32K OK", SEMANTIC_OK)
                                        } else if r.block_reason == "cap_16k" {
                                            ("CAP <32K", SEMANTIC_WARN)
                                        } else {
                                            (r.block_reason.as_str(), SEMANTIC_ERR)
                                        };
                                        ui.label(
                                            RichText::new(st_txt)
                                                .monospace()
                                                .strong()
                                                .size(10.0)
                                                .color(st_col),
                                        );
                                        ui.label(
                                            RichText::new(format!("{} ms", r.rtt_ms))
                                                .monospace()
                                                .size(10.0)
                                                .color(TEXT_SECONDARY),
                                        );
                                        if ui.small_button(use_lbl).clicked() {
                                            self.builder_cfg = r.config.clone();
                                            self.builder_dirty = true;
                                            self.selected_profile_id = None;
                                            if self.builder_profile_name.trim().is_empty() {
                                                self.builder_profile_name =
                                                    format!("{} #{:02}", rep.domain, r.recipe_id);
                                            }
                                        }
                                        let loc_title = localize_recipe_title(
                                            r.recipe_id,
                                            &r.recipe_title,
                                            is_en,
                                        );
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(format!(
                                                    "#{:02} {}",
                                                    r.recipe_id, loc_title
                                                ))
                                                .monospace()
                                                .size(10.0)
                                                .color(TEXT_PRIMARY),
                                            )
                                            .wrap(),
                                        )
                                        .on_hover_text(localize_runtime_text(&r.detail, is_en));
                                    });
                                });
                            }
                        });
                }
            }

            // Визуальная анатомия разреза пакета TLS 1.3 ClientHello (Moment 2)
            self.draw_packet_slicer(ui);
        });

        // 2. Конструктор стратегий (основной профиль + неограниченные именованные профили)
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Strategy & Profile Builder"
                    } else {
                        "Конструктор стратегий и профилей"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let save_lbl = if is_en {
                        "Save Global"
                    } else {
                        "Сохранить основной"
                    };
                    if ui
                        .add(Self::primary_button(save_lbl))
                        .on_hover_text(if is_en {
                            "Save into the global 'Generator Profile' slot"
                        } else {
                            "Сохранить параметры в основной слот «Профиль Генератора»"
                        })
                        .clicked()
                    {
                        self.builder_dirty = false;
                        if let Ok(val) = serde_json::to_value(&self.builder_cfg) {
                            self.dispatch_ipc("update_global_desync", val);
                            self.push_toast(
                                ToastKind::Success,
                                if is_en {
                                    "Global profile updated"
                                } else {
                                    "Основной профиль сохранён"
                                },
                                format!(
                                    "{} + {}, TTL={}",
                                    self.builder_cfg.mode,
                                    self.builder_cfg.fooling,
                                    self.builder_cfg.fake_ttl
                                ),
                            );
                        }
                    }

                    let test_lbl = if is_en { "Test" } else { "Тест" };
                    if ui
                        .add_enabled(
                            !is_probing,
                            egui::Button::new(RichText::new(test_lbl).size(10.0)),
                        )
                        .clicked()
                    {
                        self.start_custom_builder_probe();
                    }

                    let copy_lbl = if self.copied_toast_until.is_some_and(|t| Instant::now() < t) {
                        if is_en {
                            "Copied"
                        } else {
                            "Скопировано"
                        }
                    } else {
                        "JSON"
                    };
                    if ui.small_button(copy_lbl).clicked() {
                        let json_str = build_outbound_json_string(&self.builder_cfg);
                        ui.ctx().copy_text(json_str);
                        self.copied_toast_until =
                            Some(Instant::now() + Duration::from_millis(1500));
                    }
                });
            });

            // Управление именованными пользовательскими профилями (для назначения разным спискам и .exe)
            let saved_profiles = self.snap.config.custom_profiles.clone();
            let mut save_named_clicked = false;
            let mut load_profile_id: Option<String> = None;
            let mut delete_profile_id: Option<(String, String)> = None;

            Self::card_frame(!saved_profiles.is_empty()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(if is_en {
                            format!("Saved Profiles ({}):", saved_profiles.len())
                        } else {
                            format!("Мои профили ({}):", saved_profiles.len())
                        })
                        .strong()
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                    let has_sel = self.selected_profile_id.is_some();
                    let right_reserve = if has_sel { 184.0 } else { 132.0 };
                    let inp_w = (ui.available_width() - right_reserve).max(96.0);
                    let resp = ui.add(
                        TextEdit::singleline(&mut self.builder_profile_name)
                            .hint_text(if is_en {
                                "Profile name (e.g. YouTube CDN, Discord TTL4)..."
                            } else {
                                "Имя профиля (напр. YouTube CDN, Discord TTL4)..."
                            })
                            .desired_width(inp_w),
                    );
                    let enter_save = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));

                    let save_p_lbl = if has_sel {
                        if is_en {
                            "Update Profile"
                        } else {
                            "Обновить профиль"
                        }
                    } else if is_en {
                        "+ Save Profile"
                    } else {
                        "+ Сохранить профиль"
                    };
                    if ui.button(RichText::new(save_p_lbl).size(10.0)).clicked() || enter_save {
                        save_named_clicked = true;
                    }
                    if has_sel
                        && ui
                            .small_button(if is_en { "New" } else { "Новый" })
                            .on_hover_text(if is_en {
                                "Unlink from selected profile to save as a new separate profile"
                            } else {
                                "Снять выбор текущего профиля, чтобы сохранить настройки как новый"
                            })
                            .clicked()
                    {
                        self.selected_profile_id = None;
                        self.builder_profile_name.clear();
                    }
                });

                if saved_profiles.is_empty() {
                    ui.label(
                        RichText::new(if is_en {
                            "Save multiple custom strategies here and assign each one independently in Lists or .exe filter"
                        } else {
                            "Сохраняйте любое число своих стратегий и назначайте каждую отдельно в «Списках» или для нужных .exe"
                        })
                        .size(9.5)
                        .color(TEXT_MUTED),
                    );
                } else {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);
                        let tk = active_tokens();
                        for p in &saved_profiles {
                            let is_sel = self
                                .selected_profile_id
                                .as_deref()
                                .is_some_and(|id| id.eq_ignore_ascii_case(&p.id));
                            let chip_lbl = format!("{} ({})", p.name, p.config.mode);
                            let btn = egui::Button::new(
                                RichText::new(chip_lbl).monospace().size(9.5).color(if is_sel {
                                    TEXT_PRIMARY
                                } else {
                                    TEXT_SECONDARY
                                }),
                            )
                            .fill(if is_sel { tk.bg_hover } else { tk.bg_deepest })
                            .stroke(Stroke::new(
                                1.0_f32,
                                if is_sel { tk.accent } else { tk.border_subtle },
                            ));
                            if ui
                                .add(btn)
                                .on_hover_text(format!(
                                    "{} + {} | split={} | SNI={} | TTL={}",
                                    p.config.mode,
                                    p.config.fooling,
                                    p.config.split_pos,
                                    p.config.fake_sni,
                                    p.config.fake_ttl
                                ))
                                .clicked()
                            {
                                load_profile_id = Some(p.id.clone());
                            }
                            if ui
                                .small_button(RichText::new("×").size(9.5).color(SEMANTIC_ERR))
                                .on_hover_text(if is_en {
                                    "Delete profile"
                                } else {
                                    "Удалить профиль"
                                })
                                .clicked()
                            {
                                delete_profile_id = Some((p.id.clone(), p.name.clone()));
                            }
                        }
                    });
                }
            });

            if save_named_clicked {
                let next_idx = self.snap.config.custom_profiles.len() + 1;
                let final_name = if self.builder_profile_name.trim().is_empty() {
                    if is_en {
                        format!("Profile #{next_idx} ({})", self.builder_cfg.mode)
                    } else {
                        format!("Профиль #{next_idx} ({})", self.builder_cfg.mode)
                    }
                } else {
                    self.builder_profile_name.trim().to_string()
                };
                self.builder_profile_name = final_name.clone();
                self.builder_dirty = false;
                let payload = if let Some(ref pid) = self.selected_profile_id {
                    serde_json::json!({
                        "id": pid,
                        "name": final_name,
                        "config": self.builder_cfg
                    })
                } else {
                    serde_json::json!({
                        "name": final_name,
                        "config": self.builder_cfg
                    })
                };
                self.dispatch_ipc("save_custom_profile", payload);
                if let Some(saved) = self
                    .snap
                    .config
                    .custom_profiles
                    .iter()
                    .find(|p| p.name.eq_ignore_ascii_case(&final_name))
                {
                    self.selected_profile_id = Some(saved.id.clone());
                }
                self.push_toast(
                    ToastKind::Success,
                    if is_en {
                        format!("Saved profile: {final_name}")
                    } else {
                        format!("Сохранён профиль: {final_name}")
                    },
                    if is_en {
                        "Select it in Domain Lists, .exe Filter or Default route"
                    } else {
                        "Выберите его во вкладке «Списки», для .exe или «Вне списков»"
                    },
                );
            }

            if let Some(pid) = load_profile_id
                && let Some(found) = saved_profiles
                    .iter()
                    .find(|p| p.id.eq_ignore_ascii_case(&pid))
            {
                self.builder_cfg = found.config.clone();
                self.builder_profile_name = found.name.clone();
                self.selected_profile_id = Some(found.id.clone());
                self.builder_dirty = true;
                self.push_toast(
                    ToastKind::Info,
                    if is_en {
                        format!("Loaded: {}", found.name)
                    } else {
                        format!("Загружен: {}", found.name)
                    },
                    format!(
                        "{} + {}, TTL={}",
                        found.config.mode, found.config.fooling, found.config.fake_ttl
                    ),
                );
            }

            if let Some((pid, pname)) = delete_profile_id {
                if self
                    .selected_profile_id
                    .as_deref()
                    .is_some_and(|cur| cur.eq_ignore_ascii_case(&pid))
                {
                    self.selected_profile_id = None;
                }
                self.dispatch_ipc("delete_custom_profile", serde_json::json!({ "id": pid }));
                self.push_toast(
                    ToastKind::Warn,
                    if is_en {
                        format!("Deleted profile: {pname}")
                    } else {
                        format!("Профиль удалён: {pname}")
                    },
                    if is_en {
                        "Linked lists reverted to Auto (24 recipes)"
                    } else {
                        "Привязанные списки переключены обратно на Авто"
                    },
                );
            }

            // Выбор шаблона из 24 рецептов
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en { "Template:" } else { "Шаблон:" })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                let cur_title = self
                    .snap
                    .recipes_catalog
                    .iter()
                    .find(|r| r.id == self.builder_preset_id)
                    .map(|r| {
                        format!(
                            "#{:02} — {}",
                            r.id,
                            localize_recipe_title(r.id, &r.title, is_en)
                        )
                    })
                    .unwrap_or_else(|| format!("#{:02}", self.builder_preset_id));

                let catalog_clone = self.snap.recipes_catalog.clone();
                let w = (ui.available_width() - 4.0).max(120.0);
                egui::ComboBox::from_id_salt("combo_builder_preset")
                    .width(w)
                    .selected_text(RichText::new(cur_title).size(10.0))
                    .show_ui(ui, |ui| {
                        for r in &catalog_clone {
                            let r_title = localize_recipe_title(r.id, &r.title, is_en);
                            if ui
                                .selectable_label(
                                    self.builder_preset_id == r.id,
                                    format!("#{:02} — {}", r.id, r_title),
                                )
                                .clicked()
                            {
                                self.builder_preset_id = r.id;
                                self.builder_cfg = r.config.clone();
                                self.builder_dirty = true;
                            }
                        }
                    });
            });

            // Сетка селекторов TCP Mode / Fooling / SplitPos / Fake SNI
            ui.columns(2, |cols| {
                cols[0].horizontal(|ui| {
                    ui.label(RichText::new("Mode:").size(10.0).color(TEXT_SECONDARY));
                    let w = (ui.available_width() - 4.0).max(80.0);
                    egui::ComboBox::from_id_salt("b_mode")
                        .width(w)
                        .selected_text(RichText::new(&self.builder_cfg.mode).monospace().size(10.0))
                        .show_ui(ui, |ui| {
                            for m in [
                                "fake_split",
                                "fake_disorder",
                                "multi_split",
                                "multi_disorder",
                                "pad_encap",
                                "tlsrec",
                                "oob",
                                "disoob",
                                "disorder",
                                "split",
                                "fake",
                            ] {
                                if ui.selectable_label(self.builder_cfg.mode == m, m).clicked() {
                                    self.builder_cfg.mode = m.to_string();
                                    self.builder_dirty = true;
                                }
                            }
                        });
                });

                cols[1].horizontal(|ui| {
                    ui.label(RichText::new("Fooling:").size(10.0).color(TEXT_SECONDARY));
                    let w = (ui.available_width() - 4.0).max(80.0);
                    egui::ComboBox::from_id_salt("b_fooling")
                        .width(w)
                        .selected_text(
                            RichText::new(&self.builder_cfg.fooling)
                                .monospace()
                                .size(10.0),
                        )
                        .show_ui(ui, |ui| {
                            for f in [
                                "md5",
                                "badseq",
                                "badsum",
                                "ts",
                                "ttl",
                                "autottl",
                                "datanoack",
                                "badack",
                                "md5_badack",
                                "badseq_badack_badsum",
                                "hopbyhop",
                            ] {
                                if ui
                                    .selectable_label(self.builder_cfg.fooling == f, f)
                                    .clicked()
                                {
                                    self.builder_cfg.fooling = f.to_string();
                                    self.builder_dirty = true;
                                }
                            }
                        });
                });
            });

            ui.columns(2, |cols| {
                cols[0].horizontal(|ui| {
                    ui.label(RichText::new("SplitPos:").size(10.0).color(TEXT_SECONDARY));
                    let w = (ui.available_width() - 4.0).max(80.0);
                    egui::ComboBox::from_id_salt("b_split_pos")
                        .width(w)
                        .selected_text(
                            RichText::new(&self.builder_cfg.split_pos)
                                .monospace()
                                .size(10.0),
                        )
                        .show_ui(ui, |ui| {
                            for sp in [
                                "midsld",
                                "1,sniext+1,midsld",
                                "sniext+1",
                                "host+1",
                                "midsld-2",
                                "midsld+2",
                                "endhost-1",
                                "2",
                            ] {
                                if ui
                                    .selectable_label(self.builder_cfg.split_pos == sp, sp)
                                    .clicked()
                                {
                                    self.builder_cfg.split_pos = sp.to_string();
                                    self.builder_dirty = true;
                                }
                            }
                        });
                });

                cols[1].horizontal(|ui| {
                    ui.label(RichText::new("SNI:").size(10.0).color(TEXT_SECONDARY));
                    let w = (ui.available_width() - 4.0).max(80.0);
                    if ui
                        .add(TextEdit::singleline(&mut self.builder_cfg.fake_sni).desired_width(w))
                        .changed()
                    {
                        self.builder_dirty = true;
                    }
                });
            });

            ui.horizontal_wrapped(|ui| {
                for sni in [
                    "www.google.com",
                    "dl.google.com",
                    "ya.ru",
                    "vk.com",
                    "rnd",
                    "orig",
                    "padencap",
                    "sni_del",
                    "bin_noise",
                ] {
                    if ui
                        .small_button(RichText::new(sni).monospace().size(10.0))
                        .clicked()
                    {
                        self.builder_cfg.fake_sni = sni.to_string();
                        self.builder_dirty = true;
                    }
                }
                egui::ComboBox::from_id_salt("b_white_sni_pool")
                    .width(120.0)
                    .selected_text(RichText::new("WHITE_SNI_POOL").monospace().size(9.5))
                    .show_ui(ui, |ui| {
                        for &sni in white_sni_pool() {
                            if ui
                                .selectable_label(self.builder_cfg.fake_sni == sni, sni)
                                .clicked()
                            {
                                self.builder_cfg.fake_sni = sni.to_string();
                                self.builder_dirty = true;
                            }
                        }
                    });
                ui.separator();
                if ui
                    .small_button(
                        RichText::new("googlevideo (wsize=1:scale=1)")
                            .monospace()
                            .size(10.0)
                            .color(ACCENT),
                    )
                    .on_hover_text(if is_en {
                        "Apply multidisorder:pos=midsld + wssize:wsize=1:scale=1 preset for googlevideo.com"
                    } else {
                        "Применить пресет multidisorder:pos=midsld + wssize:wsize=1:scale=1 для googlevideo.com"
                    })
                    .clicked()
                {
                    self.builder_cfg.auto = false;
                    self.builder_cfg.mode = "multi_disorder".to_string();
                    self.builder_cfg.fooling = "autottl".to_string();
                    self.builder_cfg.split_pos = "midsld".to_string();
                    self.builder_cfg.fake_sni = "sni_del".to_string();
                    self.builder_cfg.tlsrec_first = false;
                    self.builder_cfg.multi_seven_point = false;
                    self.builder_cfg.host_fake = false;
                    self.builder_cfg.wsize = 1;
                    self.builder_cfg.wscale = Some(1);
                    self.builder_dirty = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Fake Payload (Hex):")
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                let pw = (ui.available_width() - 4.0).max(120.0);
                if ui
                    .add(
                        TextEdit::singleline(&mut self.builder_cfg.fake_payload_hex)
                            .hint_text("160301... (опционально)")
                            .font(TextStyle::Monospace)
                            .desired_width(pw),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
            });

            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("TTL:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(egui::DragValue::new(&mut self.builder_cfg.fake_ttl).range(1..=64))
                    .changed()
                {
                    self.builder_dirty = true;
                }

                ui.label(RichText::new("Rep:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(egui::DragValue::new(&mut self.builder_cfg.repeats).range(1..=12))
                    .changed()
                {
                    self.builder_dirty = true;
                }

                ui.label(RichText::new("SeqOvl:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(egui::DragValue::new(&mut self.builder_cfg.seqovl).range(0..=1024))
                    .changed()
                {
                    self.builder_dirty = true;
                }

                ui.label(RichText::new("wsize:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(egui::DragValue::new(&mut self.builder_cfg.wsize).range(0..=65535))
                    .changed()
                {
                    self.builder_dirty = true;
                }

                ui.label(RichText::new("scale:").size(10.0).color(TEXT_SECONDARY));
                let scale_txt = match self.builder_cfg.wscale {
                    Some(ws) => ws.to_string(),
                    None => "Auto".to_string(),
                };
                egui::ComboBox::from_id_salt("b_wscale")
                    .width(56.0)
                    .selected_text(RichText::new(scale_txt).monospace().size(10.0))
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(self.builder_cfg.wscale.is_none(), "Auto")
                            .clicked()
                        {
                            self.builder_cfg.wscale = None;
                            self.builder_dirty = true;
                        }
                        for ws in 0u8..=14 {
                            if ui
                                .selectable_label(
                                    self.builder_cfg.wscale == Some(ws),
                                    ws.to_string(),
                                )
                                .clicked()
                            {
                                self.builder_cfg.wscale = Some(ws);
                                self.builder_dirty = true;
                            }
                        }
                    });

                ui.label(RichText::new("UDP Rep:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(egui::DragValue::new(&mut self.builder_cfg.udp_repeats).range(1..=12))
                    .changed()
                {
                    self.builder_dirty = true;
                }

                ui.label(RichText::new("UDP TTL:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(egui::DragValue::new(&mut self.builder_cfg.udp_fake_ttl).range(1..=64))
                    .changed()
                {
                    self.builder_dirty = true;
                }

                ui.label(RichText::new("QUIC Rep:").size(10.0).color(TEXT_SECONDARY));
                if ui
                    .add(
                        egui::DragValue::new(&mut self.builder_cfg.quic_repeats)
                            .range(0..=50)
                            .custom_formatter(|v, _| {
                                let n = v as u32;
                                if n == 0 {
                                    "Auto".to_string()
                                } else {
                                    n.to_string()
                                }
                            }),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
            });

            ui.columns(2, |cols| {
                if Self::gpui_switch(
                    &mut cols[0],
                    &mut self.builder_cfg.tlsrec_first,
                    "tlsrec_first (TLS Split)",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
                if Self::gpui_switch(
                    &mut cols[0],
                    &mut self.builder_cfg.multi_seven_point,
                    "7-Point MultiSplit",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
                if Self::gpui_switch(
                    &mut cols[0],
                    &mut self.builder_cfg.host_fake,
                    "HostFakeSplit",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
                if Self::gpui_switch(
                    &mut cols[0],
                    &mut self.builder_cfg.syndata,
                    "SYN Data (syndata)",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }

                if Self::gpui_switch(
                    &mut cols[1],
                    &mut self.builder_cfg.ipfrag,
                    "L3 IP Fragmentation",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
                if Self::gpui_switch(
                    &mut cols[1],
                    &mut self.builder_cfg.udp_fake,
                    "UDP Fakes (QUIC/Voice)",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
                if Self::gpui_switch(
                    &mut cols[1],
                    &mut self.builder_cfg.quic_desync,
                    "QUIC Initial Desync",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
                if Self::gpui_switch(
                    &mut cols[1],
                    &mut self.builder_cfg.block_quic,
                    "Block QUIC UDP/443 -> TCP",
                )
                .changed()
                {
                    self.builder_dirty = true;
                }
            });
        });
    }

    // Moment 2: Диаграмма срезов TLS 1.3 ClientHello (нейтральные сегменты + один акцент на инжектируемом срезе)
    fn draw_packet_slicer(&self, ui: &mut egui::Ui) {
        let p = &self.packet_preview;
        let cfg = &self.builder_cfg;
        let is_en = self.is_en();

        Self::card_frame(false).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "TLS 1.3 ClientHello slice anatomy"
                    } else {
                        "Анатомия разреза TLS 1.3 ClientHello"
                    })
                    .strong()
                    .size(10.0),
                );
                ui.label(
                    RichText::new(format!(
                        "sni={} | host={} | midsld={} | len={}B",
                        p.sni_ext_offset, p.host_offset, p.midsld_offset, p.packet_len
                    ))
                    .monospace()
                    .size(10.0)
                    .color(TEXT_SECONDARY),
                );
            });

            ui.horizontal(|ui| {
                let avail_w = ui.available_width();
                let has_tlsrec = cfg.tlsrec_first || cfg.mode == "tlsrec";
                let has_fake = matches!(
                    cfg.mode.as_str(),
                    "fake_split" | "fake_disorder" | "multi_disorder" | "fake"
                );
                // (text, is_accented)
                let mut blocks: Vec<(String, bool)> = Vec::new();
                if has_tlsrec {
                    blocks.push((format!("TLSRec @{}", p.sni_ext_offset), false));
                }
                if has_fake {
                    let lbl = if cfg.host_fake {
                        format!("HostFake ({})", cfg.fooling)
                    } else {
                        format!("Fake ({}, ttl={})", cfg.fooling, cfg.fake_ttl)
                    };
                    blocks.push((lbl, true));
                }
                if cfg.multi_seven_point {
                    blocks.push(("7-Point [1,sni+1,host+1,sld±2]".to_string(), !has_fake));
                    blocks.push(("Disorder (7 segs)".to_string(), false));
                } else {
                    blocks.push((format!("Seg1 [0..{}]", cfg.split_pos), !has_fake));
                    blocks.push((format!("Seg2 [{}..{}]", cfg.split_pos, p.packet_len), false));
                }

                let bw = ((avail_w - ((blocks.len() as f32 - 1.0) * 4.0)) / blocks.len() as f32)
                    .max(56.0);
                for (text, is_accent) in blocks {
                    let (r, _) = ui.allocate_exact_size(Vec2::new(bw, 20.0), Sense::hover());
                    let (fill, stroke_col, fg_col) = if is_accent {
                        (
                            Color32::from_rgba_unmultiplied(56, 189, 248, 28),
                            ACCENT,
                            ACCENT,
                        )
                    } else {
                        (BG_DEEPEST, BORDER_STRONG, TEXT_SECONDARY)
                    };
                    ui.painter().rect_filled(r, CornerRadius::same(4), fill);
                    ui.painter().rect_stroke(
                        r,
                        CornerRadius::same(4),
                        Stroke::new(1.0_f32, stroke_col),
                        StrokeKind::Inside,
                    );
                    ui.painter().text(
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        text,
                        FontId::new(10.0, FontFamily::Monospace),
                        fg_col,
                    );
                }
            });
        });
    }

    fn render_tab_lists(&mut self, ui: &mut egui::Ui) {
        let is_en = self.is_en();

        // 1. Фильтр по приложениям (.exe)
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Application Filter (.exe)"
                    } else {
                        "Фильтр по приложениям (.exe)"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let scan_lbl = if is_en {
                        "Refresh Processes"
                    } else {
                        "Обновить процессы"
                    };
                    if ui.small_button(scan_lbl).clicked() {
                        self.dispatch_ipc("scan_running_apps", serde_json::json!({}));
                    }
                });
            });

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en { "Mode:" } else { "Режим:" })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                let cur_app_mode = self.snap.config.app_filter_mode;
                let app_mode_txt = match cur_app_mode {
                    AppFilterMode::All => {
                        if is_en {
                            "All apps (use domain lists)"
                        } else {
                            "Все приложения (по спискам доменов)"
                        }
                    }
                    AppFilterMode::Include => {
                        if is_en {
                            "Only selected .exe (Whitelist)"
                        } else {
                            "Только выбранные .exe (Whitelist)"
                        }
                    }
                    AppFilterMode::Exclude => {
                        if is_en {
                            "All except selected (Bypass)"
                        } else {
                            "Все кроме выбранных (Bypass)"
                        }
                    }
                };

                let mut next_app_mode: Option<&'static str> = None;
                let w = (ui.available_width() - 4.0).max(140.0);
                egui::ComboBox::from_id_salt("combo_app_filter_mode")
                    .width(w)
                    .selected_text(RichText::new(app_mode_txt).size(10.0))
                    .show_ui(ui, |ui| {
                        let modes = [
                            (
                                "all",
                                AppFilterMode::All,
                                if is_en {
                                    "All apps (use domain lists)"
                                } else {
                                    "Все приложения (по спискам доменов)"
                                },
                            ),
                            (
                                "include",
                                AppFilterMode::Include,
                                if is_en {
                                    "Only selected .exe (Whitelist)"
                                } else {
                                    "Только выбранные .exe (Whitelist)"
                                },
                            ),
                            (
                                "exclude",
                                AppFilterMode::Exclude,
                                if is_en {
                                    "All except selected (Bypass)"
                                } else {
                                    "Все кроме выбранных (Bypass)"
                                },
                            ),
                        ];
                        for (code, m_enum, lbl) in modes {
                            if ui.selectable_label(cur_app_mode == m_enum, lbl).clicked() {
                                next_app_mode = Some(code);
                            }
                        }
                    });
                if let Some(code) = next_app_mode {
                    self.dispatch_ipc(
                        "update_app_filter",
                        serde_json::json!({ "app_filter_mode": code }),
                    );
                }
            });

            let mut force_apps = self.snap.config.force_desync_selected_apps;
            let force_lbl = if is_en {
                "Force desync all traffic of selected .exe (even outside domain lists)"
            } else {
                "Десинкать весь трафик выбранных .exe (даже вне списков доменов)"
            };
            if ui
                .checkbox(&mut force_apps, RichText::new(force_lbl).size(10.0))
                .changed()
            {
                self.dispatch_ipc(
                    "update_app_filter",
                    serde_json::json!({ "force_desync_selected_apps": force_apps }),
                );
            }

            let mut override_game = self.snap.config.lists_override_game_bypass;
            let override_lbl = if is_en {
                "Apply domain lists above built-in game bypass (Anti-Cheat / Game, e.g. CloudFront CDN)"
            } else {
                "Применять доменные списки поверх игрового байпаса (Античит / Игра, напр. CloudFront CDN)"
            };
            if ui
                .checkbox(&mut override_game, RichText::new(override_lbl).size(10.0))
                .changed()
            {
                self.dispatch_ipc(
                    "update_app_filter",
                    serde_json::json!({ "lists_override_game_bypass": override_game }),
                );
            }

            let selected_apps = self.snap.config.selected_apps.clone();
            let app_strats_map = self.snap.config.app_strategies.clone();
            let all_app_strat_opts = self.all_strategy_options(is_en);
            let mut app_to_toggle: Option<(String, bool)> = None;
            let mut upd_app_strat: Option<(String, String)> = None;

            if selected_apps.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(if is_en {
                            "No apps selected — click a process below or enter an .exe name"
                        } else {
                            "Приложения не выбраны — кликните по процессу ниже или введите имя .exe"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    )
                    .wrap(),
                );
            } else {
                for app in &selected_apps {
                    let cur_s = app_strats_map
                        .get(app)
                        .map(|s| s.as_str())
                        .unwrap_or("default");
                    let cur_s_lbl = if cur_s == "default" {
                        if is_en {
                            "Use Lists / Mode".to_string()
                        } else {
                            "По спискам / Режиму".to_string()
                        }
                    } else {
                        resolve_strategy_label(cur_s, &all_app_strat_opts, is_en)
                    };
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(format!("{app} ×"))
                                        .monospace()
                                        .size(10.0)
                                        .color(TEXT_PRIMARY),
                                )
                                .fill(BG_HOVER)
                                .stroke(Stroke::new(1.0_f32, BORDER_STRONG)),
                            )
                            .clicked()
                        {
                            app_to_toggle = Some((app.clone(), false));
                        }
                        ui.label(RichText::new("->").monospace().size(10.0).color(TEXT_MUTED));
                        egui::ComboBox::from_id_salt(format!("app_strat_{app}"))
                            .width((ui.available_width() - 8.0).max(136.0))
                            .selected_text(RichText::new(cur_s_lbl).size(10.0))
                            .show_ui(ui, |ui| {
                                let def_lbl = if is_en {
                                    "Use Lists / Filter Mode"
                                } else {
                                    "По спискам доменов / Режиму"
                                };
                                if ui.selectable_label(cur_s == "default", def_lbl).clicked() {
                                    upd_app_strat = Some((app.clone(), "default".to_string()));
                                }
                                for (code, lbl) in &all_app_strat_opts {
                                    if ui.selectable_label(cur_s == code, lbl).clicked() {
                                        upd_app_strat = Some((app.clone(), code.clone()));
                                    }
                                }
                            });
                    });
                }
            }

            if let Some((app, st)) = upd_app_strat {
                self.dispatch_ipc(
                    "set_app_strategy",
                    serde_json::json!({ "app": app, "strategy": st }),
                );
            }

            ui.horizontal(|ui| {
                let hint = if is_en {
                    "Process name (discord.exe)"
                } else {
                    "Имя процесса (discord.exe)"
                };
                let inp_w = (ui.available_width() - 88.0).max(100.0);
                let resp = ui.add(
                    TextEdit::singleline(&mut self.add_app_input)
                        .hint_text(hint)
                        .desired_width(inp_w),
                );
                let enter_pressed = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                let add_btn_lbl = if is_en { "+ Add" } else { "+ Добавить" };
                if ui.button(add_btn_lbl).clicked() || enter_pressed {
                    let val = self.add_app_input.trim().to_string();
                    if !val.is_empty() {
                        self.add_app_input.clear();
                        app_to_toggle = Some((val, true));
                    }
                }
            });

            ui.label(
                RichText::new(if is_en {
                    "Running processes (click to toggle)"
                } else {
                    "Активные процессы (клик — выбрать / убрать)"
                })
                .size(10.0)
                .color(TEXT_SECONDARY),
            );

            ui.horizontal_wrapped(|ui| {
                let mut merged: Vec<(String, usize)> = Vec::new();
                for r in &self.snap.running_apps {
                    let k = r.name.to_ascii_lowercase();
                    if !k.is_empty() && !merged.iter().any(|(x, _)| x == &k) {
                        merged.push((k, r.active_sockets));
                    }
                }
                for preset in [
                    "discord.exe",
                    "chrome.exe",
                    "firefox.exe",
                    "msedge.exe",
                    "telegram.exe",
                    "brave.exe",
                    "opera.exe",
                    "spotify.exe",
                    "steam.exe",
                    "robloxplayerbeta.exe",
                ] {
                    if !merged.iter().any(|(x, _)| x == preset) {
                        merged.push((preset.to_string(), 0));
                    }
                }

                for (exe, socks) in merged.into_iter().take(18) {
                    let is_sel = selected_apps.iter().any(|s| s.eq_ignore_ascii_case(&exe));
                    let lbl = if socks > 0 {
                        format!("{exe} ({socks})")
                    } else {
                        exe.clone()
                    };
                    let btn = egui::Button::new(
                        RichText::new(lbl).monospace().size(10.0).color(if is_sel {
                            TEXT_PRIMARY
                        } else {
                            TEXT_SECONDARY
                        }),
                    )
                    .fill(if is_sel { BG_HOVER } else { BG_ELEVATED })
                    .stroke(Stroke::new(
                        1.0_f32,
                        if is_sel { ACCENT } else { BORDER_SUBTLE },
                    ));
                    if ui.add(btn).clicked() {
                        app_to_toggle = Some((exe, false));
                    }
                }
            });

            if let Some((app, add_only)) = app_to_toggle {
                self.dispatch_ipc(
                    "toggle_app",
                    serde_json::json!({ "app": app, "add_only": add_only }),
                );
            }
        });

        // 2. Списки доменов и подсетей
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Domain & Subnet Lists"
                    } else {
                        "Списки доменов и подсетей"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let new_lbl = if is_en { "+ List" } else { "+ Список" };
                    if ui.add(Self::primary_button(new_lbl)).clicked() {
                        self.open_list_modal(None);
                    }
                    let sync_lbl = if is_en { "Sync" } else { "Синхр." };
                    if ui.small_button(sync_lbl).clicked() {
                        self.dispatch_ipc("sync_tachyon_lists", serde_json::json!({}));
                    }
                    let imp_lbl = if is_en { "Import" } else { "Импорт" };
                    let imp_tip = if is_en {
                        "Import JSON profile backup from clipboard or tachyon-desync-backup.json"
                    } else {
                        "Импортировать JSON-резервную копию из буфера обмена или файла tachyon-desync-backup.json"
                    };
                    if ui.small_button(imp_lbl).on_hover_text(imp_tip).clicked()
                        && let Some(text) = read_clipboard_or_backup_file()
                    {
                        self.dispatch_ipc(
                            "import_backup_json",
                            serde_json::json!({ "json": text }),
                        );
                        self.backup_toast_until =
                            Some(Instant::now() + Duration::from_secs(2));
                    }
                    let exp_lbl = if self
                        .backup_toast_until
                        .is_some_and(|t| Instant::now() < t)
                    {
                        if is_en { "Copied" } else { "Скопировано" }
                    } else if is_en {
                        "Export"
                    } else {
                        "Экспорт"
                    };
                    let exp_tip = if is_en {
                        "Copy full JSON profile backup to clipboard & save tachyon-desync-backup.json"
                    } else {
                        "Скопировать полную JSON-копию профиля в буфер обмена и сохранить tachyon-desync-backup.json"
                    };
                    if ui.small_button(exp_lbl).on_hover_text(exp_tip).clicked()
                        && let Ok(json_str) = serde_json::to_string_pretty(&self.snap.config)
                    {
                        write_backup_file(&json_str);
                        ui.ctx().copy_text(json_str);
                        self.backup_toast_until =
                            Some(Instant::now() + Duration::from_secs(2));
                    }
                });
            });

            // Строка внешнего прокси (SOCKS5 / HTTP)
            let mut save_up_proxy = false;
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Upstream Proxy:"
                    } else {
                        "Внешний прокси:"
                    })
                    .size(10.0)
                    .color(TEXT_SECONDARY),
                );
                let up_w = (ui.available_width() - 84.0).max(96.0);
                let resp = ui.add(
                    TextEdit::singleline(&mut self.upstream_proxy_input)
                        .hint_text(if is_en {
                            "127.0.0.1:1080 or http://127.0.0.1:8080"
                        } else {
                            "127.0.0.1:1080 или http://127.0.0.1:8080"
                        })
                        .desired_width(up_w),
                );
                if resp.changed() {
                    self.upstream_proxy_dirty = true;
                }
                let enter_up = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                let apply_lbl = if is_en { "Apply" } else { "Применить" };
                if ui.small_button(apply_lbl).clicked() || enter_up {
                    save_up_proxy = true;
                }
            });
            if save_up_proxy {
                self.upstream_proxy_dirty = false;
                let val = self.upstream_proxy_input.trim().to_string();
                self.dispatch_ipc(
                    "set_upstream_proxy",
                    serde_json::json!({ "upstream_proxy": val }),
                );
            }

            let filter_hint = if is_en {
                "Filter lists or domains"
            } else {
                "Поиск по списку или домену"
            };
            ui.add(
                TextEdit::singleline(&mut self.list_search_filter)
                    .hint_text(filter_hint)
                    .desired_width(ui.available_width()),
            );

            let q = self.list_search_filter.trim().to_ascii_lowercase();
            let lists_snap = self.snap.config.lists.clone();
            let all_list_strat_opts = self.all_strategy_options(is_en);

            let mut upd_enable: Option<(String, bool)> = None;
            let mut upd_strat: Option<(String, String)> = None;
            let mut upd_quic: Option<(String, bool)> = None;
            let mut upd_udp: Option<(String, bool)> = None;
            let mut upd_udp_ttl: Option<(String, u8)> = None;
            let mut open_edit: Option<String> = None;
            let mut del_list: Option<String> = None;

            let del_lbl = if is_en { "Delete" } else { "Удалить" };
            let rules_lbl = if is_en { "Rules" } else { "Правила" };

            ScrollArea::vertical()
                .id_salt("scroll_all_lists")
                .max_height(264.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for item in &lists_snap {
                        if !q.is_empty() {
                            let match_name = item.name.to_ascii_lowercase().contains(&q)
                                || item.description.to_ascii_lowercase().contains(&q)
                                || item
                                    .entries
                                    .iter()
                                    .any(|e| e.to_ascii_lowercase().contains(&q));
                            if !match_name {
                                continue;
                            }
                        }

                        Self::card_frame(item.enabled).show(ui, |ui| {
                            let loc_name = localize_list_name(&item.id, &item.name, is_en);
                            let loc_desc = localize_list_desc(&item.id, &item.description, is_en);
                            ui.horizontal_wrapped(|ui| {
                                let mut en = item.enabled;
                                if ui.checkbox(&mut en, "").changed() {
                                    upd_enable = Some((item.id.clone(), en));
                                }
                                ui.label(
                                    RichText::new(&loc_name)
                                        .strong()
                                        .size(11.0)
                                        .color(TEXT_PRIMARY),
                                );
                                ui.label(
                                    RichText::new(format!("({})", item.entries.len()))
                                        .monospace()
                                        .size(10.0)
                                        .color(TEXT_MUTED),
                                );
                                if ui.small_button(rules_lbl).clicked() {
                                    open_edit = Some(item.id.clone());
                                }
                                if !item.builtin
                                    && ui
                                        .small_button(RichText::new(del_lbl).color(SEMANTIC_ERR))
                                        .clicked()
                                {
                                    del_list = Some(item.id.clone());
                                }
                            });

                            ui.add(
                                egui::Label::new(
                                    RichText::new(&loc_desc).size(10.0).color(TEXT_MUTED),
                                )
                                .wrap(),
                            );

                            ui.horizontal_wrapped(|ui| {
                                let cur_s = item.strategy.as_code();
                                egui::ComboBox::from_id_salt(format!("lst_s_{}", item.id))
                                    .width(156.0)
                                    .selected_text(
                                        RichText::new(resolve_strategy_label(
                                            &cur_s,
                                            &all_list_strat_opts,
                                            is_en,
                                        ))
                                        .size(10.0),
                                    )
                                    .show_ui(ui, |ui| {
                                        for (code, lbl) in &all_list_strat_opts {
                                            if ui.selectable_label(&cur_s == code, lbl).clicked() {
                                                upd_strat = Some((item.id.clone(), code.clone()));
                                            }
                                        }
                                    });

                                let mut bq = item.block_quic;
                                if ui
                                    .checkbox(&mut bq, RichText::new("Block QUIC").size(10.0))
                                    .changed()
                                {
                                    upd_quic = Some((item.id.clone(), bq));
                                }

                                let mut uf = item.udp_fake;
                                if ui
                                    .checkbox(&mut uf, RichText::new("UDP Fake").size(10.0))
                                    .changed()
                                {
                                    upd_udp = Some((item.id.clone(), uf));
                                }

                                if item.udp_fake {
                                    ui.label(
                                        RichText::new("UDP TTL:")
                                            .size(10.0)
                                            .color(TEXT_SECONDARY),
                                    );
                                    let mut uttl = item.udp_fake_ttl;
                                    if ui
                                        .add(
                                            egui::DragValue::new(&mut uttl)
                                                .range(0..=64)
                                                .custom_formatter(|v, _| {
                                                    let n = v as u8;
                                                    if n == 0 {
                                                        "Auto".to_string()
                                                    } else {
                                                        n.to_string()
                                                    }
                                                }),
                                        )
                                        .on_hover_text(if is_en {
                                            "UDP fake packet TTL for this list (0 = Auto: TTL=3 on Voice/STUN ports)"
                                        } else {
                                            "TTL фейковых UDP-пакетов для этого списка (0 = Авто: TTL=3 для голосовых портов)"
                                        })
                                        .changed()
                                    {
                                        upd_udp_ttl = Some((item.id.clone(), uttl));
                                    }

                                    let ports_btn_lbl = if item.udp_ports.trim().is_empty() {
                                        if is_en {
                                            "UDP ports...".to_string()
                                        } else {
                                            "UDP порты...".to_string()
                                        }
                                    } else {
                                        format!("UDP: {}", item.udp_ports.trim())
                                    };
                                    if ui
                                        .small_button(
                                            RichText::new(ports_btn_lbl).monospace().size(9.5),
                                        )
                                        .on_hover_text(if is_en {
                                            "Configure UDP port ranges for this list (e.g. 19294-19344, 50000-50100)"
                                        } else {
                                            "Настроить диапазоны UDP-портов списка (напр. 19294-19344, 50000-50100)"
                                        })
                                        .clicked()
                                    {
                                        open_edit = Some(item.id.clone());
                                    }
                                }
                            });
                        });
                    }
                });

            if let Some((id, en)) = upd_enable {
                self.dispatch_ipc("update_list", serde_json::json!({ "id": id, "enabled": en }));
            }
            if let Some((id, st)) = upd_strat {
                self.dispatch_ipc(
                    "update_list",
                    serde_json::json!({ "id": id, "strategy": st }),
                );
            }
            if let Some((id, bq)) = upd_quic {
                self.dispatch_ipc(
                    "update_list",
                    serde_json::json!({ "id": id, "block_quic": bq }),
                );
            }
            if let Some((id, uf)) = upd_udp {
                self.dispatch_ipc(
                    "update_list",
                    serde_json::json!({ "id": id, "udp_fake": uf }),
                );
            }
            if let Some((id, uttl)) = upd_udp_ttl {
                self.dispatch_ipc(
                    "update_list",
                    serde_json::json!({ "id": id, "udp_fake_ttl": uttl }),
                );
            }
            if let Some(id) = open_edit {
                self.open_list_modal(Some(&id));
            }
            if let Some(id) = del_list {
                self.dispatch_ipc("delete_custom_list", serde_json::json!({ "id": id }));
            }
        });
    }

    fn open_list_modal(&mut self, list_id: Option<&str>) {
        if let Some(id) = list_id
            && let Some(found) = self.snap.config.lists.iter().find(|l| l.id == id)
        {
            self.list_modal = ListEditorModal {
                open: true,
                list_id: Some(found.id.clone()),
                name: found.name.clone(),
                strategy: found.strategy.as_code(),
                udp_ports: found.udp_ports.clone(),
                udp_fake_ttl: found.udp_fake_ttl,
                entries_text: found.entries.join("\n"),
                quick_entry: String::new(),
            };
            return;
        }
        self.list_modal = ListEditorModal {
            open: true,
            list_id: None,
            name: String::new(),
            strategy: "auto".to_string(),
            udp_ports: String::new(),
            udp_fake_ttl: 0,
            entries_text: String::new(),
            quick_entry: String::new(),
        };
    }

    fn render_list_modal(&mut self, ctx: &egui::Context) {
        if !self.list_modal.open {
            return;
        }
        let is_en = self.is_en();
        let all_modal_strat_opts = self.all_strategy_options(is_en);
        let mut open = self.list_modal.open;
        let mut save_clicked = false;
        let mut close_clicked = false;

        let wnd_title = if self.list_modal.list_id.is_some() {
            if is_en {
                "Edit Rule List"
            } else {
                "Редактор списка правил"
            }
        } else if is_en {
            "New List"
        } else {
            "Новый список"
        };

        egui::Window::new(wnd_title)
            .id(Id::new("modal_list_editor_wnd"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(416.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(if is_en { "Name:" } else { "Название:" }).size(10.0));
                    ui.add(TextEdit::singleline(&mut self.list_modal.name).desired_width(172.0));

                    egui::ComboBox::from_id_salt("modal_strat_combo")
                        .width(132.0)
                        .selected_text(
                            RichText::new(resolve_strategy_label(
                                &self.list_modal.strategy,
                                &all_modal_strat_opts,
                                is_en,
                            ))
                            .size(10.0),
                        )
                        .show_ui(ui, |ui| {
                            for (code, lbl) in &all_modal_strat_opts {
                                if ui
                                    .selectable_label(&self.list_modal.strategy == code, lbl)
                                    .clicked()
                                {
                                    self.list_modal.strategy = code.clone();
                                }
                            }
                        });
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "UDP Ports:"
                        } else {
                            "UDP порты:"
                        })
                        .size(10.0),
                    );
                    ui.add(
                        TextEdit::singleline(&mut self.list_modal.udp_ports)
                            .hint_text("19294-19344, 50000-50100")
                            .desired_width(188.0),
                    );
                    ui.label(RichText::new("UDP TTL:").size(10.0));
                    ui.add(
                        egui::DragValue::new(&mut self.list_modal.udp_fake_ttl)
                            .range(0..=64)
                            .custom_formatter(|v, _| {
                                let n = v as u8;
                                if n == 0 {
                                    "Auto (3)".to_string()
                                } else {
                                    n.to_string()
                                }
                            }),
                    );
                });

                ui.horizontal(|ui| {
                    let hint = if is_en {
                        "Domain, kw:word or CIDR"
                    } else {
                        "Домен, kw:слово или CIDR"
                    };
                    let resp = ui.add(
                        TextEdit::singleline(&mut self.list_modal.quick_entry)
                            .hint_text(hint)
                            .desired_width(ui.available_width() - 88.0),
                    );
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    let add_lbl = if is_en { "+ Add" } else { "+ Добавить" };
                    if ui.button(add_lbl).clicked() || enter {
                        let v = self.list_modal.quick_entry.trim().to_string();
                        if !v.is_empty() {
                            if !self.list_modal.entries_text.trim().is_empty() {
                                self.list_modal.entries_text.push('\n');
                            }
                            self.list_modal.entries_text.push_str(&v);
                            self.list_modal.quick_entry.clear();
                        }
                    }
                });

                let rules_cnt = self
                    .list_modal
                    .entries_text
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                    .count();
                ui.label(
                    RichText::new(format!(
                        "{} ({})",
                        if is_en {
                            "Domains, kw:... and CIDR subnets (one per line)"
                        } else {
                            "Домены, kw:... и подсети CIDR (по одному на строке)"
                        },
                        rules_cnt
                    ))
                    .size(10.0)
                    .color(TEXT_SECONDARY),
                );

                ScrollArea::vertical()
                    .id_salt("scroll_modal_entries")
                    .max_height(208.0)
                    .show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut self.list_modal.entries_text)
                                .font(TextStyle::Monospace)
                                .desired_rows(10)
                                .desired_width(ui.available_width()),
                        );
                    });

                ui.horizontal(|ui| {
                    if ui.button(if is_en { "Cancel" } else { "Отмена" }).clicked() {
                        close_clicked = true;
                    }
                    let sv_lbl = if is_en { "Save" } else { "Сохранить" };
                    if ui.add(Self::primary_button(sv_lbl)).clicked() {
                        save_clicked = true;
                    }
                });
            });

        if save_clicked {
            let name = if self.list_modal.name.trim().is_empty() {
                "Custom List".to_string()
            } else {
                self.list_modal.name.trim().to_string()
            };
            let strategy = self.list_modal.strategy.clone();
            let udp_ports = self.list_modal.udp_ports.trim().to_string();
            let udp_fake_ttl = self.list_modal.udp_fake_ttl;
            let entries_text = self.list_modal.entries_text.clone();
            if let Some(id) = self.list_modal.list_id.clone() {
                self.dispatch_ipc(
                    "update_list",
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "strategy": strategy,
                        "udp_ports": udp_ports,
                        "udp_fake_ttl": udp_fake_ttl,
                        "entries_text": entries_text
                    }),
                );
            } else {
                self.dispatch_ipc(
                    "create_custom_list",
                    serde_json::json!({
                        "name": name,
                        "strategy": strategy,
                        "udp_ports": udp_ports,
                        "udp_fake_ttl": udp_fake_ttl,
                        "entries_text": entries_text
                    }),
                );
            }
            self.list_modal.open = false;
        } else if close_clicked || !open {
            self.list_modal.open = false;
        }
    }

    fn render_tab_logs(&mut self, ui: &mut egui::Ui) {
        let is_en = self.is_en();

        // 1. Рейтинг рецептов на канале (L3 Scoreboard)
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Channel Recipe Scoreboard (L3)"
                    } else {
                        "Рейтинг рецептов на канале (L3)"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let toggle_lbl = if self.show_scoreboard_in_logs {
                        if is_en { "Hide" } else { "Скрыть" }
                    } else if is_en {
                        "Show"
                    } else {
                        "Показать"
                    };
                    if ui
                        .small_button(RichText::new(toggle_lbl).size(10.0).color(TEXT_SECONDARY))
                        .clicked()
                    {
                        self.show_scoreboard_in_logs = !self.show_scoreboard_in_logs;
                    }
                });
            });

            if self.show_scoreboard_in_logs {
                let scores = self.snap.scoreboard.clone();
                let max_score = scores.iter().map(|s| s.score).max().unwrap_or(1).max(1);
                let load_tip = if is_en {
                    "Load this recipe into Builder"
                } else {
                    "Загрузить этот рецепт в Конструктор"
                };
                let mut pick_recipe_id: Option<u8> = None;

                ScrollArea::vertical()
                    .id_salt("scroll_scoreboard")
                    .max_height(128.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let row_max_w = (ui.available_width() - 8.0).max(180.0);
                        for s in &scores {
                            let is_leader = s.score > 0 && s.score == max_score;
                            ui.horizontal_top(|ui| {
                                ui.set_max_width(row_max_w);
                                if ui
                                    .small_button(
                                        RichText::new(format!("#{:02}", s.id))
                                            .monospace()
                                            .size(10.0),
                                    )
                                    .on_hover_text(load_tip)
                                    .clicked()
                                {
                                    pick_recipe_id = Some(s.id);
                                }

                                let frac = (s.score as f32 / max_score as f32).clamp(0.0, 1.0);
                                let (bar_rect, _) =
                                    ui.allocate_exact_size(Vec2::new(48.0, 4.0), Sense::hover());
                                ui.painter().rect_filled(
                                    bar_rect,
                                    CornerRadius::same(2),
                                    BG_DEEPEST,
                                );
                                let fill_w = bar_rect.width() * frac;
                                if fill_w > 0.5 {
                                    let fill_rect = Rect::from_min_size(
                                        bar_rect.min,
                                        Vec2::new(fill_w, bar_rect.height()),
                                    );
                                    ui.painter().rect_filled(
                                        fill_rect,
                                        CornerRadius::same(2),
                                        if is_leader { ACCENT } else { TEXT_MUTED },
                                    );
                                }

                                ui.add_sized(
                                    Vec2::new(32.0, 16.0),
                                    egui::Label::new(
                                        RichText::new(format!("{:>3}", s.score))
                                            .monospace()
                                            .strong()
                                            .size(10.0)
                                            .color(if is_leader { ACCENT } else { TEXT_SECONDARY }),
                                    ),
                                );

                                let title_w = (ui.available_width() - 8.0).max(80.0);
                                let loc_title = localize_recipe_title(s.id, &s.title, is_en);
                                let mut job = egui::text::LayoutJob {
                                    wrap: egui::text::TextWrapping {
                                        max_width: title_w,
                                        break_anywhere: true,
                                        ..Default::default()
                                    },
                                    ..Default::default()
                                };
                                job.append(
                                    &loc_title,
                                    0.0,
                                    egui::TextFormat {
                                        font_id: FontId::new(10.0, FontFamily::Proportional),
                                        color: TEXT_PRIMARY,
                                        ..Default::default()
                                    },
                                );
                                ui.add(egui::Label::new(job).wrap());
                            });
                        }
                    });

                if let Some(rid) = pick_recipe_id
                    && let Some(item) = self.snap.recipes_catalog.iter().find(|r| r.id == rid)
                {
                    self.builder_cfg = item.config.clone();
                    self.builder_dirty = true;
                    self.active_tab = ActiveTab::Generator;
                }
            }
        });

        // 2. Журнал событий
        Self::panel_frame().show(ui, |ui| {
            let log_q = self.log_search_query.trim().to_ascii_lowercase();
            let filtered: Vec<_> = self
                .snap
                .logs
                .iter()
                .rev()
                .filter(|l| {
                    let cat_ok =
                        self.log_category_filter == "all" || l.category == self.log_category_filter;
                    if !cat_ok {
                        return false;
                    }
                    if log_q.is_empty() {
                        return true;
                    }
                    l.message.to_ascii_lowercase().contains(&log_q)
                        || l.category.to_ascii_lowercase().contains(&log_q)
                })
                .cloned()
                .collect();

            let full_log_text = {
                let mut lines = Vec::with_capacity(filtered.len() + 2);
                lines.push(format!(
                    "# Tachyon Desync v{} | mode={} | active={} | desynced={}",
                    env!("CARGO_PKG_VERSION"),
                    self.snap.active_mode,
                    self.snap.active_connections,
                    self.snap.desynced_connections
                ));
                for l in filtered.iter().rev() {
                    let loc_msg = localize_runtime_text(&l.message, is_en);
                    lines.push(format!(
                        "{} [{}] {}",
                        format_hms(l.ts_ms),
                        l.category,
                        loc_msg
                    ));
                }
                lines.join("\n")
            };

            let log_toast_active = self
                .log_copied_toast_until
                .map(|t| Instant::now() < t)
                .unwrap_or(false);

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Event Log"
                    } else {
                        "Журнал событий"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .small_button(if is_en { "Clear" } else { "Очистить" })
                        .clicked()
                    {
                        self.dispatch_ipc("clear_logs", serde_json::json!({}));
                    }

                    let copy_all_lbl = if log_toast_active {
                        RichText::new(if is_en {
                            "Copied ✓"
                        } else {
                            "Скопировано ✓"
                        })
                        .size(10.0)
                        .color(SEMANTIC_OK)
                    } else {
                        RichText::new(if is_en {
                            "Copy Log"
                        } else {
                            "Копировать лог"
                        })
                        .size(10.0)
                        .color(active_tokens().accent)
                    };
                    if ui
                        .add_enabled(
                            !filtered.is_empty(),
                            egui::Button::new(copy_all_lbl).small(),
                        )
                        .on_hover_text(if is_en {
                            "Copy all visible log entries to clipboard"
                        } else {
                            "Скопировать весь отображаемый журнал событий в буфер обмена"
                        })
                        .clicked()
                    {
                        ui.ctx().copy_text(full_log_text.clone());
                        self.log_copied_toast_until =
                            Some(Instant::now() + Duration::from_millis(1600));
                        self.push_toast(
                            ToastKind::Success,
                            if is_en {
                                "Event log copied"
                            } else {
                                "Журнал скопирован"
                            },
                            if is_en {
                                format!("{} lines copied to clipboard", filtered.len())
                            } else {
                                format!("Скопировано записей в буфер: {}", filtered.len())
                            },
                        );
                    }

                    egui::ComboBox::from_id_salt("combo_log_cat")
                        .width(120.0)
                        .selected_text(
                            RichText::new(self.log_category_filter.as_str())
                                .monospace()
                                .size(10.0),
                        )
                        .show_ui(ui, |ui| {
                            for (code, lbl) in [
                                ("all", if is_en { "All" } else { "Все" }),
                                ("desync", "TCP Desync"),
                                ("udp_desync", "UDP Desync"),
                                ("direct", "Direct"),
                                ("quic", "QUIC"),
                                ("apps", "Apps (.exe)"),
                                ("probe", "Generator"),
                                ("system", "System"),
                            ] {
                                if ui
                                    .selectable_label(self.log_category_filter == code, lbl)
                                    .clicked()
                                {
                                    self.log_category_filter = code.to_string();
                                }
                            }
                        });
                });
            });

            let search_hint = if is_en {
                "Filter log lines by domain, recipe or text..."
            } else {
                "Поиск по тексту события, домену или рецепту..."
            };
            ui.add(
                TextEdit::singleline(&mut self.log_search_query)
                    .hint_text(search_hint)
                    .desired_width(ui.available_width()),
            );

            if filtered.is_empty() {
                ui.label(
                    RichText::new(if is_en {
                        "No events recorded"
                    } else {
                        "Журнал событий пуст"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
            } else {
                let log_h = ui.available_height().max(264.0);
                ScrollArea::vertical()
                    .id_salt("scroll_event_logs")
                    .max_height(log_h)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let max_row_w = (ui.available_width() - 8.0).max(160.0);
                        let inner_text_w = (max_row_w - 52.0).max(120.0);
                        for l in &filtered {
                            Self::card_frame(false).show(ui, |ui| {
                                ui.set_width(max_row_w - 16.0);
                                let cat_col = match l.level.as_str() {
                                    "error" => SEMANTIC_ERR,
                                    "warn" => SEMANTIC_WARN,
                                    _ => TEXT_SECONDARY,
                                };
                                let loc_msg = localize_runtime_text(&l.message, is_en);
                                let line_plain =
                                    format!("{} [{}] {}", format_hms(l.ts_ms), l.category, loc_msg);
                                ui.horizontal_top(|ui| {
                                    let mut job = egui::text::LayoutJob {
                                        wrap: egui::text::TextWrapping {
                                            max_width: inner_text_w,
                                            break_anywhere: true,
                                            ..Default::default()
                                        },
                                        ..Default::default()
                                    };
                                    job.append(
                                        &format!("{} ", format_hms(l.ts_ms)),
                                        0.0,
                                        egui::TextFormat {
                                            font_id: FontId::new(10.0, FontFamily::Monospace),
                                            color: TEXT_MUTED,
                                            ..Default::default()
                                        },
                                    );
                                    job.append(
                                        &format!("[{}] ", l.category),
                                        0.0,
                                        egui::TextFormat {
                                            font_id: FontId::new(10.0, FontFamily::Monospace),
                                            color: cat_col,
                                            ..Default::default()
                                        },
                                    );
                                    job.append(
                                        &loc_msg,
                                        0.0,
                                        egui::TextFormat {
                                            font_id: FontId::new(10.0, FontFamily::Monospace),
                                            color: TEXT_PRIMARY,
                                            ..Default::default()
                                        },
                                    );
                                    let resp =
                                        ui.add(egui::Label::new(job).wrap().selectable(true));
                                    resp.context_menu(|ui| {
                                        if ui
                                            .button(if is_en {
                                                "Copy line"
                                            } else {
                                                "Копировать строку"
                                            })
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(line_plain.clone());
                                            self.log_copied_toast_until =
                                                Some(Instant::now() + Duration::from_millis(1600));
                                            ui.close_menu();
                                        }
                                        if ui
                                            .button(if is_en {
                                                "Copy entire log"
                                            } else {
                                                "Копировать весь лог"
                                            })
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(full_log_text.clone());
                                            self.log_copied_toast_until =
                                                Some(Instant::now() + Duration::from_millis(1600));
                                            ui.close_menu();
                                        }
                                    });

                                    ui.with_layout(Layout::right_to_left(Align::TOP), |ui| {
                                        if ui
                                            .small_button(
                                                RichText::new(if is_en {
                                                    "Copy"
                                                } else {
                                                    "Копир."
                                                })
                                                .size(9.0)
                                                .color(TEXT_MUTED),
                                            )
                                            .on_hover_text(if is_en {
                                                "Copy this log line"
                                            } else {
                                                "Скопировать эту строку журнала"
                                            })
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(line_plain);
                                            self.log_copied_toast_until =
                                                Some(Instant::now() + Duration::from_millis(1600));
                                        }
                                    });
                                });
                            });
                        }
                    });
            }
        });
    }

    fn parse_speed_domains(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
            let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if d.len() >= 3 && d.contains('.') && !out.iter().any(|x| x == &d) {
                out.push(d);
                if out.len() >= 32 {
                    break;
                }
            }
        }
        out
    }

    fn save_dns_overrides_input(&mut self) {
        self.dns_overrides_dirty = false;
        let txt = self.dns_overrides_input.clone();
        self.dispatch_ipc("set_dns_overrides", serde_json::json!({ "text": txt }));
        let is_en = self.is_en();
        let cnt = self.snap.config.dns_overrides.len();
        self.push_toast(
            ToastKind::Success,
            if is_en {
                "Local hosts updated"
            } else {
                "Локальные переопределения сохранены"
            },
            if is_en {
                format!("{cnt} domain overrides active")
            } else {
                format!("Активно записей: {cnt}")
            },
        );
    }

    fn render_dns_overrides_editor(&mut self, ui: &mut egui::Ui, is_en: bool, id_salt: &str) {
        let mut save_dns_ov = false;
        Self::card_frame(self.dns_overrides_dirty).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Format: domain=IP or IP domain (one per line, no system hosts edit)"
                    } else {
                        "Формат: домен=IP или IP домен (по одному на строку, без правки системного hosts)"
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let sv_lbl = if is_en {
                        "Save hosts"
                    } else {
                        "Сохранить hosts"
                    };
                    if ui.add(Self::primary_button(sv_lbl)).clicked() {
                        save_dns_ov = true;
                    }
                });
            });
            ui.add_space(4.0);
            if ui
                .add(
                    TextEdit::multiline(&mut self.dns_overrides_input)
                        .id_salt(id_salt)
                        .font(FontId::new(10.0, FontFamily::Monospace))
                        .desired_rows(4)
                        .desired_width(ui.available_width())
                        .hint_text("chatgpt.com=172.64.155.209\n*.googlevideo.com=142.250.74.14"),
                )
                .changed()
            {
                self.dns_overrides_dirty = true;
            }
        });
        if save_dns_ov {
            self.save_dns_overrides_input();
        }
    }

    fn apply_dns_recommendation_with_toast(&mut self, rec: &DnsRecommendation) {
        if let Ok(val) = serde_json::to_value(rec) {
            self.dns_dirty = false;
            self.dispatch_ipc("apply_dns_recommendation", val);
            let is_en = self.is_en();
            let proto_lbl = if is_en {
                rec.protocol.label_en()
            } else {
                rec.protocol.label_ru()
            };
            let title = if is_en {
                format!("DNS applied: {proto_lbl}")
            } else {
                format!("DNS применён: {proto_lbl}")
            };
            let detail = if is_en {
                rec.reason_en.clone()
            } else {
                rec.reason_ru.clone()
            };
            self.push_toast(ToastKind::Success, title, detail);
        }
    }

    fn flush_dns_cache_with_toast(&mut self) {
        self.dispatch_ipc("flush_dns_cache", serde_json::Value::Null);
        let is_en = self.is_en();
        self.push_toast(
            ToastKind::Info,
            if is_en {
                "DNS cache flushed"
            } else {
                "Кэш DNS очищен"
            },
            if is_en {
                "Resolver cache and address table cleared"
            } else {
                "Локальный кэш ответов и обратная таблица очищены"
            },
        );
    }

    fn start_dns_benchmark(&mut self, auto_apply: bool) {
        if let Ok(mut st) = self.dns_bench_state.lock() {
            if st.running {
                if auto_apply {
                    self.dns_auto_apply_on_finish.store(true, Ordering::Release);
                }
                return;
            }
            *st = DnsBenchmarkState {
                running: true,
                progress_pct: 0,
                current_target: String::new(),
                results: Vec::new(),
                recommendation: None,
                error: None,
            };
        } else {
            return;
        }

        self.dns_bench_cancel.store(false, Ordering::SeqCst);
        self.dns_auto_apply_on_finish
            .store(auto_apply, Ordering::Release);

        let state_slot = self.dns_bench_state.clone();
        let cancel = self.dns_bench_cancel.clone();
        let cfg = self.snap.config.custom_global_config.clone();
        let rt = self.rt.clone();

        self.tokio_handle.spawn(async move {
            struct BenchStateGuard(Arc<Mutex<DnsBenchmarkState>>);
            impl Drop for BenchStateGuard {
                fn drop(&mut self) {
                    if let Ok(mut st) = self.0.lock() {
                        st.running = false;
                    }
                }
            }
            let _guard = BenchStateGuard(state_slot.clone());
            let rec_opt = run_dns_benchmark(state_slot.clone(), cancel.clone(), cfg).await;
            let summary = if let Ok(mut st) = state_slot.lock() {
                if st.recommendation.is_none() {
                    st.recommendation = rec_opt;
                }
                st.running = false;
                let ok_cnt = st.results.iter().filter(|r| r.latency_ms >= 0).count();
                Some((ok_cnt, st.results.len()))
            } else {
                None
            };
            if let Some((ok_cnt, total)) = summary
                && total > 0
                && !cancel.load(Ordering::Relaxed)
            {
                rt.push_log(
                    "info",
                    "dns",
                    &format!("Бенчмарк DNS завершён: доступно {ok_cnt}/{total} узлов"),
                );
            }
        });
    }

    fn start_dns_speed_test(&mut self) {
        if let Ok(mut st) = self.dns_speed_state.lock() {
            if st.running {
                return;
            }
            *st = DnsSpeedTestState {
                running: true,
                progress_pct: 0,
                current_target: String::new(),
                reports: Vec::new(),
                error: None,
            };
        } else {
            return;
        }

        self.dns_speed_cancel.store(false, Ordering::SeqCst);
        self.selected_speed_server_idx = None;

        let mut settings = self.dns_draft.clone();
        let parsed = Self::parse_speed_domains(&self.dns_speed_domains_input);
        settings.speed_test_domains = if parsed.is_empty() {
            default_speed_test_domains()
        } else {
            parsed
        };

        let state_slot = self.dns_speed_state.clone();
        let cancel = self.dns_speed_cancel.clone();
        let cfg = self.snap.config.custom_global_config.clone();
        let rt = self.rt.clone();

        self.tokio_handle.spawn(async move {
            struct SpeedStateGuard(Arc<Mutex<DnsSpeedTestState>>);
            impl Drop for SpeedStateGuard {
                fn drop(&mut self) {
                    if let Ok(mut st) = self.0.lock() {
                        st.running = false;
                    }
                }
            }
            let _guard = SpeedStateGuard(state_slot.clone());
            run_dns_speed_test(settings, state_slot.clone(), cancel.clone(), cfg).await;
            let count = if let Ok(mut st) = state_slot.lock() {
                st.running = false;
                st.reports.len()
            } else {
                0
            };
            if count > 0 && !cancel.load(Ordering::Relaxed) {
                rt.push_log(
                    "info",
                    "dns",
                    &format!("Тест скорости DNS завершён: проверено серверов — {count}"),
                );
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn render_dns_server_list_editor(
        ui: &mut egui::Ui,
        is_en: bool,
        title: &str,
        hint: &str,
        list: &mut Vec<String>,
        input: &mut String,
        dirty: &mut bool,
        proto: DnsProtocol,
        id_salt: &str,
        max_items: usize,
        min_items: usize,
    ) -> Option<String> {
        let mut validation_err: Option<String> = None;
        Self::card_frame(false).show(ui, |ui| {
            ui.push_id(id_salt, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{title} ({})", list.len()))
                            .strong()
                            .size(10.5)
                            .color(TEXT_PRIMARY),
                    );
                });
                ui.add_space(4.0);

                let mut promote_idx: Option<usize> = None;
                let mut remove_idx: Option<usize> = None;
                for (idx, addr) in list.iter().enumerate() {
                    ui.horizontal(|ui| {
                        let role_lbl = if idx == 0 {
                            if is_en { "Primary" } else { "Осн." }
                        } else if is_en {
                            "Backup"
                        } else {
                            "Рез."
                        };
                        Self::semantic_tag(
                            ui,
                            role_lbl,
                            if idx == 0 { ACCENT } else { TEXT_MUTED },
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(addr)
                                    .monospace()
                                    .size(10.0)
                                    .color(TEXT_PRIMARY),
                            )
                            .truncate(),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add_enabled(
                                    list.len() > min_items,
                                    egui::Button::new(
                                        RichText::new("×").monospace().size(10.0).color(TEXT_MUTED),
                                    )
                                    .small(),
                                )
                                .on_hover_text(if is_en { "Remove" } else { "Удалить" })
                                .clicked()
                            {
                                remove_idx = Some(idx);
                            }
                            if idx > 0
                                && ui
                                    .small_button(
                                        RichText::new("▲")
                                            .monospace()
                                            .size(9.5)
                                            .color(TEXT_SECONDARY),
                                    )
                                    .on_hover_text(if is_en {
                                        "Promote to primary"
                                    } else {
                                        "Сделать основным"
                                    })
                                    .clicked()
                            {
                                promote_idx = Some(idx);
                            }
                        });
                    });
                }

                if let Some(idx) = promote_idx
                    && idx < list.len()
                {
                    let item = list.remove(idx);
                    list.insert(0, item);
                    *dirty = true;
                } else if let Some(idx) = remove_idx
                    && idx < list.len()
                    && list.len() > min_items
                {
                    list.remove(idx);
                    *dirty = true;
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let inp_w = (ui.available_width() - 68.0).max(96.0);
                    let resp = ui.add(
                        TextEdit::singleline(input)
                            .font(FontId::new(10.0, FontFamily::Monospace))
                            .hint_text(hint)
                            .desired_width(inp_w),
                    );
                    let enter_hit = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    let add_lbl = if is_en { "Add" } else { "Добавить" };
                    if ui.small_button(RichText::new(add_lbl).size(10.0)).clicked() || enter_hit {
                        let trimmed = input.trim();
                        if !trimmed.is_empty() {
                            if list.len() >= max_items {
                                validation_err = Some(if is_en {
                                    format!("Maximum {max_items} entries allowed")
                                } else {
                                    format!("Максимум записей: {max_items}")
                                });
                            } else {
                                match validate_dns_server_entry(trimmed, proto) {
                                    Ok(norm) => {
                                        if !list.iter().any(|x| x.eq_ignore_ascii_case(&norm)) {
                                            list.push(norm);
                                            *dirty = true;
                                        }
                                        input.clear();
                                    }
                                    Err(e) => {
                                        validation_err = Some(e);
                                    }
                                }
                            }
                        }
                    }
                });
            });
        });
        validation_err
    }

    fn render_dns_telemetry_bar(
        &mut self,
        ui: &mut egui::Ui,
        is_en: bool,
        bench_running: bool,
        speed_running: bool,
    ) {
        let mut trigger_auto_tune = false;
        let mut trigger_benchmark = false;
        let mut trigger_speed = false;
        let mut trigger_flush = false;

        Self::panel_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "DNS Subsystem & Auto-Tune"
                    } else {
                        "Подсистема DNS и автонастройка"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let flush_lbl = if is_en {
                        "Flush Cache"
                    } else {
                        "Сбросить кэш"
                    };
                    if ui.small_button(RichText::new(flush_lbl).size(10.0)).clicked() {
                        trigger_flush = true;
                    }

                    let speed_lbl = if speed_running {
                        if is_en {
                            "Speed Running..."
                        } else {
                            "Тест скорости..."
                        }
                    } else if is_en {
                        "Speed Test"
                    } else {
                        "Тест скорости"
                    };
                    if ui
                        .add_enabled(
                            !speed_running,
                            egui::Button::new(
                                RichText::new(speed_lbl).size(10.0).color(TEXT_PRIMARY),
                            ),
                        )
                        .clicked()
                    {
                        trigger_speed = true;
                    }

                    let bench_lbl = if bench_running {
                        if is_en {
                            "Benchmarking..."
                        } else {
                            "Бенчмарк..."
                        }
                    } else if is_en {
                        "DNS Benchmark"
                    } else {
                        "Бенчмарк DNS"
                    };
                    if ui
                        .add_enabled(
                            !bench_running,
                            egui::Button::new(
                                RichText::new(bench_lbl).size(10.0).color(TEXT_PRIMARY),
                            ),
                        )
                        .clicked()
                    {
                        trigger_benchmark = true;
                    }

                    let auto_lbl = if bench_running {
                        if is_en {
                            "Auto-Tuning..."
                        } else {
                            "Автонастройка..."
                        }
                    } else if is_en {
                        "Auto-Tune (1-Click)"
                    } else {
                        "Автонастройка в 1 клик"
                    };
                    if ui
                        .add_enabled(!bench_running, Self::primary_button(auto_lbl))
                        .on_hover_text(if is_en {
                            "Test public UDP/DoT/DoH resolvers and automatically apply the best configuration"
                        } else {
                            "Проверить публичные UDP/DoT/DoH резолверы и автоматически применить лучшую конфигурацию"
                        })
                        .clicked()
                    {
                        trigger_auto_tune = true;
                    }
                });
            });

            ui.add_space(4.0);

            let st = &self.snap.dns_status;
            let hit_pct = if st.total_queries > 0 {
                (st.cache_hits as f64 / st.total_queries as f64) * 100.0
            } else {
                0.0
            };
            let primary_display = if !st.enabled {
                if is_en {
                    "System OS".to_string()
                } else {
                    "Системный ОС".to_string()
                }
            } else if st.active_primary.is_empty() {
                "-".to_string()
            } else {
                st.active_primary.clone()
            };

            ui.columns(4, |cols| {
                Self::card_frame(false).show(&mut cols[0], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Active Upstream"
                        } else {
                            "Активный узел"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(&primary_display)
                                .monospace()
                                .strong()
                                .size(11.0)
                                .color(if !st.enabled {
                                    TEXT_MUTED
                                } else if st.consecutive_failures > 0 {
                                    SEMANTIC_WARN
                                } else {
                                    TEXT_PRIMARY
                                }),
                        )
                        .truncate(),
                    );
                    let proto_str = if is_en {
                        st.protocol.label_en()
                    } else {
                        st.protocol.label_ru()
                    };
                    let mode_str = if is_en {
                        st.upstream_mode.label_en()
                    } else {
                        st.upstream_mode.label_ru()
                    };
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "{proto_str} · {mode_str} ({}/{})",
                                if st.primary_count > 0 {
                                    st.active_index + 1
                                } else {
                                    0
                                },
                                st.primary_count
                            ))
                            .monospace()
                            .size(9.5)
                            .color(TEXT_SECONDARY),
                        )
                        .truncate(),
                    );
                });

                Self::card_frame(false).show(&mut cols[1], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Cache Hits / Total"
                        } else {
                            "Кэш / Запросы"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{}/{}", st.cache_hits, st.total_queries))
                            .monospace()
                            .strong()
                            .size(14.0)
                            .color(ACCENT),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{:.0}% hit · {} DoH/DoT",
                            hit_pct, st.encrypted_queries
                        ))
                        .monospace()
                        .size(9.5)
                        .color(TEXT_SECONDARY),
                    );
                });

                Self::card_frame(false).show(&mut cols[2], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Cache Entries"
                        } else {
                            "Размер кэша"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{}/{}", st.cache_entries, st.cache_capacity))
                            .monospace()
                            .strong()
                            .size(14.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(format!(
                            "~{} {}",
                            st.approx_ram_kb,
                            if is_en { "KiB RAM" } else { "КиБ ОЗУ" }
                        ))
                        .monospace()
                        .size(9.5)
                        .color(TEXT_SECONDARY),
                    );
                });

                Self::card_frame(false).show(&mut cols[3], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Failover Switches"
                        } else {
                            "Переключения"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new(st.failover_switches.to_string())
                            .monospace()
                            .strong()
                            .size(14.0)
                            .color(if st.failover_switches > 0 {
                                SEMANTIC_WARN
                            } else {
                                TEXT_PRIMARY
                            }),
                    );
                    ui.label(
                        RichText::new(if is_en {
                            format!("Consecutive fails: {}", st.consecutive_failures)
                        } else {
                            format!("Сбоев подряд: {}", st.consecutive_failures)
                        })
                        .monospace()
                        .size(9.5)
                        .color(if st.consecutive_failures > 0 {
                            SEMANTIC_WARN
                        } else {
                            TEXT_SECONDARY
                        }),
                    );
                });
            });
        });

        if trigger_auto_tune {
            self.start_dns_benchmark(true);
        } else if trigger_benchmark {
            self.start_dns_benchmark(false);
        }
        if trigger_speed {
            self.start_dns_speed_test();
        }
        if trigger_flush {
            self.flush_dns_cache_with_toast();
        }
    }

    fn render_dns_benchmark_section(&mut self, ui: &mut egui::Ui, is_en: bool) {
        let bench_snap = self
            .dns_bench_state
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let mut apply_rec_opt: Option<DnsRecommendation> = None;

        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "1. Resolver Benchmark & Auto-Tune"
                    } else {
                        "1. Бенчмарк резолверов и автонастройка"
                    })
                    .strong()
                    .size(12.0),
                );
                if bench_snap.running {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let stop_lbl = if is_en { "Stop" } else { "Остановить" };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(stop_lbl).size(10.0).color(Color32::WHITE),
                                )
                                .fill(SEMANTIC_ERR),
                            )
                            .clicked()
                        {
                            self.dns_bench_cancel.store(true, Ordering::SeqCst);
                            self.dns_auto_apply_on_finish
                                .store(false, Ordering::Release);
                        }
                    });
                }
            });

            if bench_snap.running || bench_snap.progress_pct > 0 {
                ui.add_space(4.0);
                let frac = (bench_snap.progress_pct.min(100) as f32) / 100.0;
                let bar_txt = if bench_snap.current_target.is_empty() {
                    format!("{}%", bench_snap.progress_pct)
                } else {
                    format!("{}% · {}", bench_snap.progress_pct, bench_snap.current_target)
                };
                ui.add(
                    egui::ProgressBar::new(frac)
                        .desired_width(ui.available_width())
                        .desired_height(16.0)
                        .fill(active_tokens().accent)
                        .text(RichText::new(bar_txt).monospace().size(10.0)),
                );
            }

            if let Some(ref err) = bench_snap.error {
                ui.add_space(4.0);
                ui.label(RichText::new(err).size(10.0).color(SEMANTIC_ERR));
            }

            if let Some(ref rec) = bench_snap.recommendation {
                ui.add_space(4.0);
                Self::card_frame(true).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        Self::semantic_tag(
                            ui,
                            if is_en {
                                "RECOMMENDED"
                            } else {
                                "РЕКОМЕНДАЦИЯ"
                            },
                            SEMANTIC_OK,
                        );
                        let p_lbl = if is_en {
                            rec.protocol.label_en()
                        } else {
                            rec.protocol.label_ru()
                        };
                        let m_lbl = if is_en {
                            rec.upstream_mode.label_en()
                        } else {
                            rec.upstream_mode.label_ru()
                        };
                        Self::keycap(ui, &format!("{p_lbl} · {m_lbl}"));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let apply_lbl = if is_en {
                                "Apply Recommendation"
                            } else {
                                "Применить рекомендацию"
                            };
                            if ui.add(Self::primary_button(apply_lbl)).clicked() {
                                apply_rec_opt = Some(rec.clone());
                            }
                        });
                    });
                    ui.add_space(4.0);
                    let reason = if is_en {
                        &rec.reason_en
                    } else {
                        &rec.reason_ru
                    };
                    ui.add(
                        egui::Label::new(RichText::new(reason).size(10.5).color(TEXT_PRIMARY))
                            .wrap(),
                    );
                    ui.label(
                        RichText::new(format!(
                            "Servers: {}  |  Bootstrap: {}  |  Fallback: {}",
                            rec.servers.join(", "),
                            rec.bootstrap_servers.join(", "),
                            rec.fallback_servers.join(", ")
                        ))
                        .monospace()
                        .size(9.5)
                        .color(TEXT_SECONDARY),
                    );
                });
            }

            if !bench_snap.results.is_empty() {
                ui.add_space(4.0);
                ScrollArea::horizontal()
                    .id_salt("scroll_dns_bench_h")
                    .show(ui, |ui| {
                        ScrollArea::vertical()
                            .id_salt("scroll_dns_bench_v")
                            .max_height(240.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                egui::Grid::new("dns_benchmark_table")
                                    .num_columns(8)
                                    .striped(true)
                                    .spacing([12.0, 4.0])
                                    .show(ui, |ui| {
                                        let headers = if is_en {
                                            [
                                                "Provider",
                                                "Protocol",
                                                "Address",
                                                "Tag",
                                                "Latency",
                                                "Loss",
                                                "Status",
                                                "TLS Split",
                                            ]
                                        } else {
                                            [
                                                "Провайдер",
                                                "Протокол",
                                                "Адрес",
                                                "Тег",
                                                "Задержка",
                                                "Потери",
                                                "Статус",
                                                "TLS Split",
                                            ]
                                        };
                                        for h in headers {
                                            ui.label(
                                                RichText::new(h)
                                                    .strong()
                                                    .size(10.0)
                                                    .color(TEXT_SECONDARY),
                                            );
                                        }
                                        ui.end_row();

                                        for row in &bench_snap.results {
                                            ui.label(
                                                RichText::new(&row.provider)
                                                    .size(10.0)
                                                    .color(TEXT_PRIMARY),
                                            );
                                            ui.label(
                                                RichText::new(
                                                    row.protocol.as_str().to_ascii_uppercase(),
                                                )
                                                .monospace()
                                                .size(10.0)
                                                .color(ACCENT),
                                            );
                                            ui.label(
                                                RichText::new(&row.address)
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(TEXT_PRIMARY),
                                            );
                                            ui.label(
                                                RichText::new(&row.tag)
                                                    .size(10.0)
                                                    .color(TEXT_SECONDARY),
                                            );

                                            let lat_txt = if row.latency_ms < 0 {
                                                "—".to_string()
                                            } else {
                                                format!("{} ms", row.latency_ms)
                                            };
                                            let (rating_lbl, rating_col) = match row.rating.as_str()
                                            {
                                                "excellent" => (
                                                    if is_en { "Excellent" } else { "Отлично" },
                                                    SEMANTIC_OK,
                                                ),
                                                "good" => (
                                                    if is_en { "Good" } else { "Хорошо" },
                                                    ACCENT,
                                                ),
                                                "fair" => (
                                                    if is_en { "Fair" } else { "Средне" },
                                                    TEXT_SECONDARY,
                                                ),
                                                "slow" => (
                                                    if is_en { "Slow" } else { "Медленно" },
                                                    SEMANTIC_WARN,
                                                ),
                                                "failed" => (
                                                    if is_en { "Failed" } else { "Отказ" },
                                                    SEMANTIC_ERR,
                                                ),
                                                other => (other, TEXT_MUTED),
                                            };
                                            ui.label(
                                                RichText::new(lat_txt)
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(rating_col),
                                            );
                                            ui.label(
                                                RichText::new(format!("{}%", row.loss_pct))
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(if row.loss_pct > 0 {
                                                        SEMANTIC_WARN
                                                    } else {
                                                        TEXT_SECONDARY
                                                    }),
                                            );
                                            ui.label(
                                                RichText::new(rating_lbl)
                                                    .size(10.0)
                                                    .color(rating_col),
                                            );
                                            let (split_txt, split_col) =
                                                if row.protocol == DnsProtocol::Udp {
                                                    ("—", TEXT_MUTED)
                                                } else if row.used_desync {
                                                    (if is_en { "Yes" } else { "Да" }, ACCENT)
                                                } else {
                                                    (
                                                        if is_en { "No" } else { "Нет" },
                                                        TEXT_SECONDARY,
                                                    )
                                                };
                                            ui.label(
                                                RichText::new(split_txt)
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(split_col),
                                            );
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            } else if !bench_snap.running {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(if is_en {
                        "Click \"Auto-Tune (1-Click)\" or \"DNS Benchmark\" above to measure latency across UDP, DoT, and DoH resolvers."
                    } else {
                        "Нажмите «Автонастройка в 1 клик» или «Бенчмарк DNS» выше, чтобы замерить задержку публичных UDP, DoT и DoH серверов."
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
            }
        });

        if let Some(rec) = apply_rec_opt {
            self.apply_dns_recommendation_with_toast(&rec);
        }
    }

    fn render_dns_settings_section(&mut self, ui: &mut egui::Ui, is_en: bool) {
        let tk = active_tokens();
        let mut save_clicked = false;
        let mut discard_clicked = false;
        let mut validation_toasts: Vec<String> = Vec::new();

        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "2. Core DNS Settings & Tuning"
                    } else {
                        "2. Основные настройки и параметры DNS"
                    })
                    .strong()
                    .size(12.0),
                );
            });

            if self.dns_dirty {
                ui.add_space(4.0);
                Self::card_frame(true).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        Self::semantic_tag(
                            ui,
                            if is_en { "UNSAVED" } else { "ИЗМЕНЕНО" },
                            SEMANTIC_WARN,
                        );
                        ui.label(
                            RichText::new(if is_en {
                                "DNS settings have unsaved changes"
                            } else {
                                "Есть несохранённые изменения настроек DNS"
                            })
                            .size(10.5)
                            .color(TEXT_PRIMARY),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let sv_lbl = if is_en {
                                "Save Settings"
                            } else {
                                "Сохранить"
                            };
                            if ui.add(Self::primary_button(sv_lbl)).clicked() {
                                save_clicked = true;
                            }
                            let disc_lbl = if is_en { "Discard" } else { "Отменить" };
                            if ui.small_button(RichText::new(disc_lbl).size(10.0)).clicked() {
                                discard_clicked = true;
                            }
                        });
                    });
                });
            }

            ui.add_space(4.0);
            if Self::gpui_switch(
                ui,
                &mut self.dns_draft.enabled,
                if is_en {
                    "Enable built-in Smart DNS resolver (disable to pass through OS DNS)"
                } else {
                    "Включить встроенный DNS-резолвер (при выключении используется системный DNS ОС)"
                },
            )
            .changed()
            {
                self.dns_dirty = true;
            }

            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if is_en { "Protocol:" } else { "Протокол:" })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                for proto in [DnsProtocol::Doh, DnsProtocol::Dot, DnsProtocol::Udp] {
                    let is_cur = self.dns_draft.protocol == proto;
                    let lbl = if is_en {
                        proto.label_en()
                    } else {
                        proto.label_ru()
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(lbl).size(10.0).color(if is_cur {
                                tk.bg_deepest
                            } else {
                                TEXT_PRIMARY
                            }))
                            .fill(if is_cur { ACCENT } else { tk.bg_elevated }),
                        )
                        .clicked()
                        && !is_cur
                    {
                        self.dns_draft.protocol = proto;
                        if self
                            .dns_draft
                            .servers
                            .iter()
                            .all(|s| validate_dns_server_entry(s, proto).is_err())
                            && let Some(first_preset) = presets_for_protocol(proto).first()
                        {
                            self.dns_draft.servers =
                                first_preset.servers.iter().map(|s| (*s).to_string()).collect();
                            if !first_preset.bootstrap_ip.is_empty()
                                && !self
                                    .dns_draft
                                    .bootstrap_servers
                                    .iter()
                                    .any(|b| b.eq_ignore_ascii_case(first_preset.bootstrap_ip))
                            {
                                self.dns_draft
                                    .bootstrap_servers
                                    .insert(0, first_preset.bootstrap_ip.to_string());
                            }
                        }
                        self.dns_dirty = true;
                    }
                }

                ui.separator();
                ui.label(
                    RichText::new(if is_en { "Upstream:" } else { "Режим:" })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                for mode in [DnsUpstreamMode::Parallel, DnsUpstreamMode::Sequential] {
                    let is_cur = self.dns_draft.upstream_mode == mode;
                    let lbl = if is_en {
                        mode.label_en()
                    } else {
                        mode.label_ru()
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(lbl).size(10.0).color(if is_cur {
                                tk.bg_deepest
                            } else {
                                TEXT_PRIMARY
                            }))
                            .fill(if is_cur { ACCENT } else { tk.bg_elevated }),
                        )
                        .clicked()
                        && !is_cur
                    {
                        self.dns_draft.upstream_mode = mode;
                        self.dns_dirty = true;
                    }
                }
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "IP Strategy:"
                    } else {
                        "Стратегия IP:"
                    })
                    .size(10.0)
                    .color(TEXT_SECONDARY),
                );
                let cur_strat_lbl = if is_en {
                    self.dns_draft.strategy.label_en()
                } else {
                    self.dns_draft.strategy.label_ru()
                };
                egui::ComboBox::from_id_salt("combo_dns_ip_strategy")
                    .width(220.0)
                    .selected_text(RichText::new(cur_strat_lbl).size(10.0))
                    .show_ui(ui, |ui| {
                        for st in DnsIpStrategy::ALL {
                            let lbl = if is_en { st.label_en() } else { st.label_ru() };
                            if ui
                                .selectable_label(self.dns_draft.strategy == st, lbl)
                                .clicked()
                            {
                                self.dns_draft.strategy = st;
                                self.dns_dirty = true;
                            }
                        }
                    });
            });

            // Чипы провайдеров из presets_for_protocol
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Provider presets:"
                    } else {
                        "Пресеты провайдеров:"
                    })
                    .size(10.0)
                    .color(TEXT_SECONDARY),
                );
                for preset in presets_for_protocol(self.dns_draft.protocol) {
                    let is_cur = self.dns_draft.servers.len() == preset.servers.len()
                        && self
                            .dns_draft
                            .servers
                            .iter()
                            .zip(preset.servers.iter())
                            .all(|(a, b)| a.eq_ignore_ascii_case(b));
                    let lbl = if preset.tag.is_empty() {
                        preset.provider.to_string()
                    } else {
                        format!("{} [{}]", preset.provider, preset.tag)
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(lbl).size(10.0).color(if is_cur {
                                ACCENT
                            } else {
                                TEXT_PRIMARY
                            }))
                            .fill(if is_cur { tk.bg_hover } else { tk.bg_elevated })
                            .stroke(Stroke::new(
                                1.0_f32,
                                if is_cur { ACCENT } else { tk.border_subtle },
                            )),
                        )
                        .on_hover_text(preset.servers.join(", "))
                        .clicked()
                    {
                        self.dns_draft.servers =
                            preset.servers.iter().map(|s| (*s).to_string()).collect();
                        if !preset.bootstrap_ip.is_empty()
                            && !self
                                .dns_draft
                                .bootstrap_servers
                                .iter()
                                .any(|b| b.eq_ignore_ascii_case(preset.bootstrap_ip))
                        {
                            self.dns_draft
                                .bootstrap_servers
                                .insert(0, preset.bootstrap_ip.to_string());
                        }
                        self.dns_dirty = true;
                    }
                }
            });

            // Редакторы списков servers / bootstrap_servers / fallback_servers
            ui.add_space(4.0);
            let main_hint = match self.dns_draft.protocol {
                DnsProtocol::Doh => "https://dns.example/dns-query",
                DnsProtocol::Dot => "tls://dns.example:853",
                DnsProtocol::Udp => {
                    if is_en {
                        "1.1.1.1 or 77.88.8.8:1253"
                    } else {
                        "1.1.1.1 или 77.88.8.8:1253"
                    }
                }
            };
            if let Some(err) = Self::render_dns_server_list_editor(
                ui,
                is_en,
                if is_en {
                    "Upstream DNS Servers"
                } else {
                    "Основные DNS-серверы"
                },
                main_hint,
                &mut self.dns_draft.servers,
                &mut self.dns_server_input,
                &mut self.dns_dirty,
                self.dns_draft.protocol,
                "dns_main_servers_editor",
                8,
                1,
            ) {
                validation_toasts.push(err);
            }

            ui.add_space(4.0);
            ui.columns(2, |cols| {
                if let Some(err) = Self::render_dns_server_list_editor(
                    &mut cols[0],
                    is_en,
                    if is_en {
                        "Bootstrap UDP Servers"
                    } else {
                        "Bootstrap UDP-серверы"
                    },
                    "77.88.8.8:1253 / 1.1.1.1",
                    &mut self.dns_draft.bootstrap_servers,
                    &mut self.dns_bootstrap_input,
                    &mut self.dns_dirty,
                    DnsProtocol::Udp,
                    "dns_bootstrap_servers_editor",
                    6,
                    0,
                ) {
                    validation_toasts.push(err);
                }

                if let Some(err) = Self::render_dns_server_list_editor(
                    &mut cols[1],
                    is_en,
                    if is_en {
                        "Fallback UDP Servers"
                    } else {
                        "Резервные UDP-серверы"
                    },
                    "208.67.222.222:5353 / 1.0.0.1",
                    &mut self.dns_draft.fallback_servers,
                    &mut self.dns_fallback_input,
                    &mut self.dns_dirty,
                    DnsProtocol::Udp,
                    "dns_fallback_servers_editor",
                    6,
                    0,
                ) {
                    validation_toasts.push(err);
                }
            });

            // Пресеты Bootstrap
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Bootstrap presets:"
                    } else {
                        "Пресеты Bootstrap:"
                    })
                    .size(9.5)
                    .color(TEXT_MUTED),
                );
                for (lbl, addrs) in bootstrap_presets() {
                    if ui
                        .small_button(RichText::new(*lbl).size(9.5))
                        .on_hover_text(addrs.join(", "))
                        .clicked()
                    {
                        self.dns_draft.bootstrap_servers =
                            addrs.iter().map(|s| (*s).to_string()).collect();
                        self.dns_dirty = true;
                    }
                }
            });

            // Инженерные переключатели
            ui.add_space(4.0);
            Self::card_frame(false).show(ui, |ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Engine & Cache Tuning"
                    } else {
                        "Инженерные параметры и кэш"
                    })
                    .strong()
                    .size(10.5)
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);

                ui.columns(2, |cols| {
                    if Self::gpui_switch(
                        &mut cols[0],
                        &mut self.dns_draft.desync_doh_dot,
                        if is_en {
                            "TLS Record Split for DoH/DoT"
                        } else {
                            "TLS Record Split для DoH/DoT"
                        },
                    )
                    .on_hover_text(if is_en {
                        "Fragment TLS 1.3 ClientHello records on encrypted DoH/DoT connections"
                    } else {
                        "Применять фрагментацию TLS-записей к зашифрованным соединениям DoH и DoT"
                    })
                    .changed()
                    {
                        self.dns_dirty = true;
                    }

                    if Self::gpui_switch(
                        &mut cols[1],
                        &mut self.dns_draft.split_local_ru,
                        if is_en {
                            "Fast local UDP for .ru/.su/.рф/.local"
                        } else {
                            "Быстрый UDP для .ru/.su/.рф/.local"
                        },
                    )
                    .on_hover_text(if is_en {
                        "Resolve domestic and local-network zones directly via fast UDP bootstrap"
                    } else {
                        "Направлять запросы локальных и .ru/.su/.рф зон напрямую через быстрый UDP bootstrap"
                    })
                    .changed()
                    {
                        self.dns_dirty = true;
                    }
                });

                ui.columns(2, |cols| {
                    if Self::gpui_switch(
                        &mut cols[0],
                        &mut self.dns_draft.local_cache,
                        if is_en {
                            "In-memory DNS cache"
                        } else {
                            "Локальный кэш DNS в памяти"
                        },
                    )
                    .changed()
                    {
                        self.dns_dirty = true;
                    }

                    if Self::gpui_switch(
                        &mut cols[1],
                        &mut self.dns_draft.turbo_cache,
                        if is_en {
                            "Turbo startup cache pre-resolve"
                        } else {
                            "Турбо-предразрешение при старте"
                        },
                    )
                    .changed()
                    {
                        self.dns_dirty = true;
                    }
                });

                ui.columns(2, |cols| {
                    if Self::gpui_switch(
                        &mut cols[0],
                        &mut self.dns_draft.reverse_mapping,
                        if is_en {
                            "Reverse IP -> domain table (TUN)"
                        } else {
                            "Обратная таблица IP -> домен (TUN)"
                        },
                    )
                    .changed()
                    {
                        self.dns_dirty = true;
                    }

                    if Self::gpui_switch(
                        &mut cols[1],
                        &mut self.dns_draft.reject_fake_ip,
                        if is_en {
                            "Filter synthetic / bogon IPs"
                        } else {
                            "Отсеивать синтетические / локальные IP"
                        },
                    )
                    .changed()
                    {
                        self.dns_dirty = true;
                    }
                });

                if Self::gpui_switch(
                    ui,
                    &mut self.dns_draft.fallback_system_dns,
                    if is_en {
                        "Fallback to OS DNS when all upstreams fail"
                    } else {
                        "Переходить на системный DNS ОС при отказе всех серверов"
                    },
                )
                .changed()
                {
                    self.dns_dirty = true;
                }

                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Cache size:"
                        } else {
                            "Размер кэша:"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                    if ui
                        .add_enabled(
                            self.dns_draft.local_cache,
                            egui::DragValue::new(&mut self.dns_draft.cache_size)
                                .range(256..=65536)
                                .speed(64),
                        )
                        .changed()
                    {
                        self.dns_dirty = true;
                    }
                    Self::keycap(
                        ui,
                        &format!(
                            "~{} {}",
                            estimate_cache_ram_kb(self.dns_draft.cache_size),
                            if is_en { "KiB RAM" } else { "КиБ ОЗУ" }
                        ),
                    );
                    for preset_sz in [1024usize, 4096, 16384] {
                        if ui
                            .small_button(RichText::new(preset_sz.to_string()).monospace().size(9.5))
                            .clicked()
                        {
                            self.dns_draft.cache_size = preset_sz;
                            self.dns_dirty = true;
                        }
                    }

                    ui.separator();
                    ui.label(
                        RichText::new(if is_en {
                            "Min TTL rewrite (s):"
                        } else {
                            "Мин. TTL ответа (с):"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                    if ui
                        .add(
                            egui::DragValue::new(&mut self.dns_draft.rewrite_ttl_secs)
                                .range(0..=3600),
                        )
                        .changed()
                    {
                        self.dns_dirty = true;
                    }
                });
            });

            // Блок таймингов переключения при Sequential
            if self.dns_draft.upstream_mode == DnsUpstreamMode::Sequential {
                ui.add_space(4.0);
                Self::card_frame(false).show(ui, |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Sequential Health & Failover Timings"
                        } else {
                            "Тайминги проверки и автопереключения (Последовательный режим)"
                        })
                        .strong()
                        .size(10.5)
                        .color(TEXT_PRIMARY),
                    );
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(if is_en {
                                "Check interval (s):"
                            } else {
                                "Интервал (с):"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        );
                        if ui
                            .add(
                                egui::DragValue::new(&mut self.dns_draft.check_interval_secs)
                                    .range(5..=600),
                            )
                            .changed()
                        {
                            self.dns_dirty = true;
                        }

                        ui.label(
                            RichText::new(if is_en {
                                "Recovery interval (s):"
                            } else {
                                "Возврат (с):"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        );
                        if ui
                            .add(
                                egui::DragValue::new(
                                    &mut self.dns_draft.recovery_check_interval_secs,
                                )
                                .range(10..=1800),
                            )
                            .changed()
                        {
                            self.dns_dirty = true;
                        }

                        ui.label(
                            RichText::new(if is_en {
                                "Timeout (ms):"
                            } else {
                                "Таймаут (мс):"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        );
                        if ui
                            .add(
                                egui::DragValue::new(&mut self.dns_draft.check_timeout_ms)
                                    .range(300..=10000)
                                    .speed(50),
                            )
                            .changed()
                        {
                            self.dns_dirty = true;
                        }

                        ui.label(
                            RichText::new(if is_en {
                                "Fail thr:"
                            } else {
                                "Порог сбоев:"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        );
                        if ui
                            .add(
                                egui::DragValue::new(&mut self.dns_draft.failure_threshold)
                                    .range(1..=10),
                            )
                            .changed()
                        {
                            self.dns_dirty = true;
                        }

                        ui.label(
                            RichText::new(if is_en {
                                "Rec thr:"
                            } else {
                                "Порог восст.:"
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        );
                        if ui
                            .add(
                                egui::DragValue::new(&mut self.dns_draft.recovery_threshold)
                                    .range(1..=10),
                            )
                            .changed()
                        {
                            self.dns_dirty = true;
                        }
                    });
                });
            }
        });

        for err in validation_toasts {
            self.push_toast(
                ToastKind::Warn,
                if is_en {
                    "Invalid DNS server entry"
                } else {
                    "Некорректный адрес DNS-сервера"
                },
                err,
            );
        }

        if save_clicked {
            let parsed = Self::parse_speed_domains(&self.dns_speed_domains_input);
            self.dns_draft.speed_test_domains = if parsed.is_empty() {
                default_speed_test_domains()
            } else {
                parsed
            };
            if let Ok(val) = serde_json::to_value(&self.dns_draft) {
                self.dns_dirty = false;
                self.dispatch_ipc("update_dns_settings", val);
                self.push_toast(
                    ToastKind::Success,
                    if is_en {
                        "DNS settings saved"
                    } else {
                        "Настройки DNS сохранены"
                    },
                    format!(
                        "{} · {} {}",
                        self.dns_draft.protocol.as_str().to_ascii_uppercase(),
                        self.dns_draft.servers.len(),
                        if is_en {
                            "servers"
                        } else {
                            "сервер(ов)"
                        }
                    ),
                );
            }
        } else if discard_clicked {
            self.dns_draft = self.snap.config.dns.clone();
            self.dns_speed_domains_input = self.dns_draft.speed_test_domains.join("\n");
            self.dns_dirty = false;
        }
    }

    fn render_dns_speed_test_section(&mut self, ui: &mut egui::Ui, is_en: bool) {
        let speed_snap = self
            .dns_speed_state
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let mut trigger_start = false;
        let mut trigger_stop = false;

        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "3. Multi-Domain Speed Test (Current Servers)"
                    } else {
                        "3. Многодоменный тест скорости текущих серверов"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if speed_snap.running {
                        let stop_lbl = if is_en { "Stop" } else { "Остановить" };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(stop_lbl).size(10.0).color(Color32::WHITE),
                                )
                                .fill(SEMANTIC_ERR),
                            )
                            .clicked()
                        {
                            trigger_stop = true;
                        }
                    } else {
                        let start_lbl = if is_en {
                            "Run Speed Test"
                        } else {
                            "Запустить тест"
                        };
                        if ui.add(Self::primary_button(start_lbl)).clicked() {
                            trigger_start = true;
                        }
                    }
                    let rst_lbl = if is_en {
                        "Reset defaults"
                    } else {
                        "Сбросить к дефолтам"
                    };
                    if ui.small_button(RichText::new(rst_lbl).size(10.0)).clicked() {
                        let defs = default_speed_test_domains();
                        self.dns_draft.speed_test_domains = defs;
                        self.dns_speed_domains_input =
                            self.dns_draft.speed_test_domains.join("\n");
                        self.dns_dirty = true;
                    }
                });
            });

            let parsed_cnt = Self::parse_speed_domains(&self.dns_speed_domains_input).len();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        format!(
                            "Test domains ({parsed_cnt}/32, newline/comma separated):"
                        )
                    } else {
                        format!(
                            "Домены для замера ({parsed_cnt}/32, по одному на строку или через запятую):"
                        )
                    })
                    .size(10.0)
                    .color(TEXT_MUTED),
                );
            });
            if ui
                .add(
                    TextEdit::multiline(&mut self.dns_speed_domains_input)
                        .id_salt("dns_speed_domains_editor")
                        .font(FontId::new(10.0, FontFamily::Monospace))
                        .desired_rows(3)
                        .desired_width(ui.available_width())
                        .hint_text("google.com\nyoutube.com\ndiscord.com"),
                )
                .changed()
            {
                let parsed = Self::parse_speed_domains(&self.dns_speed_domains_input);
                if !parsed.is_empty() {
                    self.dns_draft.speed_test_domains = parsed;
                }
                self.dns_dirty = true;
            }

            if speed_snap.running || speed_snap.progress_pct > 0 {
                ui.add_space(4.0);
                let frac = (speed_snap.progress_pct.min(100) as f32) / 100.0;
                let bar_txt = if speed_snap.current_target.is_empty() {
                    format!("{}%", speed_snap.progress_pct)
                } else {
                    format!("{}% · {}", speed_snap.progress_pct, speed_snap.current_target)
                };
                ui.add(
                    egui::ProgressBar::new(frac)
                        .desired_width(ui.available_width())
                        .desired_height(16.0)
                        .fill(active_tokens().accent)
                        .text(RichText::new(bar_txt).monospace().size(10.0)),
                );
            }

            if let Some(ref err) = speed_snap.error {
                ui.add_space(4.0);
                ui.label(RichText::new(err).size(10.0).color(SEMANTIC_ERR));
            }

            if !speed_snap.reports.is_empty() {
                ui.add_space(4.0);
                let fmt_ms = |v: i32| -> String {
                    if v < 0 {
                        "—".to_string()
                    } else {
                        format!("{v} ms")
                    }
                };
                ScrollArea::horizontal()
                    .id_salt("scroll_dns_speed_h")
                    .show(ui, |ui| {
                        egui::Grid::new("dns_speed_table")
                            .num_columns(7)
                            .striped(true)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                let headers = if is_en {
                                    ["Server", "Role", "Min", "Median", "Avg", "Max", "Success"]
                                } else {
                                    ["Сервер", "Роль", "Min", "Median", "Avg", "Max", "Успешно"]
                                };
                                for h in headers {
                                    ui.label(
                                        RichText::new(h)
                                            .strong()
                                            .size(10.0)
                                            .color(TEXT_SECONDARY),
                                    );
                                }
                                ui.end_row();

                                for (idx, rep) in speed_snap.reports.iter().enumerate() {
                                    let is_sel = self.selected_speed_server_idx == Some(idx);
                                    let srv_lbl = format!(
                                        "{} ({})",
                                        rep.server,
                                        rep.protocol.as_str().to_ascii_uppercase()
                                    );
                                    if ui
                                        .selectable_label(
                                            is_sel,
                                            RichText::new(srv_lbl)
                                                .monospace()
                                                .size(10.0)
                                                .color(if is_sel { ACCENT } else { TEXT_PRIMARY }),
                                        )
                                        .on_hover_text(if is_en {
                                            "Click to expand per-domain details"
                                        } else {
                                            "Нажмите, чтобы раскрыть детали по доменам"
                                        })
                                        .clicked()
                                    {
                                        self.selected_speed_server_idx =
                                            if is_sel { None } else { Some(idx) };
                                    }

                                    let role_lbl = match rep.role.as_str() {
                                        "main" => {
                                            if is_en { "Primary" } else { "Основной" }
                                        }
                                        "bootstrap" => "Bootstrap",
                                        "fallback" => {
                                            if is_en { "Fallback" } else { "Резерв" }
                                        }
                                        other => other,
                                    };
                                    ui.label(
                                        RichText::new(role_lbl).size(10.0).color(TEXT_SECONDARY),
                                    );
                                    ui.label(
                                        RichText::new(fmt_ms(rep.min_ms))
                                            .monospace()
                                            .size(10.0)
                                            .color(TEXT_PRIMARY),
                                    );
                                    ui.label(
                                        RichText::new(fmt_ms(rep.median_ms))
                                            .monospace()
                                            .strong()
                                            .size(10.0)
                                            .color(ACCENT),
                                    );
                                    ui.label(
                                        RichText::new(fmt_ms(rep.avg_ms))
                                            .monospace()
                                            .size(10.0)
                                            .color(TEXT_PRIMARY),
                                    );
                                    ui.label(
                                        RichText::new(fmt_ms(rep.max_ms))
                                            .monospace()
                                            .size(10.0)
                                            .color(TEXT_SECONDARY),
                                    );
                                    let ok_col = if rep.success_count == rep.total_count {
                                        SEMANTIC_OK
                                    } else if rep.success_count > 0 {
                                        SEMANTIC_WARN
                                    } else {
                                        SEMANTIC_ERR
                                    };
                                    ui.label(
                                        RichText::new(format!(
                                            "{}/{}",
                                            rep.success_count, rep.total_count
                                        ))
                                        .monospace()
                                        .size(10.0)
                                        .color(ok_col),
                                    );
                                    ui.end_row();
                                }
                            });
                    });

                if let Some(sel_idx) = self.selected_speed_server_idx
                    && let Some(rep) = speed_snap.reports.get(sel_idx)
                {
                    ui.add_space(4.0);
                    Self::card_frame(true).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(if is_en {
                                    format!("Per-domain breakdown: {}", rep.server)
                                } else {
                                    format!("Детализация по доменам: {}", rep.server)
                                })
                                .strong()
                                .size(10.5)
                                .color(TEXT_PRIMARY),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .small_button(if is_en { "Collapse" } else { "Скрыть" })
                                    .clicked()
                                {
                                    self.selected_speed_server_idx = None;
                                }
                            });
                        });
                        ui.add_space(4.0);
                        ScrollArea::vertical()
                            .id_salt("scroll_dns_speed_samples")
                            .max_height(180.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                egui::Grid::new("dns_speed_samples_grid")
                                    .num_columns(4)
                                    .striped(true)
                                    .spacing([12.0, 4.0])
                                    .show(ui, |ui| {
                                        for s in &rep.samples {
                                            ui.label(
                                                RichText::new(&s.domain)
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(TEXT_PRIMARY),
                                            );
                                            ui.label(
                                                RichText::new(if s.ok { "OK" } else { "FAIL" })
                                                    .monospace()
                                                    .size(10.0)
                                                    .color(if s.ok {
                                                        SEMANTIC_OK
                                                    } else {
                                                        SEMANTIC_ERR
                                                    }),
                                            );
                                            ui.label(
                                                RichText::new(if s.ms < 0 {
                                                    "—".to_string()
                                                } else {
                                                    format!("{} ms", s.ms)
                                                })
                                                .monospace()
                                                .size(10.0)
                                                .color(TEXT_SECONDARY),
                                            );
                                            ui.label(
                                                RichText::new(&s.detail)
                                                    .size(10.0)
                                                    .color(TEXT_MUTED),
                                            );
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
                }
            }
        });

        if trigger_stop {
            self.dns_speed_cancel.store(true, Ordering::SeqCst);
        } else if trigger_start {
            self.start_dns_speed_test();
        }
    }

    fn render_tab_dns(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let is_en = self.is_en();
        let bench_running = self
            .dns_bench_state
            .lock()
            .map(|g| g.running)
            .unwrap_or(false);
        let speed_running = self
            .dns_speed_state
            .lock()
            .map(|g| g.running)
            .unwrap_or(false);
        if bench_running || speed_running {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        // Верхняя плашка live-телеметрии + кнопки действий
        self.render_dns_telemetry_bar(ui, is_en, bench_running, speed_running);
        ui.add_space(4.0);

        // Секция 1: Бенчмарк и автонастройка
        self.render_dns_benchmark_section(ui, is_en);
        ui.add_space(4.0);

        // Секция 2: Основные настройки и параметры DNS
        self.render_dns_settings_section(ui, is_en);
        ui.add_space(4.0);

        // Секция 3: Многодоменный тест скорости текущих серверов
        self.render_dns_speed_test_section(ui, is_en);
        ui.add_space(4.0);

        // Секция 4: Локальные переопределения домен=IP
        Self::panel_frame().show(ui, |ui| {
            let hosts_cnt = self.snap.config.dns_overrides.len();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        format!("4. Local Domain Overrides ({hosts_cnt})")
                    } else {
                        format!("4. Локальные переопределения домен=IP ({hosts_cnt})")
                    })
                    .strong()
                    .size(12.0),
                );
            });
            ui.add_space(4.0);
            self.render_dns_overrides_editor(ui, is_en, "dns_tab_overrides");
        });
    }

    fn render_about_modal(&mut self, ctx: &egui::Context) {
        if !self.about_modal_open {
            return;
        }
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.about_modal_open = false;
            return;
        }

        let is_en = self.is_en();
        let mut open_flag = self.about_modal_open;
        let repo_url = "https://github.com/Dushnilin/tachyon-desync";
        let core_url = "https://github.com/Dushnilin/tachyon-core";
        let lists_url = "https://github.com/Dushnilin/tachyon-lists";

        egui::Window::new(if is_en {
            "About Tachyon Desync"
        } else {
            "О программе Tachyon Desync"
        })
        .open(&mut open_flag)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
        .default_width(420.0)
        .frame(
            Frame::new()
                .fill(BG_PANEL)
                .stroke(Stroke::new(1.0_f32, BORDER_STRONG))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::same(12)),
        )
        .show(ctx, |ui| {
            ui.set_width(412.0);

            // Шапка окна About: Монограмма [T] + название + бейдж версии v0.0.1
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::new(28.0, 28.0), Sense::hover());
                ui.painter()
                    .rect_filled(rect, CornerRadius::same(4), BG_ELEVATED);
                ui.painter().rect_stroke(
                    rect,
                    CornerRadius::same(4),
                    Stroke::new(1.0_f32, BORDER_STRONG),
                    StrokeKind::Inside,
                );
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "T",
                    FontId::new(13.0, FontFamily::Monospace),
                    ACCENT,
                );

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Tachyon Desync")
                                .strong()
                                .size(13.0)
                                .color(TEXT_PRIMARY),
                        );
                        Self::keycap(ui, concat!("v", env!("CARGO_PKG_VERSION")));
                        Self::keycap(ui, "Pure Rust 2024");
                    });
                    ui.label(
                        RichText::new(if is_en {
                            "Adaptive L4/L7 packet desynchronization & traffic segmentation client"
                        } else {
                            "Клиент адаптивной L4/L7-десинхронизации и сегментации сетевых пакетов"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                });
            });

            ui.add_space(8.0);

            // Четыре карточки технических параметров
            ui.columns(2, |cols| {
                Self::card_frame(false).show(&mut cols[0], |ui| {
                    ui.label(
                        RichText::new(if is_en { "Engine" } else { "Движок" })
                            .size(10.0)
                            .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new("AdaptiveBrain L1–L3")
                            .monospace()
                            .strong()
                            .size(11.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(if is_en {
                            "16 TCP + 4 UDP recipes · 32 KiB gate"
                        } else {
                            "16 TCP + 4 UDP рецепта · гейт 32 КиБ"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                });

                Self::card_frame(false).show(&mut cols[1], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Traffic capture"
                        } else {
                            "Перехват трафика"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new("Wintun / utun / tun · SOCKS5")
                            .monospace()
                            .strong()
                            .size(11.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(if is_en {
                            "smoltcp stack · Per-App process filter"
                        } else {
                            "стек smoltcp · фильтр по процессам"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                });
            });

            ui.add_space(4.0);

            ui.columns(2, |cols| {
                Self::card_frame(false).show(&mut cols[0], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Diagnostics & DNS"
                        } else {
                            "Диагностика и DNS"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new("Auto-TTL · RST Re-learn")
                            .monospace()
                            .strong()
                            .size(11.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(if is_en {
                            "Smart DNS (DoH/DoT/UDP) · Local hosts"
                        } else {
                            "Умный DNS (DoH/DoT/UDP) · Local hosts"
                        })
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                    );
                });

                Self::card_frame(false).show(&mut cols[1], |ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Runtime & Hotkey"
                        } else {
                            "Рантайм и управление"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new("Ctrl + Alt + D")
                            .monospace()
                            .strong()
                            .size(11.0)
                            .color(ACCENT),
                    );
                    ui.label(
                        RichText::new("Windows · Linux · macOS · OpenGL UI")
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                    );
                });
            });

            ui.add_space(8.0);

            // Карточка самообновления программы (Auto-Update)
            let upd_snapshot = self
                .update_state
                .lock()
                .ok()
                .map(|g| g.clone())
                .unwrap_or(GuiUpdateState::Idle);
            Self::card_frame(matches!(upd_snapshot, GuiUpdateState::Available(_))).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Software Update"
                        } else {
                            "Обновление программы"
                        })
                        .strong()
                        .size(11.0)
                        .color(TEXT_PRIMARY),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let check_busy = matches!(
                            upd_snapshot,
                            GuiUpdateState::Checking | GuiUpdateState::Downloading(_)
                        );
                        let check_lbl = if is_en {
                            "Check for updates"
                        } else {
                            "Проверить обновления"
                        };
                        if ui
                            .add_enabled(
                                !check_busy,
                                egui::Button::new(
                                    RichText::new(check_lbl).size(10.0).color(TEXT_PRIMARY),
                                )
                                .fill(BG_PANEL),
                            )
                            .clicked()
                        {
                            self.trigger_update_check();
                        }
                    });
                });

                ui.add_space(4.0);
                match upd_snapshot {
                    GuiUpdateState::Idle => {
                        ui.label(
                            RichText::new(if is_en {
                                format!(
                                    "Installed version: v{} (automatic background check enabled)",
                                    env!("CARGO_PKG_VERSION")
                                )
                            } else {
                                format!(
                                    "Установлена версия v{} (фоновая проверка при запуске включена)",
                                    env!("CARGO_PKG_VERSION")
                                )
                            })
                            .size(10.0)
                            .color(TEXT_SECONDARY),
                        );
                    }
                    GuiUpdateState::Checking => {
                        ui.label(
                            RichText::new(if is_en {
                                "Checking GitHub Releases for new version..."
                            } else {
                                "Проверка наличия новой версии на GitHub Releases..."
                            })
                            .size(10.0)
                            .color(ACCENT),
                        );
                    }
                    GuiUpdateState::UpToDate(ver) => {
                        ui.label(
                            RichText::new(if is_en {
                                format!("You are running the latest version (v{ver}).")
                            } else {
                                format!("Установлена самая свежая версия (v{ver}).")
                            })
                            .size(10.0)
                            .color(SEMANTIC_OK),
                        );
                    }
                    GuiUpdateState::Available(info) => {
                        let size_mb = (info.asset_size as f64) / (1024.0 * 1024.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(if is_en {
                                    format!("New release available: v{}", info.latest_version)
                                } else {
                                    format!("Доступен новый релиз: v{}", info.latest_version)
                                })
                                .strong()
                                .size(11.0)
                                .color(SEMANTIC_OK),
                            );
                            if info.asset_size > 0 {
                                Self::keycap(ui, &format!("{size_mb:.1} MiB"));
                            }
                            if info.sha256sums_url.is_some() {
                                Self::keycap(ui, "SHA-256");
                            }
                        });

                        if !info.release_notes.is_empty() {
                            ui.add_space(4.0);
                            egui::ScrollArea::vertical()
                                .id_salt("update_release_notes_scroll")
                                .max_height(88.0)
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(&info.release_notes)
                                            .monospace()
                                            .size(9.5)
                                            .color(TEXT_SECONDARY),
                                    );
                                });
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            let install_lbl = if is_en {
                                format!("Download & Install v{}", info.latest_version)
                            } else {
                                format!("Скачать и установить v{}", info.latest_version)
                            };
                            if ui.add(Self::primary_button(&install_lbl)).clicked() {
                                self.trigger_update_install(info.clone());
                            }
                            let notes_lbl = if is_en {
                                "Release page"
                            } else {
                                "Страница релиза"
                            };
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(notes_lbl).size(10.0).color(TEXT_SECONDARY),
                                    )
                                    .fill(BG_PANEL),
                                )
                                .clicked()
                            {
                                crate::tray::open_url_in_browser(&info.release_url);
                            }
                        });
                    }
                    GuiUpdateState::Downloading(info) => {
                        ui.label(
                            RichText::new(if is_en {
                                format!(
                                    "Downloading {} and verifying SHA-256...",
                                    info.asset_name
                                )
                            } else {
                                format!(
                                    "Скачивание {} и проверка SHA-256 (приложение перезапустится автоматически)...",
                                    info.asset_name
                                )
                            })
                            .size(10.0)
                            .color(ACCENT),
                        );
                    }
                    GuiUpdateState::ReadyToRestart(_) => {
                        ui.label(
                            RichText::new(if is_en {
                                "Update verified. Restarting application..."
                            } else {
                                "Обновление проверено. Перезапуск приложения..."
                            })
                            .size(10.0)
                            .color(SEMANTIC_OK),
                        );
                    }
                    GuiUpdateState::Error(err) => {
                        ui.label(
                            RichText::new(&err)
                                .size(10.0)
                                .color(SEMANTIC_ERR),
                        );
                    }
                }
            });

            ui.add_space(8.0);

            // Карточка со ссылкой на основной репозиторий GitHub и экосистему Tachyon
            Self::card_frame(true).show(ui, |ui| {
                ui.label(
                    RichText::new(if is_en {
                        "GitHub Repository"
                    } else {
                        "Официальный репозиторий GitHub"
                    })
                    .strong()
                    .size(11.0)
                    .color(TEXT_PRIMARY),
                );
                let link_resp = ui.add(
                    egui::Label::new(
                        RichText::new(repo_url)
                            .monospace()
                            .size(11.0)
                            .color(ACCENT)
                            .underline(),
                    )
                    .sense(Sense::click()),
                );
                if link_resp
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text(if is_en {
                        "Open repository in browser"
                    } else {
                        "Открыть репозиторий в браузере"
                    })
                    .clicked()
                {
                    crate::tray::open_url_in_browser(repo_url);
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(if is_en {
                            "Ecosystem:"
                        } else {
                            "Экосистема:"
                        })
                        .size(10.0)
                        .color(TEXT_MUTED),
                    );
                    let core_resp = ui.add(
                        egui::Label::new(
                            RichText::new("Dushnilin/tachyon-core")
                                .monospace()
                                .size(10.0)
                                .color(TEXT_SECONDARY)
                                .underline(),
                        )
                        .sense(Sense::click()),
                    );
                    if core_resp
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(core_url)
                        .clicked()
                    {
                        crate::tray::open_url_in_browser(core_url);
                    }
                    ui.label(RichText::new("·").size(10.0).color(TEXT_MUTED));
                    let lists_resp = ui.add(
                        egui::Label::new(
                            RichText::new("Dushnilin/tachyon-lists")
                                .monospace()
                                .size(10.0)
                                .color(TEXT_SECONDARY)
                                .underline(),
                        )
                        .sense(Sense::click()),
                    );
                    if lists_resp
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(lists_url)
                        .clicked()
                    {
                        crate::tray::open_url_in_browser(lists_url);
                    }
                });
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Tachyon Binary License v1.0 · Copyright (c) 2026 Dushnilin")
                        .monospace()
                        .size(10.0)
                        .color(TEXT_MUTED),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let close_lbl = if is_en { "Close" } else { "Закрыть" };
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(close_lbl).size(11.0).color(TEXT_PRIMARY),
                            )
                            .fill(BG_ELEVATED),
                        )
                        .clicked()
                    {
                        self.about_modal_open = false;
                    }
                });
            });
        });

        if !open_flag {
            self.about_modal_open = false;
        }
    }

    // Нижняя приборная панель StatusBar (left / center / right из gpui-kit/src/status_bar.rs)
    fn render_gpui_status_bar(&mut self, ctx: &egui::Context) {
        let tk = active_tokens();
        let is_en = self.is_en();

        egui::TopBottomPanel::bottom("gpui_status_bar")
            .exact_height(22.0)
            .frame(
                Frame::new()
                    .fill(tk.bg_deepest)
                    .stroke(Stroke::new(1.0_f32, tk.border_subtle))
                    .inner_margin(Margin::symmetric(8, 2)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    // LEFT REGION: Статус контура + DNS + Кэш L1/L2
                    let dot_col = if self.snap.running {
                        SEMANTIC_OK
                    } else {
                        TEXT_MUTED
                    };
                    let (dot_r, _) = ui.allocate_exact_size(Vec2::new(7.0, 7.0), Sense::hover());
                    ui.painter().circle_filled(dot_r.center(), 3.0, dot_col);

                    let cap_short = match self.snap.config.capture_mode {
                        CaptureMode::Tun => "TUN L3",
                        CaptureMode::SystemProxy => "SysProxy",
                        CaptureMode::LocalProxy => "SOCKS5",
                    };
                    ui.label(
                        RichText::new(cap_short)
                            .monospace()
                            .strong()
                            .size(9.5)
                            .color(if self.snap.running {
                                TEXT_PRIMARY
                            } else {
                                TEXT_MUTED
                            }),
                    );
                    ui.label(RichText::new("│").size(9.5).color(tk.border_strong));

                    let dns_st = &self.snap.dns_status;
                    let dns_short = if !dns_st.enabled {
                        if is_en {
                            "DNS: OS".to_string()
                        } else {
                            "DNS: ОС".to_string()
                        }
                    } else {
                        let primary = if dns_st.active_primary.is_empty() {
                            self.snap
                                .config
                                .dns
                                .servers
                                .first()
                                .map(String::as_str)
                                .unwrap_or("-")
                        } else {
                            dns_st.active_primary.as_str()
                        };
                        format!(
                            "DNS: {} {primary}",
                            dns_st.protocol.as_str().to_ascii_uppercase()
                        )
                    };
                    let dns_col = if !dns_st.enabled {
                        TEXT_MUTED
                    } else if dns_st.consecutive_failures > 0 {
                        SEMANTIC_WARN
                    } else {
                        TEXT_SECONDARY
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(dns_short)
                                    .monospace()
                                    .size(9.5)
                                    .color(dns_col),
                            )
                            .fill(tk.bg_elevated)
                            .small(),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(if is_en {
                            "Active DNS resolver — click to open DNS tab"
                        } else {
                            "Активный DNS-резолвер — нажмите, чтобы открыть вкладку DNS"
                        })
                        .clicked()
                    {
                        self.active_tab = ActiveTab::Dns;
                    }
                    ui.label(RichText::new("│").size(9.5).color(tk.border_strong));

                    let cc_lbl = format!(
                        "CC: {}",
                        self.snap
                            .config
                            .network
                            .tcp_congestion
                            .as_str()
                            .to_ascii_uppercase()
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(cc_lbl)
                                    .monospace()
                                    .size(9.5)
                                    .color(TEXT_SECONDARY),
                            )
                            .fill(tk.bg_elevated)
                            .small(),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(if is_en {
                            "TCP Congestion Control & TUN tuning — click to open"
                        } else {
                            "Алгоритм перегрузки TCP и настройки TUN — нажмите для открытия"
                        })
                        .clicked()
                    {
                        self.active_tab = ActiveTab::Overview;
                        self.show_net_tuning_panel = true;
                    }
                    ui.label(RichText::new("│").size(9.5).color(tk.border_strong));

                    let verified_cnt = self
                        .snap
                        .learned_domains
                        .iter()
                        .filter(|d| d.verified)
                        .count();
                    ui.label(
                        RichText::new(format!(
                            "32K: {}/{}",
                            verified_cnt,
                            self.snap.learned_domains.len()
                        ))
                        .monospace()
                        .size(9.5)
                        .color(tk.accent),
                    );

                    // RIGHT REGION (закреплён справа): Трафик ↓RX ↑TX + Аптайм + Ctrl+K
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Ctrl+K")
                                        .monospace()
                                        .size(9.0)
                                        .color(TEXT_SECONDARY),
                                )
                                .fill(tk.bg_elevated)
                                .small(),
                            )
                            .on_hover_text(if is_en {
                                "Open Command Palette (Ctrl+K)"
                            } else {
                                "Палитра быстрых команд (Ctrl+K)"
                            })
                            .clicked()
                        {
                            self.cmd_palette_open = true;
                            self.cmd_palette_just_opened = true;
                            self.cmd_palette_selected = 0;
                        }

                        ui.label(RichText::new("│").size(9.5).color(tk.border_strong));
                        ui.label(
                            RichText::new(format_uptime(self.snap.uptime_sec))
                                .monospace()
                                .size(9.5)
                                .color(TEXT_MUTED),
                        );
                        ui.label(RichText::new("│").size(9.5).color(tk.border_strong));
                        ui.label(
                            RichText::new(format!(
                                "↓{} ↑{}",
                                format_rate_bps(self.cur_rx_bps, is_en),
                                format_rate_bps(self.cur_tx_bps, is_en)
                            ))
                            .monospace()
                            .size(9.5)
                            .color(TEXT_PRIMARY),
                        );

                        // CENTER REGION: последняя строка живого журнала событий
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            if let Some(last_log) = self.snap.logs.last() {
                                ui.label(RichText::new("│").size(9.5).color(tk.border_strong));
                                let msg = localize_runtime_text(&last_log.message, is_en);
                                let line = format!("[{}] {}", last_log.category, msg);
                                let resp = ui.add(
                                    egui::Label::new(
                                        RichText::new(line).monospace().size(9.5).color(TEXT_MUTED),
                                    )
                                    .truncate()
                                    .sense(Sense::click()),
                                );
                                if resp
                                    .on_hover_text(if is_en {
                                        "Click to open Event Log tab"
                                    } else {
                                        "Нажмите, чтобы перейти во вкладку Журнал"
                                    })
                                    .clicked()
                                {
                                    self.active_tab = ActiveTab::Logs;
                                }
                            }
                        });
                    });
                });
            });
    }

    // Стек неблокирующих уведомлений Toast / Notification (из gpui-kit/src/notification.rs)
    fn render_toast_stack(&mut self, ctx: &egui::Context) {
        let now = Instant::now();
        self.toasts
            .retain(|t| now.duration_since(t.created) < t.duration);
        if self.toasts.is_empty() {
            return;
        }

        let tk = active_tokens();
        let screen = ctx.screen_rect();
        let anchor_pos = Pos2::new(screen.max.x - 12.0, screen.max.y - 32.0);
        let mut dismiss_idx: Option<usize> = None;

        egui::Area::new(Id::new("gpui_toast_stack_area"))
            .order(egui::Order::Foreground)
            .pivot(egui::Align2::RIGHT_BOTTOM)
            .fixed_pos(anchor_pos)
            .show(ctx, |ui| {
                ui.set_width(284.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    for (idx, toast) in self.toasts.iter().enumerate() {
                        let accent_col = match toast.kind {
                            ToastKind::Info => tk.accent,
                            ToastKind::Success => SEMANTIC_OK,
                            ToastKind::Warn => SEMANTIC_WARN,
                            ToastKind::Error => SEMANTIC_ERR,
                        };
                        let elapsed = now.duration_since(toast.created).as_secs_f32();
                        let total = toast.duration.as_secs_f32().max(0.1);
                        let rem_frac = (1.0 - (elapsed / total)).clamp(0.0, 1.0);

                        let frame_resp = Frame::new()
                            .fill(tk.bg_elevated)
                            .stroke(Stroke::new(1.0_f32, tk.border_strong))
                            .corner_radius(CornerRadius::same(6))
                            .inner_margin(Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.set_width(264.0);
                                ui.horizontal(|ui| {
                                    let (bar_r, _) = ui
                                        .allocate_exact_size(Vec2::new(3.0, 26.0), Sense::hover());
                                    ui.painter().rect_filled(
                                        bar_r,
                                        CornerRadius::same(1),
                                        accent_col,
                                    );
                                    ui.vertical(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new(&toast.title)
                                                    .strong()
                                                    .size(10.5)
                                                    .color(TEXT_PRIMARY),
                                            );
                                            ui.with_layout(
                                                Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if ui
                                                        .small_button(
                                                            RichText::new("×")
                                                                .size(10.0)
                                                                .color(TEXT_MUTED),
                                                        )
                                                        .clicked()
                                                    {
                                                        dismiss_idx = Some(idx);
                                                    }
                                                },
                                            );
                                        });
                                        if !toast.detail.is_empty() {
                                            ui.label(
                                                RichText::new(&toast.detail)
                                                    .size(9.5)
                                                    .color(TEXT_SECONDARY),
                                            );
                                        }
                                    });
                                });
                            });

                        // Тонкая полоска таймера авто-скрытия внизу карточки
                        let r = frame_resp.response.rect;
                        let prog_w = (r.width() - 4.0) * rem_frac;
                        if prog_w > 1.0 {
                            let prog_rect = Rect::from_min_size(
                                Pos2::new(r.min.x + 2.0, r.max.y - 2.0),
                                Vec2::new(prog_w, 1.5),
                            );
                            ui.painter()
                                .rect_filled(prog_rect, CornerRadius::same(1), accent_col);
                        }
                    }
                });
            });

        if let Some(i) = dismiss_idx {
            self.toasts.remove(i);
        }
        ctx.request_repaint_after(Duration::from_millis(80));
    }

    // Модальная палитра быстрых команд Command Palette (Ctrl+K / F1 из gpui-kit/src/command/)
    fn render_command_palette(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| (i.modifiers.ctrl || i.modifiers.command) && i.key_pressed(Key::K))
            || ctx.input(|i| i.key_pressed(Key::F1))
        {
            self.cmd_palette_open = !self.cmd_palette_open;
            if self.cmd_palette_open {
                self.cmd_palette_just_opened = true;
                self.cmd_palette_selected = 0;
            }
        }

        if !self.cmd_palette_open {
            return;
        }
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.cmd_palette_open = false;
            return;
        }

        let is_en = self.is_en();
        let tk = active_tokens();

        // Формируем список команд: (код, категория, заголовок, бейдж справа)
        let mut items: Vec<(String, &'static str, String, &'static str)> = vec![
            (
                "toggle_run".to_string(),
                if is_en {
                    "Control"
                } else {
                    "Управление"
                },
                if self.snap.running {
                    if is_en {
                        "Stop Packet Desynchronization Capture".to_string()
                    } else {
                        "Остановить перехват и десинхронизацию".to_string()
                    }
                } else if is_en {
                    "Start Packet Desynchronization Capture".to_string()
                } else {
                    "Запустить перехват и десинхронизацию".to_string()
                },
                "Run",
            ),
            (
                "mode_tun".to_string(),
                if is_en { "Capture" } else { "Перехват" },
                if is_en {
                    "Switch Capture to TUN Adapter (Wintun L3)".to_string()
                } else {
                    "Режим перехвата: Адаптер TUN (Wintun L3)".to_string()
                },
                "TUN L3",
            ),
            (
                "mode_sysproxy".to_string(),
                if is_en { "Capture" } else { "Перехват" },
                if is_en {
                    "Switch Capture to System Proxy (:7897)".to_string()
                } else {
                    "Режим перехвата: Системный прокси (:7897)".to_string()
                },
                ":7897",
            ),
            (
                "health_check".to_string(),
                if is_en {
                    "Probe"
                } else {
                    "Диагностика"
                },
                if is_en {
                    "Check Availability of 6 Key Services".to_string()
                } else {
                    "Проверить доступность 6 ключевых узлов".to_string()
                },
                "6 Nodes",
            ),
            (
                "probe_24".to_string(),
                if is_en {
                    "Generator"
                } else {
                    "Генератор"
                },
                if is_en {
                    "Generate Strategy: Full Scan (24 Recipes)".to_string()
                } else {
                    "Подобрать стратегию: Полный скан (24 рецепта)".to_string()
                },
                "24 Rec",
            ),
            (
                "probe_12".to_string(),
                if is_en {
                    "Generator"
                } else {
                    "Генератор"
                },
                if is_en {
                    "Generate Strategy: Quick Scan (12 Recipes)".to_string()
                } else {
                    "Подобрать стратегию: Быстрый скан (12 рецептов)".to_string()
                },
                "12 Rec",
            ),
            (
                "calib_ttl".to_string(),
                if is_en {
                    "Generator"
                } else {
                    "Генератор"
                },
                if is_en {
                    "Calibrate Optimal Auto-TTL Distance (Hops 2..10)".to_string()
                } else {
                    "Авто-калибровка оптимального Auto-TTL (2..10 хопов)".to_string()
                },
                "Auto-TTL",
            ),
            (
                "reset_domain_cache".to_string(),
                if is_en {
                    "Generator"
                } else {
                    "Генератор"
                },
                if is_en {
                    format!("Reset Adaptive Cache for Domain ({})", self.probe_domain)
                } else {
                    format!("Сбросить кэш для домена ({})", self.probe_domain)
                },
                "Cache",
            ),
            (
                "clear_brain_cache".to_string(),
                if is_en {
                    "Generator"
                } else {
                    "Генератор"
                },
                if is_en {
                    "Reset Entire AdaptiveBrain Cache (adaptive_cache.json)".to_string()
                } else {
                    "Сбросить весь кэш адаптивного подбора (adaptive_cache.json)".to_string()
                },
                "Flush",
            ),
            (
                "copy_logs".to_string(),
                if is_en { "Logs" } else { "Журнал" },
                if is_en {
                    "Copy Full Event Log to Clipboard".to_string()
                } else {
                    "Скопировать весь журнал событий в буфер обмена".to_string()
                },
                "Ctrl+C",
            ),
            (
                "clear_logs".to_string(),
                if is_en { "Logs" } else { "Журнал" },
                if is_en {
                    "Clear Event Log".to_string()
                } else {
                    "Очистить журнал событий".to_string()
                },
                "Clear",
            ),
            (
                "check_updates".to_string(),
                if is_en { "System" } else { "Система" },
                if is_en {
                    "Check for Tachyon Desync Updates on GitHub".to_string()
                } else {
                    "Проверить наличие обновлений программы на GitHub".to_string()
                },
                "Update",
            ),
            (
                "tab_overview".to_string(),
                if is_en { "Navigate" } else { "Вкладка" },
                if is_en {
                    "Go to Tab: Auto & Telemetry".to_string()
                } else {
                    "Перейти: Авто и телеметрия".to_string()
                },
                "Tab 1",
            ),
            (
                "tab_flows".to_string(),
                if is_en { "Navigate" } else { "Вкладка" },
                if is_en {
                    "Go to Tab: Live Connections".to_string()
                } else {
                    "Перейти: Потоки (Активные соединения)".to_string()
                },
                "Tab 2",
            ),
            (
                "tab_generator".to_string(),
                if is_en { "Navigate" } else { "Вкладка" },
                if is_en {
                    "Go to Tab: Strategy Generator & Builder".to_string()
                } else {
                    "Перейти: Генератор и конструктор стратегий".to_string()
                },
                "Tab 3",
            ),
            (
                "tab_lists".to_string(),
                if is_en { "Navigate" } else { "Вкладка" },
                if is_en {
                    "Go to Tab: Domain Lists & .exe Filter".to_string()
                } else {
                    "Перейти: Списки доменов и фильтр .exe".to_string()
                },
                "Tab 4",
            ),
            (
                "tab_dns".to_string(),
                if is_en { "Navigate" } else { "Вкладка" },
                if is_en {
                    "Go to Tab: DNS & Auto-Tune".to_string()
                } else {
                    "Перейти: DNS и автонастройка".to_string()
                },
                "Tab 5",
            ),
            (
                "tab_logs".to_string(),
                if is_en { "Navigate" } else { "Вкладка" },
                if is_en {
                    "Go to Tab: Scoreboard & Event Log".to_string()
                } else {
                    "Перейти: Рейтинг L3 и Журнал событий".to_string()
                },
                "Tab 6",
            ),
            (
                "dns_auto_tune".to_string(),
                "DNS",
                if is_en {
                    "DNS Auto-Tune (Benchmark + Apply Best)".to_string()
                } else {
                    "Автонастройка DNS (бенчмарк и выбор лучшего)".to_string()
                },
                "Auto",
            ),
            (
                "dns_benchmark".to_string(),
                "DNS",
                if is_en {
                    "Run DNS Benchmark (UDP / DoT / DoH)".to_string()
                } else {
                    "Запустить бенчмарк DNS (UDP / DoT / DoH)".to_string()
                },
                "Bench",
            ),
            (
                "dns_speed_test".to_string(),
                "DNS",
                if is_en {
                    "Run Multi-Domain DNS Speed Test".to_string()
                } else {
                    "Запустить многодоменный тест скорости DNS".to_string()
                },
                "Speed",
            ),
            (
                "dns_flush_cache".to_string(),
                "DNS",
                if is_en {
                    "Flush DNS Resolver Cache".to_string()
                } else {
                    "Сбросить локальный кэш DNS".to_string()
                },
                "Flush",
            ),
            (
                "net_preset_turbo".to_string(),
                "Net",
                if is_en {
                    "Apply Turbo 4K Stack Profile (BBR + 2 MiB + Happy Eyeballs v2)".to_string()
                } else {
                    "Включить профиль Турбо 4K (BBR + 2 MiB + Happy Eyeballs v2)".to_string()
                },
                "Turbo",
            ),
            (
                "net_preset_default".to_string(),
                "Net",
                if is_en {
                    "Reset Network Stack Tuning to Defaults (BBR + Auto)".to_string()
                } else {
                    "Сбросить сетевой стек на стандарт (BBR + Авто)".to_string()
                },
                "Reset",
            ),
        ];

        for preset in GpuiThemePreset::ALL {
            items.push((
                format!("theme_{}", preset as u8),
                if is_en { "Theme" } else { "Тема" },
                if is_en {
                    format!("Apply Theme: {}", preset.label())
                } else {
                    format!("Применить тему: {}", preset.label())
                },
                preset.label(),
            ));
        }

        for p in &self.snap.config.custom_profiles {
            items.push((
                format!("profile_{}", p.id),
                if is_en { "Profile" } else { "Профиль" },
                format!(
                    "{} ({} + {}, TTL={})",
                    p.name, p.config.mode, p.config.fooling, p.config.fake_ttl
                ),
                "Custom",
            ));
        }

        for r in &self.snap.recipes_catalog {
            let loc_t = localize_recipe_title(r.id, &r.title, is_en);
            items.push((
                format!("recipe_{}", r.id),
                if is_en { "Recipe" } else { "Рецепт" },
                format!("#{:02} {}", r.id, loc_t),
                "Apply",
            ));
        }

        let q = self.cmd_palette_query.trim().to_ascii_lowercase();
        let filtered: Vec<_> = items
            .into_iter()
            .filter(|(_, cat, title, badge)| {
                if q.is_empty() {
                    return true;
                }
                cat.to_ascii_lowercase().contains(&q)
                    || title.to_ascii_lowercase().contains(&q)
                    || badge.to_ascii_lowercase().contains(&q)
            })
            .collect();

        if !filtered.is_empty() {
            if self.cmd_palette_selected >= filtered.len() {
                self.cmd_palette_selected = filtered.len() - 1;
            }
            if ctx.input(|i| i.key_pressed(Key::ArrowDown)) {
                self.cmd_palette_selected = (self.cmd_palette_selected + 1) % filtered.len();
            }
            if ctx.input(|i| i.key_pressed(Key::ArrowUp)) {
                self.cmd_palette_selected = if self.cmd_palette_selected == 0 {
                    filtered.len() - 1
                } else {
                    self.cmd_palette_selected - 1
                };
            }
        } else {
            self.cmd_palette_selected = 0;
        }

        let mut triggered_code: Option<String> = None;
        if ctx.input(|i| i.key_pressed(Key::Enter))
            && let Some((code, _, _, _)) = filtered.get(self.cmd_palette_selected)
        {
            triggered_code = Some(code.clone());
        }

        let screen = ctx.screen_rect();
        egui::Area::new(Id::new("gpui_command_palette_modal"))
            .order(egui::Order::Foreground)
            .pivot(egui::Align2::CENTER_TOP)
            .fixed_pos(Pos2::new(screen.center().x, screen.top() + 52.0))
            .show(ctx, |ui| {
                Frame::new()
                    .fill(tk.bg_panel)
                    .stroke(Stroke::new(1.0_f32, tk.border_strong))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_width((screen.width() - 48.0).clamp(320.0, 480.0));

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("⌘")
                                    .monospace()
                                    .strong()
                                    .size(12.0)
                                    .color(tk.accent),
                            );
                            let inp_w = (ui.available_width() - 44.0).max(160.0);
                            let resp = ui.add(
                                TextEdit::singleline(&mut self.cmd_palette_query)
                                    .hint_text(if is_en {
                                        "Type a command, recipe #00..#15, or theme..."
                                    } else {
                                        "Введите команду, номер рецепта #00..#15 или тему..."
                                    })
                                    .desired_width(inp_w),
                            );
                            if self.cmd_palette_just_opened {
                                resp.request_focus();
                                self.cmd_palette_just_opened = false;
                            }
                            if resp.changed() {
                                self.cmd_palette_selected = 0;
                            }
                            Self::kbd_badge(ui, "Esc");
                        });

                        ui.add_space(4.0);

                        ScrollArea::vertical()
                            .id_salt("scroll_cmd_palette")
                            .max_height(260.0)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if filtered.is_empty() {
                                    ui.label(
                                        RichText::new(if is_en {
                                            "No matching commands"
                                        } else {
                                            "Команды не найдены"
                                        })
                                        .size(10.0)
                                        .color(TEXT_MUTED),
                                    );
                                    return;
                                }
                                for (idx, (code, cat, title, badge)) in filtered.iter().enumerate()
                                {
                                    let is_sel = idx == self.cmd_palette_selected;
                                    let row_fill = if is_sel {
                                        tk.bg_hover
                                    } else {
                                        Color32::TRANSPARENT
                                    };
                                    let row_stroke = if is_sel {
                                        Stroke::new(1.0_f32, tk.border_strong)
                                    } else {
                                        Stroke::NONE
                                    };
                                    let row_resp = Frame::new()
                                        .fill(row_fill)
                                        .stroke(row_stroke)
                                        .corner_radius(CornerRadius::same(4))
                                        .inner_margin(Margin::symmetric(6, 4))
                                        .show(ui, |ui| {
                                            ui.set_width(ui.available_width());
                                            ui.horizontal(|ui| {
                                                Self::semantic_tag(ui, cat, tk.accent);
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(title)
                                                            .size(10.5)
                                                            .color(TEXT_PRIMARY),
                                                    )
                                                    .truncate(),
                                                );
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        Self::kbd_badge(ui, badge);
                                                    },
                                                );
                                            });
                                        })
                                        .response
                                        .interact(Sense::click());

                                    if row_resp.hovered() {
                                        self.cmd_palette_selected = idx;
                                    }
                                    if row_resp.clicked() {
                                        triggered_code = Some(code.clone());
                                    }
                                }
                            });
                    });
            });

        if let Some(code) = triggered_code {
            self.cmd_palette_open = false;
            self.cmd_palette_query.clear();
            match code.as_str() {
                "toggle_run" => {
                    let was_running = self.snap.running;
                    self.dispatch_ipc("toggle_running", serde_json::json!({}));
                    let mode_str = self.snap.active_mode.clone();
                    if was_running && !self.snap.running {
                        self.push_toast(
                            ToastKind::Warn,
                            if is_en {
                                "Capture stopped"
                            } else {
                                "Перехват остановлен"
                            },
                            mode_str,
                        );
                    } else if self.snap.running {
                        self.push_toast(
                            ToastKind::Success,
                            if is_en {
                                "Capture active"
                            } else {
                                "Перехват запущен"
                            },
                            mode_str,
                        );
                    } else {
                        self.push_toast(
                            ToastKind::Error,
                            if is_en {
                                "Failed to start capture"
                            } else {
                                "Не удалось запустить перехват"
                            },
                            mode_str,
                        );
                    }
                }
                "mode_tun" => {
                    self.dispatch_ipc(
                        "set_capture_mode",
                        serde_json::json!({ "capture_mode": "tun" }),
                    );
                    self.push_toast(
                        ToastKind::Info,
                        "TUN L3 (Wintun)",
                        if is_en {
                            "Capture mode switched to TUN"
                        } else {
                            "Режим перехвата переключён на Адаптер TUN"
                        },
                    );
                }
                "mode_sysproxy" => {
                    self.dispatch_ipc(
                        "set_capture_mode",
                        serde_json::json!({ "capture_mode": "system_proxy" }),
                    );
                    self.push_toast(
                        ToastKind::Info,
                        "System Proxy (:7897)",
                        if is_en {
                            "Capture mode switched to System Proxy"
                        } else {
                            "Режим перехвата переключён на Системный прокси"
                        },
                    );
                }
                "health_check" => {
                    self.active_tab = ActiveTab::Overview;
                    self.start_health_check();
                    self.push_toast(
                        ToastKind::Info,
                        if is_en {
                            "Checking 6 services..."
                        } else {
                            "Проверка 6 узлов..."
                        },
                        "TLS 1.3 + 32 KiB Gate",
                    );
                }
                "probe_24" => {
                    self.active_tab = ActiveTab::Generator;
                    self.start_probe_scan(true);
                }
                "probe_12" => {
                    self.active_tab = ActiveTab::Generator;
                    self.start_probe_scan(false);
                }
                "calib_ttl" => {
                    self.active_tab = ActiveTab::Generator;
                    self.start_ttl_calibration();
                }
                "copy_logs" => {
                    let mut lines = Vec::with_capacity(self.snap.logs.len() + 1);
                    lines.push(format!(
                        "# Tachyon Desync v{} | mode={}",
                        env!("CARGO_PKG_VERSION"),
                        self.snap.active_mode
                    ));
                    for l in &self.snap.logs {
                        lines.push(format!(
                            "{} [{}] {}",
                            format_hms(l.ts_ms),
                            l.category,
                            localize_runtime_text(&l.message, is_en)
                        ));
                    }
                    ctx.copy_text(lines.join("\n"));
                    self.push_toast(
                        ToastKind::Success,
                        if is_en {
                            "Event log copied"
                        } else {
                            "Журнал скопирован"
                        },
                        format!("{} lines", self.snap.logs.len()),
                    );
                }
                "clear_logs" => {
                    self.dispatch_ipc("clear_logs", serde_json::json!({}));
                }
                "reset_domain_cache" => {
                    let dom = self.probe_domain.trim().to_string();
                    if !dom.is_empty() {
                        self.dispatch_ipc(
                            "remove_learned_domain",
                            serde_json::json!({ "host": dom.clone() }),
                        );
                        self.push_toast(
                            ToastKind::Info,
                            if is_en {
                                "Domain cache reset"
                            } else {
                                "Кэш домена сброшен"
                            },
                            dom,
                        );
                    }
                }
                "clear_brain_cache" => {
                    self.dispatch_ipc("clear_brain", serde_json::json!({}));
                    self.push_toast(
                        ToastKind::Info,
                        if is_en {
                            "Adaptive cache cleared"
                        } else {
                            "Кэш адаптивного подбора очищен"
                        },
                        "adaptive_cache.json",
                    );
                }
                "check_updates" => {
                    self.about_modal_open = true;
                    self.trigger_update_check();
                }
                "tab_overview" => self.active_tab = ActiveTab::Overview,
                "tab_flows" => self.active_tab = ActiveTab::Flows,
                "tab_generator" => self.active_tab = ActiveTab::Generator,
                "tab_lists" => self.active_tab = ActiveTab::Lists,
                "tab_dns" => self.active_tab = ActiveTab::Dns,
                "tab_logs" => self.active_tab = ActiveTab::Logs,
                "dns_auto_tune" => {
                    self.active_tab = ActiveTab::Dns;
                    self.start_dns_benchmark(true);
                }
                "dns_benchmark" => {
                    self.active_tab = ActiveTab::Dns;
                    self.start_dns_benchmark(false);
                }
                "dns_speed_test" => {
                    self.active_tab = ActiveTab::Dns;
                    self.start_dns_speed_test();
                }
                "dns_flush_cache" => {
                    self.flush_dns_cache_with_toast();
                }
                "net_preset_turbo" => {
                    let turbo = NetworkTuningConfig {
                        tcp_congestion: TcpCongestionMode::Bbr,
                        tun_buffer_mode: TunBufferMode::Turbo2m,
                        tun_mss_clamp: true,
                        tun_mtu: self.net_draft.tun_mtu,
                        tun_ipv6: self.net_draft.tun_ipv6,
                        happy_eyeballs: true,
                        quic_fast_failover: true,
                        stream_verify_192k: true,
                    };
                    self.net_draft = turbo.clone();
                    self.net_dirty = false;
                    self.probe_stream_192k = true;
                    self.dispatch_ipc("update_network_tuning", serde_json::json!(turbo));
                }
                "net_preset_default" => {
                    let def = NetworkTuningConfig::default();
                    self.net_draft = def.clone();
                    self.net_dirty = false;
                    self.probe_stream_192k = def.stream_verify_192k;
                    self.dispatch_ipc("update_network_tuning", serde_json::json!(def));
                }
                other if other.starts_with("theme_") => {
                    if let Ok(idx) = other.trim_start_matches("theme_").parse::<u8>() {
                        self.set_theme_preset(GpuiThemePreset::from_u8(idx));
                    }
                }
                other if other.starts_with("profile_") => {
                    let pid = other.trim_start_matches("profile_");
                    if let Some(found) = self
                        .snap
                        .config
                        .custom_profiles
                        .iter()
                        .find(|p| p.id.eq_ignore_ascii_case(pid))
                        .cloned()
                    {
                        self.builder_cfg = found.config.clone();
                        self.builder_profile_name = found.name.clone();
                        self.selected_profile_id = Some(found.id.clone());
                        self.builder_dirty = true;
                        self.active_tab = ActiveTab::Generator;
                        self.push_toast(
                            ToastKind::Info,
                            if is_en {
                                format!("Profile loaded: {}", found.name)
                            } else {
                                format!("Профиль загружен: {}", found.name)
                            },
                            format!(
                                "{} + {}, TTL={}",
                                found.config.mode, found.config.fooling, found.config.fake_ttl
                            ),
                        );
                    }
                }
                other if other.starts_with("recipe_") => {
                    if let Ok(rid) = other.trim_start_matches("recipe_").parse::<u8>()
                        && let Some(item) = self
                            .snap
                            .recipes_catalog
                            .iter()
                            .find(|r| r.id == rid)
                            .cloned()
                    {
                        self.builder_cfg = item.config.clone();
                        self.builder_dirty = false;
                        if let Ok(val) = serde_json::to_value(&self.builder_cfg) {
                            self.dispatch_ipc("update_global_desync", val);
                        }
                        self.active_tab = ActiveTab::Generator;
                        self.push_toast(
                            ToastKind::Success,
                            format!("Recipe #{:02} applied", rid),
                            localize_recipe_title(rid, &item.title, is_en),
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

impl eframe::App for TachyonGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.configure_gpui_theme(ctx);
        Self::handle_custom_window_resize(ctx);

        if self.start_minimized && !self.start_minimized_done {
            self.start_minimized_done = true;
            crate::tray::hide_main_window_to_tray();
        }

        let restart_exe = self.update_state.lock().ok().and_then(|g| match &*g {
            GuiUpdateState::ReadyToRestart(p) => Some(p.clone()),
            _ => None,
        });
        if let Some(exe_path) = restart_exe {
            self.tokio_handle.block_on(self.rt.stop());
            crate::updater::spawn_updated_binary_and_exit(&exe_path);
        }

        if crate::tray::take_show_window_request() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        if ctx.input(|i| i.viewport().close_requested()) && !crate::tray::is_exit_requested() {
            if self.snap.config.minimize_to_tray {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                crate::tray::hide_main_window_to_tray();
            } else {
                self.tokio_handle.block_on(self.rt.stop());
            }
        }

        self.poll_snapshot_if_due();

        if self.dns_auto_apply_on_finish.load(Ordering::Acquire) {
            let bench_done = self.dns_bench_state.lock().ok().and_then(|st| {
                if !st.running {
                    Some((st.recommendation.clone(), st.error.clone()))
                } else {
                    None
                }
            });
            if let Some((rec_opt, err_opt)) = bench_done {
                self.dns_auto_apply_on_finish
                    .store(false, Ordering::Release);
                if !self.dns_bench_cancel.load(Ordering::Relaxed) {
                    if let Some(rec) = rec_opt {
                        self.apply_dns_recommendation_with_toast(&rec);
                    } else if let Some(err) = err_opt {
                        let is_en = self.is_en();
                        self.push_toast(
                            ToastKind::Warn,
                            if is_en {
                                "DNS auto-tune finished"
                            } else {
                                "Автонастройка DNS"
                            },
                            err,
                        );
                    }
                }
            }
        }

        let tk = active_tokens();

        egui::TopBottomPanel::top("custom_window_titlebar")
            .frame(
                Frame::new()
                    .fill(tk.bg_deepest)
                    .stroke(Stroke::new(1.0_f32, tk.border_subtle))
                    .inner_margin(Margin::symmetric(8, 4)),
            )
            .show(ctx, |ui| {
                self.render_custom_titlebar(ctx, ui);
            });

        self.render_gpui_status_bar(ctx);

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(tk.bg_canvas)
                    .inner_margin(Margin::same(8)),
            )
            .show(ctx, |ui| {
                self.render_top_header(ui);
                ui.add_space(8.0);

                ScrollArea::vertical()
                    .id_salt("main_tab_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.active_tab {
                        ActiveTab::Overview => self.render_tab_overview(ui),
                        ActiveTab::Flows => self.render_tab_flows(ui),
                        ActiveTab::Generator => self.render_tab_generator(ui),
                        ActiveTab::Lists => self.render_tab_lists(ui),
                        ActiveTab::Dns => self.render_tab_dns(ui, ctx),
                        ActiveTab::Logs => self.render_tab_logs(ui),
                    });
            });

        self.render_list_modal(ctx);
        self.render_about_modal(ctx);
        self.render_command_palette(ctx);
        self.render_toast_stack(ctx);

        // Тонкая внешняя рамка 1px вокруг безрамочного окна (когда окно не развёрнуто на весь экран)
        if !ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
            let fg_painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                Id::new("custom_window_outer_border"),
            ));
            fg_painter.rect_stroke(
                ctx.screen_rect(),
                CornerRadius::ZERO,
                Stroke::new(1.0_f32, tk.border_strong),
                StrokeKind::Inside,
            );
        }

        let dns_active = self
            .dns_bench_state
            .lock()
            .map(|g| g.running)
            .unwrap_or(false)
            || self
                .dns_speed_state
                .lock()
                .map(|g| g.running)
                .unwrap_or(false);
        ctx.request_repaint_after(Duration::from_millis(if dns_active { 120 } else { 500 }));
    }
}

fn strategy_options(en: bool) -> [(&'static str, &'static str); 12] {
    if en {
        [
            ("auto", "Auto (24 recipes)"),
            ("custom", "Generator Profile"),
            ("fake_split", "FakeSplit (midsld)"),
            ("fake_disorder", "FakeDisorder (midsld)"),
            ("seven_point_disorder", "7-Point MultiDisorder"),
            ("host_fake_split", "HostFakeSplit"),
            ("pad_encap", "PadEncap"),
            ("multi_split", "MultiSplit"),
            ("multi_disorder", "MultiDisorder"),
            ("tlsrec", "TlsRec (TLS Split)"),
            ("upstream", "Upstream Proxy (SOCKS5/HTTP)"),
            ("direct", "Direct (Bypass)"),
        ]
    } else {
        [
            ("auto", "Авто (24 рецепта)"),
            ("custom", "Профиль Генератора"),
            ("fake_split", "FakeSplit (midsld)"),
            ("fake_disorder", "FakeDisorder (midsld)"),
            ("seven_point_disorder", "7-Point MultiDisorder"),
            ("host_fake_split", "HostFakeSplit"),
            ("pad_encap", "PadEncap"),
            ("multi_split", "MultiSplit"),
            ("multi_disorder", "MultiDisorder"),
            ("tlsrec", "TlsRec (фрагментация TLS)"),
            ("upstream", "Внешний прокси (SOCKS5/HTTP)"),
            ("direct", "Прямое (Исключение)"),
        ]
    }
}

fn strategy_short_label(code: &str, en: bool) -> &'static str {
    for (c, lbl) in strategy_options(en) {
        if c == code {
            return lbl;
        }
    }
    if en { "Auto" } else { "Авто" }
}

fn resolve_strategy_label(code: &str, opts: &[(String, String)], en: bool) -> String {
    let trimmed = code.trim();
    for (c, lbl) in opts {
        if c.eq_ignore_ascii_case(trimmed) {
            return lbl.clone();
        }
    }
    strategy_short_label(trimmed, en).to_string()
}

fn format_bytes(bytes: u64, en: bool) -> String {
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{} {}", bytes, if en { "B" } else { "Б" })
    } else if bytes < 1024 * 1024 {
        format!("{:.1} {}", b / 1024.0, if en { "KiB" } else { "КиБ" })
    } else if bytes < 1024 * 1024 * 1024 {
        format!(
            "{:.1} {}",
            b / (1024.0 * 1024.0),
            if en { "MiB" } else { "МиБ" }
        )
    } else {
        format!(
            "{:.2} {}",
            b / (1024.0 * 1024.0 * 1024.0),
            if en { "GiB" } else { "ГиБ" }
        )
    }
}

fn format_rate_bps(bytes_per_sec: f64, en: bool) -> String {
    let bits = bytes_per_sec * 8.0;
    if bits < 1000.0 {
        format!("{:.0} {}", bytes_per_sec, if en { "B/s" } else { "Б/с" })
    } else if bits < 1_000_000.0 {
        format!(
            "{:.1} {}",
            bits / 1000.0,
            if en { "Kbit/s" } else { "Кбит/с" }
        )
    } else {
        format!(
            "{:.2} {}",
            bits / 1_000_000.0,
            if en { "Mbit/s" } else { "Мбит/с" }
        )
    }
}

fn format_uptime(sec: u64) -> String {
    let hh = sec / 3600;
    let mm = (sec % 3600) / 60;
    let ss = sec % 60;
    format!("{hh:02}:{mm:02}:{ss:02}")
}

fn format_hms(ts_ms: u64) -> String {
    let total_secs = (ts_ms / 1000) % 86400;
    let hh = (total_secs / 3600 + 3) % 24;
    let mm = (total_secs % 3600) / 60;
    let ss = total_secs % 60;
    format!("{hh:02}:{mm:02}:{ss:02}")
}

fn build_outbound_json_string(cfg: &DesyncConfig) -> String {
    let mut c = cfg.clone();
    c.auto = false;
    serde_json::to_string_pretty(&c.to_core_outbound_json()).unwrap_or_default()
}

const ACTIVE_MODE_EN: &[(&str, &str)] = &[
    ("Остановлен", "Stopped"),
    ("Адаптер TUN (Wintun L3)", "TUN Adapter (Wintun L3)"),
    (
        "Системный прокси (127.0.0.1:7897)",
        "System Proxy (127.0.0.1:7897)",
    ),
    (
        "Локальный прокси (127.0.0.1:7897)",
        "Local Proxy (127.0.0.1:7897)",
    ),
];

const RECIPE_TITLES_EN: &[&str] = &[
    "#0 FakeSplit (midsld, MD5 ClientHello clone)",
    "#1 TlsRec + Split (SNI TLS record split, no fake)",
    "#2 FakeSplit + TlsRec (midsld, PAWS Timestamp, max.ru)",
    "#3 FakeDisorder (midsld, MD5, vk.com)",
    "#4 FakeDisorder + TlsRec (midsld, BadSeq -10000, rzd.ru)",
    "#5 IPv6 HopByHop2 + FakeSplit (midsld, fonts.google.com)",
    "#6 MultiSplit [2, sni_ext, host, midsld] + TlsRec",
    "#7 FakeSplit AutoTTL (SNI boundary, gosuslugi.ru)",
    "#8 MultiDisorder [2, sni_ext, host, midsld] (MD5, vk.com)",
    "#9 Disorder (1st byte AutoTTL + retransmit)",
    "#10 7-Point MultiDisorder (Md5BadAck + rndsni)",
    "#11 HostFakeSplit Disorder (in-band host slice, Md5BadAck, rzd.ru)",
    "#12 FakeDisorder (BadAck -66000 + PadEncap + seqovl=8)",
    "#13 7-Point MultiDisorder (BadSeq+BadAck+BadSum, ozon.ru)",
    "#14 FakeSplit DataNoAck (PSH no-ACK + sniext+1 + seqovl=12, aws.amazon.com)",
    "#15 HostFakeSplit Disorder (AutoTTL, max.ru)",
    "#16 OOB Urgent (MSG_OOB urgent pointer at midsld, no fake)",
    "#17 Disoob + TlsRec (out-of-order MSG_OOB at host+1 + wsize=64)",
    "#18 MultiSplit + SeqOvl=210 (pure segment overlap, no fake)",
    "#19 FakeSplit sni_del (SNI-stripped clone + DataNoAck + seqovl=16)",
    "#20 MultiDisorder bin_noise (0x0F0F0F0F decoy + BadSeq+BadAck+BadSum)",
    "#21 FakeDisorder SYNData (SYN decoy + Md5BadAck + PadEncap + seqovl=10)",
    "#22 FakeSplit + TlsRec + wsize=64 (host+1, BadSum, ya.ru)",
    "#23 MultiDisorder + wsize=1:scale=1 (midsld, AutoTTL + sni_del, googlevideo)",
];

const LIST_LOCALE_EN: &[(&str, &str, &str)] = &[
    (
        "youtube",
        "YouTube & Google Video",
        "googlevideo.com CDN, youtube.com, ytimg, ggpht + QUIC Initial desync",
    ),
    (
        "discord",
        "Discord (Voice, Gateway & Media)",
        "discord.gg, discordapp.com, discord.media + UDP voice packet desync",
    ),
    (
        "telegram",
        "Telegram & Media Servers",
        "t.me, telegram.org, telesco.pe + DC IPv4/IPv6 CIDR subnets",
    ),
    (
        "ai_services",
        "AI Platforms (OpenAI, Claude, Gemini, xAI)",
        "chatgpt.com, openai.com, claude.ai, anthropic.com, gemini.google.com",
    ),
    (
        "social_media",
        "Social Networks (X, Instagram, Meta)",
        "x.com, twitter.com, t.co, instagram.com, facebook.com, fbcdn.net",
    ),
    (
        "gaming",
        "Gaming & Launchers (Steam, Roblox, Epic)",
        "roblox.com, rbxcdn.com, steamcommunity.com, epicgames.com",
    ),
    (
        "streaming",
        "Streaming & Audio (Twitch, Spotify, Netflix)",
        "twitch.tv, ttvnw.net, spotify.com, scdn.co, soundcloud.com",
    ),
    (
        "dev_cloud",
        "Dev & Cloud (GitHub, Docker, Cloudflare)",
        "github.com, ghcr.io, docker.io, huggingface.co, medium.com",
    ),
    (
        "trackers",
        "Trackers & Archives (RuTracker, NNM)",
        "rutracker.org, nnmclub.to, rutor.info, animego.org",
    ),
    (
        "ru_direct",
        "Domestic & Banking (Direct Bypass)",
        ".ru / .рф domains, banking & government services — always direct without desync",
    ),
    (
        "direct_bypass",
        "Direct (Desync Exclusions)",
        "Domains & subnets connected directly without packet modification",
    ),
];

const RUNTIME_REPLACEMENTS_EN: &[(&str, &str)] = &[
    ("По умолчанию", "Default"),
    ("по умолчанию", "default"),
    ("Профиль", "Profile"),
    ("Прямое (Bypass .exe)", "Direct (Bypass .exe)"),
    ("Прямое (Исключение)", "Direct (Bypass)"),
    ("Прямое", "Direct"),
    ("Принуд. .exe", "Forced .exe"),
    ("YouTube и Google Video", "YouTube & Google Video"),
    ("Discord (Голос и Чат)", "Discord (Voice & Chat)"),
    ("Telegram и Медиа-серверы", "Telegram & Media"),
    ("AI и Нейросети", "AI Services"),
    ("Социальные сети и Медиа", "Social Networks"),
    ("Игровые сервисы и лаунчеры", "Gaming & Launchers"),
    ("Стриминг и аудиосервисы", "Streaming & Audio"),
    ("Разработка и облака", "Dev & Cloud"),
    ("Торрент-трекеры и архивы", "Trackers & Archives"),
    (
        "QUIC UDP/443 отключён профилем",
        "QUIC UDP/443 blocked by profile",
    ),
    ("переход на TCP/TLS", "fallback to TCP/TLS"),
    ("клон ClientHello", "ClientHello clone"),
    ("разрез TLS-записи по SNI без фейка", "SNI TLS record split"),
    (
        "Системный интерфейс TUN «TachyonDesync» активирован",
        "System TUN interface 'TachyonDesync' active",
    ),
    (
        "Локальный узел SOCKS5/HTTP запущен на",
        "Local SOCKS5/HTTP node listening on",
    ),
    (
        "Системный прокси Windows направлен на",
        "Windows System Proxy set to",
    ),
    (
        "Движок десинхронизации Tachyon Desync инициализирован",
        "Tachyon Desync engine initialized",
    ),
    (
        "Служба Tachyon Desync остановлена",
        "Tachyon Desync service stopped",
    ),
    ("Генератор стратегий", "Strategy Generator"),
    (
        "Бенчмарк DNS завершён: доступно",
        "DNS benchmark finished: reachable",
    ),
    (
        "Тест скорости DNS завершён: проверено серверов —",
        "DNS speed test finished: servers tested -",
    ),
    ("Настройки DNS обновлены", "DNS settings updated"),
    ("Применена рекомендация DNS", "DNS recommendation applied"),
    ("Кэш DNS очищен", "DNS cache flushed"),
    ("«", "\""),
    ("»", "\""),
];

fn localize_active_mode(mode: &str, is_en: bool) -> String {
    if !is_en {
        return mode.to_string();
    }
    ACTIVE_MODE_EN
        .iter()
        .find(|&&(ru, _)| ru == mode)
        .map(|&(_, en)| en.to_string())
        .unwrap_or_else(|| localize_runtime_text(mode, true))
}

fn localize_recipe_title(id: u8, fallback: &str, is_en: bool) -> String {
    if !is_en {
        return fallback.to_string();
    }
    RECIPE_TITLES_EN
        .get(id as usize)
        .map(|&title| title.to_string())
        .unwrap_or_else(|| localize_runtime_text(fallback, true))
}

fn find_list_locale_en(id: &str) -> Option<(&'static str, &'static str)> {
    let norm = if id == "ai_all" { "ai_services" } else { id };
    LIST_LOCALE_EN
        .iter()
        .find(|&&(entry_id, _, _)| entry_id == norm)
        .map(|&(_, name, desc)| (name, desc))
}

fn localize_list_name(id: &str, fallback: &str, is_en: bool) -> String {
    if is_en && let Some((name, _)) = find_list_locale_en(id) {
        return name.to_string();
    }
    fallback.to_string()
}

fn localize_list_desc(id: &str, fallback: &str, is_en: bool) -> String {
    if is_en && let Some((_, desc)) = find_list_locale_en(id) {
        return desc.to_string();
    }
    fallback.to_string()
}

fn localize_runtime_text(text: &str, is_en: bool) -> String {
    if !is_en || text.is_empty() {
        return text.to_string();
    }
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        if let Some(&(needle, repl)) = RUNTIME_REPLACEMENTS_EN
            .iter()
            .find(|&&(needle, _)| rest.starts_with(needle))
        {
            let buf = out.get_or_insert_with(|| {
                let mut s = String::with_capacity(text.len());
                s.push_str(&text[..i]);
                s
            });
            buf.push_str(repl);
            i += needle.len();
        } else {
            let ch_len = rest.chars().next().map_or(1, char::len_utf8);
            if let Some(buf) = out.as_mut() {
                buf.push_str(&rest[..ch_len]);
            }
            i += ch_len;
        }
    }
    out.unwrap_or_else(|| text.to_string())
}

fn backup_file_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("tachyon-desync-backup.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("tachyon-desync-backup.json"))
}

fn write_backup_file(json_str: &str) {
    let _ = std::fs::write(backup_file_path(), json_str);
}

fn read_clipboard_or_backup_file() -> Option<String> {
    #[cfg(windows)]
    if let Some(txt) = read_win32_clipboard_text()
        && txt.trim_start().starts_with('{')
    {
        return Some(txt);
    }
    std::fs::read_to_string(backup_file_path())
        .ok()
        .filter(|s| s.trim_start().starts_with('{'))
}

#[cfg(windows)]
fn read_win32_clipboard_text() -> Option<String> {
    use windows_sys::Win32::Foundation::HGLOBAL;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};

    const CF_UNICODETEXT: u32 = 13;

    struct ClipboardGuard;
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }

    struct GlobalLockGuard(HGLOBAL);
    impl Drop for GlobalLockGuard {
        fn drop(&mut self) {
            unsafe {
                GlobalUnlock(self.0);
            }
        }
    }

    unsafe {
        if OpenClipboard(core::ptr::null_mut()) == 0 {
            return None;
        }
        let _clipboard_guard = ClipboardGuard;

        let hmem = GetClipboardData(CF_UNICODETEXT);
        if hmem.is_null() {
            return None;
        }
        let locked = GlobalLock(hmem);
        if locked.is_null() {
            return None;
        }
        let _lock_guard = GlobalLockGuard(hmem);

        let ptr = locked.cast::<u16>();
        let mut len = 0usize;
        while len < 1_048_576 && *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        Some(String::from_utf16_lossy(slice))
    }
}
