//! Нативный аппаратно-ускоренный графический интерфейс `Tachyon Desync` (GPU / `eframe` + `egui`).
//!
//! Работает напрямую поверх видеокарты (OpenGL / `glow`) в строгой миниатюрной теме GPUI / Zed Dark
//! без использования WebView2, браузерных процессов и локального HTTP-сервера.

use crate::desync::{
    AutoTtlReport, DesyncConfig, PacketSlicePreview, ServiceHealthItem, StrategyGeneratorReport,
    calibrate_optimal_ttl, generate_domain_strategy, inspect_client_hello_slices,
    probe_custom_strategy, run_services_health_check,
};
use crate::lists::AppFilterMode;
use crate::runtime::{CaptureMode, DesyncRuntime, UiSnapshot};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontFamily, FontId, Frame, Id, Key, Layout, Margin, Pos2,
    Rect, RichText, ScrollArea, Sense, Stroke, StrokeKind, TextEdit, TextStyle, Vec2,
};
use std::collections::VecDeque;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Overview,
    Flows,
    Generator,
    Lists,
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
            entries_text: String::new(),
            quick_entry: String::new(),
        }
    }
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

    // Вкладка Потоки (Live Flows)
    flow_filter: String,
    flows_only_active: bool,

    // Вкладка Генератор и Конструктор
    probe_domain: String,
    probe_port: u16,
    probe_in_progress: Arc<Mutex<bool>>,
    probe_report: Arc<Mutex<Option<StrategyGeneratorReport>>>,
    ttl_calib_in_progress: Arc<Mutex<bool>>,
    ttl_calib_report: Arc<Mutex<Option<AutoTtlReport>>>,
    packet_preview: PacketSlicePreview,
    builder_cfg: DesyncConfig,
    builder_dirty: bool,
    builder_preset_id: u8,
    copied_toast_until: Option<Instant>,

    // Вкладка Списки и .exe
    add_app_input: String,
    upstream_proxy_input: String,
    upstream_proxy_dirty: bool,
    list_search_filter: String,
    list_modal: ListEditorModal,

    // Вкладка Журнал
    log_category_filter: String,
    show_scoreboard_in_logs: bool,

    // Флаг первого применения темы и окна «О программе»
    theme_configured: bool,
    about_modal_open: bool,
    start_minimized_done: bool,
    start_minimized: bool,
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
        let probe_domain = "www.youtube.com".to_string();
        let packet_preview = inspect_client_hello_slices(&probe_domain);
        let mut telemetry = VecDeque::with_capacity(HISTORY_LEN);
        for _ in 0..HISTORY_LEN {
            telemetry.push_back(TelemetryPoint::default());
        }

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
            flow_filter: String::new(),
            flows_only_active: false,
            probe_domain,
            probe_port: 443,
            probe_in_progress: Arc::new(Mutex::new(false)),
            probe_report: Arc::new(Mutex::new(None)),
            ttl_calib_in_progress: Arc::new(Mutex::new(false)),
            ttl_calib_report: Arc::new(Mutex::new(None)),
            packet_preview,
            builder_cfg,
            builder_dirty: false,
            builder_preset_id: 0,
            copied_toast_until: None,
            add_app_input: String::new(),
            upstream_proxy_input,
            upstream_proxy_dirty: false,
            list_search_filter: String::new(),
            list_modal: ListEditorModal::default(),
            log_category_filter: "all".to_string(),
            show_scoreboard_in_logs: true,
            theme_configured: false,
            about_modal_open: false,
            start_minimized_done: false,
            start_minimized,
        }
    }

    fn is_en(&self) -> bool {
        self.snap.config.language.eq_ignore_ascii_case("en")
    }

    fn dispatch_ipc(&mut self, action: &str, payload: serde_json::Value) {
        let rt = self.rt.clone();
        let _ = self
            .tokio_handle
            .block_on(rt.handle_ipc_action(action, payload));
        self.snap = self.tokio_handle.block_on(self.rt.snapshot());
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
    }

    fn poll_snapshot_if_due(&mut self) {
        if self.last_refresh.elapsed() < Duration::from_millis(500) {
            return;
        }
        self.last_refresh = Instant::now();
        self.snap = self.tokio_handle.block_on(self.rt.snapshot());
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
        visuals.panel_fill = BG_CANVAS;
        visuals.window_fill = BG_PANEL;
        visuals.extreme_bg_color = BG_DEEPEST;
        visuals.faint_bg_color = BG_ELEVATED;
        visuals.code_bg_color = BG_DEEPEST;

        visuals.widgets.noninteractive.bg_fill = BG_PANEL;
        visuals.widgets.noninteractive.weak_bg_fill = BG_PANEL;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER_SUBTLE);
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.noninteractive.corner_radius = CornerRadius::same(4);

        visuals.widgets.inactive.bg_fill = BG_ELEVATED;
        visuals.widgets.inactive.weak_bg_fill = BG_ELEVATED;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.inactive.corner_radius = CornerRadius::same(4);

        // Спокойный шаг поверхности при наведении без неоновой обводки
        visuals.widgets.hovered.bg_fill = BG_HOVER;
        visuals.widgets.hovered.weak_bg_fill = BG_HOVER;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, BORDER_STRONG);
        visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.hovered.corner_radius = CornerRadius::same(4);

        visuals.widgets.active.bg_fill = BG_HOVER;
        visuals.widgets.active.weak_bg_fill = BG_HOVER;
        visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, TEXT_SECONDARY);
        visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.active.corner_radius = CornerRadius::same(4);

        visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(56, 189, 248, 44);
        visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);

        style.visuals = visuals;
        ctx.set_style(style);
    }

    // Внешняя панель: радиус 8px, внутренний отступ 8px -> вложенные карточки имеют радиус 4px (8 - 4 = 4)
    fn panel_frame() -> Frame {
        Frame::new()
            .fill(BG_PANEL)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(8, 8))
    }

    fn card_frame(active_border: bool) -> Frame {
        Frame::new()
            .fill(BG_ELEVATED)
            .stroke(Stroke::new(
                1.0_f32,
                if active_border {
                    BORDER_STRONG
                } else {
                    BORDER_SUBTLE
                },
            ))
            .corner_radius(CornerRadius::same(4))
            .inner_margin(Margin::symmetric(8, 8))
    }

    // Основная кнопка на тёмной теме: светлая поверхность из нейтральной шкалы с тёмным текстом
    fn primary_button(label: &str) -> egui::Button<'static> {
        egui::Button::new(
            RichText::new(label.to_string())
                .strong()
                .size(11.0)
                .color(BG_DEEPEST),
        )
        .fill(TEXT_PRIMARY)
        .corner_radius(CornerRadius::same(4))
    }

    // Фирменная деталь (Signature): моноширинный кейкап 4px с тонкой рамкой 1px
    fn keycap(ui: &mut egui::Ui, text: &str) {
        Frame::new()
            .fill(BG_DEEPEST)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
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
                        .fill(BG_ELEVATED),
                    )
                    .on_hover_text(lang_tip)
                    .clicked()
                {
                    let next_lang = if is_en { "ru" } else { "en" };
                    self.dispatch_ipc("set_language", serde_json::json!({ "language": next_lang }));
                }

                // Кнопка «О программе» / «About»
                let about_lbl = if is_en {
                    "About"
                } else {
                    "О программе"
                };
                let about_tip = if is_en {
                    "Version info, architecture, and GitHub repository link"
                } else {
                    "Сведения о версии, архитектуре и ссылка на репозиторий GitHub"
                };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(about_lbl).size(10.0).color(TEXT_SECONDARY),
                        )
                        .fill(BG_ELEVATED),
                    )
                    .on_hover_text(about_tip)
                    .clicked()
                {
                    self.about_modal_open = true;
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
                    if ui
                        .checkbox(
                            &mut min_tray,
                            RichText::new(tray_lbl).size(10.0).color(TEXT_SECONDARY),
                        )
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
                    if ui
                        .checkbox(
                            &mut auto_on,
                            RichText::new(auto_lbl).size(10.0).color(TEXT_SECONDARY),
                        )
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
            let mut next_def_strat: Option<&'static str> = None;

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
                    let strat_text = match cur_strat.as_str() {
                        "auto" => {
                            if is_en {
                                "Auto (16 recipes)"
                            } else {
                                "Авто (16 рецептов)"
                            }
                        }
                        "direct" => {
                            if is_en {
                                "Direct (lists only)"
                            } else {
                                "Только списки"
                            }
                        }
                        "tlsrec" => "TlsRec Split",
                        "custom" => {
                            if is_en {
                                "Generator Profile"
                            } else {
                                "Профиль Генератора"
                            }
                        }
                        other => other,
                    };
                    let w = (ui.available_width() - 4.0).max(88.0);
                    egui::ComboBox::from_id_salt("combo_default_strategy")
                        .width(w)
                        .selected_text(RichText::new(strat_text).size(10.0))
                        .show_ui(ui, |ui| {
                            let opts = [
                                (
                                    "auto",
                                    if is_en {
                                        "Auto (16 recipes)"
                                    } else {
                                        "Авто (16 рецептов)"
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
                                    next_def_strat = Some(code);
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
                (
                    ActiveTab::Logs,
                    format!("{} ({})", if is_en { "Logs" } else { "Журнал" }, logs_cnt),
                ),
            ];

            ui.columns(5, |cols| {
                for (i, (tab_id, label)) in tabs.into_iter().enumerate() {
                    let is_active = self.active_tab == tab_id;
                    let fill = if is_active { BG_HOVER } else { BG_DEEPEST };
                    let stroke = if is_active {
                        Stroke::new(1.0_f32, BORDER_STRONG)
                    } else {
                        Stroke::new(1.0_f32, BORDER_SUBTLE)
                    };
                    let text_col = if is_active {
                        TEXT_PRIMARY
                    } else {
                        TEXT_SECONDARY
                    };
                    let col_w = cols[i].available_width();
                    if cols[i]
                        .add_sized(
                            Vec2::new(col_w, 24.0),
                            egui::Button::new(RichText::new(label).size(10.0).color(text_col))
                                .fill(fill)
                                .stroke(stroke),
                        )
                        .clicked()
                    {
                        self.active_tab = tab_id;
                    }
                }
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

        // 2.5. Чистый DNS + Проверка доступности 6 ключевых узлов
        Self::panel_frame().show(ui, |ui| {
            let is_checking = self.health_in_progress.lock().map(|g| *g).unwrap_or(false);
            let cur_dns_owned = self.snap.config.dns_mode.clone();
            let cur_dns = cur_dns_owned.as_str();
            let mut next_dns_mode: Option<&'static str> = None;
            let mut trigger_hc = false;

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("DNS:")
                        .size(10.0)
                        .color(TEXT_SECONDARY),
                );
                let dns_label = match cur_dns {
                    "cloudflare" => "Cloudflare (1.1.1.1)",
                    "google" => "Google (8.8.8.8)",
                    "port1253" => {
                        if is_en {
                            "Alt-Port (77.88.8.8:1253 / :5353)"
                        } else {
                            "Порт 1253/5353 (Анти-перехват)"
                        }
                    }
                    "system" => {
                        if is_en {
                            "OS System DNS"
                        } else {
                            "Системный DNS ОС"
                        }
                    }
                    _ => {
                        if is_en {
                            "Auto Clean (1253/5353 + 1.1.1.1)"
                        } else {
                            "Авто Чистый (1253/5353 + 1.1.1.1)"
                        }
                    }
                };
                let combo_w = (ui.available_width() - 156.0).max(116.0);
                egui::ComboBox::from_id_salt("combo_clean_dns_mode")
                    .width(combo_w)
                    .selected_text(RichText::new(dns_label).size(10.0))
                    .show_ui(ui, |ui| {
                        let dns_opts = [
                            (
                                "auto",
                                if is_en {
                                    "Auto Clean (77.88.8.8:1253 + 1.1.1.1 + 8.8.8.8)"
                                } else {
                                    "Авто Чистый (77.88.8.8:1253 + 1.1.1.1 + 8.8.8.8)"
                                },
                            ),
                            ("cloudflare", "Cloudflare (1.1.1.1 / 1.0.0.1)"),
                            ("google", "Google (8.8.8.8 / 8.8.4.4)"),
                            (
                                "port1253",
                                if is_en {
                                    "Alt-Port (77.88.8.8:1253 + OpenDNS :5353)"
                                } else {
                                    "Нестандартные порты (77.88.8.8:1253 + OpenDNS :5353)"
                                },
                            ),
                            (
                                "system",
                                if is_en {
                                    "OS System DNS (off)"
                                } else {
                                    "Системный DNS ОС (выкл.)"
                                },
                            ),
                        ];
                        for (code, lbl) in dns_opts {
                            if ui.selectable_label(cur_dns == code, lbl).clicked() {
                                next_dns_mode = Some(code);
                            }
                        }
                    });

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
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
            });

            if trigger_hc {
                self.start_health_check();
            }
            if let Some(m) = next_dns_mode {
                self.dispatch_ipc("set_dns_mode", serde_json::json!({ "dns_mode": m }));
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
                if ui
                    .checkbox(&mut auto_rel, RichText::new(rel_lbl).size(10.0))
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
                let mut save_dns_ov = false;
                Self::card_frame(false).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(if is_en {
                                "Format: domain=IP (one per line, e.g. chatgpt.com=172.64.155.209)"
                            } else {
                                "Формат: домен=IP (по одному на строку, напр. chatgpt.com=172.64.155.209)"
                            })
                            .size(10.0)
                            .color(TEXT_MUTED),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let sv_lbl = if is_en { "Save hosts" } else { "Сохранить hosts" };
                            if ui.add(Self::primary_button(sv_lbl)).clicked() {
                                save_dns_ov = true;
                            }
                        });
                    });
                    if ui
                        .add(
                            TextEdit::multiline(&mut self.dns_overrides_input)
                                .font(FontId::new(10.0, FontFamily::Monospace))
                                .desired_rows(3)
                                .desired_width(ui.available_width())
                                .hint_text("chatgpt.com=172.64.155.209\n*.googlevideo.com=142.250.74.14"),
                        )
                        .changed()
                    {
                        self.dns_overrides_dirty = true;
                    }
                });
                if save_dns_ov {
                    self.dns_overrides_dirty = false;
                    let txt = self.dns_overrides_input.clone();
                    self.dispatch_ipc(
                        "set_dns_overrides_text",
                        serde_json::json!({ "text": txt }),
                    );
                }
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
                                            RichText::new(strategy_short_label(&cur_s, is_en))
                                                .size(10.0),
                                        )
                                        .show_ui(ui, |ui| {
                                            for (code, lbl) in strategy_options(is_en) {
                                                if ui.selectable_label(cur_s == code, lbl).clicked()
                                                {
                                                    strat_action =
                                                        Some((item.id.clone(), code.to_string()));
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
                                "Reset Cache"
                            } else {
                                "Сбросить кэш"
                            })
                            .size(10.0),
                        )
                        .clicked()
                    {
                        self.dispatch_ipc("clear_brain", serde_json::json!({}));
                    }
                });
            });

            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
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
                    self.dispatch_ipc("remove_learned_domain", serde_json::json!({ "host": h }));
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
                    ui.checkbox(
                        &mut self.flows_only_active,
                        RichText::new(act_lbl).size(10.0),
                    );
                });
            });

            let hint = if is_en {
                "Filter by .exe, domain or IP"
            } else {
                "Поиск по .exe, домену или IP"
            };
            ui.add(
                TextEdit::singleline(&mut self.flow_filter)
                    .hint_text(hint)
                    .desired_width(ui.available_width()),
            );

            let query = self.flow_filter.trim().to_ascii_lowercase();
            let selected_apps_set: Vec<String> = self
                .snap
                .config
                .selected_apps
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();

            let filtered: Vec<_> = self
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

    fn start_health_check(&mut self) {
        if let Ok(mut busy) = self.health_in_progress.lock() {
            if *busy {
                return;
            }
            *busy = true;
        }
        let cfg = self.snap.config.custom_global_config.clone();
        let rt = self.rt.clone();
        let busy_flag = self.health_in_progress.clone();
        let results_slot = self.health_results.clone();

        self.tokio_handle.spawn(async move {
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
            if let Ok(mut busy) = busy_flag.lock() {
                *busy = false;
            }
        });
    }

    fn start_probe_scan(&mut self, scan_all: bool) {
        if let Ok(mut busy) = self.probe_in_progress.lock() {
            if *busy {
                return;
            }
            *busy = true;
        }
        let domain = self.probe_domain.trim().to_string();
        let domain = if domain.is_empty() {
            "www.youtube.com".to_string()
        } else {
            domain
        };
        self.packet_preview = inspect_client_hello_slices(&domain);

        let port = self.probe_port;
        let rt = self.rt.clone();
        let busy_flag = self.probe_in_progress.clone();
        let report_slot = self.probe_report.clone();

        self.tokio_handle.spawn(async move {
            if let Ok(rep) = generate_domain_strategy(&domain, port, scan_all, 2500).await {
                rt.push_log(
                    "info",
                    "probe",
                    &format!("Генератор стратегий ({domain}:{port}): {}", rep.diagnosis),
                );
                if let Ok(mut guard) = report_slot.lock() {
                    *guard = Some(rep);
                }
            }
            if let Ok(mut busy) = busy_flag.lock() {
                *busy = false;
            }
        });
    }

    fn start_custom_builder_probe(&mut self) {
        if let Ok(mut busy) = self.probe_in_progress.lock() {
            if *busy {
                return;
            }
            *busy = true;
        }
        let domain = self.probe_domain.trim().to_string();
        let domain = if domain.is_empty() {
            "www.youtube.com".to_string()
        } else {
            domain
        };
        let port = self.probe_port;
        let cfg = self.builder_cfg.clone();
        let rt = self.rt.clone();
        let busy_flag = self.probe_in_progress.clone();
        let report_slot = self.probe_report.clone();

        self.tokio_handle.spawn(async move {
            if let Ok(rep) = probe_custom_strategy(&domain, port, &cfg, 2500).await {
                rt.push_log(
                    if rep.passed_count > 0 { "info" } else { "warn" },
                    "probe",
                    &rep.diagnosis,
                );
                if let Ok(mut guard) = report_slot.lock() {
                    *guard = Some(rep);
                }
            }
            if let Ok(mut busy) = busy_flag.lock() {
                *busy = false;
            }
        });
    }

    fn start_ttl_calibration(&mut self) {
        if let Ok(mut busy) = self.ttl_calib_in_progress.lock() {
            if *busy {
                return;
            }
            *busy = true;
        }
        let domain = self.probe_domain.trim().to_string();
        let domain = if domain.is_empty() {
            "www.youtube.com".to_string()
        } else {
            domain
        };
        let port = self.probe_port;
        let rt = self.rt.clone();
        let busy_flag = self.ttl_calib_in_progress.clone();
        let report_slot = self.ttl_calib_report.clone();

        self.tokio_handle.spawn(async move {
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
            if let Ok(mut busy) = busy_flag.lock() {
                *busy = false;
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

        // 1. Панель генератора стратегий (16 рецептов)
        Self::panel_frame().show(ui, |ui| {
            ui.label(
                RichText::new(if is_en {
                    "Strategy Generator (16 recipes)"
                } else {
                    "Генератор стратегий (16 рецептов)"
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
                        "Generate (16)"
                    } else {
                        "Подобрать (16)"
                    };
                    if ui.add(Self::primary_button(full_lbl)).clicked() {
                        self.start_probe_scan(true);
                    }

                    let quick_lbl = if is_en { "Quick (8)" } else { "Быстрый (8)" };
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

            // Быстрые чипы целей
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
                        }
                        let cp_lbl = if is_en {
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
                                            ("OK", SEMANTIC_OK)
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

        // 2. Конструктор стратегии (Глобальный профиль)
        Self::panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if is_en {
                        "Strategy Builder (Global Profile)"
                    } else {
                        "Конструктор стратегии (Глобальный)"
                    })
                    .strong()
                    .size(12.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let save_lbl = if is_en { "Save" } else { "Сохранить" };
                    if ui.add(Self::primary_button(save_lbl)).clicked() {
                        self.builder_dirty = false;
                        if let Ok(val) = serde_json::to_value(&self.builder_cfg) {
                            self.dispatch_ipc("update_global_desync", val);
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

            // Выбор шаблона из 16 рецептов
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
                                "datanoack",
                                "md5+badseq",
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
                ] {
                    if ui
                        .small_button(RichText::new(sni).monospace().size(10.0))
                        .clicked()
                    {
                        self.builder_cfg.fake_sni = sni.to_string();
                        self.builder_dirty = true;
                    }
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
            });

            ui.columns(2, |cols| {
                if cols[0]
                    .checkbox(
                        &mut self.builder_cfg.tlsrec_first,
                        RichText::new("tlsrec_first (TLS Split)").size(10.0),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
                if cols[0]
                    .checkbox(
                        &mut self.builder_cfg.multi_seven_point,
                        RichText::new("7-Point MultiSplit").size(10.0),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
                if cols[0]
                    .checkbox(
                        &mut self.builder_cfg.host_fake,
                        RichText::new("HostFakeSplit").size(10.0),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
                if cols[0]
                    .checkbox(
                        &mut self.builder_cfg.syndata,
                        RichText::new("SYN Data (syndata)").size(10.0),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }

                if cols[1]
                    .checkbox(
                        &mut self.builder_cfg.ipfrag,
                        RichText::new("L3 IP Fragmentation").size(10.0),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
                if cols[1]
                    .checkbox(
                        &mut self.builder_cfg.udp_fake,
                        RichText::new("UDP Fakes (QUIC/Voice)").size(10.0),
                    )
                    .changed()
                {
                    self.builder_dirty = true;
                }
                if cols[1]
                    .checkbox(
                        &mut self.builder_cfg.block_quic,
                        RichText::new("Block QUIC UDP/443 -> TCP").size(10.0),
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

            let selected_apps = self.snap.config.selected_apps.clone();
            let app_strats_map = self.snap.config.app_strategies.clone();
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
                            "Use Lists / Mode"
                        } else {
                            "По спискам / Режиму"
                        }
                    } else {
                        strategy_short_label(cur_s, is_en)
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
                                for (code, lbl) in strategy_options(is_en) {
                                    if ui.selectable_label(cur_s == code, lbl).clicked() {
                                        upd_app_strat = Some((app.clone(), code.to_string()));
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

            let mut upd_enable: Option<(String, bool)> = None;
            let mut upd_strat: Option<(String, String)> = None;
            let mut upd_quic: Option<(String, bool)> = None;
            let mut upd_udp: Option<(String, bool)> = None;
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
                                        RichText::new(strategy_short_label(&cur_s, is_en))
                                            .size(10.0),
                                    )
                                    .show_ui(ui, |ui| {
                                        for (code, lbl) in strategy_options(is_en) {
                                            if ui.selectable_label(cur_s == code, lbl).clicked() {
                                                upd_strat =
                                                    Some((item.id.clone(), code.to_string()));
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
            entries_text: String::new(),
            quick_entry: String::new(),
        };
    }

    fn render_list_modal(&mut self, ctx: &egui::Context) {
        if !self.list_modal.open {
            return;
        }
        let is_en = self.is_en();
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
                            RichText::new(strategy_short_label(&self.list_modal.strategy, is_en))
                                .size(10.0),
                        )
                        .show_ui(ui, |ui| {
                            for (code, lbl) in strategy_options(is_en) {
                                if ui
                                    .selectable_label(self.list_modal.strategy == code, lbl)
                                    .clicked()
                                {
                                    self.list_modal.strategy = code.to_string();
                                }
                            }
                        });
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
            let entries_text = self.list_modal.entries_text.clone();
            if let Some(id) = self.list_modal.list_id.clone() {
                self.dispatch_ipc(
                    "update_list",
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "strategy": strategy,
                        "entries_text": entries_text
                    }),
                );
            } else {
                self.dispatch_ipc(
                    "create_custom_list",
                    serde_json::json!({
                        "name": name,
                        "strategy": strategy,
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

            let filtered: Vec<_> = self
                .snap
                .logs
                .iter()
                .rev()
                .filter(|l| {
                    self.log_category_filter == "all" || l.category == self.log_category_filter
                })
                .cloned()
                .collect();

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
                        let inner_text_w = (max_row_w - 16.0).max(140.0);
                        for l in &filtered {
                            Self::card_frame(false).show(ui, |ui| {
                                ui.set_width(inner_text_w);
                                ui.set_max_width(inner_text_w);
                                let cat_col = match l.level.as_str() {
                                    "error" => SEMANTIC_ERR,
                                    "warn" => SEMANTIC_WARN,
                                    _ => TEXT_SECONDARY,
                                };
                                let loc_msg = localize_runtime_text(&l.message, is_en);
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
                                    ui.add(egui::Label::new(job).wrap().sense(Sense::click()));
                                if resp
                                    .on_hover_text(if is_en {
                                        "Click to copy log line"
                                    } else {
                                        "Клик — скопировать строку журнала"
                                    })
                                    .clicked()
                                {
                                    ui.ctx().copy_text(format!(
                                        "{} [{}] {}",
                                        format_hms(l.ts_ms),
                                        l.category,
                                        loc_msg
                                    ));
                                }
                            });
                        }
                    });
            }
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
                            "Clean DNS (:1253/:5353) · Local hosts"
                        } else {
                            "Чистый DNS (:1253/:5353) · Local hosts"
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
}

impl eframe::App for TachyonGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.configure_gpui_theme(ctx);
        Self::handle_custom_window_resize(ctx);

        if self.start_minimized && !self.start_minimized_done {
            self.start_minimized_done = true;
            crate::tray::hide_main_window_to_tray();
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

        egui::TopBottomPanel::top("custom_window_titlebar")
            .frame(
                Frame::new()
                    .fill(BG_DEEPEST)
                    .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                    .inner_margin(Margin::symmetric(8, 4)),
            )
            .show(ctx, |ui| {
                self.render_custom_titlebar(ctx, ui);
            });

        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG_CANVAS).inner_margin(Margin::same(8)))
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
                        ActiveTab::Logs => self.render_tab_logs(ui),
                    });
            });

        self.render_list_modal(ctx);
        self.render_about_modal(ctx);

        // Тонкая внешняя рамка 1px вокруг безрамочного окна (когда окно не развёрнуто на весь экран)
        if !ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
            let fg_painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                Id::new("custom_window_outer_border"),
            ));
            fg_painter.rect_stroke(
                ctx.screen_rect(),
                CornerRadius::ZERO,
                Stroke::new(1.0_f32, BORDER_STRONG),
                StrokeKind::Inside,
            );
        }

        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

fn strategy_options(en: bool) -> [(&'static str, &'static str); 12] {
    if en {
        [
            ("auto", "Auto (16 recipes)"),
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
            ("auto", "Авто (16 рецептов)"),
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
    let mut map = serde_json::Map::new();
    map.insert("type".to_string(), serde_json::json!("desync"));
    map.insert("tag".to_string(), serde_json::json!("desync-out"));
    map.insert("mode".to_string(), serde_json::json!(cfg.mode));
    map.insert("fooling".to_string(), serde_json::json!(cfg.fooling));
    map.insert("split_pos".to_string(), serde_json::json!(cfg.split_pos));
    map.insert(
        "tlsrec_first".to_string(),
        serde_json::json!(cfg.tlsrec_first),
    );
    map.insert("fake_sni".to_string(), serde_json::json!(cfg.fake_sni));
    map.insert("fake_ttl".to_string(), serde_json::json!(cfg.fake_ttl));
    if cfg.multi_seven_point {
        map.insert(
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
    } else if cfg.host_fake {
        map.insert(
            "split_positions".to_string(),
            serde_json::json!(["sni", "endhost-1"]),
        );
    }
    if cfg.repeats > 1 {
        map.insert("repeats".to_string(), serde_json::json!(cfg.repeats));
    }
    if cfg.seqovl > 0 {
        map.insert("seqovl".to_string(), serde_json::json!(cfg.seqovl));
    }
    if cfg.wsize > 0 {
        map.insert("wsize".to_string(), serde_json::json!(cfg.wsize));
    }
    if cfg.syndata {
        map.insert("syndata".to_string(), serde_json::json!(true));
    }
    if cfg.ipfrag {
        map.insert("ipfrag".to_string(), serde_json::json!(true));
    }
    map.insert("udp_fake".to_string(), serde_json::json!(cfg.udp_fake));
    map.insert(
        "udp_repeats".to_string(),
        serde_json::json!(cfg.udp_repeats),
    );
    map.insert(
        "udp_fake_ttl".to_string(),
        serde_json::json!(cfg.udp_fake_ttl),
    );
    serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap_or_default()
}

fn localize_active_mode(mode: &str, is_en: bool) -> String {
    if !is_en {
        return mode.to_string();
    }
    match mode {
        "Остановлен" => "Stopped".to_string(),
        "Адаптер TUN (Wintun L3)" => "TUN Adapter (Wintun L3)".to_string(),
        "Системный прокси (127.0.0.1:7897)" => {
            "System Proxy (127.0.0.1:7897)".to_string()
        }
        "Локальный прокси (127.0.0.1:7897)" => {
            "Local Proxy (127.0.0.1:7897)".to_string()
        }
        other => localize_runtime_text(other, true),
    }
}

fn localize_recipe_title(id: u8, fallback: &str, is_en: bool) -> String {
    if !is_en {
        return fallback.to_string();
    }
    match id {
        0 => "#0 FakeSplit (midsld, MD5 ClientHello clone)".to_string(),
        1 => "#1 TlsRec + Split (SNI TLS record split, no fake)".to_string(),
        2 => "#2 FakeSplit + TlsRec (midsld, PAWS Timestamp, max.ru)".to_string(),
        3 => "#3 FakeDisorder (midsld, MD5, vk.com)".to_string(),
        4 => "#4 FakeDisorder + TlsRec (midsld, BadSeq -10000, rzd.ru)".to_string(),
        5 => "#5 IPv6 HopByHop2 + FakeSplit (midsld, fonts.google.com)".to_string(),
        6 => "#6 MultiSplit + TlsRec (1,sniext+1,midsld)".to_string(),
        7 => "#7 MultiDisorder (1,sniext+1,midsld, MD5, ya.ru)".to_string(),
        8 => "#8 FakeDisorder (midsld, BadSum, mail.ru)".to_string(),
        9 => "#9 FakeSplit (midsld, Auto-TTL=4, ozon.ru)".to_string(),
        10 => "#10 OOB Urgent + TlsRec (URG pointer at midsld)".to_string(),
        11 => "#11 HostFakeSplit (SNI..endhost-1, MD5, ya.ru)".to_string(),
        12 => "#12 7-Point MultiDisorder (7 slices + TlsRec + MD5)".to_string(),
        13 => "#13 PadEncap Framing (length-matched TLS 1.3 decoy)".to_string(),
        14 => "#14 SYNData + wsize=2 + 7-Point MultiDisorder (BadSeq)".to_string(),
        15 => "#15 HostFakeSplit + SeqOvl=336 + DataNoAck (Gosuslugi)".to_string(),
        _ => localize_runtime_text(fallback, true),
    }
}

fn localize_list_name(id: &str, fallback: &str, is_en: bool) -> String {
    if !is_en {
        return fallback.to_string();
    }
    match id {
        "youtube" => "YouTube & Google Video".to_string(),
        "discord" => "Discord (Voice, Gateway & Media)".to_string(),
        "telegram" => "Telegram & Media Servers".to_string(),
        "ai_services" | "ai_all" => "AI Platforms (OpenAI, Claude, Gemini, xAI)".to_string(),
        "social_media" => "Social Networks (X, Instagram, Meta)".to_string(),
        "gaming" => "Gaming & Launchers (Steam, Roblox, Epic)".to_string(),
        "streaming" => "Streaming & Audio (Twitch, Spotify, Netflix)".to_string(),
        "dev_cloud" => "Dev & Cloud (GitHub, Docker, Cloudflare)".to_string(),
        "trackers" => "Trackers & Archives (RuTracker, NNM)".to_string(),
        "ru_direct" => "Domestic & Banking (Direct Bypass)".to_string(),
        "direct_bypass" => "Direct (Desync Exclusions)".to_string(),
        _ => fallback.to_string(),
    }
}

fn localize_list_desc(id: &str, fallback: &str, is_en: bool) -> String {
    if !is_en {
        return fallback.to_string();
    }
    match id {
        "youtube" => {
            "googlevideo.com CDN, youtube.com, ytimg, ggpht + QUIC UDP/443 block".to_string()
        }
        "discord" => {
            "discord.gg, discordapp.com, discord.media + UDP voice packet desync".to_string()
        }
        "telegram" => "t.me, telegram.org, telesco.pe + DC IPv4/IPv6 CIDR subnets".to_string(),
        "ai_services" | "ai_all" => {
            "chatgpt.com, openai.com, claude.ai, anthropic.com, gemini.google.com".to_string()
        }
        "social_media" => {
            "x.com, twitter.com, t.co, instagram.com, facebook.com, fbcdn.net".to_string()
        }
        "gaming" => "roblox.com, rbxcdn.com, steamcommunity.com, epicgames.com".to_string(),
        "streaming" => "twitch.tv, ttvnw.net, spotify.com, scdn.co, soundcloud.com".to_string(),
        "dev_cloud" => "github.com, ghcr.io, docker.io, huggingface.co, medium.com".to_string(),
        "trackers" => "rutracker.org, nnmclub.to, rutor.info, animego.org".to_string(),
        "ru_direct" => {
            ".ru / .рф domains, banking & government services — always direct without desync"
                .to_string()
        }
        "direct_bypass" => {
            "Domains & subnets connected directly without packet modification".to_string()
        }
        _ => fallback.to_string(),
    }
}

fn localize_runtime_text(text: &str, is_en: bool) -> String {
    if !is_en {
        return text.to_string();
    }
    text.replace("По умолчанию", "Default")
        .replace("по умолчанию", "default")
        .replace("Профиль", "Profile")
        .replace("Прямое (Bypass .exe)", "Direct (Bypass .exe)")
        .replace("Прямое (Исключение)", "Direct (Bypass)")
        .replace("Прямое", "Direct")
        .replace("Принуд. .exe", "Forced .exe")
        .replace("YouTube и Google Video", "YouTube & Google Video")
        .replace("Discord (Голос и Чат)", "Discord (Voice & Chat)")
        .replace("Telegram и Медиа-серверы", "Telegram & Media")
        .replace("AI и Нейросети", "AI Services")
        .replace("Социальные сети и Медиа", "Social Networks")
        .replace("Игровые сервисы и лаунчеры", "Gaming & Launchers")
        .replace("Стриминг и аудиосервисы", "Streaming & Audio")
        .replace("Разработка и облака", "Dev & Cloud")
        .replace("Торрент-трекеры и архивы", "Trackers & Archives")
        .replace(
            "QUIC UDP/443 отключён профилем",
            "QUIC UDP/443 blocked by profile",
        )
        .replace("переход на TCP/TLS", "fallback to TCP/TLS")
        .replace("клон ClientHello", "ClientHello clone")
        .replace("разрез TLS-записи по SNI без фейка", "SNI TLS record split")
        .replace(
            "Системный интерфейс TUN «TachyonDesync» активирован",
            "System TUN interface 'TachyonDesync' active",
        )
        .replace(
            "Локальный узел SOCKS5/HTTP запущен на",
            "Local SOCKS5/HTTP node listening on",
        )
        .replace(
            "Системный прокси Windows направлен на",
            "Windows System Proxy set to",
        )
        .replace(
            "Движок десинхронизации Tachyon Desync инициализирован",
            "Tachyon Desync engine initialized",
        )
        .replace(
            "Служба Tachyon Desync остановлена",
            "Tachyon Desync service stopped",
        )
        .replace("Генератор стратегий", "Strategy Generator")
        .replace("«", "\"")
        .replace("»", "\"")
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
    const CF_UNICODETEXT: u32 = 13;
    #[link(name = "user32")]
    unsafe extern "system" {
        fn OpenClipboard(hwnd: isize) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(format: u32) -> isize;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalLock(hmem: isize) -> *const u16;
        fn GlobalUnlock(hmem: isize) -> i32;
    }
    unsafe {
        if OpenClipboard(0) == 0 {
            return None;
        }
        let hmem = GetClipboardData(CF_UNICODETEXT);
        let mut out = None;
        if hmem != 0 {
            let ptr = GlobalLock(hmem);
            if !ptr.is_null() {
                let mut len = 0usize;
                while len < 1_048_576 && *ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                out = Some(String::from_utf16_lossy(slice));
                GlobalUnlock(hmem);
            }
        }
        CloseClipboard();
        out
    }
}
