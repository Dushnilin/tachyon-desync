#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod upstream_compat;
pub use upstream_compat::{cache_file, core_tls, dns, hardware, inbound, logging, outbound, util};

pub mod apps;
pub mod desync;
pub mod dns_resolver;
pub mod flows;
pub mod gui;
pub mod lists;
pub mod proxy;
pub mod runtime;
pub mod tray;
pub mod tun;
pub mod updater;

use crate::desync::{
    DesyncConfig, RECIPE_TITLES, all_recipe_summaries, calibrate_optimal_ttl,
    flush_persistent_cache, generate_domain_strategy_with_options,
    probe_custom_strategy_with_options,
};
use crate::dns_resolver::{
    DnsBenchmarkState, DnsSpeedTestState, flush_dns_caches, run_dns_benchmark, run_dns_speed_test,
};
use crate::gui::TachyonGuiApp;
use crate::runtime::{
    AppStateConfig, CaptureMode, DesyncRuntime, resolve_app_data_dir, try_send_control_command,
};
use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn build_app_icon_data() -> egui::IconData {
    let width = 32u32;
    let height = 32u32;
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            let border = x == 0 || y == 0 || x == width - 1 || y == height - 1;
            let diag = ((7..=24).contains(&x) && (7..=11).contains(&y))
                || ((14..=18).contains(&x) && (11..=25).contains(&y));
            if diag {
                rgba.extend_from_slice(&[56, 189, 248, 255]);
            } else if border {
                rgba.extend_from_slice(&[38, 43, 54, 255]);
            } else {
                rgba.extend_from_slice(&[15, 18, 24, 255]);
            }
        }
    }
    egui::IconData {
        rgba,
        width,
        height,
    }
}

/// Подключить стандартные потоки к родительской консоли на Windows в release-сборке
/// (`windows_subsystem = "windows"`), чтобы CLI-команды выводили текст в PowerShell/CMD.
#[cfg(target_os = "windows")]
fn attach_parent_console_for_cli() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AttachConsole(dw_process_id: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(target_os = "windows"))]
fn attach_parent_console_for_cli() {}

fn should_attach_console(raw_args: &[String]) -> bool {
    if raw_args.len() <= 1 {
        return false;
    }
    !raw_args[1..]
        .iter()
        .all(|a| matches!(a.as_str(), "--minimized" | "--tray" | "--no-autostart"))
}

/// Проверить, не запущен ли уже экземпляр `Tachyon Desync` (например, свёрнутый в системный трей).
/// Если запущен новый интерактивный процесс — отправляем старому команду штатного выхода (`IDM_EXIT`)
/// через окно трея и дожидаемся освобождения мьютекса, чтобы всегда запускалась актуальная сборка.
#[cfg(target_os = "windows")]
fn ensure_single_instance_or_focus(start_minimized: bool) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, PostMessageW, WM_COMMAND};

    const IDM_EXIT: usize = 1006;

    let name: Vec<u16> = "Local\\TachyonDesyncSingleInstanceMutex"
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    unsafe {
        let h = CreateMutexW(core::ptr::null(), 0, name.as_ptr());
        if !h.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            if start_minimized {
                crate::tray::restore_main_window_from_tray();
                return false;
            }
            CloseHandle(h);
            let tray_cls: Vec<u16> = "TachyonDesyncTrayHiddenWnd"
                .encode_utf16()
                .chain(core::iter::once(0))
                .collect();
            let tray_hwnd = FindWindowW(tray_cls.as_ptr(), tray_cls.as_ptr());
            if !tray_hwnd.is_null() {
                PostMessageW(tray_hwnd, WM_COMMAND, IDM_EXIT, 0);
                for _ in 0..25 {
                    std::thread::sleep(std::time::Duration::from_millis(80));
                    let h2 = CreateMutexW(core::ptr::null(), 0, name.as_ptr());
                    if !h2.is_null() && GetLastError() != ERROR_ALREADY_EXISTS {
                        return true;
                    }
                    if !h2.is_null() {
                        CloseHandle(h2);
                    }
                }
            }
            crate::tray::restore_main_window_from_tray();
            return false;
        }
    }
    true
}

#[cfg(unix)]
static INSTANCE_LOCK: std::sync::OnceLock<std::sync::Mutex<Option<std::fs::File>>> =
    std::sync::OnceLock::new();

#[cfg(unix)]
fn ensure_single_instance_or_focus(_start_minimized: bool) -> bool {
    use std::os::unix::io::AsRawFd;

    let data_dir = resolve_app_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);
    let lock_path = data_dir.join(".instance.lock");
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "Предупреждение: не удалось открыть lock-файл {:?}: {e}",
                lock_path
            );
            return true;
        }
    };

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        let cell = INSTANCE_LOCK.get_or_init(|| std::sync::Mutex::new(None));
        if let Ok(mut guard) = cell.lock() {
            *guard = Some(file);
        }
        true
    } else {
        let _ = try_send_control_command(&data_dir, "get_state", serde_json::json!({}));
        eprintln!("Tachyon Desync уже запущен");
        false
    }
}

#[cfg(not(any(target_os = "windows", unix)))]
fn ensure_single_instance_or_focus(_start_minimized: bool) -> bool {
    true
}

#[derive(Debug, PartialEq, Eq)]
enum CliCommand {
    Gui {
        start_minimized: bool,
        autostart: bool,
    },
    Help,
    Version {
        json: bool,
    },
    Recipes {
        json: bool,
    },
    Run {
        mode: Option<CaptureMode>,
        port: Option<u16>,
        config_dir: Option<PathBuf>,
        no_autostart: bool,
    },
    Probe {
        domain: String,
        port: u16,
        stream_192k: bool,
        ttl: bool,
        recipe: Option<u8>,
        json: bool,
    },
    DnsBench {
        apply: bool,
        json: bool,
    },
    DnsSpeed {
        domains: Vec<String>,
        json: bool,
    },
    DnsFlush,
    Doctor {
        json: bool,
    },
    Control {
        action: String,
        payload: serde_json::Value,
        json: bool,
        config_dir: Option<PathBuf>,
    },
    ConfigExport {
        path: PathBuf,
        config_dir: Option<PathBuf>,
    },
    ConfigImport {
        path: PathBuf,
        config_dir: Option<PathBuf>,
    },
}

fn parse_capture_mode(raw: &str) -> Result<CaptureMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tun" => Ok(CaptureMode::Tun),
        "system-proxy" | "system_proxy" | "proxy" | "system" => Ok(CaptureMode::SystemProxy),
        "local-proxy" | "local_proxy" | "local" => Ok(CaptureMode::LocalProxy),
        _ => Err(format!(
            "Неизвестный режим перехвата: '{raw}'. Допустимо: tun, system-proxy, local-proxy"
        )),
    }
}

fn parse_port_value(raw: &str) -> Result<u16, String> {
    let port: u16 = raw
        .trim()
        .parse()
        .map_err(|_| format!("Некорректный порт: '{raw}'"))?;
    if port == 0 {
        return Err("Порт должен быть в диапазоне 1..=65535".to_string());
    }
    Ok(port)
}

fn parse_recipe_id(raw: &str) -> Result<u8, String> {
    let max_id = (RECIPE_TITLES.len() - 1) as u8;
    let id: u8 = raw.trim().parse().map_err(|_| {
        format!("Некорректный идентификатор рецепта: '{raw}' (ожидается 0..={max_id})")
    })?;
    if id > max_id {
        return Err(format!(
            "Идентификатор рецепта {id} вне диапазона 0..={max_id}"
        ));
    }
    Ok(id)
}

fn parse_flag_value<'a>(
    args: &'a [&'a str],
    idx: &mut usize,
    flag_name: &str,
) -> Result<&'a str, String> {
    let arg = args[*idx];
    if let Some((_, val)) = arg.split_once('=') {
        if val.is_empty() {
            return Err(format!("Пустое значение для флага {flag_name}"));
        }
        return Ok(val);
    }
    if *idx + 1 >= args.len() {
        return Err(format!("Ожидается значение после флага {flag_name}"));
    }
    *idx += 1;
    Ok(args[*idx])
}

fn parse_control_common(
    args: &[&str],
    action: &str,
    mut payload: serde_json::Value,
    allow_limit: bool,
    allow_exit: bool,
) -> Result<CliCommand, String> {
    let mut json = false;
    let mut config_dir = None;
    let mut action_str = action.to_string();
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i];
        if arg == "--json" {
            json = true;
        } else if arg == "--config" || arg.starts_with("--config=") {
            let val = parse_flag_value(args, &mut i, "--config")?;
            config_dir = Some(PathBuf::from(val));
        } else if allow_limit && (arg == "--limit" || arg.starts_with("--limit=")) {
            let val = parse_flag_value(args, &mut i, "--limit")?;
            let limit: usize = val
                .trim()
                .parse()
                .map_err(|_| format!("Некорректное значение --limit: '{val}'"))?;
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("limit".to_string(), serde_json::json!(limit));
            }
        } else if allow_exit && arg == "--exit" {
            action_str = "stop_process".to_string();
        } else {
            return Err(format!("Неизвестный аргумент: '{arg}'"));
        }
        i += 1;
    }
    Ok(CliCommand::Control {
        action: action_str,
        payload,
        json,
        config_dir,
    })
}

fn parse_cli_args(args: &[&str]) -> Result<CliCommand, String> {
    if args.is_empty() {
        return Ok(CliCommand::Gui {
            start_minimized: false,
            autostart: true,
        });
    }

    if args.iter().any(|a| matches!(*a, "-h" | "--help" | "help")) {
        return Ok(CliCommand::Help);
    }

    if args[0] == "run" || args.iter().any(|a| matches!(*a, "--headless" | "--cli")) {
        let mut mode = None;
        let mut port = None;
        let mut config_dir = None;
        let mut no_autostart = false;
        let mut i = 0usize;
        while i < args.len() {
            let arg = args[i];
            if matches!(arg, "run" | "--headless" | "--cli") {
                // Маркер консольного режима
            } else if arg == "--mode" || arg.starts_with("--mode=") {
                let val = parse_flag_value(args, &mut i, "--mode")?;
                mode = Some(parse_capture_mode(val)?);
            } else if arg == "--port" || arg.starts_with("--port=") {
                let val = parse_flag_value(args, &mut i, "--port")?;
                port = Some(parse_port_value(val)?);
            } else if arg == "--config" || arg.starts_with("--config=") {
                let val = parse_flag_value(args, &mut i, "--config")?;
                config_dir = Some(PathBuf::from(val));
            } else if arg == "--no-autostart" {
                no_autostart = true;
            } else {
                return Err(format!("Неизвестный аргумент для команды run: '{arg}'"));
            }
            i += 1;
        }
        return Ok(CliCommand::Run {
            mode,
            port,
            config_dir,
            no_autostart,
        });
    }

    match args[0] {
        "-V" | "--version" | "version" => {
            let mut json = false;
            for &arg in &args[1..] {
                if arg == "--json" {
                    json = true;
                } else {
                    return Err(format!("Неизвестный флаг для version: '{arg}'"));
                }
            }
            Ok(CliCommand::Version { json })
        }
        "recipes" | "--check-upstream" => {
            let mut json = false;
            for &arg in &args[1..] {
                if arg == "--json" {
                    json = true;
                } else {
                    return Err(format!("Неизвестный флаг для recipes: '{arg}'"));
                }
            }
            Ok(CliCommand::Recipes { json })
        }
        "probe" => {
            let mut domain: Option<String> = None;
            let mut port = 443u16;
            let mut stream_192k = false;
            let mut ttl = false;
            let mut recipe = None;
            let mut json = false;
            let mut i = 1usize;
            while i < args.len() {
                let arg = args[i];
                if arg == "--port" || arg.starts_with("--port=") {
                    let val = parse_flag_value(args, &mut i, "--port")?;
                    port = parse_port_value(val)?;
                } else if arg == "--stream-192k" {
                    stream_192k = true;
                } else if arg == "--ttl" {
                    ttl = true;
                } else if arg == "--recipe" || arg.starts_with("--recipe=") {
                    let val = parse_flag_value(args, &mut i, "--recipe")?;
                    recipe = Some(parse_recipe_id(val)?);
                } else if arg == "--json" {
                    json = true;
                } else if arg.starts_with('-') {
                    return Err(format!("Неизвестный флаг для probe: '{arg}'"));
                } else if domain.is_none() {
                    domain = Some(arg.to_string());
                } else {
                    return Err(format!("Лишний позиционный аргумент для probe: '{arg}'"));
                }
                i += 1;
            }
            let domain = domain.ok_or_else(|| {
                "Укажите домен: tachyon-desync probe <domain> [--port 443] [--stream-192k] [--ttl] [--recipe <0..27>] [--json]".to_string()
            })?;
            Ok(CliCommand::Probe {
                domain,
                port,
                stream_192k,
                ttl,
                recipe,
                json,
            })
        }
        "dns" => {
            if args.len() < 2 {
                return Err("Укажите подкоманду dns: bench | speed | flush".to_string());
            }
            match args[1] {
                "bench" => {
                    let mut apply = false;
                    let mut json = false;
                    for &arg in &args[2..] {
                        match arg {
                            "--apply" => apply = true,
                            "--json" => json = true,
                            _ => return Err(format!("Неизвестный флаг для dns bench: '{arg}'")),
                        }
                    }
                    Ok(CliCommand::DnsBench { apply, json })
                }
                "speed" => {
                    let mut domains = Vec::new();
                    let mut json = false;
                    for &arg in &args[2..] {
                        if arg == "--json" {
                            json = true;
                        } else if arg.starts_with('-') {
                            return Err(format!("Неизвестный флаг для dns speed: '{arg}'"));
                        } else {
                            domains.push(arg.to_string());
                        }
                    }
                    Ok(CliCommand::DnsSpeed { domains, json })
                }
                "flush" => {
                    if args.len() > 2 {
                        return Err(format!("Неизвестный аргумент для dns flush: '{}'", args[2]));
                    }
                    Ok(CliCommand::DnsFlush)
                }
                other => Err(format!(
                    "Неизвестная подкоманда dns: '{other}'. Допустимо: bench, speed, flush"
                )),
            }
        }
        "doctor" => {
            let mut json = false;
            for &arg in &args[1..] {
                if arg == "--json" {
                    json = true;
                } else {
                    return Err(format!("Неизвестный флаг для doctor: '{arg}'"));
                }
            }
            Ok(CliCommand::Doctor { json })
        }
        "status" => {
            parse_control_common(&args[1..], "get_state", serde_json::json!({}), false, false)
        }
        "flows" => parse_control_common(
            &args[1..],
            "get_state",
            serde_json::json!({ "view": "flows" }),
            false,
            false,
        ),
        "logs" => parse_control_common(
            &args[1..],
            "get_state",
            serde_json::json!({ "view": "logs", "limit": 50 }),
            true,
            false,
        ),
        "toggle" => parse_control_common(&args[1..], "toggle", serde_json::json!({}), false, false),
        "stop" => parse_control_common(&args[1..], "stop", serde_json::json!({}), false, true),
        "reload" => parse_control_common(
            &args[1..],
            "reload_matcher",
            serde_json::json!({}),
            false,
            false,
        ),
        "pin" => {
            let mut domain: Option<String> = None;
            let mut recipe_id: Option<u8> = None;
            let mut json = false;
            let mut config_dir = None;
            let mut i = 1usize;
            while i < args.len() {
                let arg = args[i];
                if arg == "--json" {
                    json = true;
                } else if arg == "--config" || arg.starts_with("--config=") {
                    let val = parse_flag_value(args, &mut i, "--config")?;
                    config_dir = Some(PathBuf::from(val));
                } else if arg.starts_with('-') {
                    return Err(format!("Неизвестный флаг для pin: '{arg}'"));
                } else if domain.is_none() {
                    domain = Some(arg.to_string());
                } else if recipe_id.is_none() {
                    recipe_id = Some(parse_recipe_id(arg)?);
                } else {
                    return Err(format!("Лишний аргумент для pin: '{arg}'"));
                }
                i += 1;
            }
            let host = domain.ok_or_else(|| {
                "Укажите домен и рецепт: tachyon-desync pin <domain> <recipe_id>".to_string()
            })?;
            let id = recipe_id.ok_or_else(|| {
                "Укажите идентификатор рецепта (0..=27): tachyon-desync pin <domain> <recipe_id>"
                    .to_string()
            })?;
            Ok(CliCommand::Control {
                action: "pin_domain".to_string(),
                payload: serde_json::json!({ "host": host, "recipe_id": id }),
                json,
                config_dir,
            })
        }
        "config" => {
            if args.len() < 2 {
                return Err("Укажите подкоманду config: export <path> | import <path>".to_string());
            }
            let sub = args[1];
            if !matches!(sub, "export" | "import") {
                return Err(format!(
                    "Неизвестная подкоманда config: '{sub}'. Допустимо: export, import"
                ));
            }
            let mut path: Option<PathBuf> = None;
            let mut config_dir = None;
            let mut i = 2usize;
            while i < args.len() {
                let arg = args[i];
                if arg == "--config" || arg.starts_with("--config=") {
                    let val = parse_flag_value(args, &mut i, "--config")?;
                    config_dir = Some(PathBuf::from(val));
                } else if arg.starts_with('-') {
                    return Err(format!("Неизвестный флаг для config {sub}: '{arg}'"));
                } else if path.is_none() {
                    path = Some(PathBuf::from(arg));
                } else {
                    return Err(format!("Лишний аргумент для config {sub}: '{arg}'"));
                }
                i += 1;
            }
            let file_path = path.ok_or_else(|| {
                format!("Укажите путь к файлу: tachyon-desync config {sub} <path>")
            })?;
            if sub == "export" {
                Ok(CliCommand::ConfigExport {
                    path: file_path,
                    config_dir,
                })
            } else {
                Ok(CliCommand::ConfigImport {
                    path: file_path,
                    config_dir,
                })
            }
        }
        _ => {
            let mut start_minimized = false;
            let mut autostart = true;
            for &arg in args {
                match arg {
                    "--minimized" | "--tray" => start_minimized = true,
                    "--no-autostart" => autostart = false,
                    _ => return Err(format!("Неизвестная команда или флаг: '{arg}'")),
                }
            }
            Ok(CliCommand::Gui {
                start_minimized,
                autostart,
            })
        }
    }
}

fn print_help() {
    println!(
        "\
tachyon-desync {} — автономный клиент адаптивной десинхронизации пакетов

Использование:
  tachyon-desync [опции GUI]
  tachyon-desync <команда> [опции]

Опции GUI:
  --minimized, --tray          Запустить свёрнутым в системный трей
  --no-autostart               Не запускать захват трафика автоматически при старте

Команды:
  run | --headless | --cli     Консольный режим без GUI
    --mode <tun|system-proxy|local-proxy>  Переопределить режим перехвата
    --port <1..65535>                      Переопределить порт локального прокси
    --config <dir>                         Каталог конфигурации (по умолчанию системный)
    --no-autostart                         Не запускать перехват автоматически
  probe <domain>               Подобрать и проверить адаптивные рецепты для домена
    --port <N>                             Порт назначения (по умолчанию 443)
    --stream-192k                          Проверка чтения потока > 192 КиБ
    --ttl                                  Дополнительно выполнить авто-калибровку TTL (хопы 2..10)
    --recipe <0..27>                       Проверить конкретный рецепт
    --json                                 Вывести отчёт в JSON
  dns bench [--apply] [--json]             Бенчмарк доступных DNS-серверов (UDP/DoT/DoH)
  dns speed [domains...] [--json]          Многодоменный тест скорости текущих DNS
  dns flush                                Очистить локальный кэш DNS
  doctor [--json]                          Сформировать диагностический отчёт системы
  recipes | --check-upstream [--json]      Список синхронизированных рецептов апстрима
  status [--json] [--config <dir>]         Текущее состояние работающего процесса
  flows [--json] [--config <dir>]          Таблица активных и недавних потоков
  logs [--limit N] [--json] [--config <dir>]  Последние записи журнала событий
  toggle [--json] [--config <dir>]         Переключить перехват (старт/стоп)
  stop [--exit] [--json] [--config <dir>]  Остановить перехват (или завершить процесс с --exit)
  reload [--json] [--config <dir>]         Перезагрузить списки и правила десинхронизации
  pin <domain> <0..27> [--json]            Закрепить рецепт для домена
  config export <path> [--config <dir>]    Экспортировать state.json в файл
  config import <path> [--config <dir>]    Проверить и импортировать state.json из файла
  version | -V | --version [--json]        Версия приложения
  help | -h | --help                       Показать эту справку",
        env!("CARGO_PKG_VERSION")
    );
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn send_control_with_fallback(
    dir: &std::path::Path,
    action: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let clean_payload = if action == "get_state" {
        serde_json::json!({})
    } else {
        payload.clone()
    };
    let resp = try_send_control_command(dir, action, clean_payload.clone())?;
    if resp.get("error").is_some() {
        let fallback_action = match action {
            "toggle" => Some("toggle_running"),
            "stop" => Some("stop_service"),
            "pin_domain" => Some("pin_domain_recipe"),
            "reload_matcher" => Some("get_state"),
            _ => None,
        };
        if let Some(alt) = fallback_action {
            return try_send_control_command(dir, alt, clean_payload);
        }
    }
    Ok(resp)
}

fn print_control_response(
    action: &str,
    payload: &serde_json::Value,
    resp: &serde_json::Value,
    json: bool,
) -> anyhow::Result<()> {
    if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
        if json {
            println!("{}", serde_json::to_string_pretty(resp)?);
            std::process::exit(1);
        }
        anyhow::bail!("{err}");
    }

    let view = payload.get("view").and_then(|v| v.as_str());
    if json {
        match view {
            Some("flows") => {
                let flows = resp
                    .get("live_flows")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([]));
                println!("{}", serde_json::to_string_pretty(&flows)?);
            }
            Some("logs") => {
                let limit = payload.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
                let logs = resp
                    .get("logs")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        let start = arr.len().saturating_sub(limit);
                        serde_json::Value::Array(arr[start..].to_vec())
                    })
                    .unwrap_or_else(|| serde_json::json!([]));
                println!("{}", serde_json::to_string_pretty(&logs)?);
            }
            _ => {
                println!("{}", serde_json::to_string_pretty(resp)?);
            }
        }
        return Ok(());
    }

    match (action, view) {
        ("get_state", Some("flows")) => {
            let flows = resp
                .get("live_flows")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if flows.is_empty() {
                println!("Активных или недавних потоков нет.");
                return Ok(());
            }
            println!(
                "{:<6} {:<5} {:<18} {:<28} {:<22} {:<12} {:>10} {:>10} STATE",
                "ID", "PROTO", "APP", "HOST", "DST", "ACTION", "TX", "RX"
            );
            for f in flows {
                let id = f.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let proto = f.get("proto").and_then(|v| v.as_str()).unwrap_or("-");
                let app = f.get("app_name").and_then(|v| v.as_str()).unwrap_or("-");
                let host = f.get("host").and_then(|v| v.as_str()).unwrap_or("-");
                let dst = f.get("dst_addr").and_then(|v| v.as_str()).unwrap_or("-");
                let act = f.get("action").and_then(|v| v.as_str()).unwrap_or("-");
                let tx = format_bytes(f.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0));
                let rx = format_bytes(f.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0));
                let active = if f.get("active").and_then(|v| v.as_bool()).unwrap_or(false) {
                    "ACTIVE"
                } else {
                    "CLOSED"
                };
                println!(
                    "{id:<6} {proto:<5} {app:<18.18} {host:<28.28} {dst:<22.22} {act:<12.12} {tx:>10} {rx:>10} {active}"
                );
            }
        }
        ("get_state", Some("logs")) => {
            let limit = payload.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let logs = resp
                .get("logs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if logs.is_empty() {
                println!("Журнал событий пуст.");
                return Ok(());
            }
            let start = logs.len().saturating_sub(limit);
            for entry in &logs[start..] {
                let ts = entry.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                let lvl = entry
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("info");
                let cat = entry
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("sys");
                let msg = entry.get("message").and_then(|v| v.as_str()).unwrap_or("");
                println!("[{ts}] [{lvl:<5}] [{cat}] {msg}");
            }
        }
        ("get_state", _) => {
            let running = resp
                .get("running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let active_mode = resp
                .get("active_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let uptime = resp.get("uptime_sec").and_then(|v| v.as_u64()).unwrap_or(0);
            let active_conn = resp
                .get("active_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total_conn = resp
                .get("total_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let desynced_conn = resp
                .get("desynced_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let tx = format_bytes(resp.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0));
            let rx = format_bytes(resp.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0));
            let port = resp
                .pointer("/config/listen_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(7897);
            let dns_proto = resp
                .pointer("/dns_status/protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let dns_primary = resp
                .pointer("/dns_status/active_primary")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            println!(
                "Состояние:    {}",
                if running {
                    "Запущен"
                } else {
                    "Остановлен"
                }
            );
            println!("Режим:        {active_mode} (порт {port})");
            println!("Время работы: {uptime} с");
            println!(
                "Соединения:   активных={active_conn}, всего={total_conn}, десинк={desynced_conn}"
            );
            println!("Трафик:       TX {tx} / RX {rx}");
            println!("DNS:          {dns_proto} ({dns_primary})");
        }
        ("toggle", _) => {
            let running = resp
                .get("running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let active_mode = resp
                .get("active_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            println!(
                "Переключение выполнено: {} ({active_mode})",
                if running {
                    "Запущен"
                } else {
                    "Остановлен"
                }
            );
        }
        ("stop", _) => println!("Перехват трафика остановлен."),
        ("stop_process", _) => println!("Процесс Tachyon Desync завершён."),
        ("reload_matcher", _) => println!("Матчер списков и конфигурация обновлены."),
        ("pin_domain", _) => {
            let host = payload.get("host").and_then(|v| v.as_str()).unwrap_or("-");
            let rid = payload
                .get("recipe_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("Для домена {host} закреплён рецепт #{rid:02}.");
        }
        _ => println!("{}", serde_json::to_string_pretty(resp)?),
    }

    Ok(())
}

fn run_cli_command(cmd: CliCommand) -> anyhow::Result<()> {
    match cmd {
        CliCommand::Help => {
            print_help();
            Ok(())
        }
        CliCommand::Version { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "name": "tachyon-desync",
                        "version": env!("CARGO_PKG_VERSION"),
                        "recipes_count": all_recipe_summaries().len(),
                    }))?
                );
            } else {
                println!("tachyon-desync {}", env!("CARGO_PKG_VERSION"));
            }
            Ok(())
        }
        CliCommand::Recipes { json } => {
            let recipes = all_recipe_summaries();
            if json {
                let items: Vec<serde_json::Value> = recipes
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "code": r.code,
                            "title": r.title,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                println!(
                    "tachyon-desync {}: синхронизировано {} адаптивных рецептов апстрима:",
                    env!("CARGO_PKG_VERSION"),
                    recipes.len()
                );
                for r in recipes {
                    println!("  #{:02} [{}] -> {}", r.id, r.code, r.title);
                }
            }
            Ok(())
        }
        CliCommand::Run {
            mode,
            port,
            config_dir,
            no_autostart,
        } => {
            crate::proxy::install_crash_guard();
            let tokio_rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()?;

            tokio_rt.block_on(async move {
                let rt = match config_dir {
                    Some(dir) => DesyncRuntime::new_with_data_dir(dir),
                    None => DesyncRuntime::new(),
                };
                if let Err(e) = rt.start_control_server().await {
                    eprintln!("Предупреждение: не удалось запустить control-IPC: {e}");
                }
                rt.apply_cli_overrides(mode, port).await;
                if !no_autostart && let Err(e) = rt.start().await {
                    eprintln!("Ошибка запуска перехвата: {e}");
                }
                let snap = rt.snapshot().await;
                println!(
                    "Tachyon Desync запущен в консольном режиме (режим: {}, порт: {}, Ctrl+C для остановки)",
                    snap.active_mode, snap.config.listen_port
                );
                let _ = tokio::signal::ctrl_c().await;
                rt.stop().await;
            });
            Ok(())
        }
        CliCommand::Probe {
            domain,
            port,
            stream_192k,
            ttl,
            recipe,
            json,
        } => {
            let tokio_rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()?;

            tokio_rt.block_on(async move {
                let _rt = DesyncRuntime::new();
                let ttl_report = if ttl {
                    Some(calibrate_optimal_ttl(&domain, port).await?)
                } else {
                    None
                };
                let report = if let Some(rid) = recipe {
                    let cfg = DesyncConfig::from_recipe_id(rid);
                    probe_custom_strategy_with_options(&domain, port, &cfg, 2500, stream_192k)
                        .await?
                } else {
                    generate_domain_strategy_with_options(&domain, port, true, 1800, stream_192k)
                        .await?
                };
                flush_persistent_cache();

                if json {
                    if let Some(tr) = ttl_report {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "report": report,
                                "ttl": tr,
                            }))?
                        );
                    } else {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                } else {
                    println!("Домен: {} ({})", report.domain, report.resolved_ip);
                    println!(
                        "{:<4} {:<6} {:>7} {:<12} RECIPE",
                        "ID", "STATUS", "RTT", "REASON"
                    );
                    for r in &report.results {
                        let status = if r.ok { "OK" } else { "FAIL" };
                        let reason = if r.block_reason.is_empty() {
                            "-"
                        } else {
                            r.block_reason.as_str()
                        };
                        println!(
                            "#{:02}  {:<6} {:>4} ms {:<12} {}",
                            r.recipe_id, status, r.rtt_ms, reason, r.recipe_title
                        );
                    }
                    println!("\nИтог: {}", report.diagnosis);
                    if let Some(tr) = ttl_report {
                        println!("\nАвто-TTL: {} ({})", tr.optimal_ttl, tr.summary);
                        for p in &tr.probes {
                            println!(
                                "  TTL={:<2} {:<10} {} ms ({})",
                                p.ttl,
                                if p.ok { "OK" } else { p.status.as_str() },
                                p.rtt_ms,
                                p.status
                            );
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        }
        CliCommand::DnsBench { apply, json } => {
            let tokio_rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()?;

            tokio_rt.block_on(async move {
                let rt = DesyncRuntime::new();
                let snap = rt.snapshot().await;
                let shared_state = Arc::new(std::sync::Mutex::new(DnsBenchmarkState::default()));
                let cancel = Arc::new(AtomicBool::new(false));
                let rec = run_dns_benchmark(
                    shared_state.clone(),
                    cancel,
                    snap.config.custom_global_config,
                )
                .await;

                if apply && let Some(ref r) = rec {
                    let rec_val = serde_json::json!(r);
                    if try_send_control_command(
                        &resolve_app_data_dir(),
                        "apply_dns_recommendation",
                        rec_val.clone(),
                    )
                    .is_err()
                    {
                        let _ = rt
                            .handle_ipc_action("apply_dns_recommendation", rec_val)
                            .await;
                    }
                }

                let state = shared_state.lock().map(|g| g.clone()).unwrap_or_default();
                if json {
                    println!("{}", serde_json::to_string_pretty(&state)?);
                } else {
                    println!(
                        "{:<16} {:<10} {:<24} {:>8} {:>6} {:>7} RATING",
                        "PROVIDER", "PROTO", "ADDRESS", "LATENCY", "LOSS", "SCORE"
                    );
                    for row in &state.results {
                        println!(
                            "{:<16.16} {:<10} {:<24.24} {:>5} ms {:>5}% {:>7} {}",
                            row.provider,
                            row.protocol.label_en(),
                            row.address,
                            row.latency_ms,
                            row.loss_pct,
                            row.score,
                            row.rating
                        );
                    }
                    if let Some(ref r) = state.recommendation {
                        println!(
                            "\nРекомендация: {} [{}] — {}",
                            r.protocol.label_en(),
                            r.servers.join(", "),
                            r.reason_ru
                        );
                        if apply {
                            println!("Рекомендованные настройки DNS применены.");
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        }
        CliCommand::DnsSpeed { domains, json } => {
            let tokio_rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()?;

            tokio_rt.block_on(async move {
                let rt = DesyncRuntime::new();
                let snap = rt.snapshot().await;
                let mut dns_settings = snap.config.dns;
                if !domains.is_empty() {
                    dns_settings.speed_test_domains = domains;
                }
                let shared_state = Arc::new(std::sync::Mutex::new(DnsSpeedTestState::default()));
                let cancel = Arc::new(AtomicBool::new(false));
                run_dns_speed_test(
                    dns_settings,
                    shared_state.clone(),
                    cancel,
                    snap.config.custom_global_config,
                )
                .await;

                let state = shared_state.lock().map(|g| g.clone()).unwrap_or_default();
                if json {
                    println!("{}", serde_json::to_string_pretty(&state)?);
                } else {
                    println!(
                        "{:<26} {:<10} {:<10} {:>6} {:>6} {:>6} {:>6} OK",
                        "SERVER", "PROTO", "ROLE", "MIN", "MED", "AVG", "MAX"
                    );
                    for rep in &state.reports {
                        println!(
                            "{:<26.26} {:<10} {:<10} {:>5}  {:>5}  {:>5}  {:>5}  {}/{}",
                            rep.server,
                            rep.protocol.label_en(),
                            rep.role,
                            rep.min_ms,
                            rep.median_ms,
                            rep.avg_ms,
                            rep.max_ms,
                            rep.success_count,
                            rep.total_count
                        );
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        }
        CliCommand::DnsFlush => {
            flush_dns_caches();
            let _ = try_send_control_command(
                &resolve_app_data_dir(),
                "flush_dns_cache",
                serde_json::json!({}),
            );
            println!("Локальный кэш DNS очищен.");
            Ok(())
        }
        CliCommand::Doctor { json } => {
            if let Ok(resp) = try_send_control_command(
                &resolve_app_data_dir(),
                "export_diagnostics",
                serde_json::json!({}),
            ) && resp.get("ok").and_then(|v| v.as_bool()) == Some(true)
            {
                if json {
                    if let Some(rep) = resp.get("report") {
                        println!("{}", serde_json::to_string_pretty(rep)?);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    }
                    return Ok(());
                } else if let Some(txt) = resp.get("text").and_then(|v| v.as_str()) {
                    println!("{txt}");
                    return Ok(());
                }
            }

            let tokio_rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            tokio_rt.block_on(async move {
                let rt = DesyncRuntime::new();
                let report = rt.build_diagnostic_report().await;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    let is_en = rt
                        .snapshot()
                        .await
                        .config
                        .language
                        .eq_ignore_ascii_case("en");
                    println!("{}", report.format_text(is_en));
                }
                Ok::<(), anyhow::Error>(())
            })
        }
        CliCommand::Control {
            action,
            payload,
            json,
            config_dir,
        } => {
            let dir = config_dir.unwrap_or_else(resolve_app_data_dir);
            let resp = send_control_with_fallback(&dir, &action, &payload).map_err(|e| {
                anyhow::anyhow!("Не удалось связаться с процессом Tachyon Desync: {e}")
            })?;
            print_control_response(&action, &payload, &resp, json)
        }
        CliCommand::ConfigExport { path, config_dir } => {
            let dir = config_dir.unwrap_or_else(resolve_app_data_dir);
            let state_path = dir.join("state.json");
            let cfg: AppStateConfig = if state_path.exists() {
                let raw = std::fs::read_to_string(&state_path)?;
                serde_json::from_str(&raw)?
            } else {
                AppStateConfig::default()
            };
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let pretty = serde_json::to_string_pretty(&cfg)?;
            std::fs::write(&path, pretty)?;
            println!("Конфигурация экспортирована в {}", path.display());
            Ok(())
        }
        CliCommand::ConfigImport { path, config_dir } => {
            let raw = std::fs::read_to_string(&path)?;
            let cfg: AppStateConfig = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("Ошибка валидации конфигурации JSON: {e}"))?;
            let dir = config_dir.unwrap_or_else(resolve_app_data_dir);
            std::fs::create_dir_all(&dir)?;
            let state_path = dir.join("state.json");
            let pretty = serde_json::to_string_pretty(&cfg)?;
            std::fs::write(&state_path, pretty)?;
            println!(
                "Конфигурация проверена и импортирована в {}",
                state_path.display()
            );
            Ok(())
        }
        CliCommand::Gui { .. } => unreachable!(),
    }
}

fn main() -> anyhow::Result<()> {
    crate::updater::cleanup_old_update_artifacts();
    let raw_args: Vec<String> = std::env::args().collect();

    if should_attach_console(&raw_args) {
        attach_parent_console_for_cli();
    }

    let arg_refs: Vec<&str> = raw_args.iter().skip(1).map(String::as_str).collect();
    let cmd = match parse_cli_args(&arg_refs) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Ошибка аргументов: {err}");
            eprintln!("Используйте --help для списка доступных команд.");
            std::process::exit(2);
        }
    };

    let (start_minimized, autostart) = match cmd {
        CliCommand::Gui {
            start_minimized,
            autostart,
        } => (start_minimized, autostart),
        other => {
            if let Err(err) = run_cli_command(other) {
                eprintln!("Ошибка: {err}");
                std::process::exit(1);
            }
            return Ok(());
        }
    };

    if !ensure_single_instance_or_focus(start_minimized) {
        return Ok(());
    }

    crate::proxy::install_crash_guard();

    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;

    let desync_rt = tokio_rt.block_on(async {
        let rt = DesyncRuntime::new();
        let _ = rt.start_control_server().await;
        if autostart {
            let _ = rt.start().await;
        }
        rt
    });

    let tokio_handle = tokio_rt.handle().clone();
    crate::tray::spawn_system_tray(desync_rt.clone(), tokio_handle.clone());

    let viewport = egui::ViewportBuilder::default()
        .with_title("Tachyon Desync")
        .with_decorations(false)
        .with_inner_size([515.0, 720.0])
        .with_min_inner_size([440.0, 560.0])
        .with_icon(Arc::new(build_app_icon_data()));

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let rt_for_ui = desync_rt.clone();
    let handle_for_ui = tokio_handle.clone();
    let _ = eframe::run_native(
        "Tachyon Desync",
        native_options,
        Box::new(move |_cc| {
            Ok(Box::new(TachyonGuiApp::new(
                rt_for_ui,
                handle_for_ui,
                start_minimized,
            )))
        }),
    );

    tokio_rt.block_on(async {
        desync_rt.stop().await;
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gui_and_meta_commands() {
        assert_eq!(
            parse_cli_args(&[]),
            Ok(CliCommand::Gui {
                start_minimized: false,
                autostart: true,
            })
        );
        assert_eq!(
            parse_cli_args(&["--minimized", "--no-autostart"]),
            Ok(CliCommand::Gui {
                start_minimized: true,
                autostart: false,
            })
        );
        assert_eq!(parse_cli_args(&["--help"]), Ok(CliCommand::Help));
        assert_eq!(parse_cli_args(&["-h"]), Ok(CliCommand::Help));
        assert_eq!(parse_cli_args(&["help"]), Ok(CliCommand::Help));
        assert_eq!(
            parse_cli_args(&["version", "--json"]),
            Ok(CliCommand::Version { json: true })
        );
        assert_eq!(
            parse_cli_args(&["-V"]),
            Ok(CliCommand::Version { json: false })
        );
        assert_eq!(
            parse_cli_args(&["recipes"]),
            Ok(CliCommand::Recipes { json: false })
        );
        assert_eq!(
            parse_cli_args(&["--check-upstream", "--json"]),
            Ok(CliCommand::Recipes { json: true })
        );
    }

    #[test]
    fn parses_run_and_headless_commands() {
        assert_eq!(
            parse_cli_args(&["run", "--mode", "proxy", "--port", "7899"]),
            Ok(CliCommand::Run {
                mode: Some(CaptureMode::SystemProxy),
                port: Some(7899),
                config_dir: None,
                no_autostart: false,
            })
        );
        assert_eq!(
            parse_cli_args(&[
                "--headless",
                "--mode=tun",
                "--port=7880",
                "--config",
                "/tmp/td",
                "--no-autostart"
            ]),
            Ok(CliCommand::Run {
                mode: Some(CaptureMode::Tun),
                port: Some(7880),
                config_dir: Some(PathBuf::from("/tmp/td")),
                no_autostart: true,
            })
        );
    }

    #[test]
    fn parses_probe_dns_doctor_and_config_commands() {
        assert_eq!(
            parse_cli_args(&["probe", "youtube.com", "--stream-192k", "--ttl"]),
            Ok(CliCommand::Probe {
                domain: "youtube.com".to_string(),
                port: 443,
                stream_192k: true,
                ttl: true,
                recipe: None,
                json: false,
            })
        );
        assert_eq!(
            parse_cli_args(&[
                "probe",
                "discord.com",
                "--port",
                "8443",
                "--recipe",
                "27",
                "--json"
            ]),
            Ok(CliCommand::Probe {
                domain: "discord.com".to_string(),
                port: 8443,
                stream_192k: false,
                ttl: false,
                recipe: Some(27),
                json: true,
            })
        );
        assert_eq!(
            parse_cli_args(&["dns", "bench", "--apply"]),
            Ok(CliCommand::DnsBench {
                apply: true,
                json: false,
            })
        );
        assert_eq!(
            parse_cli_args(&["dns", "speed", "youtube.com", "github.com", "--json"]),
            Ok(CliCommand::DnsSpeed {
                domains: vec!["youtube.com".to_string(), "github.com".to_string()],
                json: true,
            })
        );
        assert_eq!(parse_cli_args(&["dns", "flush"]), Ok(CliCommand::DnsFlush));
        assert_eq!(
            parse_cli_args(&["doctor", "--json"]),
            Ok(CliCommand::Doctor { json: true })
        );
        assert_eq!(
            parse_cli_args(&["config", "export", "backup.json", "--config", "./cfg"]),
            Ok(CliCommand::ConfigExport {
                path: PathBuf::from("backup.json"),
                config_dir: Some(PathBuf::from("./cfg")),
            })
        );
        assert_eq!(
            parse_cli_args(&["config", "import", "backup.json"]),
            Ok(CliCommand::ConfigImport {
                path: PathBuf::from("backup.json"),
                config_dir: None,
            })
        );
    }

    #[test]
    fn parses_control_commands() {
        assert_eq!(
            parse_cli_args(&["status", "--json"]),
            Ok(CliCommand::Control {
                action: "get_state".to_string(),
                payload: serde_json::json!({}),
                json: true,
                config_dir: None,
            })
        );
        assert_eq!(
            parse_cli_args(&["flows"]),
            Ok(CliCommand::Control {
                action: "get_state".to_string(),
                payload: serde_json::json!({ "view": "flows" }),
                json: false,
                config_dir: None,
            })
        );
        assert_eq!(
            parse_cli_args(&["logs", "--limit", "20", "--json"]),
            Ok(CliCommand::Control {
                action: "get_state".to_string(),
                payload: serde_json::json!({ "view": "logs", "limit": 20 }),
                json: true,
                config_dir: None,
            })
        );
        assert_eq!(
            parse_cli_args(&["toggle"]),
            Ok(CliCommand::Control {
                action: "toggle".to_string(),
                payload: serde_json::json!({}),
                json: false,
                config_dir: None,
            })
        );
        assert_eq!(
            parse_cli_args(&["stop", "--exit"]),
            Ok(CliCommand::Control {
                action: "stop_process".to_string(),
                payload: serde_json::json!({}),
                json: false,
                config_dir: None,
            })
        );
        assert_eq!(
            parse_cli_args(&["reload"]),
            Ok(CliCommand::Control {
                action: "reload_matcher".to_string(),
                payload: serde_json::json!({}),
                json: false,
                config_dir: None,
            })
        );
        assert_eq!(
            parse_cli_args(&["pin", "example.com", "14"]),
            Ok(CliCommand::Control {
                action: "pin_domain".to_string(),
                payload: serde_json::json!({ "host": "example.com", "recipe_id": 14 }),
                json: false,
                config_dir: None,
            })
        );
    }

    #[test]
    fn rejects_invalid_flags_and_missing_args() {
        assert!(parse_cli_args(&["--unknown-flag"]).is_err());
        assert!(parse_cli_args(&["run", "--mode", "invalid"]).is_err());
        assert!(parse_cli_args(&["run", "--port", "0"]).is_err());
        assert!(parse_cli_args(&["run", "--port", "abc"]).is_err());
        assert!(parse_cli_args(&["probe"]).is_err());
        assert!(parse_cli_args(&["probe", "youtube.com", "--recipe", "28"]).is_err());
        assert!(parse_cli_args(&["probe", "youtube.com", "--bogus"]).is_err());
        assert!(parse_cli_args(&["dns"]).is_err());
        assert!(parse_cli_args(&["dns", "unknown"]).is_err());
        assert!(parse_cli_args(&["pin", "example.com"]).is_err());
        assert!(parse_cli_args(&["pin", "example.com", "99"]).is_err());
        assert!(parse_cli_args(&["config", "export"]).is_err());
    }
}
