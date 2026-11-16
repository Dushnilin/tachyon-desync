//! Системный трей ОС (`Shell_NotifyIconW` на Windows), контекстное меню, автозапуск и повышение привилегий (Windows / Linux / macOS).
//!
//! Позволяет сворачивать окно Tachyon Desync в область уведомлений без прерывания
//! работы прокси/TUN, управлять запуском и режимом перехвата из трея и включать
//! автоматический старт вместе с ОС (`HKCU\...\Run`, XDG `~/.config/autostart`, macOS `LaunchAgents`).

#[cfg(windows)]
use crate::runtime::CaptureMode;
use crate::runtime::DesyncRuntime;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);
static SHOW_WINDOW_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Проверить, запрошен ли полный выход из приложения через меню трея или кнопку «Выход».
pub fn is_exit_requested() -> bool {
    EXIT_REQUESTED.load(Ordering::Relaxed)
}

/// Запросить полный выход из приложения.
pub fn request_app_exit() {
    EXIT_REQUESTED.store(true, Ordering::Relaxed);
}

/// Забрать флаг запроса показа главного окна из трея.
pub fn take_show_window_request() -> bool {
    SHOW_WINDOW_REQUESTED.swap(false, Ordering::Relaxed)
}

/// Проверить, включён ли автозапуск Tachyon Desync для текущего пользователя.
pub fn is_autostart_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let out = std::process::Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "TachyonDesync",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        matches!(out, Ok(o) if o.status.success())
    }
    #[cfg(target_os = "linux")]
    {
        linux_autostart_desktop_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    {
        macos_launch_agent_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_autostart_desktop_path() -> Option<std::path::PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.trim().is_empty()
    {
        return Some(
            std::path::PathBuf::from(xdg)
                .join("autostart")
                .join("tachyon-desync.desktop"),
        );
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        std::path::PathBuf::from(home)
            .join(".config")
            .join("autostart")
            .join("tachyon-desync.desktop"),
    )
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(
        std::path::PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join("io.tachyon.desync.plist"),
    )
}

/// Включить или отключить автозапуск Tachyon Desync при входе в систему (`--minimized`).
pub fn set_autostart_enabled(enable: bool) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        if enable {
            let Ok(exe_path) = std::env::current_exe() else {
                return false;
            };
            let cmd_val = format!("\"{}\" --minimized", exe_path.display());
            let status = std::process::Command::new("reg")
                .args([
                    "add",
                    reg_path,
                    "/v",
                    "TachyonDesync",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &cmd_val,
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            matches!(status, Ok(s) if s.success())
        } else {
            let status = std::process::Command::new("reg")
                .args(["delete", reg_path, "/v", "TachyonDesync", "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            let _ = status;
            false
        }
    }
    #[cfg(target_os = "linux")]
    {
        let Some(desktop_path) = linux_autostart_desktop_path() else {
            return false;
        };
        if enable {
            let Ok(exe_path) = std::env::current_exe() else {
                return false;
            };
            if let Some(parent) = desktop_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let content = format!(
                "[Desktop Entry]\nType=Application\nName=Tachyon Desync\nComment=L3/L4/L7 adaptive packet desynchronizer\nExec=\"{}\" --minimized\nTerminal=false\nStartupNotify=false\nCategories=Network;Utility;\n",
                exe_path.display()
            );
            std::fs::write(&desktop_path, content).is_ok()
        } else {
            let _ = std::fs::remove_file(&desktop_path);
            false
        }
    }
    #[cfg(target_os = "macos")]
    {
        let Some(plist_path) = macos_launch_agent_path() else {
            return false;
        };
        if enable {
            let Ok(exe_path) = std::env::current_exe() else {
                return false;
            };
            if let Some(parent) = plist_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let content = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>io.tachyon.desync</string>\n    <key>ProgramArguments</key>\n    <array>\n        <string>{}</string>\n        <string>--minimized</string>\n    </array>\n    <key>RunAtLoad</key>\n    <true/>\n</dict>\n</plist>\n",
                exe_path.display()
            );
            std::fs::write(&plist_path, content).is_ok()
        } else {
            let _ = std::fs::remove_file(&plist_path);
            false
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = enable;
        false
    }
}

/// Спрятать главное окно приложения в системный трей (без завершения работы).
pub fn hide_main_window_to_tray() {
    #[cfg(target_os = "windows")]
    unsafe {
        let hwnd = win32::find_tachyon_window();
        if !hwnd.is_null() {
            win32::ShowWindow(hwnd, win32::SW_HIDE);
        }
    }
}

/// Свернуть главное окно приложения на панель задач Windows.
pub fn minimize_main_window_to_taskbar() {
    #[cfg(target_os = "windows")]
    unsafe {
        let hwnd = win32::find_tachyon_window();
        if !hwnd.is_null() {
            win32::ShowWindow(hwnd, win32::SW_MINIMIZE);
        }
    }
}

#[cfg(target_os = "windows")]
fn shell_execute_verb(verb: &str, target: &str) -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let verb_w = win32::to_wide(verb);
    let target_w = win32::to_wide(target);
    let res = unsafe {
        ShellExecuteW(
            core::ptr::null_mut(),
            verb_w.as_ptr(),
            target_w.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    (res as isize) > 32
}

/// Открыть внешнюю ссылку (например, репозиторий GitHub) в браузере по умолчанию.
pub fn open_url_in_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = shell_execute_verb("open", url);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// Развернуть главное окно из системного трея на передний план.
pub fn restore_main_window_from_tray() {
    SHOW_WINDOW_REQUESTED.store(true, Ordering::Relaxed);
    #[cfg(target_os = "windows")]
    unsafe {
        let hwnd = win32::find_tachyon_window();
        if !hwnd.is_null() {
            win32::ShowWindow(hwnd, win32::SW_SHOW);
            win32::ShowWindow(hwnd, win32::SW_RESTORE);
            win32::SetForegroundWindow(hwnd);
        }
    }
}

/// Проверить, запущен ли процесс с правами Администратора / `root` / `CAP_NET_ADMIN`.
pub fn is_running_as_admin() -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        // Check CAP_NET_ADMIN (bit 12) in /proc/self/status CapEff
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(hex) = line.strip_prefix("CapEff:")
                    && let Ok(mask) = u64::from_str_radix(hex.trim(), 16)
                {
                    return (mask & (1u64 << 12)) != 0;
                }
            }
        }
        false
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        true
    }
}

/// Перезапустить текущий исполняемый файл с запросом повышенных привилегий (UAC `runas` / `pkexec` / `osascript`).
pub fn relaunch_as_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        crate::proxy::emergency_disable_system_proxy();
        shell_execute_verb("runas", &exe.to_string_lossy())
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        crate::proxy::emergency_disable_system_proxy();
        let display = std::env::var("DISPLAY").unwrap_or_default();
        let wayland = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
        let xauth = std::env::var("XAUTHORITY").unwrap_or_default();
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
        if std::process::Command::new("pkexec")
            .args([
                "env",
                &format!("DISPLAY={display}"),
                &format!("WAYLAND_DISPLAY={wayland}"),
                &format!("XAUTHORITY={xauth}"),
                &format!("XDG_RUNTIME_DIR={runtime_dir}"),
                &exe.to_string_lossy(),
            ])
            .spawn()
            .is_ok()
        {
            return true;
        }
        std::process::Command::new("sudo")
            .arg("-E")
            .arg(&exe)
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        crate::proxy::emergency_disable_system_proxy();
        let script = format!(
            "do shell script \"\\\"{}\\\" >/dev/null 2>&1 &\" with administrator privileges",
            exe.display()
        );
        std::process::Command::new("osascript")
            .args(["-e", &script])
            .spawn()
            .is_ok()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Запустить фоновый поток иконки в системном трее Windows.
pub fn spawn_system_tray(rt: Arc<DesyncRuntime>, tokio_handle: tokio::runtime::Handle) {
    #[cfg(target_os = "windows")]
    {
        std::thread::Builder::new()
            .name("tachyon-tray".to_string())
            .spawn(move || unsafe {
                win32::run_tray_loop(rt, tokio_handle);
            })
            .ok();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (rt, tokio_handle);
    }
}

#[cfg(target_os = "windows")]
mod win32 {
    use super::*;
    use std::sync::atomic::AtomicPtr;
    use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, RegisterHotKey, UnregisterHotKey,
    };
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreateIcon, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
        DispatchMessageW, FindWindowW, GetCursorPos, GetMessageW, HICON, IDI_APPLICATION,
        LoadIconW, MF_CHECKED, MF_SEPARATOR, MF_STRING, MSG, PostQuitMessage, RegisterClassExW,
        SW_SHOWNORMAL, SetTimer, TPM_BOTTOMALIGN, TPM_RIGHTBUTTON, TrackPopupMenu,
        TranslateMessage, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_ENDSESSION, WM_HOTKEY,
        WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_QUERYENDSESSION, WM_RBUTTONUP, WM_TIMER, WM_USER,
        WNDCLASSEXW,
    };
    pub use windows_sys::Win32::UI::WindowsAndMessaging::{
        SW_HIDE, SW_MINIMIZE, SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow,
    };

    const WM_TRAYICON: u32 = WM_USER + 144;
    const ID_HOTKEY_TOGGLE: i32 = 1;

    const IDM_OPEN: usize = 1001;
    const IDM_TOGGLE_RUN: usize = 1002;
    const IDM_MODE_PROXY: usize = 1003;
    const IDM_MODE_TUN: usize = 1004;
    const IDM_AUTOSTART: usize = 1005;
    const IDM_EXIT: usize = 1006;

    struct TrayContext {
        rt: Arc<DesyncRuntime>,
        tokio_handle: tokio::runtime::Handle,
        icon_active: HICON,
        icon_warn: HICON,
        icon_stopped: HICON,
        prev_rx_bytes: std::sync::atomic::AtomicU64,
        prev_tx_bytes: std::sync::atomic::AtomicU64,
    }

    static TRAY_CTX: AtomicPtr<TrayContext> = AtomicPtr::new(core::ptr::null_mut());

    pub(super) fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    unsafe fn build_tray_status_icon(
        hinstance: HINSTANCE,
        dot_rgb: [u8; 3],
        letter_rgb: [u8; 3],
    ) -> HICON {
        let w = 16usize;
        let h = 16usize;
        let and_mask = [0u8; 32];
        let mut xor_bgra = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let idx = (y * w + x) * 4;
                let in_dot = x >= 11 && y >= 11 && (x - 13) * (x - 13) + (y - 13) * (y - 13) <= 5;
                let in_t = ((3..=12).contains(&x) && (3..=5).contains(&y))
                    || ((7..=8).contains(&x) && (5..=12).contains(&y));
                let border = x == 0 || y == 0 || x == w - 1 || y == h - 1;
                let (r, g, b) = if in_dot {
                    (dot_rgb[0], dot_rgb[1], dot_rgb[2])
                } else if in_t {
                    (letter_rgb[0], letter_rgb[1], letter_rgb[2])
                } else if border {
                    (46, 58, 78)
                } else {
                    (15, 19, 27)
                };
                xor_bgra[idx] = b;
                xor_bgra[idx + 1] = g;
                xor_bgra[idx + 2] = r;
                xor_bgra[idx + 3] = 255;
            }
        }
        unsafe {
            let ic = CreateIcon(
                hinstance,
                w as i32,
                h as i32,
                1,
                32,
                and_mask.as_ptr(),
                xor_bgra.as_ptr(),
            );
            if ic.is_null() {
                LoadIconW(core::ptr::null_mut(), IDI_APPLICATION)
            } else {
                ic
            }
        }
    }

    unsafe fn refresh_tray_status_icon(hwnd: HWND) {
        unsafe {
            let ctx_ptr = TRAY_CTX.load(Ordering::Acquire);
            if ctx_ptr.is_null() {
                return;
            }
            let ctx = &*ctx_ptr;
            let snap = ctx.tokio_handle.block_on(ctx.rt.snapshot());
            let is_en = snap.config.language.eq_ignore_ascii_case("en");

            let hicon = if !snap.running {
                ctx.icon_stopped
            } else if snap.active_mode.contains("фоллбэк") || snap.active_mode.contains("прокси")
            {
                ctx.icon_warn
            } else {
                ctx.icon_active
            };

            let (cur_rx, cur_tx) = ctx.rt.traffic_bytes();
            let prev_rx = ctx.prev_rx_bytes.swap(cur_rx, Ordering::Relaxed);
            let prev_tx = ctx.prev_tx_bytes.swap(cur_tx, Ordering::Relaxed);
            let rx_bps = cur_rx.saturating_sub(prev_rx) * 8;
            let tx_bps = cur_tx.saturating_sub(prev_tx) * 8;

            let fmt_rate = |bps: u64, en: bool| -> String {
                if bps < 1_000_000 {
                    format!(
                        "{:.0} {}",
                        (bps as f64) / 1000.0,
                        if en { "Kbps" } else { "Кбит/с" }
                    )
                } else {
                    format!(
                        "{:.1} {}",
                        (bps as f64) / 1_000_000.0,
                        if en { "Mbps" } else { "Мбит/с" }
                    )
                }
            };

            let tip_str = if snap.running {
                if is_en {
                    format!(
                        "Tachyon Desync: Active | ↓{} ↑{} | Flows: {} (Ctrl+Alt+D)",
                        fmt_rate(rx_bps, true),
                        fmt_rate(tx_bps, true),
                        snap.active_connections
                    )
                } else {
                    format!(
                        "Tachyon Desync: Активен | ↓{} ↑{} | Потоков: {} (Ctrl+Alt+D)",
                        fmt_rate(rx_bps, false),
                        fmt_rate(tx_bps, false),
                        snap.active_connections
                    )
                }
            } else if is_en {
                "Tachyon Desync: Stopped (Ctrl+Alt+D to start)".to_string()
            } else {
                "Tachyon Desync: Остановлен (Ctrl+Alt+D — старт)".to_string()
            };

            let mut nid: NOTIFYICONDATAW = core::mem::zeroed();
            nid.cbSize = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = hicon;

            let tip = to_wide(&tip_str);
            for (i, &ch) in tip.iter().take(127).enumerate() {
                nid.szTip[i] = ch;
            }
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    }

    pub unsafe fn find_tachyon_window() -> HWND {
        let title = to_wide("Tachyon Desync");
        unsafe { FindWindowW(core::ptr::null(), title.as_ptr()) }
    }

    unsafe extern "system" fn tray_wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        unsafe {
            match msg {
                WM_TRAYICON => {
                    let event = (lparam as u32) & 0xFFFF;
                    if event == WM_LBUTTONUP || event == WM_LBUTTONDBLCLK {
                        restore_main_window_from_tray();
                    } else if event == WM_RBUTTONUP || event == WM_CONTEXTMENU {
                        show_tray_context_menu(hwnd);
                    }
                    0
                }
                WM_TIMER => {
                    refresh_tray_status_icon(hwnd);
                    0
                }
                WM_HOTKEY => {
                    if wparam as i32 == ID_HOTKEY_TOGGLE {
                        let ctx_ptr = TRAY_CTX.load(Ordering::Acquire);
                        if !ctx_ptr.is_null() {
                            let ctx = &*ctx_ptr;
                            ctx.tokio_handle.block_on(async {
                                let _ = ctx
                                    .rt
                                    .handle_ipc_action("toggle_running", serde_json::json!({}))
                                    .await;
                                ctx.rt.push_log(
                                    "info",
                                    "hotkey",
                                    "Переключение состояния службы по глобальной клавише Ctrl+Alt+D",
                                );
                            });
                            refresh_tray_status_icon(hwnd);
                        }
                    }
                    0
                }
                WM_QUERYENDSESSION | WM_ENDSESSION => {
                    crate::proxy::emergency_disable_system_proxy();
                    1
                }
                WM_COMMAND => {
                    let cmd_id = wparam & 0xFFFF;
                    handle_tray_command(hwnd, cmd_id);
                    0
                }
                WM_DESTROY => {
                    crate::proxy::emergency_disable_system_proxy();
                    PostQuitMessage(0);
                    0
                }
                _ => DefWindowProcW(hwnd, msg, wparam, lparam),
            }
        }
    }

    unsafe fn show_tray_context_menu(hwnd: HWND) {
        unsafe {
            let ctx_ptr = TRAY_CTX.load(Ordering::Acquire);
            if ctx_ptr.is_null() {
                return;
            }
            let ctx = &*ctx_ptr;
            let snap = ctx.tokio_handle.block_on(ctx.rt.snapshot());
            let is_en = snap.config.language.eq_ignore_ascii_case("en");

            let hmenu = CreatePopupMenu();
            if hmenu.is_null() {
                return;
            }

            let open_lbl = to_wide(if is_en {
                "Open Tachyon Desync"
            } else {
                "Открыть Tachyon Desync"
            });
            AppendMenuW(hmenu, MF_STRING, IDM_OPEN, open_lbl.as_ptr());
            AppendMenuW(hmenu, MF_SEPARATOR, 0, core::ptr::null());

            let toggle_lbl = if snap.running {
                to_wide(if is_en {
                    "Stop Desync (Ctrl+Alt+D)"
                } else {
                    "Остановить десинк (Ctrl+Alt+D)"
                })
            } else {
                to_wide(if is_en {
                    "Start Desync (Ctrl+Alt+D)"
                } else {
                    "Запустить десинк (Ctrl+Alt+D)"
                })
            };
            let run_flags = if snap.running {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            };
            AppendMenuW(hmenu, run_flags, IDM_TOGGLE_RUN, toggle_lbl.as_ptr());

            AppendMenuW(hmenu, MF_SEPARATOR, 0, core::ptr::null());

            let proxy_flags = if snap.config.capture_mode == CaptureMode::SystemProxy {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            };
            let proxy_lbl = to_wide(if is_en {
                "Mode: System Proxy (:7897)"
            } else {
                "Режим: Системный прокси (:7897)"
            });
            AppendMenuW(hmenu, proxy_flags, IDM_MODE_PROXY, proxy_lbl.as_ptr());

            let tun_flags = if snap.config.capture_mode == CaptureMode::Tun {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            };
            let tun_lbl = to_wide(if is_en {
                "Mode: TUN Adapter (Wintun L3)"
            } else {
                "Режим: Адаптер TUN (Wintun L3)"
            });
            AppendMenuW(hmenu, tun_flags, IDM_MODE_TUN, tun_lbl.as_ptr());

            AppendMenuW(hmenu, MF_SEPARATOR, 0, core::ptr::null());

            let autostart_on = is_autostart_enabled();
            let auto_flags = if autostart_on {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            };
            let auto_lbl = to_wide(if is_en {
                "Autostart with Windows"
            } else {
                "Автозапуск вместе с Windows"
            });
            AppendMenuW(hmenu, auto_flags, IDM_AUTOSTART, auto_lbl.as_ptr());

            AppendMenuW(hmenu, MF_SEPARATOR, 0, core::ptr::null());

            let exit_lbl = to_wide(if is_en { "Quit" } else { "Выход" });
            AppendMenuW(hmenu, MF_STRING, IDM_EXIT, exit_lbl.as_ptr());

            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(
                hmenu,
                TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                pt.x,
                pt.y,
                0,
                hwnd,
                core::ptr::null(),
            );
            DestroyMenu(hmenu);
        }
    }

    unsafe fn handle_tray_command(_hwnd: HWND, cmd_id: usize) {
        unsafe {
            let ctx_ptr = TRAY_CTX.load(Ordering::Acquire);
            if ctx_ptr.is_null() {
                return;
            }
            let ctx = &*ctx_ptr;

            match cmd_id {
                IDM_OPEN => {
                    restore_main_window_from_tray();
                }
                IDM_TOGGLE_RUN => {
                    ctx.tokio_handle.block_on(async {
                        let _ = ctx
                            .rt
                            .handle_ipc_action("toggle_running", serde_json::json!({}))
                            .await;
                    });
                }
                IDM_MODE_PROXY => {
                    ctx.tokio_handle.block_on(async {
                        let _ = ctx
                            .rt
                            .handle_ipc_action(
                                "set_capture_mode",
                                serde_json::json!({ "capture_mode": "system_proxy" }),
                            )
                            .await;
                    });
                }
                IDM_MODE_TUN => {
                    ctx.tokio_handle.block_on(async {
                        let _ = ctx
                            .rt
                            .handle_ipc_action(
                                "set_capture_mode",
                                serde_json::json!({ "capture_mode": "tun" }),
                            )
                            .await;
                    });
                }
                IDM_AUTOSTART => {
                    let cur = is_autostart_enabled();
                    set_autostart_enabled(!cur);
                }
                IDM_EXIT => {
                    request_app_exit();
                    crate::proxy::emergency_disable_system_proxy();
                    let hwnd = find_tachyon_window();
                    if !hwnd.is_null() {
                        ShowWindow(hwnd, SW_SHOWNORMAL);
                    }
                    ctx.tokio_handle.block_on(async {
                        ctx.rt.stop().await;
                    });
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    }

    pub unsafe fn run_tray_loop(rt: Arc<DesyncRuntime>, tokio_handle: tokio::runtime::Handle) {
        unsafe {
            let hinstance = GetModuleHandleW(core::ptr::null());
            let icon_active = build_tray_status_icon(hinstance, [34, 197, 94], [56, 189, 248]);
            let icon_warn = build_tray_status_icon(hinstance, [245, 158, 11], [56, 189, 248]);
            let icon_stopped = build_tray_status_icon(hinstance, [100, 116, 139], [148, 163, 184]);

            let (init_rx, init_tx) = rt.traffic_bytes();
            let boxed_ctx = Box::new(TrayContext {
                rt,
                tokio_handle,
                icon_active,
                icon_warn,
                icon_stopped,
                prev_rx_bytes: std::sync::atomic::AtomicU64::new(init_rx),
                prev_tx_bytes: std::sync::atomic::AtomicU64::new(init_tx),
            });
            TRAY_CTX.store(Box::into_raw(boxed_ctx), Ordering::Release);

            let class_name = to_wide("TachyonDesyncTrayHiddenWnd");

            let wc = WNDCLASSEXW {
                cbSize: core::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(tray_wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinstance,
                hIcon: core::ptr::null_mut(),
                hCursor: core::ptr::null_mut(),
                hbrBackground: core::ptr::null_mut(),
                lpszMenuName: core::ptr::null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm: core::ptr::null_mut(),
            };
            RegisterClassExW(&wc);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                class_name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                hinstance,
                core::ptr::null_mut(),
            );
            if hwnd.is_null() {
                return;
            }

            let mut nid: NOTIFYICONDATAW = core::mem::zeroed();
            nid.cbSize = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = icon_active;

            let tip = to_wide("Tachyon Desync — Адаптивный десинхронизатор");
            for (i, &ch) in tip.iter().take(127).enumerate() {
                nid.szTip[i] = ch;
            }

            Shell_NotifyIconW(NIM_ADD, &nid);
            SetTimer(hwnd, 1, 1000, None);
            let _ = RegisterHotKey(
                hwnd,
                ID_HOTKEY_TOGGLE,
                MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
                b'D' as u32,
            );

            let mut msg: MSG = core::mem::zeroed();
            while GetMessageW(&mut msg, core::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
                if super::is_exit_requested() {
                    break;
                }
            }

            let _ = UnregisterHotKey(hwnd, ID_HOTKEY_TOGGLE);
            Shell_NotifyIconW(NIM_DELETE, &nid);
        }
    }
}
