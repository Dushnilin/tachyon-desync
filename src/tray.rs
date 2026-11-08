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

/// Открыть внешнюю ссылку (например, репозиторий GitHub) в браузере по умолчанию.
pub fn open_url_in_browser(url: &str) {
    #[cfg(target_os = "windows")]
    unsafe {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn ShellExecuteW(
                hwnd: *mut core::ffi::c_void,
                lp_operation: *const u16,
                lp_file: *const u16,
                lp_parameters: *const u16,
                lp_directory: *const u16,
                n_show_cmd: i32,
            ) -> isize;
        }
        let verb: Vec<u16> = "open".encode_utf16().chain(core::iter::once(0)).collect();
        let target: Vec<u16> = url.encode_utf16().chain(core::iter::once(0)).collect();
        let _ = ShellExecuteW(
            core::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            win32::SW_SHOWNORMAL,
        );
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
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        IsUserAnAdmin() != 0
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
    unsafe {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn ShellExecuteW(
                hwnd: *mut core::ffi::c_void,
                lp_operation: *const u16,
                lp_file: *const u16,
                lp_parameters: *const u16,
                lp_directory: *const u16,
                n_show_cmd: i32,
            ) -> isize;
        }
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let verb: Vec<u16> = "runas".encode_utf16().chain(core::iter::once(0)).collect();
        let file: Vec<u16> = exe
            .to_string_lossy()
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        crate::proxy::emergency_disable_system_proxy();
        let res = ShellExecuteW(
            core::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            win32::SW_SHOWNORMAL,
        );
        res > 32
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
#[allow(clippy::upper_case_acronyms, clippy::manual_dangling_ptr)]
mod win32 {
    use super::*;
    use core::ffi::c_void;

    pub const SW_HIDE: i32 = 0;
    pub const SW_SHOWNORMAL: i32 = 1;
    pub const SW_SHOW: i32 = 5;
    pub const SW_MINIMIZE: i32 = 6;
    pub const SW_RESTORE: i32 = 9;

    const WM_DESTROY: u32 = 0x0002;
    const WM_QUERYENDSESSION: u32 = 0x0011;
    const WM_ENDSESSION: u32 = 0x0016;
    const WM_COMMAND: u32 = 0x0111;
    const WM_TIMER: u32 = 0x0113;
    const WM_HOTKEY: u32 = 0x0312;
    const WM_USER: u32 = 0x0400;
    const WM_TRAYICON: u32 = WM_USER + 144;

    const MOD_ALT: u32 = 0x0001;
    const MOD_CONTROL: u32 = 0x0002;
    const MOD_NOREPEAT: u32 = 0x4000;
    const ID_HOTKEY_TOGGLE: i32 = 1;

    const WM_LBUTTONUP: u32 = 0x0202;
    const WM_LBUTTONDBLCLK: u32 = 0x0203;
    const WM_RBUTTONUP: u32 = 0x0205;
    const WM_CONTEXTMENU: u32 = 0x007B;

    const NIM_ADD: u32 = 0x00000000;
    const NIM_MODIFY: u32 = 0x00000001;
    const NIM_DELETE: u32 = 0x00000002;
    const NIF_MESSAGE: u32 = 0x00000001;
    const NIF_ICON: u32 = 0x00000002;
    const NIF_TIP: u32 = 0x00000004;

    const MF_STRING: u32 = 0x00000000;
    const MF_CHECKED: u32 = 0x00000008;
    const MF_SEPARATOR: u32 = 0x00000800;
    const TPM_RIGHTBUTTON: u32 = 0x0002;
    const TPM_BOTTOMALIGN: u32 = 0x0020;

    const IDM_OPEN: usize = 1001;
    const IDM_TOGGLE_RUN: usize = 1002;
    const IDM_MODE_PROXY: usize = 1003;
    const IDM_MODE_TUN: usize = 1004;
    const IDM_AUTOSTART: usize = 1005;
    const IDM_EXIT: usize = 1006;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct POINT {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct MSG {
        hwnd: *mut c_void,
        message: u32,
        wparam: usize,
        lparam: isize,
        time: u32,
        pt: POINT,
    }

    #[repr(C)]
    struct WNDCLASSEXW {
        cb_size: u32,
        style: u32,
        lpfn_wnd_proc: unsafe extern "system" fn(*mut c_void, u32, usize, isize) -> isize,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: *mut c_void,
        h_icon: *mut c_void,
        h_cursor: *mut c_void,
        hbr_background: *mut c_void,
        lpsz_menu_name: *const u16,
        lpsz_class_name: *const u16,
        h_icon_sm: *mut c_void,
    }

    #[repr(C)]
    struct NOTIFYICONDATAW {
        cb_size: u32,
        h_wnd: *mut c_void,
        u_id: u32,
        u_flags: u32,
        u_callback_message: u32,
        h_icon: *mut c_void,
        sz_tip: [u16; 128],
        dw_state: u32,
        dw_state_mask: u32,
        sz_info: [u16; 256],
        u_timeout_or_version: u32,
        sz_info_title: [u16; 64],
        dw_info_flags: u32,
        guid_item: [u8; 16],
        h_balloon_icon: *mut c_void,
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        pub fn FindWindowW(lp_class_name: *const u16, lp_window_name: *const u16) -> *mut c_void;
        pub fn ShowWindow(h_wnd: *mut c_void, n_cmd_show: i32) -> i32;
        pub fn SetForegroundWindow(h_wnd: *mut c_void) -> i32;
        fn RegisterClassExW(lpwcx: *const WNDCLASSEXW) -> u16;
        fn CreateWindowExW(
            dw_ex_style: u32,
            lp_class_name: *const u16,
            lp_window_name: *const u16,
            dw_style: u32,
            x: i32,
            y: i32,
            n_width: i32,
            n_height: i32,
            h_wnd_parent: *mut c_void,
            h_menu: *mut c_void,
            h_instance: *mut c_void,
            lp_param: *mut c_void,
        ) -> *mut c_void;
        fn DefWindowProcW(h_wnd: *mut c_void, msg: u32, w_param: usize, l_param: isize) -> isize;
        fn GetMessageW(
            lp_msg: *mut MSG,
            h_wnd: *mut c_void,
            w_msg_filter_min: u32,
            w_msg_filter_max: u32,
        ) -> i32;
        fn TranslateMessage(lp_msg: *const MSG) -> i32;
        fn DispatchMessageW(lp_msg: *const MSG) -> isize;
        fn PostQuitMessage(n_exit_code: i32);
        fn CreatePopupMenu() -> *mut c_void;
        fn AppendMenuW(
            h_menu: *mut c_void,
            u_flags: u32,
            u_id_new_item: usize,
            lp_new_item: *const u16,
        ) -> i32;
        fn TrackPopupMenu(
            h_menu: *mut c_void,
            u_flags: u32,
            x: i32,
            y: i32,
            n_reserved: i32,
            h_wnd: *mut c_void,
            prc_rect: *const c_void,
        ) -> i32;
        fn DestroyMenu(h_menu: *mut c_void) -> i32;
        fn GetCursorPos(lp_point: *mut POINT) -> i32;
        fn LoadIconW(h_instance: *mut c_void, lp_icon_name: *const u16) -> *mut c_void;
        fn CreateIcon(
            h_instance: *mut c_void,
            n_width: i32,
            n_height: i32,
            c_planes: u8,
            c_bits_pixel: u8,
            lpb_AND_bits: *const u8,
            lpb_XOR_bits: *const u8,
        ) -> *mut c_void;
        fn SetTimer(
            h_wnd: *mut c_void,
            n_id_event: usize,
            u_elapse: u32,
            lp_timer_func: *const c_void,
        ) -> usize;
        fn RegisterHotKey(h_wnd: *mut c_void, id: i32, fs_modifiers: u32, vk: u32) -> i32;
        fn UnregisterHotKey(h_wnd: *mut c_void, id: i32) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(lp_module_name: *const u16) -> *mut c_void;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn Shell_NotifyIconW(dw_message: u32, lp_data: *const NOTIFYICONDATAW) -> i32;
    }

    struct TrayContext {
        rt: Arc<DesyncRuntime>,
        tokio_handle: tokio::runtime::Handle,
        icon_active: *mut c_void,
        icon_warn: *mut c_void,
        icon_stopped: *mut c_void,
        prev_rx_bytes: std::sync::atomic::AtomicU64,
        prev_tx_bytes: std::sync::atomic::AtomicU64,
    }

    static mut TRAY_CTX: *const TrayContext = core::ptr::null();

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    unsafe fn build_tray_status_icon(
        hinstance: *mut c_void,
        dot_rgb: [u8; 3],
        letter_rgb: [u8; 3],
    ) -> *mut c_void {
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
                LoadIconW(core::ptr::null_mut(), 32512usize as *const u16)
            } else {
                ic
            }
        }
    }

    unsafe fn refresh_tray_status_icon(hwnd: *mut c_void) {
        unsafe {
            let ctx_ptr = TRAY_CTX;
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
            nid.cb_size = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.h_wnd = hwnd;
            nid.u_id = 1;
            nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.u_callback_message = WM_TRAYICON;
            nid.h_icon = hicon;

            let tip = to_wide(&tip_str);
            for (i, &ch) in tip.iter().take(127).enumerate() {
                nid.sz_tip[i] = ch;
            }
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    }

    pub unsafe fn find_tachyon_window() -> *mut c_void {
        let title = to_wide("Tachyon Desync");
        unsafe { FindWindowW(core::ptr::null(), title.as_ptr()) }
    }

    unsafe extern "system" fn tray_wnd_proc(
        hwnd: *mut c_void,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
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
                        let ctx_ptr = TRAY_CTX;
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

    unsafe fn show_tray_context_menu(hwnd: *mut c_void) {
        unsafe {
            let ctx_ptr = TRAY_CTX;
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

    unsafe fn handle_tray_command(_hwnd: *mut c_void, cmd_id: usize) {
        unsafe {
            let ctx_ptr = TRAY_CTX;
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
            TRAY_CTX = Box::into_raw(boxed_ctx);

            let class_name = to_wide("TachyonDesyncTrayHiddenWnd");

            let wc = WNDCLASSEXW {
                cb_size: core::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfn_wnd_proc: tray_wnd_proc,
                cb_cls_extra: 0,
                cb_wnd_extra: 0,
                h_instance: hinstance,
                h_icon: core::ptr::null_mut(),
                h_cursor: core::ptr::null_mut(),
                hbr_background: core::ptr::null_mut(),
                lpsz_menu_name: core::ptr::null(),
                lpsz_class_name: class_name.as_ptr(),
                h_icon_sm: core::ptr::null_mut(),
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
            nid.cb_size = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.h_wnd = hwnd;
            nid.u_id = 1;
            nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.u_callback_message = WM_TRAYICON;
            nid.h_icon = icon_active;

            let tip = to_wide("Tachyon Desync — Адаптивный десинхронизатор");
            for (i, &ch) in tip.iter().take(127).enumerate() {
                nid.sz_tip[i] = ch;
            }

            Shell_NotifyIconW(NIM_ADD, &nid);
            SetTimer(hwnd, 1, 1000, core::ptr::null());
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
