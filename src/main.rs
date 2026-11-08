#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod upstream_compat;
pub use upstream_compat::{cache_file, core_tls, inbound, logging, outbound};

pub mod apps;
pub mod desync;
pub mod flows;
pub mod gui;
pub mod lists;
pub mod proxy;
pub mod runtime;
pub mod tray;
pub mod tun;

use crate::gui::TachyonGuiApp;
use crate::runtime::DesyncRuntime;
use eframe::egui;
use std::sync::Arc;

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

/// Проверить, не запущен ли уже экземпляр `Tachyon Desync` (например, свёрнутый в системный трей).
/// Если запущен новый интерактивный процесс — отправляем старому команду штатного выхода (`IDM_EXIT`)
/// через окно трея и дожидаемся освобождения мьютекса, чтобы всегда запускалась актуальная сборка.
#[cfg(target_os = "windows")]
fn ensure_single_instance_or_focus(start_minimized: bool) -> bool {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(
            lp_mutex_attributes: *const core::ffi::c_void,
            b_initial_owner: i32,
            lp_name: *const u16,
        ) -> *mut core::ffi::c_void;
        fn CloseHandle(h_object: *mut core::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(
            lp_class_name: *const u16,
            lp_window_name: *const u16,
        ) -> *mut core::ffi::c_void;
        fn PostMessageW(
            h_wnd: *mut core::ffi::c_void,
            msg: u32,
            w_param: usize,
            l_param: isize,
        ) -> i32;
    }
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const WM_COMMAND: u32 = 0x0111;
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

#[cfg(not(target_os = "windows"))]
fn ensure_single_instance_or_focus(_start_minimized: bool) -> bool {
    true
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("tachyon-desync {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.iter().any(|a| a == "--check-upstream") {
        let recipes = crate::desync::all_recipe_summaries();
        println!(
            "tachyon-desync {}: синхронизировано {} адаптивных рецептов апстрима:",
            env!("CARGO_PKG_VERSION"),
            recipes.len()
        );
        for r in recipes {
            println!("  #{:02} [{}] -> {}", r.id, r.code, r.title);
        }
        return Ok(());
    }

    let headless = args.iter().any(|a| a == "--headless" || a == "--cli");
    let start_minimized = args.iter().any(|a| a == "--minimized" || a == "--tray");
    let autostart = !args.iter().any(|a| a == "--no-autostart");

    if !headless && !ensure_single_instance_or_focus(start_minimized) {
        return Ok(());
    }

    crate::proxy::install_crash_guard();

    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;

    let desync_rt = tokio_rt.block_on(async {
        let rt = DesyncRuntime::new();
        if autostart {
            let _ = rt.start().await;
        }
        rt
    });

    if headless {
        println!("Tachyon Desync запущен в консольном режиме (Ctrl+C для остановки)");
        tokio_rt.block_on(async {
            let _ = desync_rt.start().await;
            let _ = tokio::signal::ctrl_c().await;
            desync_rt.stop().await;
        });
        return Ok(());
    }

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
