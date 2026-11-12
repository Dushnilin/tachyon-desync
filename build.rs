use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // 1. Компиляция модулей десинка (из локального рабочего окружения или закрытого CI)
    println!("cargo:rerun-if-env-changed=TACHYON_CORE_OUTBOUND");
    println!("cargo:rerun-if-env-changed=PRIVATE_REPO_TOKEN");
    stage_upstream_desync(&manifest_dir, &out_dir);

    // 2. Компиляция иконки приложения на Windows
    #[cfg(target_os = "windows")]
    compile_windows_icon(&manifest_dir, &out_dir);
}

fn locate_upstream_outbound(manifest_dir: &Path, out_dir: &Path) -> PathBuf {
    if let Ok(custom) = env::var("TACHYON_CORE_OUTBOUND") {
        let p = PathBuf::from(custom);
        if p.join("desync").join("engine.rs").exists() {
            return p;
        }
    }
    let candidates = [
        manifest_dir
            .join("..")
            .join("tachyon-core-src")
            .join("crates")
            .join("core-runtime")
            .join("src")
            .join("outbound"),
        manifest_dir
            .join("..")
            .join("tachyon-core")
            .join("crates")
            .join("core-runtime")
            .join("src")
            .join("outbound"),
        manifest_dir.join(".upstream-cache"),
    ];
    for c in candidates {
        if c.join("desync").join("engine.rs").exists() && c.join("tlsspoof.rs").exists() {
            return c;
        }
    }

    // При сборке в GitHub Actions с токеном PRIVATE_REPO_TOKEN
    // клонируем только каталог outbound из закрытого репозитория.
    if let Ok(token) = env::var("PRIVATE_REPO_TOKEN")
        && !token.trim().is_empty()
    {
        let clone_dir = out_dir.join("tachyon-core-src-sparse");
        let outbound_sub = clone_dir
            .join("crates")
            .join("core-runtime")
            .join("src")
            .join("outbound");
        if !outbound_sub.join("desync").join("engine.rs").exists() {
            let _ = fs::remove_dir_all(&clone_dir);
            let repo_url = format!(
                "https://x-access-token:{}@github.com/Dushnilin/tachyon-core-src.git",
                token.trim()
            );
            let _ = std::process::Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "--sparse",
                    &repo_url,
                    &clone_dir.to_string_lossy(),
                ])
                .status();
            let _ = std::process::Command::new("git")
                .current_dir(&clone_dir)
                .args(["sparse-checkout", "set", "crates/core-runtime/src/outbound"])
                .status();
        }
        if outbound_sub.join("desync").join("engine.rs").exists() {
            return outbound_sub;
        }
    }

    panic!(
        "Не найден каталог модулей десинка. \
         Укажите путь в переменной окружения TACHYON_CORE_OUTBOUND или задайте PRIVATE_REPO_TOKEN"
    );
}

fn stage_upstream_desync(manifest_dir: &Path, out_dir: &Path) {
    let upstream_dir = locate_upstream_outbound(manifest_dir, out_dir);
    let cache_dir = manifest_dir.join(".upstream-cache");
    let _ = fs::create_dir_all(cache_dir.join("desync"));

    let out_desync_dir = out_dir.join("upstream_desync");
    let _ = fs::create_dir_all(&out_desync_dir);

    let files = [
        ("tlsspoof.rs", "tlsspoof.rs"),
        ("desync/mod.rs", "mod.rs"),
        ("desync/config.rs", "config.rs"),
        ("desync/packet.rs", "packet.rs"),
        ("desync/payload.rs", "payload.rs"),
        ("desync/engine.rs", "engine.rs"),
        ("desync/probe.rs", "probe.rs"),
    ];

    for (rel_src, out_name) in files {
        let src_path = upstream_dir.join(rel_src);
        println!("cargo:rerun-if-changed={}", src_path.display());

        let mut content = fs::read_to_string(&src_path)
            .unwrap_or_else(|e| panic!("Не удалось прочитать {}: {e}", src_path.display()));

        // Обновляем локальный gitignored .upstream-cache (если источник — не сам кэш)
        let cache_target = cache_dir.join(rel_src);
        if src_path != cache_target {
            let _ = fs::write(&cache_target, &content);
        }

        // Нормализуем переводы строк и перенаправляем апстримные зависимости на совместимый слой крейта
        content = content.replace("\r\n", "\n");
        content = content.replace("core_tls::", "crate::core_tls::");
        content = content.replace("crate::crate::core_tls::", "crate::core_tls::");
        content = content.replace("portable_atomic::", "std::sync::atomic::");

        let dst_path = out_desync_dir.join(out_name);
        fs::write(&dst_path, content).expect("write staged upstream file");
    }

    let bridge_rs = r#"
#[allow(dead_code, unused_imports, clippy::all)]
#[path = "tlsspoof.rs"]
pub mod tlsspoof;

#[allow(dead_code, unused_imports, clippy::all)]
#[path = "mod.rs"]
pub mod desync;
"#;
    fs::write(out_desync_dir.join("bridge.rs"), bridge_rs).expect("write bridge.rs");
}

#[cfg(target_os = "windows")]
fn compile_windows_icon(manifest_dir: &Path, out_dir: &Path) {
    let ico_path = manifest_dir.join("src").join("app.ico");
    println!("cargo:rerun-if-changed={}", ico_path.display());
    if !ico_path.exists() {
        return;
    }
    let rc_path = out_dir.join("app_icon.rc");
    let res_path = out_dir.join("app_icon.res");
    let escaped_ico = ico_path.to_string_lossy().replace('\\', "\\\\");
    let _ = fs::write(&rc_path, format!("1 ICON \"{escaped_ico}\"\r\n"));

    let rc_candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\rc.exe",
        "rc.exe",
    ];
    for rc in rc_candidates {
        if let Ok(status) = std::process::Command::new(rc)
            .args([
                "/nologo",
                "/fo",
                &res_path.to_string_lossy(),
                &rc_path.to_string_lossy(),
            ])
            .status()
            && status.success()
            && res_path.exists()
        {
            println!("cargo:rustc-link-arg-bins={}", res_path.display());
            break;
        }
    }
}
