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

        // В Rust 2024 вызовы `core_tls::...` внутри подмодуля перенаправляем на наш `crate::core_tls::...`
        content = content.replace("core_tls::", "crate::core_tls::");
        content = content.replace("crate::crate::core_tls::", "crate::core_tls::");

        // Для engine.rs добавляем публичные хуки инспекции и управления AdaptiveBrain для GUI
        if out_name == "engine.rs" {
            content.push_str(GUI_ENGINE_EXTENSION);
        }

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

const GUI_ENGINE_EXTENSION: &str = r#"

// === Автоматически подключаемое расширение инспекции AdaptiveBrain для GUI tachyon-desync ===

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuiLearnedDomain {
    pub host: String,
    pub tier: String,
    pub recipe_id: u8,
    pub mode: String,
    pub verified_32k: bool,
    pub consecutive_fails: u8,
    pub banned_mask: u16,
}

pub fn gui_snapshot_learned_domains() -> Vec<GuiLearnedDomain> {
    let b = brain();
    let now = Instant::now();
    let mut out = Vec::new();
    if let Ok(mut g1) = b.l1_host.lock() {
        for (h, e) in g1.iter_mut() {
            if e.verified_32k {
                e.inserted = now;
            }
            out.push(GuiLearnedDomain {
                host: h.clone(),
                tier: "L1 (Точный хост)".to_string(),
                recipe_id: e.recipe_id.unwrap_or(0),
                mode: format!("{:?}", e.mode),
                verified_32k: e.verified_32k,
                consecutive_fails: e.consecutive_fails,
                banned_mask: e.banned_mask,
            });
        }
    }
    if let Ok(mut g2) = b.l2_domain.lock() {
        for (h, e) in g2.iter_mut() {
            if e.verified_32k {
                e.inserted = now;
            }
            if !out.iter().any(|x| x.host == *h) {
                out.push(GuiLearnedDomain {
                    host: h.clone(),
                    tier: "L2 (Домен / Подсеть)".to_string(),
                    recipe_id: e.recipe_id.unwrap_or(0),
                    mode: format!("{:?}", e.mode),
                    verified_32k: e.verified_32k,
                    consecutive_fails: e.consecutive_fails,
                    banned_mask: e.banned_mask,
                });
            }
        }
    }
    out
}

pub fn gui_snapshot_l3_scores() -> [u32; ADAPTIVE_RECIPES.len()] {
    let b = brain();
    std::array::from_fn(|i| b.l3_isp_scores[i].load(Ordering::Relaxed))
}

pub fn gui_get_banned_mask(host: &str) -> u16 {
    let host_lc = host.trim().to_ascii_lowercase();
    if host_lc.is_empty() {
        return 0;
    }
    let b = brain();
    let mut mask = 0u16;
    if let Ok(mut g1) = b.l1_host.lock()
        && let Some(e) = g1.get(&host_lc)
    {
        mask |= e.banned_mask;
    }
    let etld = extract_etld_plus_one(&host_lc);
    if !etld.is_empty()
        && let Ok(mut g2) = b.l2_domain.lock()
        && let Some(e) = g2.get(etld)
    {
        mask |= e.banned_mask;
    }
    mask
}

pub fn gui_set_learned_candidate(
    host: &str,
    recipe_id: u8,
    banned_mask: u16,
    verified_32k: bool,
) {
    let idx = (recipe_id as usize).min(ADAPTIVE_RECIPES.len() - 1);
    let recipe = ADAPTIVE_RECIPES[idx];
    let host_lc = host.trim().to_ascii_lowercase();
    if host_lc.is_empty() {
        return;
    }
    let entry = LearnedEntry {
        mode: recipe.mode,
        recipe_id: Some(recipe.id),
        verified_32k,
        consecutive_fails: 0,
        banned_mask,
        inserted: Instant::now(),
    };
    let b = brain();
    if let Ok(mut g1) = b.l1_host.lock() {
        g1.put(host_lc.clone(), entry);
    }
    let mut to_persist = vec![(host_lc.clone(), entry)];
    let etld = extract_etld_plus_one(&host_lc);
    if !etld.is_empty() && etld != host_lc {
        if let Ok(mut g2) = b.l2_domain.lock() {
            g2.put(etld.to_string(), entry);
        }
        to_persist.push((etld.to_string(), entry));
    } else if !etld.is_empty() {
        if let Ok(mut g2) = b.l2_domain.lock() {
            g2.put(etld.to_string(), entry);
        }
    }
    persist_learned_entries(&to_persist, verified_32k);
}

pub fn gui_pin_domain_recipe(host: &str, recipe_id: u8) {
    gui_set_learned_candidate(host, recipe_id, 0, true);
}

pub fn gui_remove_learned_domain(host: &str) {
    let host_lc = host.trim().to_ascii_lowercase();
    let b = brain();
    if let Ok(mut g1) = b.l1_host.lock() {
        g1.pop(&host_lc);
    }
    if let Ok(mut g2) = b.l2_domain.lock() {
        g2.pop(&host_lc);
    }
    if let Ok(guard) = b.store.lock()
        && let Some(ref handle) = *guard
        && let Ok(mut cache) = handle.lock()
    {
        cache.delete(BUCKET_DESYNC, host_lc.as_bytes());
    }
}
"#;

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
