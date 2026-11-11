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

        // Нормализуем переводы строк и перенаправляем апстримные зависимости на совместимый слой крейта
        content = content.replace("\r\n", "\n");
        content = content.replace("core_tls::", "crate::core_tls::");
        content = content.replace("crate::crate::core_tls::", "crate::core_tls::");
        content = content.replace("portable_atomic::", "std::sync::atomic::");

        // Для engine.rs добавляем только read-only хуки инспекции AdaptiveBrain для GUI;
        // вся адаптивная логика (включая платформенные POST_HS_CAP_BREAKER_IDS) живёт в tachyon-core.
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
    pub banned_mask: u32,
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
                host: h.as_str().to_string(),
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
            let h_str = h.as_str();
            if !out.iter().any(|x| x.host == h_str) {
                out.push(GuiLearnedDomain {
                    host: h_str.to_string(),
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
    std::array::from_fn(|i| {
        let l3 = b.l3_isp_scores[i].load(Ordering::Relaxed);
        let vw = u32::from(b.recipe_stats[i].verified_wins.load(Ordering::Relaxed));
        let hw = u32::from(b.recipe_stats[i].hs_wins.load(Ordering::Relaxed));
        l3.saturating_add(vw.saturating_mul(3)).saturating_add(hw)
    })
}

pub fn gui_get_banned_mask(host: &str) -> u32 {
    let host_lc = InlineKey::<96>::from_ascii_lowercase(host.trim());
    if host_lc.is_empty() {
        return 0;
    }
    let b = brain();
    let mut mask = 0u32;
    if let Ok(mut g1) = b.l1_host.lock()
        && let Some(e) = g1.get(host_lc.as_str())
    {
        mask |= e.banned_mask;
    }
    let etld = extract_etld_plus_one(host_lc.as_str());
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
    banned_mask: u32,
    verified_32k: bool,
) {
    let idx = (recipe_id as usize).min(ADAPTIVE_RECIPES.len() - 1);
    let recipe = ADAPTIVE_RECIPES[idx];
    let host_lc = InlineKey::<96>::from_ascii_lowercase(host.trim());
    if host_lc.is_empty() {
        return;
    }
    let entry = LearnedEntry {
        mode: recipe.mode,
        recipe_id: Some(recipe.id),
        backup_recipe_id: None,
        verified_32k,
        consecutive_fails: 0,
        last_fail_at: None,
        banned_mask,
        inserted: Instant::now(),
    };
    let b = brain();
    if let Ok(mut g1) = b.l1_host.lock() {
        g1.put(host_lc, entry);
    }
    let mut to_persist = vec![(host_lc, entry)];
    let etld = extract_etld_plus_one(host_lc.as_str());
    if !etld.is_empty() && etld != host_lc.as_str() {
        let etld_key = InlineKey::<96>::from_str_trunc(etld);
        if let Ok(mut g2) = b.l2_domain.lock() {
            g2.put(etld_key, entry);
        }
        to_persist.push((etld_key, entry));
    } else if !etld.is_empty() {
        let etld_key = InlineKey::<96>::from_str_trunc(etld);
        if let Ok(mut g2) = b.l2_domain.lock() {
            g2.put(etld_key, entry);
        }
    }
    persist_learned_entries(&to_persist);
    if verified_32k
        && let Ok(guard) = b.store.lock()
        && let Some(ref handle) = *guard
        && let Ok(mut cache) = handle.lock()
    {
        let _ = cache.flush();
    }
}

pub fn gui_pin_domain_recipe(host: &str, recipe_id: u8) {
    gui_set_learned_candidate(host, recipe_id, 0, true);
}

pub fn gui_remove_learned_domain(host: &str) {
    let host_lc = InlineKey::<96>::from_ascii_lowercase(host.trim());
    if host_lc.is_empty() {
        return;
    }
    let etld = extract_etld_plus_one(host_lc.as_str());
    let etld_prefix = if !etld.is_empty() {
        Some(format!("{etld}|"))
    } else {
        None
    };
    let b = brain();
    if let Ok(mut g1) = b.l1_host.lock() {
        g1.pop(host_lc.as_str());
    }
    let mut evicted_l2: Vec<InlineKey<96>> = Vec::new();
    if let Ok(mut g2) = b.l2_domain.lock() {
        g2.pop(host_lc.as_str());
        if !etld.is_empty() {
            g2.pop(etld);
        }
        if let Some(ref pfx) = etld_prefix {
            let sub_keys: Vec<InlineKey<96>> = g2
                .iter()
                .filter_map(|(k, _)| k.as_str().starts_with(pfx).then_some(*k))
                .collect();
            for k in sub_keys {
                g2.pop(&k);
                evicted_l2.push(k);
            }
        }
    }
    if let Ok(guard) = b.store.lock()
        && let Some(ref handle) = *guard
        && let Ok(mut cache) = handle.lock()
    {
        cache.delete(BUCKET_DESYNC, host_lc.as_bytes());
        if !etld.is_empty() {
            cache.delete(BUCKET_DESYNC, etld.as_bytes());
        }
        for k in &evicted_l2 {
            cache.delete(BUCKET_DESYNC, k.as_bytes());
        }
        if let Some(ref pfx) = etld_prefix {
            for k in cache.keys(BUCKET_DESYNC) {
                if k.starts_with(pfx) {
                    cache.delete(BUCKET_DESYNC, k.as_bytes());
                }
            }
        }
    }
}

pub fn gui_refresh_clean_short_transfer(host: &str, peer: Option<SocketAddr>) {
    if host.is_empty() {
        return;
    }
    let b = brain();
    let now = Instant::now();
    let host_k = InlineKey::<96>::from_ascii_lowercase(host.trim());
    if let Ok(mut g1) = b.l1_host.lock()
        && let Some(entry) = g1.get_mut(&host_k)
    {
        entry.consecutive_fails = 0;
        entry.last_fail_at = None;
        entry.inserted = now;
    }
    let etld = extract_etld_plus_one(host_k.as_str());
    if !etld.is_empty()
        && let Ok(mut g2) = b.l2_domain.lock()
    {
        for key in l2_keys(etld, peer).into_iter().flatten() {
            if let Some(entry) = g2.get_mut(&key) {
                entry.consecutive_fails = 0;
                entry.last_fail_at = None;
                entry.inserted = now;
            }
        }
    }
}

pub fn gui_sanitize_poisoned_cap_entries() {
    const MIGRATION_KEY: &[u8] = b"__gui_cap_sanitized_v009";
    let b = brain();
    let already_migrated = if let Ok(guard) = b.store.lock()
        && let Some(ref handle) = *guard
        && let Ok(cache) = handle.lock()
    {
        cache.contains_key(BUCKET_DESYNC, MIGRATION_KEY)
    } else {
        false
    };
    if already_migrated {
        return;
    }

    let mut to_delete: Vec<InlineKey<96>> = Vec::new();
    let mut to_persist: Vec<(InlineKey<96>, LearnedEntry)> = Vec::new();

    if let Ok(mut g1) = b.l1_host.lock() {
        let keys: Vec<InlineKey<96>> = g1.iter().map(|(k, _)| *k).collect();
        for k in keys {
            if let Some(e) = g1.get_mut(&k) {
                if !e.verified_32k
                    && (e.mode == DesyncMode::None || (e.banned_mask & POST_HS_CAP_DETECTED_BIT) != 0)
                {
                    g1.pop(&k);
                    to_delete.push(k);
                } else if (e.banned_mask & POST_HS_CAP_DETECTED_BIT) != 0 {
                    e.banned_mask &= !POST_HS_CAP_DETECTED_BIT;
                    e.consecutive_fails = 0;
                    to_persist.push((k, *e));
                }
            }
        }
    }

    if let Ok(mut g2) = b.l2_domain.lock() {
        let keys: Vec<InlineKey<96>> = g2.iter().map(|(k, _)| *k).collect();
        for k in keys {
            if let Some(e) = g2.get_mut(&k) {
                if !e.verified_32k
                    && (e.mode == DesyncMode::None || (e.banned_mask & POST_HS_CAP_DETECTED_BIT) != 0)
                {
                    g2.pop(&k);
                    to_delete.push(k);
                } else if (e.banned_mask & POST_HS_CAP_DETECTED_BIT) != 0 {
                    e.banned_mask &= !POST_HS_CAP_DETECTED_BIT;
                    e.consecutive_fails = 0;
                    to_persist.push((k, *e));
                }
            }
        }
    }

    if !to_persist.is_empty() {
        persist_learned_entries(&to_persist);
    }

    if let Ok(guard) = b.store.lock()
        && let Some(ref handle) = *guard
        && let Ok(mut cache) = handle.lock()
    {
        for k in &to_delete {
            cache.delete(BUCKET_DESYNC, k.as_bytes());
        }
        cache.put(BUCKET_DESYNC, MIGRATION_KEY, vec![1]);
        let _ = cache.flush();
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
