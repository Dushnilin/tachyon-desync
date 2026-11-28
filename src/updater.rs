//! Модуль автоматической проверки и установки обновлений `Tachyon Desync` из GitHub Releases
//! с проверкой контрольной суммы `SHA-256` (FIPS 180-4 на чистом Rust) и атомарной подменой исполняемого файла.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RELEASES_API_URL: &str =
    "https://api.github.com/repos/Dushnilin/tachyon-desync/releases/latest";
pub const RELEASES_PAGE_URL: &str = "https://github.com/Dushnilin/tachyon-desync/releases/latest";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub latest_tag: String,
    pub update_available: bool,
    pub release_url: String,
    pub published_at: String,
    pub release_notes: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_size: u64,
    pub sha256sums_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseDto {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    published_at: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GithubAssetDto>,
}

#[derive(Debug, Deserialize)]
struct GithubAssetDto {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// Очистить временные файлы `.old` и `.update.tmp`, оставшиеся после предыдущего самообновления.
pub fn cleanup_old_update_artifacts() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let old_path = with_appended_ext(&exe, "old");
    let tmp_path = with_appended_ext(&exe, "update.tmp");
    let new_path = with_appended_ext(&exe, "new");
    let _ = std::fs::remove_file(old_path);
    let _ = std::fs::remove_file(tmp_path);
    let _ = std::fs::remove_file(new_path);
}

fn with_appended_ext(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".");
    os.push(suffix);
    PathBuf::from(os)
}

/// Имя релизного артефакта для текущей ОС и архитектуры процессора.
pub fn expected_platform_asset_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "tachyon-desync-windows-amd64.exe"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "tachyon-desync-linux-arm64.tar.gz"
    }
    #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
    {
        "tachyon-desync-linux-amd64.tar.gz"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "tachyon-desync-macos-arm64.tar.gz"
    }
    #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
    {
        "tachyon-desync-macos-amd64.tar.gz"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        "tachyon-desync-linux-amd64.tar.gz"
    }
}

/// Разобрать строку версии `vX.Y.Z` или `X.Y.Z` в кортеж `(major, minor, patch)`.
pub fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let clean = ver.trim().trim_start_matches(['v', 'V']);
    let core_part = clean.split(['-', '+']).next()?;
    let mut parts = core_part.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(current: &str, remote: &str) -> bool {
    match (parse_semver(current), parse_semver(remote)) {
        (Some(cur), Some(rem)) => rem > cur,
        _ => false,
    }
}

/// Создать подпроцесс без появления консольного окна на Windows (`CREATE_NO_WINDOW`).
fn hidden_command(program: &str) -> Command {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut cmd = Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Выполнить HTTP GET (сначала через локальный SOCKS5-прокси десинка, если он активен, затем напрямую).
fn fetch_url_bytes(
    url: &str,
    proxy_port: Option<u16>,
    timeout_secs: u32,
) -> Result<Vec<u8>, String> {
    let t_str = timeout_secs.to_string();
    let ua = concat!("tachyon-desync/", env!("CARGO_PKG_VERSION"));

    // 1. Попытка через curl с локальным SOCKS5-прокси (если запущен), чтобы запрос шёл через десинк
    if let Some(port) = proxy_port.filter(|&p| p > 0) {
        let proxy_arg = format!("127.0.0.1:{port}");
        if let Ok(out) = hidden_command("curl")
            .args([
                "-fsSL",
                "--connect-timeout",
                "6",
                "--max-time",
                &t_str,
                "--socks5-hostname",
                &proxy_arg,
                "-H",
                "Accept: application/vnd.github+json",
                "-A",
                ua,
                url,
            ])
            .output()
            && out.status.success()
            && !out.stdout.is_empty()
        {
            return Ok(out.stdout);
        }
    }

    // 2. Прямой запрос через системный curl
    if let Ok(out) = hidden_command("curl")
        .args([
            "-fsSL",
            "--connect-timeout",
            "8",
            "--max-time",
            &t_str,
            "-H",
            "Accept: application/vnd.github+json",
            "-A",
            ua,
            url,
        ])
        .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return Ok(out.stdout);
    }

    // 3. На Linux/Unix пробуем резервный wget, если curl не установлен
    #[cfg(unix)]
    if let Ok(out) = Command::new("wget")
        .args(["-qO-", "--timeout=12", "--user-agent", ua, url])
        .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return Ok(out.stdout);
    }

    Err("Не удалось выполнить запрос к GitHub Releases (проверьте соединение)".to_string())
}

/// Скачать файл по URL в `dest_path` (с поддержкой локального SOCKS5-прокси десинка).
fn download_url_to_file(
    url: &str,
    dest_path: &Path,
    proxy_port: Option<u16>,
) -> Result<(), String> {
    let dest_str = dest_path.to_string_lossy().to_string();
    let ua = concat!("tachyon-desync/", env!("CARGO_PKG_VERSION"));

    if let Some(port) = proxy_port.filter(|&p| p > 0) {
        let proxy_arg = format!("127.0.0.1:{port}");
        if let Ok(status) = hidden_command("curl")
            .args([
                "-fSL",
                "--connect-timeout",
                "8",
                "--max-time",
                "180",
                "--socks5-hostname",
                &proxy_arg,
                "-A",
                ua,
                "-o",
                &dest_str,
                url,
            ])
            .status()
            && status.success()
            && dest_path.exists()
        {
            return Ok(());
        }
    }

    if let Ok(status) = hidden_command("curl")
        .args([
            "-fSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "180",
            "-A",
            ua,
            "-o",
            &dest_str,
            url,
        ])
        .status()
        && status.success()
        && dest_path.exists()
    {
        return Ok(());
    }

    Err("Не удалось скачать файл обновления с GitHub Releases".to_string())
}

/// Подобрать релизный артефакт строго для текущей ОС и архитектуры (без кросс-платформенного фоллбэка).
fn select_platform_asset<'a>(
    assets: &'a [GithubAssetDto],
    want_asset: &str,
) -> Option<&'a GithubAssetDto> {
    assets.iter().find(|a| a.name == want_asset)
}

/// Проверить наличие новой версии `Tachyon Desync` на GitHub Releases.
pub fn check_for_updates(proxy_port: Option<u16>) -> Result<UpdateCheckResult, String> {
    let raw = fetch_url_bytes(RELEASES_API_URL, proxy_port, 15)?;
    let rel: GithubReleaseDto = serde_json::from_slice(&raw)
        .map_err(|e| format!("Ошибка разбора ответа GitHub API: {e}"))?;

    let latest_tag = rel.tag_name.trim().to_string();
    let latest_version = latest_tag.trim_start_matches(['v', 'V']).to_string();
    let update_available = is_newer_version(CURRENT_VERSION, &latest_version);

    let want_asset = expected_platform_asset_name();
    let matched_asset = select_platform_asset(&rel.assets, want_asset);

    let (asset_name, asset_url, asset_size) = match matched_asset {
        Some(a) => (a.name.clone(), a.browser_download_url.clone(), a.size),
        None => (String::new(), String::new(), 0),
    };

    let sha256sums_url = rel
        .assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS"))
        .map(|a| a.browser_download_url.clone());

    let release_url = if rel.html_url.is_empty() {
        RELEASES_PAGE_URL.to_string()
    } else {
        rel.html_url
    };

    // Убираем служебный HTML-комментарий <!-- core-outbound-sha:... --> из текста заметок
    let clean_notes = rel
        .body
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("<!--"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();

    Ok(UpdateCheckResult {
        current_version: CURRENT_VERSION.to_string(),
        latest_version,
        latest_tag,
        update_available,
        release_url,
        published_at: rel.published_at,
        release_notes: clean_notes,
        asset_name,
        asset_url,
        asset_size,
        sha256sums_url,
    })
}

/// Извлечь ожидаемый SHA-256 хэш для `asset_name` из содержимого файла `SHA256SUMS`.
pub fn parse_sha256sums_for_asset(sums_text: &str, asset_name: &str) -> Option<String> {
    for line in sums_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let hash = parts.next()?;
        let file = parts
            .next()?
            .trim_start_matches('*')
            .trim_start_matches("./");
        if file == asset_name && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

/// Проверить, запущен ли бинарник изнутри подписанного пакета `.app/Contents/MacOS/` на macOS.
#[cfg(any(target_os = "macos", test))]
fn is_inside_macos_app_bundle(exe_path: &Path) -> bool {
    let Some(macos_dir) = exe_path.parent() else {
        return false;
    };
    let Some(contents_dir) = macos_dir.parent() else {
        return false;
    };
    let Some(app_dir) = contents_dir.parent() else {
        return false;
    };
    macos_dir.file_name().and_then(|n| n.to_str()) == Some("MacOS")
        && contents_dir.file_name().and_then(|n| n.to_str()) == Some("Contents")
        && app_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.to_ascii_lowercase().ends_with(".app"))
}

/// Проверить, можно ли безопасно выполнить самообновление для `current_exe` и метаданных `info`.
fn validate_update_preconditions(
    info: &UpdateCheckResult,
    current_exe: &Path,
) -> Result<(), String> {
    if info.asset_url.is_empty() {
        return Err("В релизе ещё не опубликована сборка для вашей платформы".to_string());
    }
    if info
        .sha256sums_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Err(
            "В релизе отсутствует файл контрольных сумм SHA256SUMS — обновление отклонено из соображений безопасности"
                .to_string(),
        );
    }

    #[cfg(target_os = "macos")]
    if is_inside_macos_app_bundle(current_exe) {
        return Err(
            "Приложение запущено из пакета .app — для обновления скачайте новый образ .dmg со страницы релизов GitHub вместо замены бинарного файла внутри бандла."
                .to_string(),
        );
    }

    #[cfg(target_os = "linux")]
    if let Some(parent_dir) = current_exe.parent() {
        let probe_path = parent_dir.join(format!(".tachyon-update-probe-{}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe_path)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe_path);
            }
            Err(_) => {
                return Err(format!(
                    "Нет прав на запись в каталог установки ({}). Если приложение установлено из системного пакета (.deb), обновите его через пакетный менеджер или запустите обновление с правами sudo.",
                    parent_dir.display()
                ));
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = current_exe;

    Ok(())
}

/// Проверить SHA-256 скачанного файла обновления по сырому содержимому `SHA256SUMS`.
fn verify_downloaded_sha256(
    downloaded_bytes: &[u8],
    sums_raw: &[u8],
    asset_name: &str,
) -> Result<(), String> {
    let sums_text = std::str::from_utf8(sums_raw)
        .map_err(|_| "Файл SHA256SUMS содержит некорректную кодировку UTF-8".to_string())?;
    let expected_hash = parse_sha256sums_for_asset(sums_text, asset_name).ok_or_else(|| {
        format!("В файле SHA256SUMS отсутствует запись для артефакта {asset_name}")
    })?;
    let actual_hash = sha256_hex(downloaded_bytes);
    if actual_hash != expected_hash {
        return Err(format!(
            "Контрольная сумма SHA-256 не совпала (ожидалось {}, получено {})",
            &expected_hash[..12],
            &actual_hash[..12]
        ));
    }
    Ok(())
}

/// Извлечь строку capabilities из вывода `getcap`.
#[cfg(any(target_os = "linux", test))]
fn parse_getcap_cap_spec(stdout: &str) -> Option<String> {
    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    if let Some((_, rhs)) = line.rsplit_once(" = ") {
        let caps = rhs.trim();
        if !caps.is_empty() {
            return Some(caps.to_string());
        }
    }
    if let Some((_, rhs)) = line.rsplit_once(char::is_whitespace) {
        let caps = rhs.trim();
        if caps.contains('=') || caps.contains('+') {
            return Some(caps.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_linux_file_caps(exe_path: &Path) -> Option<String> {
    for getcap in ["getcap", "/usr/sbin/getcap", "/sbin/getcap"] {
        if let Ok(out) = Command::new(getcap).arg(exe_path).output()
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(caps) = parse_getcap_cap_spec(&stdout) {
                return Some(caps);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn restore_linux_net_admin_caps(exe_path: &Path, saved_caps: Option<&str>) {
    let Some(caps) = saved_caps.filter(|c| c.to_ascii_lowercase().contains("cap_net_admin")) else {
        return;
    };
    for setcap in ["setcap", "/usr/sbin/setcap", "/sbin/setcap"] {
        if let Ok(status) = Command::new(setcap).arg(caps).arg(exe_path).status()
            && status.success()
        {
            break;
        }
    }
}

/// Скачать релизный артефакт, проверить его `SHA-256` и атомарно заменить текущий исполняемый файл.
/// Возвращает путь к обновлённому исполняемому файлу для последующего перезапуска.
pub fn download_and_apply_update(
    info: &UpdateCheckResult,
    proxy_port: Option<u16>,
) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к исполняемому файлу: {e}"))?;
    validate_update_preconditions(info, &current_exe)?;

    let sums_url = info
        .sha256sums_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "В релизе отсутствует файл контрольных сумм SHA256SUMS — обновление отклонено"
                .to_string()
        })?;

    let tmp_download = with_appended_ext(&current_exe, "update.tmp");
    let _ = std::fs::remove_file(&tmp_download);

    // 1. Скачиваем артефакт
    download_url_to_file(&info.asset_url, &tmp_download, proxy_port)?;

    let downloaded_bytes = match std::fs::read(&tmp_download) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_download);
            return Err(format!(
                "Не удалось прочитать скачанный файл обновления: {e}"
            ));
        }
    };
    if downloaded_bytes.len() < 256 * 1024 {
        let _ = std::fs::remove_file(&tmp_download);
        return Err(format!(
            "Скачанный файл слишком мал ({} Б), обновление отменено",
            downloaded_bytes.len()
        ));
    }

    // 2. Обязательно скачиваем SHA256SUMS и проверяем контрольную сумму SHA-256
    let sums_raw = match fetch_url_bytes(sums_url, proxy_port, 15) {
        Ok(raw) => raw,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_download);
            return Err(format!(
                "Не удалось скачать SHA256SUMS для проверки целостности: {e}"
            ));
        }
    };
    if let Err(e) = verify_downloaded_sha256(&downloaded_bytes, &sums_raw, &info.asset_name) {
        let _ = std::fs::remove_file(&tmp_download);
        return Err(e);
    }

    // 3. Готовим новый исполняемый файл (.new)
    let staged_new = with_appended_ext(&current_exe, "new");
    let _ = std::fs::remove_file(&staged_new);

    if info.asset_name.ends_with(".tar.gz") {
        let extract_dir = current_exe
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".tachyon-update-extract");
        let _ = std::fs::remove_dir_all(&extract_dir);
        if let Err(e) = std::fs::create_dir_all(&extract_dir) {
            let _ = std::fs::remove_file(&tmp_download);
            return Err(format!(
                "Не удалось создать временный каталог распаковки: {e}"
            ));
        }

        let status = match hidden_command("tar")
            .args([
                "-xzf",
                &tmp_download.to_string_lossy(),
                "-C",
                &extract_dir.to_string_lossy(),
            ])
            .status()
        {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_download);
                let _ = std::fs::remove_dir_all(&extract_dir);
                return Err(format!("Ошибка запуска tar для распаковки обновления: {e}"));
            }
        };
        let _ = std::fs::remove_file(&tmp_download);

        if !status.success() {
            let _ = std::fs::remove_dir_all(&extract_dir);
            return Err("Не удалось распаковать архив обновления (.tar.gz)".to_string());
        }

        let extracted_bin = extract_dir.join("tachyon-desync");
        if !extracted_bin.exists() {
            let _ = std::fs::remove_dir_all(&extract_dir);
            return Err("В архиве обновления не найден бинарный файл tachyon-desync".to_string());
        }

        std::fs::rename(&extracted_bin, &staged_new)
            .or_else(|_| std::fs::copy(&extracted_bin, &staged_new).map(|_| ()))
            .map_err(|e| format!("Не удалось подготовить бинарный файл обновления: {e}"))?;
        let _ = std::fs::remove_dir_all(&extract_dir);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&staged_new) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&staged_new, perms);
            }
        }
    } else {
        // Windows .exe: проверяем сигнатуру PE/MZ
        if !downloaded_bytes.starts_with(b"MZ") {
            let _ = std::fs::remove_file(&tmp_download);
            return Err(
                "Скачанный файл не является корректным исполняемым файлом Windows PE (MZ)"
                    .to_string(),
            );
        }
        std::fs::rename(&tmp_download, &staged_new)
            .map_err(|e| format!("Не удалось подготовить файл обновления: {e}"))?;
    }

    #[cfg(target_os = "linux")]
    let saved_caps = read_linux_file_caps(&current_exe);

    // 4. Атомарная замена: переименовываем текущий работающий бинарник в `.old` и ставим `.new` на его место
    let old_exe = with_appended_ext(&current_exe, "old");
    let _ = std::fs::remove_file(&old_exe);

    std::fs::rename(&current_exe, &old_exe).map_err(|e| {
        let _ = std::fs::remove_file(&staged_new);
        format!("Не удалось переименовать текущий исполняемый файл (проверьте права доступа): {e}")
    })?;

    if let Err(e) = std::fs::rename(&staged_new, &current_exe) {
        // Откатываем старый исполняемый файл обратно при ошибке
        let _ = std::fs::rename(&old_exe, &current_exe);
        return Err(format!("Не удалось установить новый исполняемый файл: {e}"));
    }

    #[cfg(target_os = "linux")]
    restore_linux_net_admin_caps(&current_exe, saved_caps.as_deref());

    Ok(current_exe)
}

/// Запустить обновлённый исполняемый файл и завершить текущий процесс.
pub fn spawn_updated_binary_and_exit(exe_path: &Path) {
    let _ = Command::new(exe_path).spawn();
    std::process::exit(0);
}

/// Вычислить контрольную сумму SHA-256 (FIPS 180-4) в нижнем регистре hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for &byte in digest.as_slice() {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_nist_vectors_and_semver_comparison() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        assert!(is_newer_version("0.0.4", "0.0.5"));
        assert!(is_newer_version("v0.0.4", "v0.1.0"));
        assert!(!is_newer_version("0.0.4", "0.0.4"));
        assert!(!is_newer_version("0.0.5", "0.0.4"));

        let sums = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  tachyon-desync-windows-amd64.exe\n";
        assert_eq!(
            parse_sha256sums_for_asset(sums, "tachyon-desync-windows-amd64.exe").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn test_parse_sha256sums_handles_prefixes_and_rejects_invalid_entries() {
        let sums = "\
# comment line should be ignored\n\
\n\
short_hash  tachyon-desync-linux-amd64.tar.gz\n\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  tachyon-desync-linux-amd64.tar.gz\n\
BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD *./tachyon-desync-linux-amd64.tar.gz\n";
        assert_eq!(
            parse_sha256sums_for_asset(sums, "tachyon-desync-linux-amd64.tar.gz").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            parse_sha256sums_for_asset(sums, "tachyon-desync-linux-arm64.tar.gz"),
            None
        );
    }

    #[test]
    fn test_select_platform_asset_strict_without_cross_arch_fallback() {
        let assets = vec![
            GithubAssetDto {
                name: "tachyon-desync-windows-amd64.exe".to_string(),
                browser_download_url: "https://example.invalid/win.exe".to_string(),
                size: 100,
            },
            GithubAssetDto {
                name: "tachyon-desync-linux-amd64.tar.gz".to_string(),
                browser_download_url: "https://example.invalid/linux-amd64.tar.gz".to_string(),
                size: 100,
            },
        ];
        assert!(select_platform_asset(&assets, "tachyon-desync-linux-arm64.tar.gz").is_none());
        assert!(select_platform_asset(&assets, "tachyon-desync-macos-arm64.tar.gz").is_none());
        assert_eq!(
            select_platform_asset(&assets, "tachyon-desync-linux-amd64.tar.gz")
                .map(|a| a.name.as_str()),
            Some("tachyon-desync-linux-amd64.tar.gz")
        );
    }

    #[test]
    fn test_strict_sha256_verification_policy() {
        let payload = b"abc";
        let valid_sums =
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  tachyon-desync-windows-amd64.exe\n";
        assert!(
            verify_downloaded_sha256(payload, valid_sums, "tachyon-desync-windows-amd64.exe")
                .is_ok()
        );

        // Невалидный UTF-8 -> Err
        assert!(
            verify_downloaded_sha256(
                payload,
                &[0xff, 0xfe, 0xfd],
                "tachyon-desync-windows-amd64.exe"
            )
            .is_err()
        );

        // Отсутствующий ассет в SHA256SUMS -> Err
        assert!(
            verify_downloaded_sha256(payload, valid_sums, "tachyon-desync-linux-amd64.tar.gz")
                .is_err()
        );

        // Несовпадение контрольной суммы -> Err
        assert!(
            verify_downloaded_sha256(b"tampered", valid_sums, "tachyon-desync-windows-amd64.exe")
                .is_err()
        );

        // Отсутствие SHA256SUMS в релизе -> Err
        let missing_sums_info = UpdateCheckResult {
            current_version: "0.2.0".to_string(),
            latest_version: "0.3.0".to_string(),
            latest_tag: "v0.3.0".to_string(),
            update_available: true,
            release_url: String::new(),
            published_at: String::new(),
            release_notes: String::new(),
            asset_name: "tachyon-desync-windows-amd64.exe".to_string(),
            asset_url: "https://example.invalid/win.exe".to_string(),
            asset_size: 100,
            sha256sums_url: None,
        };
        assert!(
            validate_update_preconditions(&missing_sums_info, Path::new("tachyon-desync.exe"))
                .is_err()
        );
    }

    #[test]
    fn test_macos_app_bundle_and_linux_getcap_parsing() {
        assert!(is_inside_macos_app_bundle(Path::new(
            "/Applications/Tachyon Desync.app/Contents/MacOS/tachyon-desync"
        )));
        assert!(!is_inside_macos_app_bundle(Path::new(
            "/usr/local/bin/tachyon-desync"
        )));

        assert_eq!(
            parse_getcap_cap_spec("/usr/bin/tachyon-desync cap_net_admin=eip\n").as_deref(),
            Some("cap_net_admin=eip")
        );
        assert_eq!(
            parse_getcap_cap_spec("/usr/bin/tachyon-desync = cap_net_admin,cap_net_raw+eip\n")
                .as_deref(),
            Some("cap_net_admin,cap_net_raw+eip")
        );
        assert_eq!(parse_getcap_cap_spec(""), None);
    }
}
