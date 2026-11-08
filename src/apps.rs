//! Определение процесса-владельца локального TCP/UDP сокета (`PID -> Имя процесса`)
//! и сканирование запущенных сетевых приложений (Windows IP Helper API `iphlpapi` / Linux `/proc` / macOS `lsof` + `ps`).

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Информация о запущенном приложении для выбора в GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningAppInfo {
    /// Имя исполняемого файла в нижнем регистре (например, `discord.exe`).
    pub name: String,
    /// Отображаемое название или оригинальный регистр (`Discord.exe`).
    pub display_name: String,
    /// Количество активных сетевых сокетов (TCP + UDP) у этого приложения.
    pub active_sockets: usize,
}

struct PortCacheEntry {
    app_name: String,
    ts: Instant,
}

struct PidCacheEntry {
    app_name: String,
    ts: Instant,
}

fn port_cache() -> &'static Mutex<LruCache<(u16, bool), PortCacheEntry>> {
    static CACHE: OnceLock<Mutex<LruCache<(u16, bool), PortCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(2048).expect("non-zero capacity"),
        ))
    })
}

fn pid_cache() -> &'static Mutex<LruCache<u32, PidCacheEntry>> {
    static CACHE: OnceLock<Mutex<LruCache<u32, PidCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(1024).expect("non-zero capacity"),
        ))
    })
}

/// Нормализовать имя приложения к базовому имени файла в нижнем регистре (`"C:\\Path\\Discord.exe"` -> `"discord.exe"`).
pub fn normalize_app_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_ascii_lowercase()
}

/// Проверить, совпадает ли имя процесса (`"discord.exe"`) с правилом из списка (`"discord.exe"` или `"discord"`).
pub fn app_matches_rule(proc_name: &str, rule_entry: &str) -> bool {
    let p = normalize_app_name(proc_name);
    let r = normalize_app_name(rule_entry);
    if p.is_empty() || r.is_empty() {
        return false;
    }
    if p == r {
        return true;
    }
    let p_stem = p.strip_suffix(".exe").unwrap_or(&p);
    let r_stem = r.strip_suffix(".exe").unwrap_or(&r);
    !p_stem.is_empty() && p_stem == r_stem
}

/// Определить имя процесса (`.exe`), открывшего локальный порт `local_port`.
pub fn resolve_socket_process_name(local_port: u16, is_udp: bool) -> Option<String> {
    if local_port == 0 {
        return None;
    }

    if let Ok(mut guard) = port_cache().lock()
        && let Some(entry) = guard.get(&(local_port, is_udp))
        && entry.ts.elapsed() < Duration::from_secs(3)
    {
        return Some(entry.app_name.clone());
    }

    let pid = lookup_socket_owner_pid(local_port, is_udp)?;
    if pid == 0 || pid == 4 {
        return None;
    }

    let app_name = resolve_pid_process_name(pid)?;
    if let Ok(mut guard) = port_cache().lock() {
        guard.put(
            (local_port, is_udp),
            PortCacheEntry {
                app_name: app_name.clone(),
                ts: Instant::now(),
            },
        );
    }
    Some(app_name)
}

fn resolve_pid_process_name(pid: u32) -> Option<String> {
    if let Ok(mut guard) = pid_cache().lock()
        && let Some(entry) = guard.get(&pid)
        && entry.ts.elapsed() < Duration::from_secs(30)
    {
        return Some(entry.app_name.clone());
    }

    let raw_name = query_os_process_name(pid)?;
    let normalized = normalize_app_name(&raw_name);
    if normalized.is_empty() {
        return None;
    }

    if let Ok(mut guard) = pid_cache().lock() {
        guard.put(
            pid,
            PidCacheEntry {
                app_name: normalized.clone(),
                ts: Instant::now(),
            },
        );
    }
    Some(normalized)
}

/// Является ли имя системным фоновым процессом ОС, который не нужно показывать в пикере.
fn is_noise_system_process(name_lc: &str) -> bool {
    if name_lc.starts_with("kworker/")
        || name_lc.starts_with("ksoftirqd/")
        || name_lc.starts_with("migration/")
        || name_lc.starts_with("rcu_")
    {
        return true;
    }
    matches!(
        name_lc,
        "" | "system"
            | "registry"
            | "memcompression"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "services.exe"
            | "lsass.exe"
            | "svchost.exe"
            | "fontdrvhost.exe"
            | "dwm.exe"
            | "conhost.exe"
            | "sihost.exe"
            | "taskhostw.exe"
            | "ctfmon.exe"
            | "dllhost.exe"
            | "spoolsv.exe"
            | "searchindexer.exe"
            | "securityhealthservice.exe"
            | "securityhealthsystray.exe"
            | "audiodg.exe"
            | "wudfhost.exe"
            | "dashost.exe"
            | "vmmem"
            | "vmmemwsl"
            | "systemd"
            | "kthreadd"
            | "dbus-daemon"
            | "systemd-journald"
            | "systemd-udevd"
            | "systemd-logind"
            | "launchd"
            | "kernel_task"
            | "windowserver"
            | "mdnsresponder"
            | "tachyon-desync.exe"
            | "tachyon-desync"
    )
}

/// Получить список запущенных пользовательских и сетевых приложений на компьютере.
pub fn list_running_apps() -> Vec<RunningAppInfo> {
    let mut socket_counts: HashMap<String, usize> = HashMap::new();
    let mut display_names: HashMap<String, String> = HashMap::new();

    for (pid, count) in collect_active_socket_pids() {
        if let Some(raw) = query_os_process_name(pid) {
            let norm = normalize_app_name(&raw);
            if !is_noise_system_process(&norm) {
                *socket_counts.entry(norm.clone()).or_insert(0) += count;
                let base = raw.rsplit(['\\', '/']).next().unwrap_or(&raw).to_string();
                display_names.entry(norm).or_insert(base);
            }
        }
    }

    for raw in enumerate_all_process_names() {
        let norm = normalize_app_name(&raw);
        if !is_noise_system_process(&norm) {
            socket_counts.entry(norm.clone()).or_insert(0);
            let base = raw.rsplit(['\\', '/']).next().unwrap_or(&raw).to_string();
            display_names.entry(norm).or_insert(base);
        }
    }

    let priority_apps: HashSet<&'static str> = [
        "discord.exe",
        "discord",
        "chrome.exe",
        "chrome",
        "google chrome",
        "chromium",
        "firefox.exe",
        "firefox",
        "msedge.exe",
        "msedge",
        "brave.exe",
        "brave",
        "opera.exe",
        "opera",
        "vivaldi.exe",
        "vivaldi",
        "yandex.exe",
        "browser.exe",
        "safari",
        "telegram.exe",
        "telegram",
        "telegram-desktop",
        "ayugram.exe",
        "ayugram",
        "64gram.exe",
        "spotify.exe",
        "spotify",
        "steam.exe",
        "steam",
        "steamwebhelper.exe",
        "steamwebhelper",
        "epicgameslauncher.exe",
        "obs64.exe",
        "obs",
        "curl.exe",
        "curl",
    ]
    .into_iter()
    .collect();

    let mut out: Vec<RunningAppInfo> = socket_counts
        .into_iter()
        .map(|(name, active_sockets)| {
            let display_name = display_names.remove(&name).unwrap_or_else(|| name.clone());
            RunningAppInfo {
                name,
                display_name,
                active_sockets,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        let a_prio = priority_apps.contains(a.name.as_str());
        let b_prio = priority_apps.contains(b.name.as_str());
        b_prio
            .cmp(&a_prio)
            .then_with(|| b.active_sockets.cmp(&a.active_sockets))
            .then_with(|| a.name.cmp(&b.name))
    });
    out.truncate(80);
    out
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use std::ffi::c_void;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const UDP_TABLE_OWNER_PID: u32 = 1;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;

    #[repr(C)]
    struct MibTcpRowOwnerPid {
        state: u32,
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
        owning_pid: u32,
    }

    #[repr(C)]
    struct MibTcp6RowOwnerPid {
        local_addr: [u8; 16],
        local_scope_id: u32,
        local_port: u32,
        remote_addr: [u8; 16],
        remote_scope_id: u32,
        remote_port: u32,
        state: u32,
        owning_pid: u32,
    }

    #[repr(C)]
    struct MibUdpRowOwnerPid {
        local_addr: u32,
        local_port: u32,
        owning_pid: u32,
    }

    #[repr(C)]
    struct MibUdp6RowOwnerPid {
        local_addr: [u8; 16],
        local_scope_id: u32,
        local_port: u32,
        owning_pid: u32,
    }

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            p_tcp_table: *mut c_void,
            pdw_size: *mut u32,
            b_order: i32,
            ul_af: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;

        fn GetExtendedUdpTable(
            p_udp_table: *mut c_void,
            pdw_size: *mut u32,
            b_order: i32,
            ul_af: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;
    }

    // Примечание: мы принципиально НЕ импортируем и НЕ вызываем `OpenProcess`,
    // чтобы не триггерить `ObRegisterCallbacks` ядерных античитов (RICOCHET / randgrid.sys,
    // EasyAntiCheat, BattlEye, Vanguard). Имя `.exe` по PID определяется исключительно
    // через снимок таблицы процессов `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
        fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    }

    struct ProcessSnapshotCache {
        map: HashMap<u32, String>,
        ts: Instant,
    }

    fn process_snapshot_cache() -> &'static Mutex<Option<ProcessSnapshotCache>> {
        static SNAP_CACHE: OnceLock<Mutex<Option<ProcessSnapshotCache>>> = OnceLock::new();
        SNAP_CACHE.get_or_init(|| Mutex::new(None))
    }

    fn snapshot_pid_map() -> HashMap<u32, String> {
        if let Ok(guard) = process_snapshot_cache().lock()
            && let Some(ref cached) = *guard
            && cached.ts.elapsed() < Duration::from_secs(3)
        {
            return cached.map.clone();
        }

        let mut map = HashMap::with_capacity(256);
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if !snap.is_null() && snap != INVALID_HANDLE_VALUE {
            let mut entry = ProcessEntry32W {
                dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
                cnt_usage: 0,
                th32_process_id: 0,
                th32_default_heap_id: 0,
                th32_module_id: 0,
                cnt_threads: 0,
                th32_parent_process_id: 0,
                pc_pri_class_base: 0,
                dw_flags: 0,
                sz_exe_file: [0u16; 260],
            };
            if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
                loop {
                    let nul = entry
                        .sz_exe_file
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.sz_exe_file.len());
                    if nul > 0 && entry.th32_process_id > 4 {
                        let exe = String::from_utf16_lossy(&entry.sz_exe_file[..nul]);
                        map.insert(entry.th32_process_id, exe);
                    }
                    if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                        break;
                    }
                }
            }
            unsafe {
                CloseHandle(snap);
            }
        }

        if let Ok(mut guard) = process_snapshot_cache().lock() {
            *guard = Some(ProcessSnapshotCache {
                map: map.clone(),
                ts: Instant::now(),
            });
        }
        map
    }

    fn fetch_raw_table(is_udp: bool, af: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 16384;
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize];
            let rc = unsafe {
                if is_udp {
                    GetExtendedUdpTable(
                        buf.as_mut_ptr() as *mut c_void,
                        &mut size,
                        0,
                        af,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                } else {
                    GetExtendedTcpTable(
                        buf.as_mut_ptr() as *mut c_void,
                        &mut size,
                        0,
                        af,
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    )
                }
            };
            if rc == 0 {
                return Some(buf);
            }
            if rc != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }

    #[inline]
    fn decode_win_port(raw_port: u32) -> u16 {
        u16::from_be((raw_port & 0xFFFF) as u16)
    }

    pub fn lookup_socket_owner_pid(local_port: u16, is_udp: bool) -> Option<u32> {
        if !is_udp {
            if let Some(buf) = fetch_raw_table(false, AF_INET)
                && buf.len() >= 4
            {
                let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let row_size = std::mem::size_of::<MibTcpRowOwnerPid>();
                let max_rows = (buf.len() - 4) / row_size;
                let rows = unsafe {
                    std::slice::from_raw_parts(
                        buf[4..].as_ptr() as *const MibTcpRowOwnerPid,
                        count.min(max_rows),
                    )
                };
                for r in rows {
                    if decode_win_port(r.local_port) == local_port && r.owning_pid > 4 {
                        return Some(r.owning_pid);
                    }
                }
            }
            if let Some(buf) = fetch_raw_table(false, AF_INET6)
                && buf.len() >= 4
            {
                let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let row_size = std::mem::size_of::<MibTcp6RowOwnerPid>();
                let max_rows = (buf.len() - 4) / row_size;
                let rows = unsafe {
                    std::slice::from_raw_parts(
                        buf[4..].as_ptr() as *const MibTcp6RowOwnerPid,
                        count.min(max_rows),
                    )
                };
                for r in rows {
                    if decode_win_port(r.local_port) == local_port && r.owning_pid > 4 {
                        return Some(r.owning_pid);
                    }
                }
            }
        } else {
            if let Some(buf) = fetch_raw_table(true, AF_INET)
                && buf.len() >= 4
            {
                let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let row_size = std::mem::size_of::<MibUdpRowOwnerPid>();
                let max_rows = (buf.len() - 4) / row_size;
                let rows = unsafe {
                    std::slice::from_raw_parts(
                        buf[4..].as_ptr() as *const MibUdpRowOwnerPid,
                        count.min(max_rows),
                    )
                };
                for r in rows {
                    if decode_win_port(r.local_port) == local_port && r.owning_pid > 4 {
                        return Some(r.owning_pid);
                    }
                }
            }
            if let Some(buf) = fetch_raw_table(true, AF_INET6)
                && buf.len() >= 4
            {
                let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let row_size = std::mem::size_of::<MibUdp6RowOwnerPid>();
                let max_rows = (buf.len() - 4) / row_size;
                let rows = unsafe {
                    std::slice::from_raw_parts(
                        buf[4..].as_ptr() as *const MibUdp6RowOwnerPid,
                        count.min(max_rows),
                    )
                };
                for r in rows {
                    if decode_win_port(r.local_port) == local_port && r.owning_pid > 4 {
                        return Some(r.owning_pid);
                    }
                }
            }
        }
        None
    }

    pub fn query_os_process_name(pid: u32) -> Option<String> {
        if pid <= 4 {
            return None;
        }
        snapshot_pid_map().remove(&pid)
    }

    pub fn collect_active_socket_pids() -> HashMap<u32, usize> {
        let mut map = HashMap::new();
        if let Some(buf) = fetch_raw_table(false, AF_INET)
            && buf.len() >= 4
        {
            let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let row_size = std::mem::size_of::<MibTcpRowOwnerPid>();
            let max_rows = (buf.len() - 4) / row_size;
            let rows = unsafe {
                std::slice::from_raw_parts(
                    buf[4..].as_ptr() as *const MibTcpRowOwnerPid,
                    count.min(max_rows),
                )
            };
            for r in rows {
                if r.owning_pid > 4 {
                    *map.entry(r.owning_pid).or_insert(0) += 1;
                }
            }
        }
        if let Some(buf) = fetch_raw_table(true, AF_INET)
            && buf.len() >= 4
        {
            let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let row_size = std::mem::size_of::<MibUdpRowOwnerPid>();
            let max_rows = (buf.len() - 4) / row_size;
            let rows = unsafe {
                std::slice::from_raw_parts(
                    buf[4..].as_ptr() as *const MibUdpRowOwnerPid,
                    count.min(max_rows),
                )
            };
            for r in rows {
                if r.owning_pid > 4 {
                    *map.entry(r.owning_pid).or_insert(0) += 1;
                }
            }
        }
        map
    }

    pub fn enumerate_all_process_names() -> Vec<String> {
        snapshot_pid_map().into_values().collect()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    fn find_socket_inode_for_port(local_port: u16, is_udp: bool) -> Option<u64> {
        let files = if is_udp {
            ["/proc/net/udp", "/proc/net/udp6"]
        } else {
            ["/proc/net/tcp", "/proc/net/tcp6"]
        };
        for path in files {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let mut cols = line.split_whitespace();
                let _sl = cols.next();
                let Some(local_addr) = cols.next() else {
                    continue;
                };
                let Some((_ip_hex, port_hex)) = local_addr.split_once(':') else {
                    continue;
                };
                let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                    continue;
                };
                if port != local_port {
                    continue;
                }
                // Columns: 2=rem_address, 3=st, 4=queues, 5=tr, 6=retrnsmt, 7=uid, 8=timeout, 9=inode
                let inode_opt = cols.nth(7).and_then(|s| s.parse::<u64>().ok());
                if let Some(inode) = inode_opt
                    && inode > 0
                {
                    return Some(inode);
                }
            }
        }
        None
    }

    pub fn lookup_socket_owner_pid(local_port: u16, is_udp: bool) -> Option<u32> {
        let inode = find_socket_inode_for_port(local_port, is_udp)?;
        let needle_a = format!("socket:[{inode}]");
        let needle_b = format!("[0000]:{inode}");
        let proc_dir = std::fs::read_dir("/proc").ok()?;
        for entry in proc_dir.flatten() {
            let fname = entry.file_name();
            let Some(pid_str) = fname.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            let fd_path = format!("/proc/{pid}/fd");
            let Ok(fds) = std::fs::read_dir(&fd_path) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path())
                    && let Some(t_str) = target.to_str()
                    && (t_str == needle_a || t_str == needle_b)
                {
                    return Some(pid);
                }
            }
        }
        None
    }

    pub fn query_os_process_name(pid: u32) -> Option<String> {
        if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
            && let Some(name) = exe.file_name().and_then(|s| s.to_str())
            && !name.is_empty()
        {
            return Some(name.trim_end_matches(" (deleted)").to_string());
        }
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn collect_active_socket_pids() -> HashMap<u32, usize> {
        let mut active_inodes = HashSet::new();
        for path in [
            "/proc/net/tcp",
            "/proc/net/tcp6",
            "/proc/net/udp",
            "/proc/net/udp6",
        ] {
            if let Ok(text) = std::fs::read_to_string(path) {
                for line in text.lines().skip(1) {
                    if let Some(inode) = line
                        .split_whitespace()
                        .nth(9)
                        .and_then(|s| s.parse::<u64>().ok())
                        && inode > 0
                    {
                        active_inodes.insert(inode);
                    }
                }
            }
        }
        let mut counts = HashMap::new();
        if active_inodes.is_empty() {
            return counts;
        }
        let Ok(proc_dir) = std::fs::read_dir("/proc") else {
            return counts;
        };
        for entry in proc_dir.flatten() {
            let fname = entry.file_name();
            let Some(pid_str) = fname.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path())
                    && let Some(t_str) = target.to_str()
                    && let Some(inner) = t_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    && let Ok(inode) = inner.parse::<u64>()
                    && active_inodes.contains(&inode)
                {
                    *counts.entry(pid).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    pub fn enumerate_all_process_names() -> Vec<String> {
        let mut names = Vec::new();
        let Ok(proc_dir) = std::fs::read_dir("/proc") else {
            return names;
        };
        for entry in proc_dir.flatten() {
            let fname = entry.file_name();
            let Some(pid_str) = fname.to_str() else {
                continue;
            };
            if let Ok(pid) = pid_str.parse::<u32>()
                && let Some(name) = query_os_process_name(pid)
                && !name.is_empty()
            {
                names.push(name);
            }
        }
        names
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::process::Command;

    pub fn lookup_socket_owner_pid(local_port: u16, is_udp: bool) -> Option<u32> {
        let proto = if is_udp { "UDP" } else { "TCP" };
        let spec = format!("{proto}:{local_port}");
        let out = Command::new("lsof")
            .args(["-nP", "-F", "p", "-i", &spec])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some(pid_s) = line.strip_prefix('p')
                && let Ok(pid) = pid_s.trim().parse::<u32>()
                && pid > 0
            {
                return Some(pid);
            }
        }
        None
    }

    pub fn query_os_process_name(pid: u32) -> Option<String> {
        let out = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if raw.is_empty() {
            return None;
        }
        Some(raw.rsplit('/').next().unwrap_or(&raw).to_string())
    }

    pub fn collect_active_socket_pids() -> HashMap<u32, usize> {
        let mut counts = HashMap::new();
        let Ok(out) = Command::new("lsof")
            .args(["-nP", "-iTCP", "-iUDP", "-F", "pn"])
            .output()
        else {
            return counts;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut current_pid: Option<u32> = None;
        for line in stdout.lines() {
            if let Some(pid_s) = line.strip_prefix('p') {
                current_pid = pid_s.trim().parse::<u32>().ok();
            } else if line.starts_with('n')
                && let Some(pid) = current_pid
            {
                *counts.entry(pid).or_insert(0) += 1;
            }
        }
        counts
    }

    pub fn enumerate_all_process_names() -> Vec<String> {
        let mut names = Vec::new();
        let Ok(out) = Command::new("ps").args(["-axo", "comm="]).output() else {
            return names;
        };
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let base = trimmed.rsplit('/').next().unwrap_or(trimmed).to_string();
                names.push(base);
            }
        }
        names
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod imp {
    use super::*;

    pub fn lookup_socket_owner_pid(_local_port: u16, _is_udp: bool) -> Option<u32> {
        None
    }

    pub fn query_os_process_name(_pid: u32) -> Option<String> {
        None
    }

    pub fn collect_active_socket_pids() -> HashMap<u32, usize> {
        HashMap::new()
    }

    pub fn enumerate_all_process_names() -> Vec<String> {
        Vec::new()
    }
}

use imp::{
    collect_active_socket_pids, enumerate_all_process_names, lookup_socket_owner_pid,
    query_os_process_name,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_name_normalization_and_matching() {
        assert_eq!(
            normalize_app_name(r"C:\Users\User\AppData\Local\Discord\app-1.0.9\Discord.exe"),
            "discord.exe"
        );
        assert!(app_matches_rule("Discord.exe", "discord"));
        assert!(app_matches_rule("discord.exe", "Discord.exe"));
        assert!(!app_matches_rule("chrome.exe", "discord.exe"));
    }

    #[test]
    fn test_list_running_apps_executes() {
        let apps = list_running_apps();
        // На живой ОС список процессов не должен паниковать
        let _ = apps.len();
    }
}
