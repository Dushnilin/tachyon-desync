//! Локальный комбинированный сервер SOCKS5 + HTTP/CONNECT с применением десинхронизатора
//! и управление системным прокси ОС (Windows / Linux / macOS).

use crate::desync::{
    RECIPE_TITLES, connect_and_apply_desync_auto, connect_outbound_tcp, connect_via_upstream_proxy,
    extract_hostname, report_transfer_outcome,
};
use crate::lists::{CompiledMatcher, MatchDecision, record_dns_mapping};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// Обратный вызов для телеметрии и журнала событий в `DesyncRuntime`.
pub type LogCallback = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

/// Общие атомарные счётчики трафика и соединений.
#[derive(Default)]
pub struct TrafficCounters {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub desynced_connections: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

/// Запустить комбинированный сервер SOCKS5 + HTTP/CONNECT на `127.0.0.1:port`.
pub async fn run_local_proxy_server(
    listen_addr: SocketAddr,
    matcher: Arc<RwLock<Arc<CompiledMatcher>>>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
    stop_flag: Arc<AtomicBool>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    (log_fn)(
        "info",
        "proxy",
        &format!("Локальный узел SOCKS5/HTTP запущен на {listen_addr}"),
    );

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let accept_res = tokio::time::timeout(Duration::from_millis(350), listener.accept()).await;
        let Ok(Ok((client, _peer))) = accept_res else {
            continue;
        };
        let _ = client.set_nodelay(true);

        let matcher_ref = matcher.read().await.clone();
        let counters_ref = counters.clone();
        let log_ref = log_fn.clone();

        tokio::spawn(async move {
            let _ = handle_proxy_client(client, matcher_ref, counters_ref, log_ref).await;
        });
    }

    Ok(())
}

async fn handle_proxy_client(
    mut client: TcpStream,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    let mut first_byte = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut first_byte))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy greeting timeout"))??;

    if first_byte[0] == 0x05 {
        handle_socks5_stream(client, matcher, counters, log_fn).await
    } else {
        handle_http_stream(client, first_byte[0], matcher, counters, log_fn).await
    }
}

async fn handle_socks5_stream(
    mut client: TcpStream,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    let mut nmethods = [0u8; 1];
    client.read_exact(&mut nmethods).await?;
    let mut methods = vec![0u8; nmethods[0] as usize];
    client.read_exact(&mut methods).await?;
    // Отвечаем: 0x05 0x00 (без аутентификации)
    client.write_all(&[0x05, 0x00]).await?;

    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != 0x05 || req_hdr[1] != 0x01 {
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Ok(());
    }

    let (target_host, target_ip_opt, target_port) = match req_hdr[3] {
        0x01 => {
            let mut ip4 = [0u8; 4];
            let mut port_b = [0u8; 2];
            client.read_exact(&mut ip4).await?;
            client.read_exact(&mut port_b).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(ip4));
            (None, Some(ip), u16::from_be_bytes(port_b))
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            client.read_exact(&mut dlen).await?;
            let mut dom = vec![0u8; dlen[0] as usize];
            let mut port_b = [0u8; 2];
            client.read_exact(&mut dom).await?;
            client.read_exact(&mut port_b).await?;
            let host = String::from_utf8_lossy(&dom).trim().to_ascii_lowercase();
            let parsed_ip = host.parse::<IpAddr>().ok();
            (
                if parsed_ip.is_none() {
                    Some(host)
                } else {
                    None
                },
                parsed_ip,
                u16::from_be_bytes(port_b),
            )
        }
        0x04 => {
            let mut ip6 = [0u8; 16];
            let mut port_b = [0u8; 2];
            client.read_exact(&mut ip6).await?;
            client.read_exact(&mut port_b).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(ip6));
            (None, Some(ip), u16::from_be_bytes(port_b))
        }
        _ => return Ok(()),
    };

    let dst_addr = resolve_target_addr(target_host.as_deref(), target_ip_opt, target_port).await?;
    // Отправляем успешный ответ SOCKS5 तुरंत, чтобы клиент прислал ClientHello
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    client.flush().await?;

    relay_with_desync_policy(
        client,
        dst_addr,
        target_host,
        Vec::new(),
        matcher,
        counters,
        log_fn,
    )
    .await
}

async fn handle_http_stream(
    mut client: TcpStream,
    first_byte: u8,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    let mut req_buf = Vec::with_capacity(2048);
    req_buf.push(first_byte);
    let mut tmp = [0u8; 2048];
    while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") && req_buf.len() < 16384 {
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP header timeout"))??;
        if n == 0 {
            return Ok(());
        }
        req_buf.extend_from_slice(&tmp[..n]);
    }

    let first_line_end = req_buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(req_buf.len());
    let first_line = String::from_utf8_lossy(&req_buf[..first_line_end]);
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let uri = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host_str, port) = parse_host_port(uri, 443);
        let parsed_ip = host_str.parse::<IpAddr>().ok();
        let host_opt = if parsed_ip.is_none() {
            Some(host_str)
        } else {
            None
        };
        let dst_addr = resolve_target_addr(host_opt.as_deref(), parsed_ip, port).await?;

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        relay_with_desync_policy(
            client,
            dst_addr,
            host_opt,
            Vec::new(),
            matcher,
            counters,
            log_fn,
        )
        .await
    } else {
        // Обычный HTTP-запрос через прокси: берём хост и порт из абсолютного URI либо из заголовка Host
        let (mut host_str, mut port) = if uri.starts_with("http://") || uri.starts_with("https://")
        {
            parse_host_port(uri, 80)
        } else {
            (String::new(), 80)
        };
        if host_str.is_empty() {
            let hdr_text = String::from_utf8_lossy(&req_buf);
            for line in hdr_text.lines() {
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("host")
                {
                    let (h, p) = parse_host_port(v.trim(), 80);
                    host_str = h;
                    port = p;
                    break;
                }
            }
        }
        if host_str.is_empty() {
            let extracted = extract_hostname(&req_buf).unwrap_or_default();
            if extracted.is_empty() {
                return Ok(());
            }
            host_str = extracted;
        }
        let parsed_ip = host_str.parse::<IpAddr>().ok();
        let host_opt = if parsed_ip.is_none() {
            Some(host_str)
        } else {
            None
        };
        let dst_addr = resolve_target_addr(host_opt.as_deref(), parsed_ip, port).await?;

        relay_with_desync_policy(
            client, dst_addr, host_opt, req_buf, matcher, counters, log_fn,
        )
        .await
    }
}

fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
    let clean = s
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    if let Some((h, p)) = clean.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return (h.trim_matches(&['[', ']'][..]).to_ascii_lowercase(), port);
    }
    (
        clean.trim_matches(&['[', ']'][..]).to_ascii_lowercase(),
        default_port,
    )
}

async fn resolve_target_addr(
    host: Option<&str>,
    ip_opt: Option<IpAddr>,
    port: u16,
) -> io::Result<SocketAddr> {
    if let Some(ip) = ip_opt {
        return Ok(SocketAddr::new(ip, port));
    }
    let Some(h) = host else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty target"));
    };
    let addrs = crate::outbound::dial::resolve(h, port).await?;
    let chosen = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS returned no addresses"))?;

    record_dns_mapping(chosen.ip(), h);
    Ok(chosen)
}

/// Универсальный конвейер TCP-соединения: читает первый пакет (`ClientHello` / HTTP),
/// вычисляет правило по списку и приложению, применяет десинхронизацию и передаёт трафик в обе стороны.
pub async fn relay_with_desync_policy(
    mut client: TcpStream,
    dst_addr: SocketAddr,
    known_host: Option<String>,
    initial_payload: Vec<u8>,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    let peer_port = client.peer_addr().map(|a| a.port()).unwrap_or(0);
    let app_name = crate::apps::resolve_socket_process_name(peer_port, false);
    let app_tag = app_name
        .as_deref()
        .map(|a| format!("[{a}] "))
        .unwrap_or_default();

    let first_pkt = if !initial_payload.is_empty() {
        initial_payload
    } else {
        let mut buf = vec![0u8; 16384];
        match tokio::time::timeout(Duration::from_millis(400), client.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.truncate(n);
                buf
            }
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => Vec::new(),
        }
    };

    let sni_host = extract_hostname(&first_pkt).or(known_host);
    if let Some(ref h) = sni_host {
        record_dns_mapping(dst_addr.ip(), h);
    }

    let decision = matcher.evaluate_with_app(
        sni_host.as_deref(),
        dst_addr.ip(),
        dst_addr.port(),
        false,
        app_name.as_deref(),
    );
    let display_target = sni_host
        .clone()
        .unwrap_or_else(|| dst_addr.ip().to_string());

    counters.total_connections.fetch_add(1, Ordering::Relaxed);
    counters.active_connections.fetch_add(1, Ordering::Relaxed);

    let t0 = Instant::now();
    let result = match decision {
        MatchDecision::Block { reason } => {
            let _flow = crate::flows::register_flow(
                "TCP",
                app_name.as_deref(),
                sni_host.as_deref(),
                dst_addr,
                "Block".to_string(),
                false,
                false,
            );
            (log_fn)(
                "warn",
                "block",
                &format!("{app_tag}{display_target}:{} — {reason}", dst_addr.port()),
            );
            Ok(())
        }
        MatchDecision::Direct { matched_list } => {
            let list_tag = matched_list.unwrap_or_else(|| "Прямое".to_string());
            let flow = crate::flows::register_flow(
                "TCP",
                app_name.as_deref(),
                sni_host.as_deref(),
                dst_addr,
                format!("Direct ({list_tag})"),
                false,
                true,
            );
            (log_fn)(
                "info",
                "direct",
                &format!(
                    "{app_tag}{display_target}:{} -> Прямое соединение ({list_tag})",
                    dst_addr.port()
                ),
            );
            let mut remote = connect_outbound_tcp(dst_addr, Duration::from_secs(6)).await?;
            if !first_pkt.is_empty() {
                remote.write_all(&first_pkt).await?;
                let n = first_pkt.len() as u64;
                counters.tx_bytes.fetch_add(n, Ordering::Relaxed);
                flow.record.add_tx(n);
            }
            let _ = crate::flows::copy_bidirectional_live(
                &mut client,
                &mut remote,
                &counters,
                &flow.record,
            )
            .await?;
            Ok(())
        }
        MatchDecision::UpstreamProxy {
            proxy_url,
            matched_list,
        } => {
            let flow = crate::flows::register_flow(
                "TCP",
                app_name.as_deref(),
                sni_host.as_deref(),
                dst_addr,
                format!("Upstream ({matched_list})"),
                true,
                true,
            );
            (log_fn)(
                "info",
                "proxy",
                &format!(
                    "{app_tag}{display_target}:{} -> Внешний прокси {proxy_url} [{matched_list}]",
                    dst_addr.port()
                ),
            );
            let mut remote =
                connect_via_upstream_proxy(&proxy_url, dst_addr, sni_host.as_deref(), &first_pkt)
                    .await?;
            if !first_pkt.is_empty() {
                let n = first_pkt.len() as u64;
                counters.tx_bytes.fetch_add(n, Ordering::Relaxed);
                flow.record.add_tx(n);
            }
            let _ = crate::flows::copy_bidirectional_live(
                &mut client,
                &mut remote,
                &counters,
                &flow.record,
            )
            .await?;
            Ok(())
        }
        MatchDecision::Desync {
            config,
            matched_list,
        } => {
            counters
                .desynced_connections
                .fetch_add(1, Ordering::Relaxed);
            let (mut remote, pre_read_reply, used_recipe, resolved_host) =
                match connect_and_apply_desync_auto(
                    dst_addr,
                    &first_pkt,
                    &config,
                    sni_host.as_deref(),
                )
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        let _flow = crate::flows::register_flow(
                            "TCP",
                            app_name.as_deref(),
                            sni_host.as_deref(),
                            dst_addr,
                            format!("Ошибка ({matched_list})"),
                            true,
                            false,
                        );
                        (log_fn)(
                            "warn",
                            "desync",
                            &format!(
                                "{app_tag}{display_target}:{} ({}) -> [{matched_list}] ошибка: {e} (first_pkt={} Б)",
                                dst_addr.port(),
                                dst_addr.ip(),
                                first_pkt.len()
                            ),
                        );
                        counters.active_connections.fetch_sub(1, Ordering::Relaxed);
                        return Err(e);
                    }
                };

            let strategy_label = if let Some(r_idx) = used_recipe {
                RECIPE_TITLES[(r_idx as usize).min(RECIPE_TITLES.len() - 1)].0
            } else {
                "custom"
            };
            let flow = crate::flows::register_flow(
                "TCP",
                app_name.as_deref(),
                sni_host.as_deref(),
                dst_addr,
                format!("Desync [{strategy_label}]"),
                true,
                true,
            );

            let first_n = first_pkt.len() as u64;
            counters.tx_bytes.fetch_add(first_n, Ordering::Relaxed);
            flow.record.add_tx(first_n);

            let strategy_title = if let Some(r_idx) = used_recipe {
                RECIPE_TITLES[(r_idx as usize).min(RECIPE_TITLES.len() - 1)].1
            } else {
                "Профиль"
            };
            (log_fn)(
                "info",
                "desync",
                &format!(
                    "{app_tag}{display_target}:{} -> [{matched_list}] {strategy_title}",
                    dst_addr.port()
                ),
            );

            let mut total_rx = 0u64;
            if !pre_read_reply.is_empty() {
                client.write_all(&pre_read_reply).await?;
                let nr = pre_read_reply.len() as u64;
                total_rx += nr;
                counters.rx_bytes.fetch_add(nr, Ordering::Relaxed);
                flow.record.add_rx(nr);
            }

            let target_host = resolved_host.as_deref().or(sni_host.as_deref());
            let relay_res = crate::flows::copy_bidirectional_desync_live(
                &mut client,
                &mut remote,
                &counters,
                &flow.record,
                target_host,
                Some(dst_addr),
                total_rx,
                !first_pkt.is_empty(),
                config.auto,
                t0,
            )
            .await;
            let (relayed_up, relayed_down, report_elapsed_ms) = match &relay_res {
                Ok((u, d, act_ms)) => (*u, *d, *act_ms),
                Err(_) => (
                    flow.record
                        .tx_bytes
                        .load(Ordering::Relaxed)
                        .saturating_sub(first_n),
                    flow.record
                        .rx_bytes
                        .load(Ordering::Relaxed)
                        .saturating_sub(total_rx),
                    t0.elapsed().as_millis() as u64,
                ),
            };
            total_rx = total_rx.saturating_add(relayed_down);

            if config.auto {
                report_transfer_outcome(
                    target_host,
                    Some(dst_addr),
                    total_rx,
                    relayed_up,
                    relayed_down,
                    report_elapsed_ms,
                    relay_res.is_ok(),
                );
            }
            relay_res.map(|_| ())
        }
    };

    counters.active_connections.fetch_sub(1, Ordering::Relaxed);
    result
}

static SYSTEM_PROXY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Аварийное синхронное отключение системного прокси ОС (при панике, сигнале завершения или выходе из сессии).
pub fn emergency_disable_system_proxy() {
    if SYSTEM_PROXY_ACTIVE.swap(false, Ordering::Relaxed) {
        let _ = set_os_system_proxy(false, 7897);
    }
}

/// Установить защиту от обрыва браузерной сети при нештатном закрытии (Crash Guard: panic hook + Ctrl/Shutdown handler).
pub fn install_crash_guard() {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        emergency_disable_system_proxy();
        prev_hook(info);
    }));

    #[cfg(target_os = "windows")]
    unsafe {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetConsoleCtrlHandler(
                handler_routine: unsafe extern "system" fn(u32) -> i32,
                add: i32,
            ) -> i32;
        }
        unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
            emergency_disable_system_proxy();
            0
        }
        let _ = SetConsoleCtrlHandler(ctrl_handler, 1);
    }
}

/// Включить или выключить системный прокси ОС (`127.0.0.1:port`).
pub fn set_os_system_proxy(enable: bool, port: u16) -> io::Result<()> {
    SYSTEM_PROXY_ACTIVE.store(enable, Ordering::Relaxed);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        if enable {
            let server = format!("127.0.0.1:{port}");
            let _ = std::process::Command::new("reg")
                .args([
                    "add",
                    reg_path,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            let _ = std::process::Command::new("reg")
                .args([
                    "add",
                    reg_path,
                    "/v",
                    "ProxyServer",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &server,
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            let _ = std::process::Command::new("reg")
                .args([
                    "add",
                    reg_path,
                    "/v",
                    "ProxyOverride",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "127.0.0.1;localhost;[::1];127.*;10.*;192.168.*;*.local;<local>",
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        } else {
            let _ = std::process::Command::new("reg")
                .args([
                    "add",
                    reg_path,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
        notify_wininet_proxy_changed();
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        if enable {
            let port_s = port.to_string();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "manual"])
                .status();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "host", "127.0.0.1"])
                .status();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.http", "port", &port_s])
                .status();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "host", "127.0.0.1"])
                .status();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.https", "port", &port_s])
                .status();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"])
                .status();
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy.socks", "port", &port_s])
                .status();
        } else {
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .status();
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let services = ["Wi-Fi", "Ethernet"];
        for svc in services {
            if enable {
                let port_s = port.to_string();
                let _ = std::process::Command::new("networksetup")
                    .args(["-setwebproxy", svc, "127.0.0.1", &port_s])
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .args(["-setsecurewebproxy", svc, "127.0.0.1", &port_s])
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .args(["-setsocksfirewallproxy", svc, "127.0.0.1", &port_s])
                    .status();
            } else {
                let _ = std::process::Command::new("networksetup")
                    .args(["-setwebproxystate", svc, "off"])
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .args(["-setsecurewebproxystate", svc, "off"])
                    .status();
                let _ = std::process::Command::new("networksetup")
                    .args(["-setsocksfirewallproxystate", svc, "off"])
                    .status();
            }
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (enable, port);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn notify_wininet_proxy_changed() {
    #[link(name = "wininet")]
    unsafe extern "system" {
        fn InternetSetOptionW(
            h_internet: *mut core::ffi::c_void,
            dw_option: u32,
            lp_buffer: *mut core::ffi::c_void,
            dw_buffer_length: u32,
        ) -> i32;
    }
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    unsafe {
        let _ = InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            core::ptr::null_mut(),
            0,
        );
        let _ = InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            core::ptr::null_mut(),
            0,
        );
    }
}
