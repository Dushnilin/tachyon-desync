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
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
#[cfg(any(target_os = "windows", test))]
use std::sync::{Mutex, OnceLock};
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

/// RAII-счётчик активных TCP-соединений: гарантирует декремент при раннем возврате через `?` или панике.
pub(crate) struct ActiveConnGuard<'a>(&'a AtomicU64);

impl Drop for ActiveConnGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl TrafficCounters {
    pub(crate) fn track_active(&self) -> ActiveConnGuard<'_> {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveConnGuard(&self.active_connections)
    }
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

    let app_name = resolve_client_app_name(&client);
    let Some(dst_addr) = resolve_unless_blocked(
        target_host.as_deref(),
        target_ip_opt,
        target_port,
        app_name.as_deref(),
        &matcher,
        &counters,
        &log_fn,
    )
    .await?
    else {
        let _ = client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        let _ = client.flush().await;
        return Ok(());
    };

    // Отправляем успешный ответ SOCKS5 сразу, чтобы клиент прислал ClientHello
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    client.flush().await?;

    relay_with_desync_policy_with_app(
        client,
        dst_addr,
        target_host,
        Vec::new(),
        Some(app_name),
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
    const MAX_HTTP_HEADER_BYTES: usize = 16384;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut req_buf = Vec::with_capacity(2048);
    req_buf.push(first_byte);
    let mut tmp = [0u8; 2048];
    loop {
        let header_end = req_buf.windows(4).position(|w| w == b"\r\n\r\n");
        if header_end.is_some_and(|pos| pos + 4 > MAX_HTTP_HEADER_BYTES)
            || (header_end.is_none() && req_buf.len() >= MAX_HTTP_HEADER_BYTES)
        {
            let _ = client
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = client.flush().await;
            return Ok(());
        }
        if header_end.is_some() {
            break;
        }
        let n = tokio::time::timeout_at(deadline, client.read(&mut tmp))
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
        let app_name = resolve_client_app_name(&client);
        let Some(dst_addr) = resolve_unless_blocked(
            host_opt.as_deref(),
            parsed_ip,
            port,
            app_name.as_deref(),
            &matcher,
            &counters,
            &log_fn,
        )
        .await?
        else {
            let _ = client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = client.flush().await;
            return Ok(());
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        relay_with_desync_policy_with_app(
            client,
            dst_addr,
            host_opt,
            Vec::new(),
            Some(app_name),
            matcher,
            counters,
            log_fn,
        )
        .await
    } else {
        // Обычный HTTP-запрос через прокси: берём хост и порт из абсолютного URI либо из заголовка Host
        let (mut host_str, mut port) = if uri
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
            || uri
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
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
        let app_name = resolve_client_app_name(&client);
        let Some(dst_addr) = resolve_unless_blocked(
            host_opt.as_deref(),
            parsed_ip,
            port,
            app_name.as_deref(),
            &matcher,
            &counters,
            &log_fn,
        )
        .await?
        else {
            let _ = client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = client.flush().await;
            return Ok(());
        };

        let normalized_req = normalize_proxied_http_request(&req_buf);
        relay_with_desync_policy_with_app(
            client,
            dst_addr,
            host_opt,
            normalized_req,
            Some(app_name),
            matcher,
            counters,
            log_fn,
        )
        .await
    }
}

/// Нормализовать не-CONNECT HTTP-запрос прокси: переписать absolute-form URI в origin-form,
/// убрать `Proxy-Connection` и принудительно выставить `Connection: close`.
pub(crate) fn normalize_proxied_http_request(raw: &[u8]) -> Vec<u8> {
    let (head, body) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => (&raw[..pos], &raw[pos + 4..]),
        None => (raw, &[][..]),
    };
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.split("\r\n");
    let mut out = Vec::with_capacity(raw.len() + 32);

    if let Some(first_line) = lines.next() {
        let mut parts = first_line.split_whitespace();
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(method), Some(uri), Some(version), None) => {
                let normalized_uri = rewrite_absolute_http_uri(uri);
                out.extend_from_slice(method.as_bytes());
                out.push(b' ');
                out.extend_from_slice(normalized_uri.as_bytes());
                out.push(b' ');
                out.extend_from_slice(version.as_bytes());
            }
            _ => {
                out.extend_from_slice(first_line.as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");
    }

    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let trimmed = name.trim();
            if trimmed.eq_ignore_ascii_case("proxy-connection")
                || trimmed.eq_ignore_ascii_case("connection")
            {
                continue;
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

fn rewrite_absolute_http_uri(uri: &str) -> std::borrow::Cow<'_, str> {
    let rest = if uri
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
    {
        &uri[7..]
    } else if uri
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        &uri[8..]
    } else {
        return std::borrow::Cow::Borrowed(uri);
    };

    if let Some(slash_pos) = rest.find('/') {
        std::borrow::Cow::Borrowed(&rest[slash_pos..])
    } else if let Some(q_pos) = rest.find('?') {
        std::borrow::Cow::Owned(format!("/{}", &rest[q_pos..]))
    } else {
        std::borrow::Cow::Borrowed("/")
    }
}

/// Нерезервируемый публичный адрес (TEST-NET-1) для предварительной проверки правил до DNS-резолва.
const UNRESOLVED_PROBE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn resolve_client_app_name(client: &TcpStream) -> Option<String> {
    client
        .peer_addr()
        .map(|a| a.port())
        .ok()
        .and_then(|p| crate::apps::resolve_socket_process_name(p, false))
}

fn record_blocked_proxy_flow(
    app_name: Option<&str>,
    host: Option<&str>,
    dst_addr: SocketAddr,
    reason: &str,
    counters: &TrafficCounters,
    log_fn: &LogCallback,
) {
    counters.total_connections.fetch_add(1, Ordering::Relaxed);
    let origin_prefix = format_tcp_origin_prefix("", app_name);
    let display_target = host
        .map(str::to_string)
        .unwrap_or_else(|| dst_addr.ip().to_string());
    let _flow = crate::flows::register_flow(
        "TCP",
        app_name,
        host,
        dst_addr,
        "Block".to_string(),
        false,
        false,
    );
    (log_fn)(
        "warn",
        "block",
        &format!(
            "{origin_prefix}{display_target}:{} — {reason}",
            dst_addr.port()
        ),
    );
}

async fn resolve_unless_blocked(
    target_host: Option<&str>,
    target_ip_opt: Option<IpAddr>,
    target_port: u16,
    app_name: Option<&str>,
    matcher: &CompiledMatcher,
    counters: &TrafficCounters,
    log_fn: &LogCallback,
) -> io::Result<Option<SocketAddr>> {
    let probe_ip = target_ip_opt.unwrap_or(UNRESOLVED_PROBE_IP);
    if let MatchDecision::Block { reason } =
        matcher.evaluate_with_app(target_host, probe_ip, target_port, false, app_name)
    {
        let block_addr = SocketAddr::new(
            target_ip_opt.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            target_port,
        );
        record_blocked_proxy_flow(app_name, target_host, block_addr, &reason, counters, log_fn);
        return Ok(None);
    }

    let dst_addr = resolve_target_addr(target_host, target_ip_opt, target_port).await?;
    if target_ip_opt.is_none()
        && let MatchDecision::Block { reason } =
            matcher.evaluate_with_app(target_host, dst_addr.ip(), dst_addr.port(), false, app_name)
    {
        record_blocked_proxy_flow(app_name, target_host, dst_addr, &reason, counters, log_fn);
        return Ok(None);
    }

    Ok(Some(dst_addr))
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

#[inline]
fn format_tcp_origin_prefix(source_prefix: &str, app_name: Option<&str>) -> String {
    match (source_prefix.is_empty(), app_name) {
        (true, Some(a)) => format!("[{a}] "),
        (true, None) => String::new(),
        (false, Some(a)) => format!("{source_prefix} [{a}] "),
        (false, None) => format!("{source_prefix} "),
    }
}

/// Общий исполнитель решения маршрутизации/десинхронизации TCP-потока для SOCKS5/HTTP прокси и TUN.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_tcp_decision<S>(
    mut client: S,
    dst_addr: SocketAddr,
    first_pkt: Vec<u8>,
    sni_host: Option<String>,
    app_name: Option<String>,
    decision: MatchDecision,
    source_prefix: &str,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let origin_prefix = format_tcp_origin_prefix(source_prefix, app_name.as_deref());
    let display_target = sni_host
        .clone()
        .unwrap_or_else(|| dst_addr.ip().to_string());

    counters.total_connections.fetch_add(1, Ordering::Relaxed);
    let _active_guard = counters.track_active();

    let t0 = Instant::now();
    match decision {
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
                &format!(
                    "{origin_prefix}{display_target}:{} — {reason}",
                    dst_addr.port()
                ),
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
                    "{origin_prefix}{display_target}:{} -> Прямое соединение ({list_tag})",
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
                    "{origin_prefix}{display_target}:{} -> Внешний прокси {proxy_url} [{matched_list}]",
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
                                "{origin_prefix}{display_target}:{} ({}) -> [{matched_list}] ошибка: {e} (first_pkt={} Б)",
                                dst_addr.port(),
                                dst_addr.ip(),
                                first_pkt.len()
                            ),
                        );
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
                    "{origin_prefix}{display_target}:{} -> [{matched_list}] {strategy_title}",
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
    }
}

/// Универсальный конвейер TCP-соединения: читает первый пакет (`ClientHello` / HTTP),
/// вычисляет правило по списку и приложению, применяет десинхронизацию и передаёт трафик в обе стороны.
pub async fn relay_with_desync_policy(
    client: TcpStream,
    dst_addr: SocketAddr,
    known_host: Option<String>,
    initial_payload: Vec<u8>,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    relay_with_desync_policy_with_app(
        client,
        dst_addr,
        known_host,
        initial_payload,
        None,
        matcher,
        counters,
        log_fn,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn relay_with_desync_policy_with_app(
    mut client: TcpStream,
    dst_addr: SocketAddr,
    known_host: Option<String>,
    initial_payload: Vec<u8>,
    app_name_override: Option<Option<String>>,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    let app_name = app_name_override.unwrap_or_else(|| resolve_client_app_name(&client));

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
    execute_tcp_decision(
        client, dst_addr, first_pkt, sni_host, app_name, decision, "", counters, log_fn,
    )
    .await
}

static SYSTEM_PROXY_ACTIVE: AtomicBool = AtomicBool::new(false);
static ACTIVE_SYSTEM_PROXY_PORT: AtomicU16 = AtomicU16::new(7897);

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SavedWinProxyState {
    proxy_enable: bool,
    proxy_server: Option<String>,
    proxy_override: Option<String>,
}

#[cfg(target_os = "windows")]
static SAVED_WIN_PROXY_STATE: OnceLock<Mutex<Option<SavedWinProxyState>>> = OnceLock::new();

#[cfg(target_os = "windows")]
fn saved_win_proxy_slot() -> &'static Mutex<Option<SavedWinProxyState>> {
    SAVED_WIN_PROXY_STATE.get_or_init(|| Mutex::new(None))
}

#[cfg(any(target_os = "windows", test))]
fn parse_reg_query_value(stdout: &str, value_name: &str) -> Option<String> {
    for raw_line in stdout.lines() {
        let line = raw_line.trim_start();
        if line.len() <= value_name.len() {
            continue;
        }
        let (head, rest) = line.split_at(value_name.len());
        if !head.eq_ignore_ascii_case(value_name) || !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let after_name = rest.trim_start();
        let Some((reg_type, after_type)) = after_name.split_once(char::is_whitespace) else {
            continue;
        };
        if !reg_type.starts_with("REG_") {
            continue;
        }
        let value = after_type.trim_start().trim_end_matches(&['\r', '\n'][..]);
        return Some(value.to_string());
    }
    None
}

#[cfg(any(target_os = "windows", test))]
fn parse_reg_dword_bool(raw: &str) -> bool {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).unwrap_or(0) != 0
    } else {
        trimmed.parse::<u32>().unwrap_or(0) != 0
    }
}

#[cfg(target_os = "windows")]
fn query_win_reg_value(reg_path: &str, value_name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("reg")
        .args(["query", reg_path, "/v", value_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_reg_query_value(&stdout, value_name)
}

#[cfg(target_os = "windows")]
fn set_win_reg_sz_or_delete(reg_path: &str, value_name: &str, value: Option<&str>) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    match value {
        Some(v) => {
            let _ = std::process::Command::new("reg")
                .args([
                    "add", reg_path, "/v", value_name, "/t", "REG_SZ", "/d", v, "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
        None => {
            let _ = std::process::Command::new("reg")
                .args(["delete", reg_path, "/v", value_name, "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }
}

/// Аварийное синхронное отключение системного прокси ОС (при панике, сигнале завершения или выходе из сессии).
pub fn emergency_disable_system_proxy() {
    if SYSTEM_PROXY_ACTIVE.swap(false, Ordering::SeqCst) {
        let port = ACTIVE_SYSTEM_PROXY_PORT.load(Ordering::Relaxed);
        let _ = set_os_system_proxy(false, port);
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
        unsafe extern "system" fn ctrl_handler(
            _ctrl_type: u32,
        ) -> windows_sys::Win32::Foundation::BOOL {
            emergency_disable_system_proxy();
            0
        }
        let _ = windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

/// Включить или выключить системный прокси ОС (`127.0.0.1:port`).
pub fn set_os_system_proxy(enable: bool, port: u16) -> io::Result<()> {
    let was_active = SYSTEM_PROXY_ACTIVE.swap(enable, Ordering::SeqCst);
    if enable {
        ACTIVE_SYSTEM_PROXY_PORT.store(port, Ordering::Relaxed);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        if enable {
            if !was_active
                && let Ok(mut guard) = saved_win_proxy_slot().lock()
                && guard.is_none()
            {
                let proxy_enable = query_win_reg_value(reg_path, "ProxyEnable")
                    .is_some_and(|v| parse_reg_dword_bool(&v));
                let proxy_server = query_win_reg_value(reg_path, "ProxyServer");
                let proxy_override = query_win_reg_value(reg_path, "ProxyOverride");
                *guard = Some(SavedWinProxyState {
                    proxy_enable,
                    proxy_server,
                    proxy_override,
                });
            }

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
            let saved = saved_win_proxy_slot()
                .lock()
                .ok()
                .and_then(|mut guard| guard.take());
            match saved {
                Some(prev) => {
                    let enable_val = if prev.proxy_enable { "1" } else { "0" };
                    let _ = std::process::Command::new("reg")
                        .args([
                            "add",
                            reg_path,
                            "/v",
                            "ProxyEnable",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            enable_val,
                            "/f",
                        ])
                        .creation_flags(CREATE_NO_WINDOW)
                        .status();
                    set_win_reg_sz_or_delete(reg_path, "ProxyServer", prev.proxy_server.as_deref());
                    set_win_reg_sz_or_delete(
                        reg_path,
                        "ProxyOverride",
                        prev.proxy_override.as_deref(),
                    );
                }
                None => {
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
            }
        }
        notify_wininet_proxy_changed();
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let _ = was_active;
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

            let http_url = format!("http://127.0.0.1:{port_s}");
            let socks_url = format!("socks://127.0.0.1:{port_s}");
            for kwrite in ["kwriteconfig6", "kwriteconfig5"] {
                if let Ok(st) = std::process::Command::new(kwrite)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        "1",
                    ])
                    .status()
                    && st.success()
                {
                    let _ = std::process::Command::new(kwrite)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "httpProxy",
                            &http_url,
                        ])
                        .status();
                    let _ = std::process::Command::new(kwrite)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "httpsProxy",
                            &http_url,
                        ])
                        .status();
                    let _ = std::process::Command::new(kwrite)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "socksProxy",
                            &socks_url,
                        ])
                        .status();
                    break;
                }
            }
        } else {
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .status();
            for kwrite in ["kwriteconfig6", "kwriteconfig5"] {
                if let Ok(st) = std::process::Command::new(kwrite)
                    .args([
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        "0",
                    ])
                    .status()
                    && st.success()
                {
                    break;
                }
            }
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
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    };
    unsafe {
        let _ = InternetSetOptionW(
            core::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            core::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(
            core::ptr::null(),
            INTERNET_OPTION_REFRESH,
            core::ptr::null(),
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_conn_guard_decrements_on_early_drop_and_unwind() {
        let counters = TrafficCounters::default();
        assert_eq!(counters.active_connections.load(Ordering::Relaxed), 0);
        {
            let _g1 = counters.track_active();
            let _g2 = counters.track_active();
            assert_eq!(counters.active_connections.load(Ordering::Relaxed), 2);
        }
        assert_eq!(counters.active_connections.load(Ordering::Relaxed), 0);

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = counters.track_active();
            assert_eq!(counters.active_connections.load(Ordering::Relaxed), 1);
            panic!("simulated early failure");
        }));
        assert!(res.is_err());
        assert_eq!(counters.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn parse_host_port_preserves_discord_alt_cloudflare_ports() {
        for port in [443u16, 2053, 2083, 2087, 2096, 8443] {
            let input = format!("cdn.discord.media:{port}");
            let (host, parsed_port) = parse_host_port(&input, 443);
            assert_eq!(host, "cdn.discord.media");
            assert_eq!(parsed_port, port);
        }
    }

    #[test]
    fn normalize_proxied_http_request_rewrites_absolute_uri_and_connection_headers() {
        let raw = b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\n\
Host: example.com:8080\r\n\
Proxy-Connection: keep-alive\r\n\
Connection: keep-alive\r\n\
User-Agent: tachyon-test\r\n\r\n";
        let normalized = normalize_proxied_http_request(raw);
        assert_eq!(
            String::from_utf8_lossy(&normalized),
            "GET /path?q=1 HTTP/1.1\r\n\
Host: example.com:8080\r\n\
User-Agent: tachyon-test\r\n\
Connection: close\r\n\r\n"
        );

        let root_raw = b"HEAD http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            String::from_utf8_lossy(&normalize_proxied_http_request(root_raw)),
            "HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );

        let query_raw = b"GET http://example.com?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            String::from_utf8_lossy(&normalize_proxied_http_request(query_raw)),
            "GET /?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );

        let origin_raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n\x00\x01\x02\xff";
        assert_eq!(
            normalize_proxied_http_request(origin_raw),
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x00\x01\x02\xff"
        );
    }

    #[test]
    fn parse_reg_query_value_extracts_wininet_values() {
        let out_enable = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n\r\n";
        let raw_enable = parse_reg_query_value(out_enable, "ProxyEnable").unwrap();
        assert_eq!(raw_enable, "0x1");
        assert!(parse_reg_dword_bool(&raw_enable));
        assert!(!parse_reg_dword_bool("0x0"));

        let out_server = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n    ProxyServer    REG_SZ    127.0.0.1:8888\r\n";
        assert_eq!(
            parse_reg_query_value(out_server, "ProxyServer").as_deref(),
            Some("127.0.0.1:8888")
        );
        assert_eq!(parse_reg_query_value(out_server, "ProxyOverride"), None);
    }
}
