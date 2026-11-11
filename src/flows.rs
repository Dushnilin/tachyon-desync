//! Живой монитор сетевых соединений (Live Flows Inspector).
//!
//! Отслеживает активные и недавние TCP/UDP потоки с привязкой к процессу (`.exe`),
//! целевому домену (SNI / DNS), IP:порту, применённому правилу и счётчикам байтов RX/TX
//! в реальном времени для отображения в нативном GPU-интерфейсе.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TRACKED_FLOWS: usize = 140;

static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);

pub struct LiveFlowRecord {
    pub id: u64,
    pub started_ms: u64,
    pub proto: &'static str,
    pub app_name: String,
    pub host: String,
    pub dst_addr: String,
    pub action: String,
    pub desynced: bool,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub active: AtomicBool,
}

impl LiveFlowRecord {
    #[inline]
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }
}

/// RAII-обёртка, автоматически помечающая поток завершённым при закрытии сокета.
pub struct FlowGuard {
    pub record: Arc<LiveFlowRecord>,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.record.active.store(false, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFlowSnapshot {
    pub id: u64,
    pub started_ms: u64,
    pub proto: String,
    pub app_name: String,
    pub host: String,
    pub dst_addr: String,
    pub action: String,
    pub desynced: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub active: bool,
}

fn flow_ring() -> &'static Mutex<VecDeque<Arc<LiveFlowRecord>>> {
    static RING: OnceLock<Mutex<VecDeque<Arc<LiveFlowRecord>>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_TRACKED_FLOWS)))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Зарегистрировать новый живой поток (TCP или UDP) и вернуть `FlowGuard`.
pub fn register_flow(
    proto: &'static str,
    app_name: Option<&str>,
    host: Option<&str>,
    dst_addr: SocketAddr,
    action: String,
    desynced: bool,
    active: bool,
) -> FlowGuard {
    let id = NEXT_FLOW_ID.fetch_add(1, Ordering::Relaxed);
    let app_str = app_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("-")
        .to_string();
    let host_str = host
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| dst_addr.ip().to_string());

    let record = Arc::new(LiveFlowRecord {
        id,
        started_ms: now_unix_ms(),
        proto,
        app_name: app_str,
        host: host_str,
        dst_addr: dst_addr.to_string(),
        action,
        desynced,
        tx_bytes: AtomicU64::new(0),
        rx_bytes: AtomicU64::new(0),
        active: AtomicBool::new(active),
    });

    if let Ok(mut guard) = flow_ring().lock() {
        if guard.len() >= MAX_TRACKED_FLOWS {
            // Сначала пытаемся удалить старую неактивную запись
            if let Some(pos) = guard.iter().position(|r| !r.active.load(Ordering::Relaxed)) {
                guard.remove(pos);
            } else {
                guard.pop_front();
            }
        }
        guard.push_back(record.clone());
    }

    FlowGuard { record }
}

/// Получить снимок всех отслеживаемых потоков (новые и активные — сверху).
pub fn snapshot_flows() -> Vec<LiveFlowSnapshot> {
    let Ok(guard) = flow_ring().lock() else {
        return Vec::new();
    };
    let mut out: Vec<LiveFlowSnapshot> = guard
        .iter()
        .rev()
        .map(|r| LiveFlowSnapshot {
            id: r.id,
            started_ms: r.started_ms,
            proto: r.proto.to_string(),
            app_name: r.app_name.clone(),
            host: r.host.clone(),
            dst_addr: r.dst_addr.clone(),
            action: r.action.clone(),
            desynced: r.desynced,
            tx_bytes: r.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: r.rx_bytes.load(Ordering::Relaxed),
            active: r.active.load(Ordering::Relaxed),
        })
        .collect();

    // Активные потоки поднимаем выше завершённых при сохранении порядка по ID
    out.sort_by(|a, b| b.active.cmp(&a.active).then_with(|| b.id.cmp(&a.id)));
    out
}

/// Очистить список потоков (оставляя только текущие активные соединения).
pub fn clear_finished_flows() {
    if let Ok(mut guard) = flow_ring().lock() {
        guard.retain(|r| r.active.load(Ordering::Relaxed));
    }
}

/// Двусторонняя передача данных с обновлением глобальных и потоковых счётчиков RX/TX в реальном времени.
pub async fn copy_bidirectional_live<A, B>(
    a: &mut A,
    b: &mut B,
    counters: &crate::proxy::TrafficCounters,
    flow: &LiveFlowRecord,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let a_to_b = async {
        let mut buf = [0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                let _ = bw.shutdown().await;
                break;
            }
            bw.write_all(&buf[..n]).await?;
            let nb = n as u64;
            total += nb;
            counters.tx_bytes.fetch_add(nb, Ordering::Relaxed);
            flow.add_tx(nb);
        }
        Ok::<u64, std::io::Error>(total)
    };

    let b_to_a = async {
        let mut buf = [0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = br.read(&mut buf).await?;
            if n == 0 {
                let _ = aw.shutdown().await;
                break;
            }
            aw.write_all(&buf[..n]).await?;
            let nb = n as u64;
            total += nb;
            counters.rx_bytes.fetch_add(nb, Ordering::Relaxed);
            flow.add_rx(nb);
        }
        Ok::<u64, std::io::Error>(total)
    };

    tokio::try_join!(a_to_b, b_to_a)
}

/// Двусторонняя передача данных для десинхронизированного потока на базе единого
/// апстримного сторожа `DesyncWatchdog` из `tachyon-core` (продвижение рецепта на лету при
/// 256 КиБ, контроль зависаний до `ServerHello` / в окне 32 КиБ / mid-stream и исключение
/// пауз HTTP/2 keep-alive и простаивающих WebSocket из расчёта скорости передачи).
/// Возвращает `(передано_клиентом, принято_от_сервера, активное_время_мс)`.
#[allow(clippy::too_many_arguments)]
pub async fn copy_bidirectional_desync_live<A, B>(
    a: &mut A,
    b: &mut B,
    counters: &crate::proxy::TrafficCounters,
    flow: &LiveFlowRecord,
    target_host: Option<&str>,
    peer_addr: Option<SocketAddr>,
    initial_down_len: u64,
    had_initial_up: bool,
    report_adaptive: bool,
    started_at: std::time::Instant,
) -> std::io::Result<(u64, u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up_bytes = AtomicU64::new(0);
    let down_bytes = AtomicU64::new(0);
    let post_req_down = AtomicU64::new(0);

    let a_to_b = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                let _ = bw.shutdown().await;
                break;
            }
            bw.write_all(&buf[..n]).await?;
            let nb = n as u64;
            up_bytes.fetch_add(nb, Ordering::Relaxed);
            counters.tx_bytes.fetch_add(nb, Ordering::Relaxed);
            flow.add_tx(nb);
        }
        Ok::<(), std::io::Error>(())
    };

    let b_to_a = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = br.read(&mut buf).await?;
            if n == 0 {
                let _ = aw.shutdown().await;
                break;
            }
            aw.write_all(&buf[..n]).await?;
            let nb = n as u64;
            down_bytes.fetch_add(nb, Ordering::Relaxed);
            if up_bytes.load(Ordering::Relaxed) > 0 {
                post_req_down.fetch_add(nb, Ordering::Relaxed);
            }
            counters.rx_bytes.fetch_add(nb, Ordering::Relaxed);
            flow.add_rx(nb);
        }
        Ok::<(), std::io::Error>(())
    };

    let mut watchdog = tokio::time::interval(Duration::from_millis(500));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    watchdog.tick().await;

    let mut guard =
        crate::desync::DesyncWatchdog::new_at(started_at, initial_down_len, had_initial_up);
    let target_key = if report_adaptive {
        target_host.unwrap_or("")
    } else {
        ""
    };
    let mut up_at_last_down = 0u64;
    let mut prev_down_seen = initial_down_len;

    let mut a_to_b = std::pin::pin!(a_to_b);
    let mut b_to_a = std::pin::pin!(b_to_a);

    let res: std::io::Result<()> = loop {
        tokio::select! {
            res = &mut a_to_b => {
                if let Err(e) = res {
                    break Err(e);
                }
                let cur_down = initial_down_len.saturating_add(down_bytes.load(Ordering::Relaxed));
                let drain_timeout = crate::desync::DesyncWatchdog::client_eof_drain_timeout(
                    cur_down,
                    HALF_CLOSE_TIMEOUT,
                );
                break match tokio::time::timeout(drain_timeout, b_to_a).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(err)) => Err(err),
                    Err(_) => {
                        let fin_relayed_up = up_bytes.load(Ordering::Relaxed);
                        let fin_relayed_down = down_bytes.load(Ordering::Relaxed);
                        let fin_post_req = post_req_down.load(Ordering::Relaxed);
                        let fin_down = initial_down_len.saturating_add(fin_relayed_down);
                        let stalled_unanswered = fin_down == 0
                            || (fin_post_req < 96 && (had_initial_up || fin_relayed_up > 0))
                            || fin_relayed_up.saturating_sub(up_at_last_down) >= 38;
                        if fin_down < crate::desync::DESYNC_LIVE_PROMOTE_BYTES && stalled_unanswered {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "desync: upstream stalled after client close",
                            ))
                        } else {
                            Ok(())
                        }
                    }
                };
            }
            res = &mut b_to_a => {
                if let Err(e) = res {
                    break Err(e);
                }
                if let Ok(Err(err)) = tokio::time::timeout(HALF_CLOSE_TIMEOUT, a_to_b).await {
                    break Err(err);
                }
                break Ok(());
            }
            _ = watchdog.tick() => {
                let relayed_up = up_bytes.load(Ordering::Relaxed);
                let relayed_down = down_bytes.load(Ordering::Relaxed);
                let cur_post = post_req_down.load(Ordering::Relaxed);
                let cur_down = initial_down_len.saturating_add(relayed_down);
                if cur_down > prev_down_seen {
                    prev_down_seen = cur_down;
                    up_at_last_down = relayed_up;
                }
                if let Err(err) = guard.on_tick_with_reply(
                    target_key,
                    peer_addr,
                    relayed_up,
                    relayed_down,
                    cur_post,
                ) {
                    break Err(err);
                }
            }
        }
    };

    let active_ms = (guard.active_elapsed(started_at.elapsed()).as_millis() as u64).max(1);
    res.map(|()| {
        (
            up_bytes.load(Ordering::Relaxed),
            down_bytes.load(Ordering::Relaxed),
            active_ms,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn idle_websocket_under_32k_stays_alive_past_cap_watchdog() {
        let (mut client_app, mut proxy_client) = tokio::io::duplex(32768);
        let (mut proxy_remote, mut server_app) = tokio::io::duplex(32768);

        let srv = tokio::spawn(async move {
            let mut up = [0u8; 2048];
            let n = server_app.read(&mut up).await.unwrap();
            assert_eq!(n, 900);
            // Сервер отвечает 22 КиБ (101 Switching Protocols + Discord Gateway READY в окне 14..32 КиБ)
            server_app.write_all(&vec![0x42u8; 22_528]).await.unwrap();
            // Затем WebSocket штатно простаивает > 3.1 с без новых сообщений (превышая старый порог 2.5 с!)
            tokio::time::sleep(Duration::from_millis(3100)).await;
            let _ = server_app.shutdown().await;
        });

        let cli = tokio::spawn(async move {
            client_app.write_all(&vec![0x11u8; 900]).await.unwrap();
            let mut down = Vec::new();
            client_app.read_to_end(&mut down).await.unwrap();
            assert_eq!(down.len(), 22_528);
            let _ = client_app.shutdown().await;
        });

        let counters = crate::proxy::TrafficCounters::default();
        let fg = register_flow(
            "TCP",
            Some("Discord.exe"),
            Some("gateway.discord.gg"),
            "162.159.135.234:443".parse().unwrap(),
            "Desync".to_string(),
            true,
            true,
        );
        let res = copy_bidirectional_desync_live(
            &mut proxy_client,
            &mut proxy_remote,
            &counters,
            &fg.record,
            Some("gateway.discord.gg"),
            None,
            2400,
            true,
            false,
            Instant::now(),
        )
        .await;

        assert!(
            res.is_ok(),
            "idle Discord WebSocket after server reply must not be killed by cap watchdog: {res:?}"
        );
        let (u, d, act_ms) = res.unwrap();
        assert_eq!((u, d), (900, 22_528));
        assert!(
            act_ms < 800,
            "trailing idle ticks must be excluded from active_ms, got {act_ms}ms"
        );
        let _ = tokio::join!(srv, cli);
    }

    #[tokio::test]
    async fn unanswered_post_server_hello_freeze_aborts_in_cap_window() {
        let (mut client_app, mut proxy_client) = tokio::io::duplex(32768);
        let (mut proxy_remote, _server_blackhole) = tokio::io::duplex(32768);

        let cli = tokio::spawn(async move {
            client_app.write_all(&vec![0x22u8; 640]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let counters = crate::proxy::TrafficCounters::default();
        let fg = register_flow(
            "TCP",
            None,
            Some("frozen.example.org"),
            "198.51.100.10:443".parse().unwrap(),
            "Desync".to_string(),
            true,
            true,
        );
        let t0 = Instant::now();
        let res = copy_bidirectional_desync_live(
            &mut proxy_client,
            &mut proxy_remote,
            &counters,
            &fg.record,
            Some("frozen.example.org"),
            None,
            3200,
            true,
            false,
            t0,
        )
        .await;

        assert!(
            res.is_err(),
            "post-ServerHello 0-byte freeze must be aborted by cap watchdog"
        );
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(t0.elapsed() < Duration::from_secs(4));
        cli.abort();
    }
}
