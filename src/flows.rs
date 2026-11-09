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

/// Двусторонняя передача данных для десинхронизированного потока с продвижением рецепта на лету
/// при прохождении порога 32 КиБ и 500-мс сторожем зависаний (в окне 32 КиБ и при mid-stream запросах без ответа).
#[allow(clippy::too_many_arguments)]
pub async fn copy_bidirectional_desync_live<A, B>(
    a: &mut A,
    b: &mut B,
    counters: &crate::proxy::TrafficCounters,
    flow: &LiveFlowRecord,
    target_host: Option<&str>,
    peer_addr: Option<SocketAddr>,
    initial_down_len: u64,
    started_at: std::time::Instant,
) -> std::io::Result<(u64, u64)>
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
            counters.rx_bytes.fetch_add(nb, Ordering::Relaxed);
            flow.add_rx(nb);
        }
        Ok::<(), std::io::Error>(())
    };

    let mut watchdog = tokio::time::interval(Duration::from_millis(500));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    watchdog.tick().await;

    let mut prev_down = initial_down_len;
    let mut up_at_last_down = 0u64;
    let mut cap_stall_ticks = 0u8;
    let mut mid_stall_ticks = 0u8;
    let mut live_promoted = initial_down_len >= crate::desync::MIN_VERIFIED_TRANSFER_BYTES;

    let mut a_to_b = std::pin::pin!(a_to_b);
    let mut b_to_a = std::pin::pin!(b_to_a);

    let res: std::io::Result<()> = loop {
        tokio::select! {
            res = &mut a_to_b => {
                if let Err(e) = res {
                    break Err(e);
                }
                let cur_down = initial_down_len.saturating_add(down_bytes.load(Ordering::Relaxed));
                let drain_timeout = if cur_down < crate::desync::MIN_VERIFIED_TRANSFER_BYTES {
                    Duration::from_millis(1200)
                } else {
                    HALF_CLOSE_TIMEOUT
                };
                break match tokio::time::timeout(drain_timeout, b_to_a).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(err)) => Err(err),
                    Err(_) if initial_down_len.saturating_add(down_bytes.load(Ordering::Relaxed)) < crate::desync::MIN_VERIFIED_TRANSFER_BYTES => {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "desync: upstream stalled after client close",
                        ))
                    }
                    Err(_) => Ok(()),
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
                let cur_up = up_bytes.load(Ordering::Relaxed);
                let cur_down = initial_down_len.saturating_add(down_bytes.load(Ordering::Relaxed));
                if !live_promoted
                    && target_host.is_some_and(|h| !h.is_empty())
                    && cur_down >= crate::desync::MIN_VERIFIED_TRANSFER_BYTES
                {
                    live_promoted = true;
                    crate::desync::report_transfer_outcome(
                        target_host,
                        peer_addr,
                        cur_down,
                        started_at.elapsed().as_millis() as u64,
                        true,
                    );
                }
                if cur_down > prev_down {
                    prev_down = cur_down;
                    up_at_last_down = cur_up;
                    cap_stall_ticks = 0;
                    mid_stall_ticks = 0;
                } else if cur_down < crate::desync::MIN_VERIFIED_TRANSFER_BYTES {
                    if cur_up > 0 {
                        cap_stall_ticks = cap_stall_ticks.saturating_add(1);
                        if cap_stall_ticks >= 5 {
                            break Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "desync: upstream stalled in cap window",
                            ));
                        }
                    }
                } else if cur_up.saturating_sub(up_at_last_down) >= 64 {
                    mid_stall_ticks = mid_stall_ticks.saturating_add(1);
                    if mid_stall_ticks >= 9 {
                        break Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "desync: mid-stream request stalled",
                        ));
                    }
                }
            }
        }
    };

    res.map(|()| {
        (
            up_bytes.load(Ordering::Relaxed),
            down_bytes.load(Ordering::Relaxed),
        )
    })
}
