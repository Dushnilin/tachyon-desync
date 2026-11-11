//! Системный захват трафика уровня L3 через виртуальный сетевой адаптер TUN
//! (`Wintun` через прямые кольцевые буферы `wintun.sys` на Windows, `/dev/net/tun` на Linux),
//! виртуальный стек `smoltcp` для TCP и обработка UDP/DNS с извлечением `IP -> Домен`.

#[cfg(windows)]
use crate::desync::WIN_OUTBOUND_IF_INDEX;
use crate::desync::{
    RECIPE_TITLES, bind_outbound_socket, connect_and_apply_desync_auto, connect_outbound_tcp,
    connect_via_upstream_proxy, extract_hostname, report_transfer_outcome, report_udp_quic_outcome,
    send_udp_fakes_same_tuple,
};
use crate::lists::{CompiledMatcher, MatchDecision, record_dns_mapping};
use crate::proxy::{LogCallback, TrafficCounters};
use bytes::Bytes;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{
    Device, DeviceCapabilities, Medium, RxToken as PhyRxToken, TxToken as PhyTxToken,
};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::HardwareAddress;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock, mpsc};

const TUN_QUEUE_CAP: usize = 512;
const MAX_TCP_SESSIONS: usize = 512;
const MAX_UDP_SESSIONS: usize = 256;

/// Преобразовать префикс маски `/prefix` в `Ipv4Addr`.
pub fn prefix_to_ipv4_netmask(prefix: u8) -> Ipv4Addr {
    let p = prefix.min(32);
    if p == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else {
        Ipv4Addr::from(u32::MAX << (32 - p))
    }
}

/// Виртуальное устройство `smoltcp`, обменивающееся IP-пакетами с платформенным TUN.
struct VirtualTunDevice {
    mtu: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualTunDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx_queue: VecDeque::with_capacity(128),
            tx_queue: VecDeque::with_capacity(128),
        }
    }
}

struct VirtualRxToken {
    packet: Vec<u8>,
}

impl PhyRxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl PhyTxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if self.queue.len() < TUN_QUEUE_CAP {
            self.queue.push_back(buffer);
        }
        result
    }
}

impl Device for VirtualTunDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { packet },
            VirtualTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() >= TUN_QUEUE_CAP {
            return None;
        }
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Адаптер `AsyncRead + AsyncWrite` поверх виртуального TCP-сокета `smoltcp`.
pub struct TunStream {
    rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<Bytes>,
    notify: Arc<Notify>,
    peer_closed: Arc<AtomicBool>,
    current: Option<(Bytes, usize)>,
}

impl AsyncRead for TunStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut copied_any = false;
        loop {
            if let Some((chunk, offset)) = &mut self.current {
                let avail = chunk.len() - *offset;
                if avail > 0 {
                    let take = avail.min(buf.remaining());
                    buf.put_slice(&chunk[*offset..*offset + take]);
                    *offset += take;
                    copied_any = true;
                    if *offset >= chunk.len() {
                        self.current = None;
                    }
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                } else {
                    self.current = None;
                }
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.notify.notify_one();
                    self.current = Some((chunk, 0));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => {
                    return if copied_any {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

impl AsyncWrite for TunStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.tx.is_closed() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(32_768);
        match self.tx.try_send(Bytes::copy_from_slice(&buf[..take])) {
            Ok(()) => {
                self.notify.notify_one();
                Poll::Ready(Ok(take))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.notify.notify_one();
                let tx = self.tx.clone();
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    let _ = tx.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.peer_closed.store(true, Ordering::Release);
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunStream {
    fn drop(&mut self) {
        self.peer_closed.store(true, Ordering::Release);
        self.notify.notify_one();
    }
}

struct TunTcpSession {
    handle: SocketHandle,
    to_app: Option<mpsc::Sender<Bytes>>,
    from_app: mpsc::Receiver<Bytes>,
    pending_app: Option<Bytes>,
    created: Instant,
    app_closed: bool,
    peer_closed: Arc<AtomicBool>,
    established: bool,
}

fn is_routable_tun_destination(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            if v4.is_broadcast() || v4.is_link_local() || oct[0] >= 224 {
                return false;
            }
            // Подсеть самого виртуального интерфейса TUN (172.19.0.0/30)
            if oct[0] == 172 && oct[1] == 19 && oct[2] == 0 && oct[3] <= 3 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // Link-local fe80::/10
            (seg[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Распарсить L3/L4 заголовки входящего IP-пакета из TUN:
/// возвращает `(proto, src_addr, dst_addr, l4_flags, l4_payload_offset)`.
fn parse_ip_packet_meta(pkt: &[u8]) -> Option<(u8, SocketAddr, SocketAddr, u8, usize)> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    if version == 4 {
        if pkt.len() < 20 {
            return None;
        }
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl + 8 {
            return None;
        }
        let proto = pkt[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        if proto == 6 {
            if pkt.len() < ihl + 20 {
                return None;
            }
            let tcp_hdr_len = ((pkt[ihl + 12] >> 4) as usize) * 4;
            let flags = pkt[ihl + 13];
            Some((
                6,
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
                flags,
                ihl + tcp_hdr_len,
            ))
        } else if proto == 17 {
            Some((
                17,
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
                0,
                ihl + 8,
            ))
        } else {
            None
        }
    } else if version == 6 {
        if pkt.len() < 48 {
            return None;
        }
        let next_hdr = pkt[6];
        let mut s6 = [0u8; 16];
        let mut d6 = [0u8; 16];
        s6.copy_from_slice(&pkt[8..24]);
        d6.copy_from_slice(&pkt[24..40]);
        let src_ip = IpAddr::V6(Ipv6Addr::from(s6));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(d6));
        let src_port = u16::from_be_bytes([pkt[40], pkt[41]]);
        let dst_port = u16::from_be_bytes([pkt[42], pkt[43]]);
        if next_hdr == 6 {
            if pkt.len() < 60 {
                return None;
            }
            let tcp_hdr_len = ((pkt[52] >> 4) as usize) * 4;
            let flags = pkt[53];
            Some((
                6,
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
                flags,
                40 + tcp_hdr_len,
            ))
        } else if next_hdr == 17 {
            Some((
                17,
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
                0,
                48,
            ))
        } else {
            None
        }
    } else {
        None
    }
}

/// Построить обратный IP + UDP пакет для записи ответа обратно в TUN.
fn build_tun_udp_response(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = vec![0u8; 8 + payload.len()];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[8..].copy_from_slice(payload);

    let fold_l4_csum = |mut sum: u32, l4: &[u8]| -> u16 {
        let (chunks, rem) = l4.as_chunks::<2>();
        for &c in chunks {
            sum += u16::from_be_bytes(c) as u32;
        }
        if let Some(&last) = rem.first() {
            sum += u16::from_be_bytes([last, 0]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let csum = !(sum as u16);
        if csum == 0 { 0xFFFF } else { csum }
    };

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            let s_oct = s4.octets();
            let d_oct = d4.octets();
            let pseudo_sum = 17u32
                + (udp.len() as u32)
                + (u16::from_be_bytes([s_oct[0], s_oct[1]]) as u32)
                + (u16::from_be_bytes([s_oct[2], s_oct[3]]) as u32)
                + (u16::from_be_bytes([d_oct[0], d_oct[1]]) as u32)
                + (u16::from_be_bytes([d_oct[2], d_oct[3]]) as u32);
            let udp_csum = fold_l4_csum(pseudo_sum, &udp);
            udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());

            let total_len = (20 + udp.len()) as u16;
            let mut ip = vec![0u8; 20 + udp.len()];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_len.to_be_bytes());
            ip[4..6].copy_from_slice(&0x2468u16.to_be_bytes());
            ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            ip[8] = 64;
            ip[9] = 17; // UDP
            ip[12..16].copy_from_slice(&s_oct);
            ip[16..20].copy_from_slice(&d_oct);
            let mut sum: u32 = 0;
            for &chunk in ip[..20].as_chunks::<2>().0 {
                sum += u16::from_be_bytes(chunk) as u32;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let ip_csum = !(sum as u16);
            ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());
            ip[20..].copy_from_slice(&udp);
            Some(ip)
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            let s_oct = s6.octets();
            let d_oct = d6.octets();
            let mut pseudo_sum = 17u32 + (udp.len() as u32);
            for &c in s_oct.as_chunks::<2>().0 {
                pseudo_sum += u16::from_be_bytes(c) as u32;
            }
            for &c in d_oct.as_chunks::<2>().0 {
                pseudo_sum += u16::from_be_bytes(c) as u32;
            }
            let udp_csum = fold_l4_csum(pseudo_sum, &udp);
            udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());

            let payload_len = udp.len() as u16;
            let mut ip = vec![0u8; 40 + udp.len()];
            ip[0..4].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]);
            ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
            ip[6] = 17; // Next Header: UDP
            ip[7] = 64; // Hop Limit
            ip[8..24].copy_from_slice(&s_oct);
            ip[24..40].copy_from_slice(&d_oct);
            ip[40..].copy_from_slice(&udp);
            Some(ip)
        }
        _ => None,
    }
}

/// Запустить системный режим перехвата TUN (`Wintun` на Windows, `/dev/net/tun` на Linux).
pub async fn run_tun_capture(
    interface_name: &str,
    matcher: Arc<RwLock<Arc<CompiledMatcher>>>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
    stop_flag: Arc<AtomicBool>,
) -> io::Result<()> {
    let mtu = 1420usize;
    let v4_addrs = [(Ipv4Addr::new(172, 19, 0, 1), 30u8)];
    let v6_addrs: [(Ipv6Addr, u8); 0] = [];

    let platform_dev = PlatformTunHandle::open(interface_name, mtu, &v4_addrs, &v6_addrs, true)?;
    (log_fn)(
        "info",
        "tun",
        &format!(
            "Системный интерфейс TUN «{}» активирован (MTU {mtu}, адрес 172.19.0.1/30)",
            platform_dev.name()
        ),
    );

    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(512);
    let mut vdev = VirtualTunDevice::new(mtu);
    let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
    iconfig.random_seed = 0x1234_5678_9ABC_DEF0;
    let mut iface = Interface::new(iconfig, &mut vdev, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|list| {
        let _ = list.push(smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::UNSPECIFIED),
            0,
        ));
        let _ = list.push(smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::UNSPECIFIED),
            0,
        ));
    });

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_sessions: HashMap<(SocketAddr, SocketAddr), TunTcpSession> = HashMap::new();
    let mut udp_sessions: HashMap<(SocketAddr, SocketAddr), Instant> = HashMap::new();
    let udp_nat: TunUdpNatTable = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let udp_permits = Arc::new(tokio::sync::Semaphore::new(512));
    let notify = Arc::new(Notify::new());
    let mut pkt_buf = vec![0u8; 65536];

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // 1. Опрашиваем виртуальный стек smoltcp и перекачиваем данные между сокетами и задачами
        let _ = iface.poll(SmolInstant::now(), &mut vdev, &mut sockets);
        pump_virtual_tcp(&mut sockets, &mut tcp_sessions);
        let _ = iface.poll(SmolInstant::now(), &mut vdev, &mut sockets);

        // 2. Отправляем готовые пакеты из smoltcp и UDP-ответов обратно в TUN
        while let Some(out_pkt) = vdev.tx_queue.pop_front() {
            let _ = platform_dev.write_packet(&out_pkt).await;
        }
        while let Ok(udp_reply_pkt) = tun_rx.try_recv() {
            let _ = platform_dev.write_packet(&udp_reply_pkt).await;
        }

        // 3. Ожидаем следующий пакет из TUN или сигнал от виртуального потока
        tokio::select! {
            biased;
            read_res = tokio::time::timeout(Duration::from_millis(25), platform_dev.read_packet(&mut pkt_buf)) => {
                if let Ok(Ok(n)) = read_res && n > 0 {
                    let pkt = &pkt_buf[..n];
                    if let Some((proto, src, dst, flags, payload_off)) = parse_ip_packet_meta(pkt) {
                        if !is_routable_tun_destination(dst.ip()) {
                            continue;
                        }
                        if proto == 6 {
                            // TCP-пакет
                            let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
                            if is_syn && !tcp_sessions.contains_key(&(src, dst)) && tcp_sessions.len() < MAX_TCP_SESSIONS {
                                spawn_tun_tcp_session(
                                    src,
                                    dst,
                                    &mut sockets,
                                    &mut tcp_sessions,
                                    &notify,
                                    &matcher,
                                    &counters,
                                    &log_fn,
                                );
                            }
                            if vdev.rx_queue.len() < TUN_QUEUE_CAP {
                                vdev.rx_queue.push_back(pkt.to_vec());
                            }
                        } else if proto == 17 && payload_off <= pkt.len() {
                            // UDP-пакет
                            let Ok(permit) = udp_permits.clone().try_acquire_owned() else {
                                continue;
                            };
                            let udp_payload = pkt[payload_off..].to_vec();
                            if udp_sessions.len() > MAX_UDP_SESSIONS {
                                udp_sessions.retain(|_, ts| ts.elapsed() < Duration::from_secs(60));
                            }
                            let is_first_udp = !udp_sessions.contains_key(&(src, dst));
                            udp_sessions.insert((src, dst), Instant::now());

                            let matcher_snap = matcher.read().await.clone();
                            let udp_nat_clone = udp_nat.clone();
                            let tun_tx_clone = tun_tx.clone();
                            let counters_clone = counters.clone();
                            let log_clone = log_fn.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                handle_tun_udp_datagram(
                                    src,
                                    dst,
                                    udp_payload,
                                    is_first_udp,
                                    matcher_snap,
                                    udp_nat_clone,
                                    tun_tx_clone,
                                    counters_clone,
                                    log_clone,
                                ).await;
                            });
                        }
                    }
                }
            }
            _ = notify.notified() => {}
        }
    }

    (log_fn)(
        "info",
        "tun",
        "Системный интерфейс TUN остановлен, маршруты восстановлены",
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_tun_tcp_session(
    src: SocketAddr,
    dst: SocketAddr,
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
    notify: &Arc<Notify>,
    matcher: &Arc<RwLock<Arc<CompiledMatcher>>>,
    counters: &Arc<TrafficCounters>,
    log_fn: &LogCallback,
) {
    let rx_buf = TcpSocketBuffer::new(vec![0u8; 65536]);
    let tx_buf = TcpSocketBuffer::new(vec![0u8; 65536]);
    let mut sock = TcpSocket::new(rx_buf, tx_buf);
    sock.set_nagle_enabled(false);
    sock.set_ack_delay(None);

    if sock.listen(dst).is_ok() {
        let handle = sockets.add(sock);
        let (to_app_tx, to_app_rx) = mpsc::channel(64);
        let (from_app_tx, from_app_rx) = mpsc::channel(64);
        let peer_closed = Arc::new(AtomicBool::new(false));

        let tun_stream = TunStream {
            rx: to_app_rx,
            tx: from_app_tx,
            notify: notify.clone(),
            peer_closed: peer_closed.clone(),
            current: None,
        };

        let matcher_lock = matcher.clone();
        let counters_ref = counters.clone();
        let log_ref = log_fn.clone();
        let src_port = src.port();

        tokio::spawn(async move {
            let matcher_snap = matcher_lock.read().await.clone();
            let _ = handle_tun_tcp_stream(
                tun_stream,
                src_port,
                dst,
                matcher_snap,
                counters_ref,
                log_ref,
            )
            .await;
        });

        sessions.insert(
            (src, dst),
            TunTcpSession {
                handle,
                to_app: Some(to_app_tx),
                from_app: from_app_rx,
                pending_app: None,
                created: Instant::now(),
                app_closed: false,
                peer_closed,
                established: false,
            },
        );
    }
}

async fn handle_tun_tcp_stream(
    mut client: TunStream,
    src_port: u16,
    dst_addr: SocketAddr,
    matcher: Arc<CompiledMatcher>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) -> io::Result<()> {
    let app_name = crate::apps::resolve_socket_process_name(src_port, false);
    let app_tag = app_name
        .as_deref()
        .map(|a| format!(" [{a}]"))
        .unwrap_or_default();

    let mut first_pkt = vec![0u8; 16384];
    match tokio::time::timeout(Duration::from_millis(500), client.read(&mut first_pkt)).await {
        Ok(Ok(n)) if n > 0 => first_pkt.truncate(n),
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => first_pkt.clear(),
    }

    let sni_host = extract_hostname(&first_pkt);
    let mut dst_addr = dst_addr;
    if let IpAddr::V4(v4) = dst_addr.ip()
        && v4.octets()[0] == 198
        && (v4.octets()[1] == 18 || v4.octets()[1] == 19)
        && let Some(ref h) = sni_host
        && let Ok(addrs) = crate::outbound::dial::resolve(h, dst_addr.port()).await
        && let Some(&real_addr) = addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first())
    {
        dst_addr = real_addr;
    }
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
    let res = match decision {
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
                    "TUN{app_tag} {display_target}:{} — {reason}",
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
            let mut remote = connect_outbound_tcp(dst_addr, Duration::from_secs(6)).await?;
            if !first_pkt.is_empty() {
                remote.write_all(&first_pkt).await?;
                let n = first_pkt.len() as u64;
                counters.tx_bytes.fetch_add(n, Ordering::Relaxed);
                flow.record.add_tx(n);
            }
            (log_fn)(
                "info",
                "direct",
                &format!(
                    "TUN{app_tag} {display_target}:{} -> Прямое ({list_tag})",
                    dst_addr.port()
                ),
            );
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
            let mut remote =
                connect_via_upstream_proxy(&proxy_url, dst_addr, sni_host.as_deref(), &first_pkt)
                    .await?;
            if !first_pkt.is_empty() {
                let n = first_pkt.len() as u64;
                counters.tx_bytes.fetch_add(n, Ordering::Relaxed);
                flow.record.add_tx(n);
            }
            (log_fn)(
                "info",
                "proxy",
                &format!(
                    "TUN{app_tag} {display_target}:{} -> Внешний прокси {proxy_url} [{matched_list}]",
                    dst_addr.port()
                ),
            );
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
            let (mut remote, pre_read, used_recipe, resolved_host) =
                connect_and_apply_desync_auto(dst_addr, &first_pkt, &config, sni_host.as_deref())
                    .await?;
            let strategy_code = if let Some(r_idx) = used_recipe {
                RECIPE_TITLES[(r_idx as usize).min(RECIPE_TITLES.len() - 1)].0
            } else {
                "custom"
            };
            let flow = crate::flows::register_flow(
                "TCP",
                app_name.as_deref(),
                sni_host.as_deref(),
                dst_addr,
                format!("Desync [{strategy_code}]"),
                true,
                true,
            );
            let first_n = first_pkt.len() as u64;
            counters.tx_bytes.fetch_add(first_n, Ordering::Relaxed);
            flow.record.add_tx(first_n);

            let strategy_label = if let Some(r_idx) = used_recipe {
                RECIPE_TITLES[(r_idx as usize).min(RECIPE_TITLES.len() - 1)].1
            } else {
                "Профиль"
            };
            (log_fn)(
                "info",
                "desync",
                &format!(
                    "TUN{app_tag} {display_target}:{} -> [{matched_list}] {strategy_label}",
                    dst_addr.port()
                ),
            );

            let mut total_rx = 0u64;
            if !pre_read.is_empty() {
                client.write_all(&pre_read).await?;
                let nr = pre_read.len() as u64;
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
    res
}

#[derive(Clone)]
struct TunUdpNatEntry {
    sock: Arc<UdpSocket>,
    /// Отслеживаемые адаптивные UDP-узлы: `peer -> (rx_bytes, reported_ok)`
    adaptive_peers: Arc<std::sync::Mutex<HashMap<SocketAddr, (u64, bool)>>>,
}

type TunUdpNatTable = Arc<std::sync::Mutex<HashMap<(SocketAddr, bool), TunUdpNatEntry>>>;

#[inline]
fn emit_tun_icmp_port_unreachable(
    tun_tx: &mpsc::Sender<Vec<u8>>,
    remote: SocketAddr,
    client: SocketAddr,
    udp_payload: &[u8],
) {
    if let Some((pkt, len)) =
        crate::outbound::tlsspoof::build_icmp_port_unreachable_buf(remote, client, udp_payload)
    {
        let _ = tun_tx.try_send(pkt[..len].to_vec());
    }
}

async fn get_or_create_udp_nat_socket(
    src: SocketAddr,
    is_ipv6: bool,
    track_adaptive_dst: Option<SocketAddr>,
    udp_nat: &TunUdpNatTable,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    counters: &Arc<TrafficCounters>,
) -> io::Result<Arc<UdpSocket>> {
    if let Ok(guard) = udp_nat.lock()
        && let Some(existing) = guard.get(&(src, is_ipv6))
    {
        if let Some(dst) = track_adaptive_dst
            && let Ok(mut peers) = existing.adaptive_peers.lock()
            && peers.len() < 32
        {
            peers.entry(dst).or_insert((0, false));
        }
        return Ok(existing.sock.clone());
    }

    let sock = Arc::new(bind_and_connect_udp(is_ipv6).await?);
    let adaptive_peers = Arc::new(std::sync::Mutex::new(HashMap::new()));
    if let Some(dst) = track_adaptive_dst
        && let Ok(mut peers) = adaptive_peers.lock()
    {
        peers.insert(dst, (0, false));
    }

    if let Ok(mut guard) = udp_nat.lock() {
        if let Some(existing) = guard.get(&(src, is_ipv6)) {
            if let Some(dst) = track_adaptive_dst
                && let Ok(mut peers) = existing.adaptive_peers.lock()
                && peers.len() < 32
            {
                peers.entry(dst).or_insert((0, false));
            }
            return Ok(existing.sock.clone());
        }
        if guard.len() < 1024 {
            guard.insert(
                (src, is_ipv6),
                TunUdpNatEntry {
                    sock: sock.clone(),
                    adaptive_peers: adaptive_peers.clone(),
                },
            );
        }
    }

    let sock_reader = sock.clone();
    let nat_reader = udp_nat.clone();
    let peers_reader = adaptive_peers;
    let tun_tx_reader = tun_tx.clone();
    let counters_reader = counters.clone();
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = tun_tx_reader.closed() => break,
                recv_res = tokio::time::timeout(Duration::from_secs(60), sock_reader.recv_from(&mut rbuf)) => {
                    match recv_res {
                        Ok(Ok((n, peer))) if n > 0 => {
                            counters_reader
                                .rx_bytes
                                .fetch_add(n as u64, Ordering::Relaxed);
                            let mut should_promote = false;
                            if let Ok(mut peers) = peers_reader.lock()
                                && let Some((rx_sum, reported)) = peers.get_mut(&peer)
                            {
                                *rx_sum = rx_sum.saturating_add(n as u64);
                                // Для UDP 443 (QUIC) закрепляем рецепт только после 256 КиБ (DESYNC_LIVE_PROMOTE_BYTES),
                                // как в tachyon-core 0.5.0, чтобы 16 KB QUIC cap не фиксировал мёртвый QUIC-узел как живой.
                                let promote_gate = if peer.port() == 443 {
                                    crate::desync::DESYNC_LIVE_PROMOTE_BYTES
                                } else {
                                    1
                                };
                                if !*reported && *rx_sum >= promote_gate {
                                    *reported = true;
                                    should_promote = true;
                                }
                            }
                            if should_promote {
                                report_udp_quic_outcome(peer, true);
                            }
                            if let Some(ip_pkt) = build_tun_udp_response(peer, src, &rbuf[..n]) {
                                let _ = tun_tx_reader.send(ip_pkt).await;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
        if !tun_tx_reader.is_closed()
            && let Ok(peers) = peers_reader.lock()
        {
            for (&peer, &(rx_sum, reported)) in peers.iter() {
                if !reported && rx_sum == 0 {
                    report_udp_quic_outcome(peer, false);
                }
            }
        }
        if let Ok(mut guard) = nat_reader.lock() {
            guard.remove(&(src, is_ipv6));
        }
    });

    Ok(sock)
}

#[allow(clippy::too_many_arguments)]
async fn handle_tun_udp_datagram(
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
    is_first: bool,
    matcher: Arc<CompiledMatcher>,
    udp_nat: TunUdpNatTable,
    tun_tx: mpsc::Sender<Vec<u8>>,
    counters: Arc<TrafficCounters>,
    log_fn: LogCallback,
) {
    // 1. Обработка DNS-запросов (порт 53): пропускаем через анти-спуфинг резолвер (1253/5353/1.1.1.1/8.8.8.8)
    // и разбираем A/AAAA ответы в кэш IP->Домен
    if dst.port() == 53 {
        if let Ok(rbuf) = crate::outbound::dial::forward_clean_dns_udp_packet(&payload, dst).await
            && let Some(ip_pkt) = build_tun_udp_response(dst, src, &rbuf)
        {
            let _ = tun_tx.send(ip_pkt).await;
        }
        return;
    }

    let app_name = crate::apps::resolve_socket_process_name(src.port(), true);
    let app_tag = app_name
        .as_deref()
        .map(|a| format!(" [{a}]"))
        .unwrap_or_default();

    let udp_host = crate::lists::lookup_dns_mapping(dst.ip());
    // 2. Оцениваем политику для UDP-потока (QUIC / Discord Voice / STUN / игры)
    let decision = matcher.evaluate_with_app(
        udp_host.as_deref(),
        dst.ip(),
        dst.port(),
        true,
        app_name.as_deref(),
    );
    match decision {
        MatchDecision::Block { reason } => {
            emit_tun_icmp_port_unreachable(&tun_tx, dst, src, &payload);
            if is_first {
                let _flow = crate::flows::register_flow(
                    "UDP",
                    app_name.as_deref(),
                    udp_host.as_deref(),
                    dst,
                    "Block QUIC".to_string(),
                    false,
                    false,
                );
                (log_fn)("info", "quic", &format!("UDP{app_tag} {dst} — {reason}"));
            }
        }
        MatchDecision::Direct { .. } | MatchDecision::UpstreamProxy { .. } => {
            if let Ok(sock) =
                get_or_create_udp_nat_socket(src, dst.is_ipv6(), None, &udp_nat, &tun_tx, &counters)
                    .await
                && sock.send_to(&payload, dst).await.is_ok()
            {
                if is_first {
                    let fg = crate::flows::register_flow(
                        "UDP",
                        app_name.as_deref(),
                        udp_host.as_deref(),
                        dst,
                        "Direct".to_string(),
                        false,
                        true,
                    );
                    fg.record.add_tx(payload.len() as u64);
                }
                counters
                    .tx_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
        }
        MatchDecision::Desync {
            config,
            matched_list,
        } => {
            if dst.port() == 443
                && ((config.block_quic && payload.len() >= 120 && (payload[0] & 0x80) != 0)
                    || (config.auto && crate::desync::is_quic_endpoint_dead(dst)))
            {
                emit_tun_icmp_port_unreachable(&tun_tx, dst, src, &payload);
                return;
            }
            let track_dst = config.auto.then_some(dst);
            if let Ok(sock) = get_or_create_udp_nat_socket(
                src,
                dst.is_ipv6(),
                track_dst,
                &udp_nat,
                &tun_tx,
                &counters,
            )
            .await
            {
                if is_first {
                    let fg = crate::flows::register_flow(
                        "UDP",
                        app_name.as_deref(),
                        udp_host.as_deref(),
                        dst,
                        format!("UDP Fake x{}", config.udp_repeats),
                        true,
                        true,
                    );
                    fg.record.add_tx(payload.len() as u64);
                    (log_fn)(
                        "info",
                        "udp_desync",
                        &format!(
                            "UDP{app_tag} {dst} -> [{matched_list}] фейков: {}, TTL={}",
                            config.udp_repeats, config.udp_fake_ttl
                        ),
                    );
                    let _ = send_udp_fakes_same_tuple(&sock, dst, &config).await;
                }
                if sock.send_to(&payload, dst).await.is_ok() {
                    counters
                        .tx_bytes
                        .fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

async fn bind_and_connect_udp(is_ipv6: bool) -> io::Result<UdpSocket> {
    let domain = if is_ipv6 {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    bind_outbound_socket(&sock, is_ipv6);
    sock.set_nonblocking(true)?;
    let bind_addr: SocketAddr = if is_ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    sock.bind(&bind_addr.into())?;
    let std_udp: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_udp)
}

fn pump_virtual_tcp(
    sockets: &mut SocketSet<'static>,
    sessions: &mut HashMap<(SocketAddr, SocketAddr), TunTcpSession>,
) {
    let mut finished = Vec::new();

    for (&key, session) in sessions.iter_mut() {
        let sock = sockets.get_mut::<TcpSocket<'static>>(session.handle);
        let state = sock.state();

        if (state == TcpState::Established || state == TcpState::CloseWait) && !session.established
        {
            session.established = true;
        }

        if session.established {
            if let Some(to_app) = session.to_app.as_ref() {
                while to_app.capacity() > 0 && sock.can_recv() {
                    let avail = sock.recv_queue().min(32768);
                    if avail == 0 {
                        break;
                    }
                    let mut buf = Vec::with_capacity(avail);
                    let _ = sock.recv(|data| {
                        let n = data.len().min(avail);
                        buf.extend_from_slice(&data[..n]);
                        (n, n)
                    });
                    if buf.is_empty() || to_app.try_send(Bytes::from(buf)).is_err() {
                        break;
                    }
                }
            }
            if !sock.may_recv() && !sock.can_recv() {
                session.to_app = None;
            }

            while sock.can_send() {
                if let Some(front) = session.pending_app.take() {
                    match sock.send_slice(&front) {
                        Ok(n) if n < front.len() => {
                            session.pending_app = Some(front.slice(n..));
                            break;
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            session.pending_app = Some(front);
                            break;
                        }
                    }
                }
                match session.from_app.try_recv() {
                    Ok(data) => match sock.send_slice(&data) {
                        Ok(n) if n < data.len() => {
                            session.pending_app = Some(data.slice(n..));
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => {
                            session.pending_app = Some(data);
                            break;
                        }
                    },
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        session.app_closed = true;
                        sock.close();
                        break;
                    }
                }
            }

            if !session.app_closed && session.peer_closed.load(Ordering::Acquire) {
                session.app_closed = true;
                sock.close();
            }
        }

        let expired = !session.established && session.created.elapsed() > Duration::from_secs(15);
        let closed = matches!(state, TcpState::Closed | TcpState::TimeWait)
            || (session.app_closed && !sock.may_send() && !sock.can_recv());
        if expired || closed {
            finished.push(key);
        }
    }

    for key in finished {
        if let Some(s) = sessions.remove(&key) {
            sockets.remove(s.handle);
        }
    }
}

// ============================================================================
// Платформенная обёртка TUN (Windows Wintun / Linux /dev/net/tun / macOS utun)
// ============================================================================

pub enum PlatformTunHandle {
    #[cfg(target_os = "windows")]
    Windows(windows_tun::WinTunDevice),
    #[cfg(target_os = "linux")]
    Linux(linux_tun::LinuxTunDevice),
    #[cfg(target_os = "macos")]
    Macos(macos_tun::MacosTunDevice),
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    Unsupported,
}

impl PlatformTunHandle {
    pub fn open(
        name: &str,
        mtu: usize,
        v4_addrs: &[(Ipv4Addr, u8)],
        v6_addrs: &[(Ipv6Addr, u8)],
        auto_route: bool,
    ) -> io::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            let dev = windows_tun::WinTunDevice::open(name, mtu, v4_addrs, v6_addrs, auto_route)?;
            Ok(Self::Windows(dev))
        }
        #[cfg(target_os = "linux")]
        {
            let _ = v6_addrs;
            let dev = linux_tun::LinuxTunDevice::open(name, mtu, v4_addrs, auto_route)?;
            Ok(Self::Linux(dev))
        }
        #[cfg(target_os = "macos")]
        {
            let _ = (name, v6_addrs);
            let dev = macos_tun::MacosTunDevice::open(mtu, v4_addrs, auto_route)?;
            Ok(Self::Macos(dev))
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = (name, mtu, v4_addrs, v6_addrs, auto_route);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN capture is supported on Windows, Linux, and macOS",
            ))
        }
    }

    pub fn name(&self) -> &str {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows(dev) => dev.name(),
            #[cfg(target_os = "linux")]
            Self::Linux(dev) => dev.name(),
            #[cfg(target_os = "macos")]
            Self::Macos(dev) => dev.name(),
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            Self::Unsupported => "unsupported",
        }
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows(dev) => dev.read_packet(buf).await,
            #[cfg(target_os = "linux")]
            Self::Linux(dev) => dev.read_packet(buf).await,
            #[cfg(target_os = "macos")]
            Self::Macos(dev) => dev.read_packet(buf).await,
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            Self::Unsupported => Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported")),
        }
    }

    pub async fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows(dev) => dev.write_packet(pkt),
            #[cfg(target_os = "linux")]
            Self::Linux(dev) => dev.write_packet(pkt).await,
            #[cfg(target_os = "macos")]
            Self::Macos(dev) => dev.write_packet(pkt).await,
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            Self::Unsupported => Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported")),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_tun {
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::unix::AsyncFd;

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    pub struct LinuxTunDevice {
        async_fd: AsyncFd<RawFd>,
        name: String,
        auto_route: bool,
    }

    impl LinuxTunDevice {
        pub fn open(
            name: &str,
            mtu: usize,
            v4_addrs: &[(Ipv4Addr, u8)],
            auto_route: bool,
        ) -> io::Result<Self> {
            let fd =
                unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut ifr = IfReq {
                ifr_name: [0; libc::IFNAMSIZ],
                ifr_flags: IFF_TUN | IFF_NO_PI,
                _pad: [0; 22],
            };
            for (i, b) in name.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
            if unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) } < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }

            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])
                .status();
            for &(ip, prefix) in v4_addrs {
                let _ = std::process::Command::new("ip")
                    .args(["addr", "add", &format!("{ip}/{prefix}"), "dev", name])
                    .status();
            }
            if auto_route {
                let _ = std::process::Command::new("ip")
                    .args(["route", "replace", "default", "dev", name, "table", "2022"])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args([
                        "rule", "del", "not", "fwmark", "0x2022", "lookup", "2022", "pref", "9000",
                    ])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args([
                        "rule", "add", "not", "fwmark", "0x2022", "lookup", "2022", "pref", "9000",
                    ])
                    .status();
            }
            let async_fd = AsyncFd::new(fd)?;
            Ok(Self {
                async_fd,
                name: name.to_string(),
                auto_route,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.async_fd.readable().await?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(res) => return res,
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.async_fd.writable().await?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::write(
                            inner.as_raw_fd(),
                            pkt.as_ptr() as *const libc::c_void,
                            pkt.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(res) => return res,
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl Drop for LinuxTunDevice {
        fn drop(&mut self) {
            if self.auto_route {
                let _ = std::process::Command::new("ip")
                    .args([
                        "rule", "del", "not", "fwmark", "0x2022", "lookup", "2022", "pref", "9000",
                    ])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args(["route", "flush", "table", "2022"])
                    .status();
            }
            let raw_fd = *self.async_fd.get_ref();
            unsafe {
                libc::close(raw_fd);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_tun {
    use crate::upstream_compat::MACOS_OUTBOUND_IF_INDEX;
    use std::ffi::CString;
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::atomic::Ordering;
    use tokio::io::unix::AsyncFd;

    const PF_SYSTEM: libc::c_int = libc::AF_SYSTEM;
    const AF_SYS_CONTROL: libc::c_ushort = 2;
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    pub struct MacosTunDevice {
        async_fd: AsyncFd<RawFd>,
        name: String,
        auto_route: bool,
    }

    fn detect_macos_default_if_index() -> Option<u32> {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix("interface:") {
                let if_name = rest.trim();
                if let Ok(c_str) = CString::new(if_name) {
                    let idx = unsafe { libc::if_nametoindex(c_str.as_ptr()) };
                    if idx != 0 {
                        return Some(idx);
                    }
                }
            }
        }
        None
    }

    impl MacosTunDevice {
        pub fn open(mtu: usize, v4_addrs: &[(Ipv4Addr, u8)], auto_route: bool) -> io::Result<Self> {
            if auto_route && let Some(idx) = detect_macos_default_if_index() {
                MACOS_OUTBOUND_IF_INDEX.store(idx, Ordering::Release);
            }

            let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0u8; 96],
            };
            info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
            if unsafe { libc::ioctl(fd, CTLIOCGINFO as _, &mut info) } < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }

            let mut connected_unit = None;
            for unit in 1..=64u32 {
                let addr = SockaddrCtl {
                    sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                    sc_family: PF_SYSTEM as u8,
                    ss_sysaddr: AF_SYS_CONTROL,
                    sc_id: info.ctl_id,
                    sc_unit: unit,
                    sc_reserved: [0; 5],
                };
                let rc = unsafe {
                    libc::connect(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
                    )
                };
                if rc == 0 {
                    connected_unit = Some(unit - 1);
                    break;
                }
            }

            let Some(unit_idx) = connected_unit else {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            };

            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }

            let if_name = format!("utun{unit_idx}");
            if let Some(&(ip, _prefix)) = v4_addrs.first() {
                let ip_s = ip.to_string();
                let _ = std::process::Command::new("ifconfig")
                    .args([
                        &if_name,
                        "inet",
                        &ip_s,
                        &ip_s,
                        "mtu",
                        &mtu.to_string(),
                        "up",
                    ])
                    .status();
            }

            if auto_route {
                let _ = std::process::Command::new("route")
                    .args(["-n", "add", "-net", "0.0.0.0/1", "-interface", &if_name])
                    .status();
                let _ = std::process::Command::new("route")
                    .args(["-n", "add", "-net", "128.0.0.0/1", "-interface", &if_name])
                    .status();
            }

            let async_fd = AsyncFd::new(fd)?;
            Ok(Self {
                async_fd,
                name: if_name,
                auto_route,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut raw = vec![0u8; buf.len() + 4];
            loop {
                let mut guard = self.async_fd.readable().await?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            raw.as_mut_ptr() as *mut libc::c_void,
                            raw.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else if (n as usize) <= 4 {
                        Ok(0)
                    } else {
                        let pay_len = (n as usize) - 4;
                        buf[..pay_len].copy_from_slice(&raw[4..4 + pay_len]);
                        Ok(pay_len)
                    }
                }) {
                    Ok(res) => return res,
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
            if pkt.is_empty() {
                return Ok(0);
            }
            let af: u32 = if (pkt[0] >> 4) == 6 {
                libc::AF_INET6 as u32
            } else {
                libc::AF_INET as u32
            };
            let mut framed = Vec::with_capacity(pkt.len() + 4);
            framed.extend_from_slice(&af.to_be_bytes());
            framed.extend_from_slice(pkt);
            loop {
                let mut guard = self.async_fd.writable().await?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::write(
                            inner.as_raw_fd(),
                            framed.as_ptr() as *const libc::c_void,
                            framed.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok((n as usize).saturating_sub(4))
                    }
                }) {
                    Ok(res) => return res,
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl Drop for MacosTunDevice {
        fn drop(&mut self) {
            if self.auto_route {
                MACOS_OUTBOUND_IF_INDEX.store(0, Ordering::Release);
                let _ = std::process::Command::new("route")
                    .args([
                        "-n",
                        "delete",
                        "-net",
                        "0.0.0.0/1",
                        "-interface",
                        &self.name,
                    ])
                    .status();
                let _ = std::process::Command::new("route")
                    .args([
                        "-n",
                        "delete",
                        "-net",
                        "128.0.0.0/1",
                        "-interface",
                        &self.name,
                    ])
                    .status();
            }
            let raw_fd = *self.async_fd.get_ref();
            unsafe {
                libc::close(raw_fd);
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_tun {
    use super::{WIN_OUTBOUND_IF_INDEX, prefix_to_ipv4_netmask};
    use std::ffi::c_void;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    use tokio::sync::{Mutex, mpsc};

    const WINTUN_INF: &[u8] = include_bytes!("wintun_driver/wintun.inf");
    const WINTUN_CAT: &[u8] = include_bytes!("wintun_driver/wintun.cat");
    const WINTUN_SYS: &[u8] = include_bytes!("wintun_driver/wintun.sys");

    type Handle = *mut c_void;
    type HKey = *mut c_void;
    type HDevInfo = *mut c_void;
    type HSwDevice = *mut c_void;

    const INVALID_HANDLE_VALUE: Handle = (-1isize) as Handle;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const RING_CAPACITY: u32 = 0x0040_0000; // 4 MiB
    const WINTUN_MAX_IP_PACKET_SIZE: u32 = 0xFFFF;
    const TUN_ALIGNMENT: u32 = 4;
    const TUN_PACKET_RELEASE: u32 = 0x8000_0000;
    const TUN_IOCTL_REGISTER_RINGS: u32 = (51820u32 << 16) | (3u32 << 14) | (0x970u32 << 2);

    const MEM_COMMIT: u32 = 0x0000_1000;
    const MEM_RESERVE: u32 = 0x0000_2000;
    const MEM_RELEASE: u32 = 0x0000_8000;
    const PAGE_READWRITE: u32 = 0x04;

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;

    const DIGCF_PRESENT: u32 = 0x0000_0002;
    const DIOD_INHERIT_CLASSDRVS: u32 = 0x0000_0002;
    const DICS_FLAG_GLOBAL: u32 = 0x0000_0001;
    const DIREG_DRV: u32 = 0x0000_0002;
    const DIF_REMOVE: u32 = 0x0000_0005;
    const DI_REMOVEDEVICE_GLOBAL: u32 = 0x0000_0001;
    const SPOST_NONE: u32 = 0;

    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_BINARY: u32 = 3;

    const CM_LOCATE_DEVNODE_NORMAL: u32 = 0x0000_0000;
    const CM_LOCATE_DEVNODE_PHANTOM: u32 = 0x0000_0001;
    const CM_REGISTRY_SOFTWARE: u32 = 0x0000_0001;
    const CM_GET_DEVICE_INTERFACE_LIST_PRESENT: u32 = 0x0000_0000;
    const CR_SUCCESS: u32 = 0x0000_0000;

    const DEVPROP_STORE_SYSTEM: u32 = 0;
    const DEVPROP_TYPE_STRING: u32 = 0x0000_0012;
    const DEVPROP_TYPE_GUID: u32 = 0x0000_000D;
    const SW_DEVICE_CAPABILITIES: u32 = 0x0000_000A;

    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const GUID_DEVCLASS_NET: Guid = Guid {
        data1: 0x4d36_e972,
        data2: 0xe325,
        data3: 0x11ce,
        data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
    };

    const GUID_DEVINTERFACE_NET: Guid = Guid {
        data1: 0xcac8_8484,
        data2: 0x7515,
        data3: 0x4c03,
        data4: [0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61],
    };

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DevPropKey {
        fmtid: Guid,
        pid: u32,
    }

    const DEVPKEY_WINTUN_NAME: DevPropKey = DevPropKey {
        fmtid: Guid {
            data1: 0x3361_c968,
            data2: 0x2f2e,
            data3: 0x4660,
            data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
        },
        pid: 3,
    };

    const DEVPKEY_DEVICE_CLASS_GUID: DevPropKey = DevPropKey {
        fmtid: Guid {
            data1: 0xa45c_254e,
            data2: 0xdf1c,
            data3: 0x4efd,
            data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
        },
        pid: 10,
    };

    const DEVPKEY_DEVICE_FRIENDLY_NAME: DevPropKey = DevPropKey {
        fmtid: Guid {
            data1: 0xa45c_254e,
            data2: 0xdf1c,
            data3: 0x4efd,
            data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
        },
        pid: 14,
    };

    const DEVPKEY_DEVICE_DESC: DevPropKey = DevPropKey {
        fmtid: Guid {
            data1: 0xa45c_254e,
            data2: 0xdf1c,
            data3: 0x4efd,
            data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
        },
        pid: 2,
    };

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DevPropCompKey {
        key: DevPropKey,
        store: u32,
        locale_name: *const u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DevProperty {
        comp_key: DevPropCompKey,
        prop_type: u32,
        buffer_size: u32,
        buffer: *const c_void,
    }

    #[repr(C)]
    struct SwDeviceCreateInfo {
        cb_size: u32,
        psz_instance_id: *const u16,
        pszz_hardware_ids: *const u16,
        pszz_compatible_ids: *const u16,
        p_container_id: *const Guid,
        capability_flags: u32,
        psz_device_description: *const u16,
        psz_device_location: *const u16,
        p_security_descriptor: *const c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SpDevInfoData {
        cb_size: u32,
        class_guid: Guid,
        dev_inst: u32,
        reserved: usize,
    }

    #[repr(C)]
    struct SpClassInstallHeader {
        cb_size: u32,
        install_function: u32,
    }

    #[repr(C)]
    struct SpRemoveDeviceParams {
        class_install_header: SpClassInstallHeader,
        scope: u32,
        hw_profile: u32,
    }

    #[repr(C)]
    pub(crate) struct TunRing {
        pub(crate) head: AtomicU32,
        pub(crate) tail: AtomicU32,
        pub(crate) alertable: AtomicI32,
    }

    #[repr(C)]
    struct TunRingDescriptor {
        ring_size: u32,
        ring: *mut TunRing,
        tail_moved: Handle,
    }

    #[repr(C)]
    struct TunRegisterRings {
        send: TunRingDescriptor,
        receive: TunRingDescriptor,
    }

    type SwDeviceCreateCallback =
        unsafe extern "system" fn(HSwDevice, i32, *mut c_void, *const u16);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(
            lpEventAttributes: *mut c_void,
            bManualReset: i32,
            bInitialState: i32,
            lpName: *const u16,
        ) -> Handle;
        fn SetEvent(hEvent: Handle) -> i32;
        fn CloseHandle(hObject: Handle) -> i32;
        fn WaitForSingleObject(hHandle: Handle, dwMilliseconds: u32) -> u32;
        fn WaitForMultipleObjects(
            nCount: u32,
            lpHandles: *const Handle,
            bWaitAll: i32,
            dwMilliseconds: u32,
        ) -> u32;
        fn VirtualAlloc(
            lpAddress: *mut c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut u8;
        fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: Handle,
        ) -> Handle;
        fn DeviceIoControl(
            hDevice: Handle,
            dwIoControlCode: u32,
            lpInBuffer: *const c_void,
            nInBufferSize: u32,
            lpOutBuffer: *mut c_void,
            nOutBufferSize: u32,
            lpBytesReturned: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegQueryValueExW(
            hKey: HKey,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hKey: HKey,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        fn RegCloseKey(hKey: HKey) -> i32;
    }

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CLSIDFromString(lpsz: *const u16, pclsid: *mut Guid) -> i32;
    }

    #[link(name = "setupapi")]
    unsafe extern "system" {
        fn SetupCopyOEMInfW(
            SourceInfFileName: *const u16,
            OEMSourceMediaLocation: *const u16,
            OEMSourceMediaType: u32,
            CopyStyle: u32,
            DestinationInfFileName: *mut u16,
            DestinationInfFileNameSize: u32,
            RequiredSize: *mut u32,
            DestinationInfFileNameComponent: *mut *mut u16,
        ) -> i32;
        fn SetupDiCreateDeviceInfoListExW(
            ClassGuid: *const Guid,
            hwndParent: Handle,
            MachineName: *const u16,
            Reserved: *mut c_void,
        ) -> HDevInfo;
        fn SetupDiGetClassDevsExW(
            ClassGuid: *const Guid,
            Enumerator: *const u16,
            hwndParent: Handle,
            Flags: u32,
            DeviceInfoSet: HDevInfo,
            MachineName: *const u16,
            Reserved: *mut c_void,
        ) -> HDevInfo;
        fn SetupDiEnumDeviceInfo(
            DeviceInfoSet: HDevInfo,
            MemberIndex: u32,
            DeviceInfoData: *mut SpDevInfoData,
        ) -> i32;
        fn SetupDiOpenDeviceInfoW(
            DeviceInfoSet: HDevInfo,
            DeviceInstanceId: *const u16,
            hwndParent: Handle,
            OpenFlags: u32,
            DeviceInfoData: *mut SpDevInfoData,
        ) -> i32;
        fn SetupDiDestroyDeviceInfoList(DeviceInfoSet: HDevInfo) -> i32;
        fn SetupDiOpenDevRegKey(
            DeviceInfoSet: HDevInfo,
            DeviceInfoData: *mut SpDevInfoData,
            Scope: u32,
            HwProfile: u32,
            KeyType: u32,
            samDesired: u32,
        ) -> HKey;
        fn SetupDiGetDevicePropertyW(
            DeviceInfoSet: HDevInfo,
            DeviceInfoData: *mut SpDevInfoData,
            PropertyKey: *const DevPropKey,
            PropertyType: *mut u32,
            PropertyBuffer: *mut u8,
            PropertyBufferSize: u32,
            RequiredSize: *mut u32,
            Flags: u32,
        ) -> i32;
        fn SetupDiGetDeviceInstanceIdW(
            DeviceInfoSet: HDevInfo,
            DeviceInfoData: *mut SpDevInfoData,
            DeviceInstanceId: *mut u16,
            DeviceInstanceIdSize: u32,
            RequiredSize: *mut u32,
        ) -> i32;
        fn SetupDiSetClassInstallParamsW(
            DeviceInfoSet: HDevInfo,
            DeviceInfoData: *mut SpDevInfoData,
            ClassInstallParams: *const SpClassInstallHeader,
            ClassInstallParamsSize: u32,
        ) -> i32;
        fn SetupDiCallClassInstaller(
            InstallFunction: u32,
            DeviceInfoSet: HDevInfo,
            DeviceInfoData: *mut SpDevInfoData,
        ) -> i32;
    }

    #[link(name = "cfgmgr32")]
    unsafe extern "system" {
        fn CM_Locate_DevNodeW(pdnDevInst: *mut u32, pDeviceID: *const u16, ulFlags: u32) -> u32;
        fn CM_Get_Device_IDW(dnDevInst: u32, Buffer: *mut u16, BufferLen: u32, ulFlags: u32)
        -> u32;
        fn CM_Open_DevNode_Key(
            dnDevInst: u32,
            samDesired: u32,
            ulHardwareProfile: u32,
            Disposition: u32,
            phkDevice: *mut HKey,
            ulFlags: u32,
        ) -> u32;
        fn CM_Get_Device_Interface_List_SizeW(
            pulLen: *mut u32,
            InterfaceClassGuid: *const Guid,
            pDeviceID: *const u16,
            ulFlags: u32,
        ) -> u32;
        fn CM_Get_Device_Interface_ListW(
            InterfaceClassGuid: *const Guid,
            pDeviceID: *const u16,
            Buffer: *mut u16,
            BufferLen: u32,
            ulFlags: u32,
        ) -> u32;
    }

    #[link(name = "swdevice")]
    unsafe extern "system" {
        fn SwDeviceCreate(
            pszEnumeratorName: *const u16,
            pszParentDeviceInstance: *const u16,
            pCreateInfo: *const SwDeviceCreateInfo,
            cPropertyCount: u32,
            pProperties: *const DevProperty,
            pCallback: SwDeviceCreateCallback,
            pContext: *mut c_void,
            phSwDevice: *mut HSwDevice,
        ) -> i32;
        fn SwDeviceClose(hSwDevice: HSwDevice);
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetBestInterface(dwDestAddr: u32, pdwBestIfIndex: *mut u32) -> u32;
        fn ConvertInterfaceGuidToLuid(InterfaceGuid: *const Guid, InterfaceLuid: *mut u64) -> u32;
        fn ConvertInterfaceLuidToAlias(
            InterfaceLuid: *const u64,
            InterfaceAlias: *mut u16,
            Length: usize,
        ) -> u32;
    }

    const fn tun_align(size: u32) -> u32 {
        (size + (TUN_ALIGNMENT - 1)) & !(TUN_ALIGNMENT - 1)
    }

    const fn tun_max_packet_size() -> u32 {
        tun_align(4 + WINTUN_MAX_IP_PACKET_SIZE)
    }

    const fn tun_ring_size(capacity: u32) -> u32 {
        std::mem::size_of::<TunRing>() as u32 + capacity + (tun_max_packet_size() - TUN_ALIGNMENT)
    }

    const fn tun_ring_wrap(value: u32, capacity: u32) -> u32 {
        value & (capacity - 1)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn to_wide_multi(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v.push(0);
        v
    }

    fn from_wide_nul(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    fn run_netsh(args: &[&str]) {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("netsh")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    fn ensure_wintun_kernel_driver_installed() -> io::Result<()> {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let driver_sys = std::path::Path::new(&sys_root)
            .join("System32")
            .join("drivers")
            .join("wintun.sys");

        let temp_dir =
            std::env::temp_dir().join(format!("tachyon-desync-wintun-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir)?;

        let inf_path = temp_dir.join("wintun.inf");
        let cat_path = temp_dir.join("wintun.cat");
        let sys_path = temp_dir.join("wintun.sys");

        let res = (|| -> io::Result<()> {
            std::fs::write(&inf_path, WINTUN_INF)?;
            std::fs::write(&cat_path, WINTUN_CAT)?;
            std::fs::write(&sys_path, WINTUN_SYS)?;

            let inf_wide = to_wide(&inf_path.to_string_lossy());
            let ok = unsafe {
                SetupCopyOEMInfW(
                    inf_wide.as_ptr(),
                    std::ptr::null(),
                    SPOST_NONE,
                    0,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 && !driver_sys.exists() {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();

        let _ = std::fs::remove_file(&inf_path);
        let _ = std::fs::remove_file(&cat_path);
        let _ = std::fs::remove_file(&sys_path);
        let _ = std::fs::remove_dir(&temp_dir);
        res
    }

    struct SwCreateCtx {
        hresult: i32,
        instance_id: [u16; 256],
        event: Handle,
    }

    unsafe extern "system" fn sw_device_create_cb(
        _h_sw_device: HSwDevice,
        create_result: i32,
        context: *mut c_void,
        device_instance_id: *const u16,
    ) {
        if context.is_null() {
            return;
        }
        let ctx = unsafe { &mut *(context as *mut SwCreateCtx) };
        ctx.hresult = create_result;
        if !device_instance_id.is_null() {
            let mut i = 0usize;
            while i + 1 < ctx.instance_id.len() {
                let ch = unsafe { *device_instance_id.add(i) };
                ctx.instance_id[i] = ch;
                if ch == 0 {
                    break;
                }
                i += 1;
            }
            ctx.instance_id[ctx.instance_id.len() - 1] = 0;
        }
        unsafe {
            SetEvent(ctx.event);
        }
    }

    fn query_device_object_filename(instance_id: &[u16]) -> Option<Vec<u16>> {
        let mut list_len: u32 = 0;
        let cr = unsafe {
            CM_Get_Device_Interface_List_SizeW(
                &mut list_len,
                &GUID_DEVINTERFACE_NET,
                instance_id.as_ptr(),
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        if cr != CR_SUCCESS || list_len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; list_len as usize];
        let cr = unsafe {
            CM_Get_Device_Interface_ListW(
                &GUID_DEVINTERFACE_NET,
                instance_id.as_ptr(),
                buf.as_mut_ptr(),
                list_len,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        if cr != CR_SUCCESS || buf[0] == 0 {
            return None;
        }
        let first_nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let mut path = buf[..first_nul].to_vec();
        path.push(0);
        Some(path)
    }

    fn query_adapter_guid_and_alias(
        dev_info: HDevInfo,
        dev_info_data: &mut SpDevInfoData,
    ) -> Option<(Guid, String)> {
        let hkey = unsafe {
            SetupDiOpenDevRegKey(
                dev_info,
                dev_info_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DRV,
                KEY_QUERY_VALUE,
            )
        };
        if hkey.is_null() || hkey == INVALID_HANDLE_VALUE {
            return None;
        }
        let val_name = to_wide("NetCfgInstanceId");
        let mut reg_type: u32 = 0;
        let mut buf = [0u16; 128];
        let mut byte_len = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut reg_type,
                buf.as_mut_ptr() as *mut u8,
                &mut byte_len,
            )
        };
        unsafe {
            RegCloseKey(hkey);
        }
        if rc != 0 {
            return None;
        }
        buf[buf.len() - 1] = 0;
        let mut guid = Guid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        let hr = unsafe { CLSIDFromString(buf.as_ptr(), &mut guid) };
        if hr < 0 {
            return None;
        }
        let mut luid: u64 = 0;
        if unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) } != 0 {
            return None;
        }
        let mut alias_buf = [0u16; 256];
        if unsafe { ConvertInterfaceLuidToAlias(&luid, alias_buf.as_mut_ptr(), alias_buf.len()) }
            != 0
        {
            return None;
        }
        let alias = from_wide_nul(&alias_buf);
        if alias.is_empty() {
            return None;
        }
        Some((guid, alias))
    }

    fn try_rename_interface_alias(current_alias: &str, desired_name: &str) -> String {
        if current_alias.eq_ignore_ascii_case(desired_name) {
            return desired_name.to_string();
        }
        run_netsh(&[
            "interface",
            "set",
            "interface",
            &format!("name={current_alias}"),
            &format!("newname={desired_name}"),
        ]);
        let enumerator = to_wide("SWD\\Wintun");
        let dev_info = unsafe {
            SetupDiGetClassDevsExW(
                &GUID_DEVCLASS_NET,
                enumerator.as_ptr(),
                std::ptr::null_mut(),
                DIGCF_PRESENT,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        if !dev_info.is_null() && dev_info != INVALID_HANDLE_VALUE {
            let mut data = SpDevInfoData {
                cb_size: std::mem::size_of::<SpDevInfoData>() as u32,
                class_guid: GUID_DEVCLASS_NET,
                dev_inst: 0,
                reserved: 0,
            };
            let mut idx = 0u32;
            while unsafe { SetupDiEnumDeviceInfo(dev_info, idx, &mut data) } != 0 {
                idx += 1;
                if let Some((_, alias)) = query_adapter_guid_and_alias(dev_info, &mut data)
                    && alias.eq_ignore_ascii_case(desired_name)
                {
                    unsafe {
                        SetupDiDestroyDeviceInfoList(dev_info);
                    }
                    return desired_name.to_string();
                }
            }
            unsafe {
                SetupDiDestroyDeviceInfoList(dev_info);
            }
        }
        current_alias.to_string()
    }

    struct NativeAdapter {
        sw_device: HSwDevice,
        dev_info: HDevInfo,
        dev_info_data: SpDevInfoData,
        interface_filename: Vec<u16>,
        effective_name: String,
    }

    impl NativeAdapter {
        fn open_existing(name: &str) -> Option<Self> {
            let enumerator = to_wide("SWD\\Wintun");
            let dev_info = unsafe {
                SetupDiGetClassDevsExW(
                    &GUID_DEVCLASS_NET,
                    enumerator.as_ptr(),
                    std::ptr::null_mut(),
                    DIGCF_PRESENT,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            if dev_info.is_null() || dev_info == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut data = SpDevInfoData {
                cb_size: std::mem::size_of::<SpDevInfoData>() as u32,
                class_guid: GUID_DEVCLASS_NET,
                dev_inst: 0,
                reserved: 0,
            };
            let mut idx = 0u32;
            while unsafe { SetupDiEnumDeviceInfo(dev_info, idx, &mut data) } != 0 {
                idx += 1;
                let mut prop_type = 0u32;
                let mut prop_buf = [0u16; 256];
                let ok = unsafe {
                    SetupDiGetDevicePropertyW(
                        dev_info,
                        &mut data,
                        &DEVPKEY_WINTUN_NAME,
                        &mut prop_type,
                        prop_buf.as_mut_ptr() as *mut u8,
                        (prop_buf.len() * 2) as u32,
                        std::ptr::null_mut(),
                        0,
                    )
                };
                let prop_name = if ok != 0 && prop_type == DEVPROP_TYPE_STRING {
                    from_wide_nul(&prop_buf)
                } else {
                    String::new()
                };
                let alias_opt = query_adapter_guid_and_alias(dev_info, &mut data);
                let matches = prop_name.eq_ignore_ascii_case(name)
                    || alias_opt
                        .as_ref()
                        .is_some_and(|(_, alias)| alias.eq_ignore_ascii_case(name));
                if !matches {
                    continue;
                }
                let mut inst_id = [0u16; 256];
                let mut req = 0u32;
                if unsafe {
                    SetupDiGetDeviceInstanceIdW(
                        dev_info,
                        &mut data,
                        inst_id.as_mut_ptr(),
                        inst_id.len() as u32,
                        &mut req,
                    )
                } == 0
                {
                    continue;
                }
                if let Some(filename) = query_device_object_filename(&inst_id) {
                    let effective_name = alias_opt
                        .map(|(_, a)| try_rename_interface_alias(&a, name))
                        .unwrap_or_else(|| name.to_string());
                    return Some(Self {
                        sw_device: std::ptr::null_mut(),
                        dev_info,
                        dev_info_data: data,
                        interface_filename: filename,
                        effective_name,
                    });
                }
            }
            unsafe {
                SetupDiDestroyDeviceInfoList(dev_info);
            }
            None
        }

        fn create_or_open(name: &str) -> io::Result<Self> {
            ensure_wintun_kernel_driver_installed()?;
            if let Some(existing) = Self::open_existing(name) {
                return Ok(existing);
            }

            let mut root_node: u32 = 0;
            let cr = unsafe {
                CM_Locate_DevNodeW(&mut root_node, std::ptr::null(), CM_LOCATE_DEVNODE_NORMAL)
            };
            if cr != CR_SUCCESS {
                return Err(io::Error::other(format!(
                    "CM_Locate_DevNodeW failed: 0x{cr:x} (требуются права Администратора)"
                )));
            }
            let mut root_name = [0u16; 200];
            let cr = unsafe {
                CM_Get_Device_IDW(root_node, root_name.as_mut_ptr(), root_name.len() as u32, 0)
            };
            if cr != CR_SUCCESS {
                return Err(io::Error::other(format!(
                    "CM_Get_Device_IDW failed: 0x{cr:x}"
                )));
            }

            let instance_guid = Guid {
                data1: 0x7461_6368,
                data2: 0x6473,
                data3: 0x796e,
                data4: *b"wintun02",
            };
            let instance_guid_str = to_wide("{74616368-6473-796E-7769-6E74756E3032}");
            let enumerator_wintun = to_wide("Wintun");
            let empty_hwids = to_wide_multi("");
            let wintun_hwids = to_wide_multi("Wintun");
            let tunnel_desc = to_wide("Tachyon Desync Tunnel");
            let wide_name = to_wide(name);

            let event = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
            if event.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut ctx = SwCreateCtx {
                hresult: 0,
                instance_id: [0u16; 256],
                event,
            };

            let stub_info = SwDeviceCreateInfo {
                cb_size: std::mem::size_of::<SwDeviceCreateInfo>() as u32,
                psz_instance_id: instance_guid_str.as_ptr(),
                pszz_hardware_ids: empty_hwids.as_ptr(),
                pszz_compatible_ids: std::ptr::null(),
                p_container_id: std::ptr::null(),
                capability_flags: SW_DEVICE_CAPABILITIES,
                psz_device_description: tunnel_desc.as_ptr(),
                psz_device_location: std::ptr::null(),
                p_security_descriptor: std::ptr::null(),
            };
            let stub_props = [DevProperty {
                comp_key: DevPropCompKey {
                    key: DEVPKEY_DEVICE_CLASS_GUID,
                    store: DEVPROP_STORE_SYSTEM,
                    locale_name: std::ptr::null(),
                },
                prop_type: DEVPROP_TYPE_GUID,
                buffer_size: std::mem::size_of::<Guid>() as u32,
                buffer: &GUID_DEVCLASS_NET as *const Guid as *const c_void,
            }];

            let mut stub_sw: HSwDevice = std::ptr::null_mut();
            let hr = unsafe {
                SwDeviceCreate(
                    enumerator_wintun.as_ptr(),
                    root_name.as_ptr(),
                    &stub_info,
                    stub_props.len() as u32,
                    stub_props.as_ptr(),
                    sw_device_create_cb,
                    &mut ctx as *mut SwCreateCtx as *mut c_void,
                    &mut stub_sw,
                )
            };
            if hr >= 0 {
                unsafe {
                    WaitForSingleObject(ctx.event, 10_000);
                }
                if ctx.hresult >= 0 {
                    let mut dev_inst: u32 = 0;
                    if unsafe {
                        CM_Locate_DevNodeW(
                            &mut dev_inst,
                            ctx.instance_id.as_ptr(),
                            CM_LOCATE_DEVNODE_PHANTOM,
                        )
                    } == CR_SUCCESS
                    {
                        let mut drv_key: HKey = std::ptr::null_mut();
                        if unsafe {
                            CM_Open_DevNode_Key(
                                dev_inst,
                                KEY_SET_VALUE,
                                0,
                                0,
                                &mut drv_key,
                                CM_REGISTRY_SOFTWARE,
                            )
                        } == CR_SUCCESS
                        {
                            let val_name = to_wide("SuggestedInstanceId");
                            unsafe {
                                RegSetValueExW(
                                    drv_key,
                                    val_name.as_ptr(),
                                    0,
                                    REG_BINARY,
                                    &instance_guid as *const Guid as *const u8,
                                    std::mem::size_of::<Guid>() as u32,
                                );
                                RegCloseKey(drv_key);
                            }
                        }
                    }
                }
                if !stub_sw.is_null() {
                    unsafe {
                        SwDeviceClose(stub_sw);
                    }
                }
            }

            let create_info = SwDeviceCreateInfo {
                cb_size: std::mem::size_of::<SwDeviceCreateInfo>() as u32,
                psz_instance_id: instance_guid_str.as_ptr(),
                pszz_hardware_ids: wintun_hwids.as_ptr(),
                pszz_compatible_ids: std::ptr::null(),
                p_container_id: std::ptr::null(),
                capability_flags: SW_DEVICE_CAPABILITIES,
                psz_device_description: tunnel_desc.as_ptr(),
                psz_device_location: std::ptr::null(),
                p_security_descriptor: std::ptr::null(),
            };
            let props = [
                DevProperty {
                    comp_key: DevPropCompKey {
                        key: DEVPKEY_WINTUN_NAME,
                        store: DEVPROP_STORE_SYSTEM,
                        locale_name: std::ptr::null(),
                    },
                    prop_type: DEVPROP_TYPE_STRING,
                    buffer_size: (wide_name.len() * 2) as u32,
                    buffer: wide_name.as_ptr() as *const c_void,
                },
                DevProperty {
                    comp_key: DevPropCompKey {
                        key: DEVPKEY_DEVICE_FRIENDLY_NAME,
                        store: DEVPROP_STORE_SYSTEM,
                        locale_name: std::ptr::null(),
                    },
                    prop_type: DEVPROP_TYPE_STRING,
                    buffer_size: (tunnel_desc.len() * 2) as u32,
                    buffer: tunnel_desc.as_ptr() as *const c_void,
                },
                DevProperty {
                    comp_key: DevPropCompKey {
                        key: DEVPKEY_DEVICE_DESC,
                        store: DEVPROP_STORE_SYSTEM,
                        locale_name: std::ptr::null(),
                    },
                    prop_type: DEVPROP_TYPE_STRING,
                    buffer_size: (tunnel_desc.len() * 2) as u32,
                    buffer: tunnel_desc.as_ptr() as *const c_void,
                },
            ];

            let mut sw_device: HSwDevice = std::ptr::null_mut();
            let hr = unsafe {
                SwDeviceCreate(
                    enumerator_wintun.as_ptr(),
                    root_name.as_ptr(),
                    &create_info,
                    props.len() as u32,
                    props.as_ptr(),
                    sw_device_create_cb,
                    &mut ctx as *mut SwCreateCtx as *mut c_void,
                    &mut sw_device,
                )
            };
            if hr < 0 {
                unsafe {
                    CloseHandle(ctx.event);
                }
                return Err(io::Error::other(format!(
                    "SwDeviceCreate failed: 0x{hr:x} (запустите приложение от имени Администратора)"
                )));
            }

            let wait_rc = unsafe { WaitForSingleObject(ctx.event, 15_000) };
            unsafe {
                CloseHandle(ctx.event);
            }
            if wait_rc != 0 || ctx.hresult < 0 {
                unsafe {
                    SwDeviceClose(sw_device);
                }
                return Err(io::Error::other(format!(
                    "SwDeviceCreate callback error: 0x{:x}",
                    ctx.hresult
                )));
            }

            let dev_info = unsafe {
                SetupDiCreateDeviceInfoListExW(
                    &GUID_DEVCLASS_NET,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            if dev_info.is_null() || dev_info == INVALID_HANDLE_VALUE {
                unsafe {
                    SwDeviceClose(sw_device);
                }
                return Err(io::Error::last_os_error());
            }

            let mut dev_info_data = SpDevInfoData {
                cb_size: std::mem::size_of::<SpDevInfoData>() as u32,
                class_guid: GUID_DEVCLASS_NET,
                dev_inst: 0,
                reserved: 0,
            };

            let mut interface_filename = None;
            let mut alias_info = None;
            for _ in 0..300 {
                if interface_filename.is_none() {
                    interface_filename = query_device_object_filename(&ctx.instance_id);
                }
                if alias_info.is_none() {
                    let opened = unsafe {
                        SetupDiOpenDeviceInfoW(
                            dev_info,
                            ctx.instance_id.as_ptr(),
                            std::ptr::null_mut(),
                            DIOD_INHERIT_CLASSDRVS,
                            &mut dev_info_data,
                        )
                    };
                    if opened != 0 {
                        alias_info = query_adapter_guid_and_alias(dev_info, &mut dev_info_data);
                    }
                }
                if interface_filename.is_some() && alias_info.is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            let Some(interface_filename) = interface_filename else {
                unsafe {
                    SetupDiDestroyDeviceInfoList(dev_info);
                    SwDeviceClose(sw_device);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for Wintun NDIS device interface",
                ));
            };

            let effective_name = alias_info
                .map(|(_, alias)| try_rename_interface_alias(&alias, name))
                .unwrap_or_else(|| name.to_string());

            Ok(Self {
                sw_device,
                dev_info,
                dev_info_data,
                interface_filename,
                effective_name,
            })
        }
    }

    impl Drop for NativeAdapter {
        fn drop(&mut self) {
            if !self.sw_device.is_null() {
                unsafe {
                    SwDeviceClose(self.sw_device);
                }
            }
            if !self.dev_info.is_null() && self.dev_info != INVALID_HANDLE_VALUE {
                let remove_params = SpRemoveDeviceParams {
                    class_install_header: SpClassInstallHeader {
                        cb_size: std::mem::size_of::<SpClassInstallHeader>() as u32,
                        install_function: DIF_REMOVE,
                    },
                    scope: DI_REMOVEDEVICE_GLOBAL,
                    hw_profile: 0,
                };
                unsafe {
                    if SetupDiSetClassInstallParamsW(
                        self.dev_info,
                        &mut self.dev_info_data,
                        &remove_params.class_install_header,
                        std::mem::size_of::<SpRemoveDeviceParams>() as u32,
                    ) != 0
                    {
                        SetupDiCallClassInstaller(
                            DIF_REMOVE,
                            self.dev_info,
                            &mut self.dev_info_data,
                        );
                    }
                    SetupDiDestroyDeviceInfoList(self.dev_info);
                }
            }
        }
    }

    struct NativeRingSession {
        dev_handle: Handle,
        region_ptr: *mut u8,
        send_ring: *mut TunRing,
        receive_ring: *mut TunRing,
        send_tail_moved: Handle,
        receive_tail_moved: Handle,
        capacity: u32,
        send_head: std::sync::Mutex<u32>,
        receive_tail: std::sync::Mutex<u32>,
    }

    unsafe impl Send for NativeRingSession {}
    unsafe impl Sync for NativeRingSession {}

    impl NativeRingSession {
        fn start(interface_filename: &[u16], capacity: u32) -> io::Result<Self> {
            let ring_size = tun_ring_size(capacity) as usize;
            let region_ptr = unsafe {
                VirtualAlloc(
                    std::ptr::null_mut(),
                    ring_size * 2,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if region_ptr.is_null() {
                return Err(io::Error::last_os_error());
            }

            let send_ring = region_ptr as *mut TunRing;
            let receive_ring = unsafe { region_ptr.add(ring_size) as *mut TunRing };

            let send_tail_moved =
                unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
            if send_tail_moved.is_null() {
                let err = io::Error::last_os_error();
                unsafe {
                    VirtualFree(region_ptr as *mut c_void, 0, MEM_RELEASE);
                }
                return Err(err);
            }

            let receive_tail_moved =
                unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
            if receive_tail_moved.is_null() {
                let err = io::Error::last_os_error();
                unsafe {
                    CloseHandle(send_tail_moved);
                    VirtualFree(region_ptr as *mut c_void, 0, MEM_RELEASE);
                }
                return Err(err);
            }

            let dev_handle = unsafe {
                CreateFileW(
                    interface_filename.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if dev_handle.is_null() || dev_handle == INVALID_HANDLE_VALUE {
                let err = io::Error::last_os_error();
                unsafe {
                    CloseHandle(receive_tail_moved);
                    CloseHandle(send_tail_moved);
                    VirtualFree(region_ptr as *mut c_void, 0, MEM_RELEASE);
                }
                return Err(err);
            }

            let reg = TunRegisterRings {
                send: TunRingDescriptor {
                    ring_size: ring_size as u32,
                    ring: send_ring,
                    tail_moved: send_tail_moved,
                },
                receive: TunRingDescriptor {
                    ring_size: ring_size as u32,
                    ring: receive_ring,
                    tail_moved: receive_tail_moved,
                },
            };

            let mut bytes_returned: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    dev_handle,
                    TUN_IOCTL_REGISTER_RINGS,
                    &reg as *const TunRegisterRings as *const c_void,
                    std::mem::size_of::<TunRegisterRings>() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    CloseHandle(dev_handle);
                    CloseHandle(receive_tail_moved);
                    CloseHandle(send_tail_moved);
                    VirtualFree(region_ptr as *mut c_void, 0, MEM_RELEASE);
                }
                return Err(err);
            }

            Ok(Self {
                dev_handle,
                region_ptr,
                send_ring,
                receive_ring,
                send_tail_moved,
                receive_tail_moved,
                capacity,
                send_head: std::sync::Mutex::new(0),
                receive_tail: std::sync::Mutex::new(0),
            })
        }

        fn try_receive_packet(&self) -> io::Result<Option<Vec<u8>>> {
            let mut head_guard = self.send_head.lock().unwrap();
            let head = *head_guard;
            if head >= self.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Wintun send ring head out of bounds",
                ));
            }
            let ring = unsafe { &*self.send_ring };
            let mut buff_tail = ring.tail.load(Ordering::Acquire);
            if buff_tail >= self.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Wintun send ring tail out of bounds",
                ));
            }
            if head == buff_tail {
                ring.alertable.store(1, Ordering::SeqCst);
                buff_tail = ring.tail.load(Ordering::Acquire);
                if head == buff_tail {
                    return Ok(None);
                }
                ring.alertable.store(0, Ordering::Relaxed);
            } else {
                ring.alertable.store(0, Ordering::Relaxed);
            }
            let buff_content = tun_ring_wrap(buff_tail.wrapping_sub(head), self.capacity);
            if buff_content < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun send ring frame shorter than header",
                ));
            }
            let data_base =
                unsafe { (self.send_ring as *const u8).add(std::mem::size_of::<TunRing>()) };
            let pkt_ptr = unsafe { data_base.add(head as usize) };
            let pkt_size =
                unsafe { std::ptr::read_unaligned(pkt_ptr as *const u32) } & !TUN_PACKET_RELEASE;
            if pkt_size > WINTUN_MAX_IP_PACKET_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun packet exceeds max IP packet size",
                ));
            }
            let aligned_pkt_size = tun_align(4 + pkt_size);
            if aligned_pkt_size > buff_content {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun incomplete packet in send ring",
                ));
            }
            let payload_slice =
                unsafe { std::slice::from_raw_parts(pkt_ptr.add(4), pkt_size as usize) };
            let owned = payload_slice.to_vec();

            let next_head = tun_ring_wrap(head.wrapping_add(aligned_pkt_size), self.capacity);
            *head_guard = next_head;
            ring.head.store(next_head, Ordering::Release);
            Ok(Some(owned))
        }

        fn send_packet(&self, pkt: &[u8]) -> io::Result<usize> {
            if pkt.is_empty() || pkt.len() > WINTUN_MAX_IP_PACKET_SIZE as usize {
                return Ok(0);
            }
            let pkt_size = pkt.len() as u32;
            let aligned_pkt_size = tun_align(4 + pkt_size);

            let mut tail_guard = self.receive_tail.lock().unwrap();
            let tail = *tail_guard;
            if tail >= self.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Wintun receive ring tail out of bounds",
                ));
            }
            let ring = unsafe { &*self.receive_ring };
            let buff_head = ring.head.load(Ordering::Acquire);
            if buff_head >= self.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Wintun receive ring head out of bounds",
                ));
            }
            let buff_space = tun_ring_wrap(
                buff_head.wrapping_sub(tail).wrapping_sub(TUN_ALIGNMENT),
                self.capacity,
            );
            if aligned_pkt_size > buff_space {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Wintun receive ring full",
                ));
            }
            let data_base =
                unsafe { (self.receive_ring as *mut u8).add(std::mem::size_of::<TunRing>()) };
            let pkt_ptr = unsafe { data_base.add(tail as usize) };
            unsafe {
                std::ptr::write_unaligned(pkt_ptr as *mut u32, pkt_size);
                std::ptr::copy_nonoverlapping(pkt.as_ptr(), pkt_ptr.add(4), pkt.len());
            }
            let next_tail = tun_ring_wrap(tail.wrapping_add(aligned_pkt_size), self.capacity);
            *tail_guard = next_tail;
            ring.tail.store(next_tail, Ordering::Release);
            std::sync::atomic::fence(Ordering::SeqCst);
            if ring.alertable.load(Ordering::Acquire) != 0 {
                unsafe {
                    SetEvent(self.receive_tail_moved);
                }
            }
            Ok(pkt.len())
        }
    }

    impl Drop for NativeRingSession {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.dev_handle);
                CloseHandle(self.send_tail_moved);
                CloseHandle(self.receive_tail_moved);
                VirtualFree(self.region_ptr as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }

    pub struct WinTunDevice {
        session: std::sync::Arc<NativeRingSession>,
        _adapter: NativeAdapter,
        stop_event: usize,
        reader_thread: Option<std::thread::JoinHandle<()>>,
        rx_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
        name: String,
        auto_route: bool,
        ipv4_gw: Option<Ipv4Addr>,
        has_v6: bool,
    }

    unsafe impl Send for WinTunDevice {}
    unsafe impl Sync for WinTunDevice {}

    impl WinTunDevice {
        pub fn open(
            name: &str,
            mtu: usize,
            v4_addrs: &[(Ipv4Addr, u8)],
            v6_addrs: &[(Ipv6Addr, u8)],
            auto_route: bool,
        ) -> io::Result<Self> {
            let mut best_if: u32 = 0;
            if auto_route {
                if let Some(&(ip, _)) = v4_addrs.first() {
                    let gw_str = ip.to_string();
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "delete",
                        "route",
                        "0.0.0.0/1",
                        name,
                        &gw_str,
                    ]);
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "delete",
                        "route",
                        "128.0.0.0/1",
                        name,
                        &gw_str,
                    ]);
                }
                let rc = unsafe { GetBestInterface(0x0808_0808, &mut best_if) };
                if rc == 0 && best_if != 0 {
                    WIN_OUTBOUND_IF_INDEX.store(best_if, Ordering::Release);
                }
            }

            let res = (|| -> io::Result<Self> {
                let adapter = NativeAdapter::create_or_open(name)?;
                let effective_name = adapter.effective_name.clone();
                let session = std::sync::Arc::new(NativeRingSession::start(
                    &adapter.interface_filename,
                    RING_CAPACITY,
                )?);

                let stop_event =
                    unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
                if stop_event.is_null() {
                    return Err(io::Error::last_os_error());
                }

                let mut ipv4_gw = None;
                if let Some(&(ip, prefix)) = v4_addrs.first() {
                    let mask = prefix_to_ipv4_netmask(prefix);
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "set",
                        "address",
                        &format!("name={effective_name}"),
                        "source=static",
                        &format!("addr={ip}"),
                        &format!("mask={mask}"),
                        "store=active",
                    ]);
                    ipv4_gw = Some(ip);
                }
                run_netsh(&[
                    "interface",
                    "ipv4",
                    "set",
                    "subinterface",
                    &effective_name,
                    &format!("mtu={mtu}"),
                    "store=active",
                ]);

                if auto_route && let Some(gw) = ipv4_gw {
                    let gw_str = gw.to_string();
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        "0.0.0.0/1",
                        &effective_name,
                        &gw_str,
                        "metric=1",
                        "store=active",
                    ]);
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        "128.0.0.0/1",
                        &effective_name,
                        &gw_str,
                        "metric=1",
                        "store=active",
                    ]);
                }

                let (rx_tx, rx_rx) = mpsc::channel::<Vec<u8>>(1024);
                let session_reader = std::sync::Arc::clone(&session);
                let read_event_addr = session.send_tail_moved as usize;
                let stop_event_addr = stop_event as usize;

                let reader_thread = std::thread::Builder::new()
                    .name(format!("wintun-rx-{effective_name}"))
                    .spawn(move || {
                        let handles = [read_event_addr as Handle, stop_event_addr as Handle];
                        loop {
                            match session_reader.try_receive_packet() {
                                Ok(Some(pkt)) => {
                                    if rx_tx.blocking_send(pkt).is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                Ok(None) => {}
                                Err(_) => break,
                            }
                            let wait_rc =
                                unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 100) };
                            if wait_rc == 1 {
                                break;
                            }
                        }
                    })?;

                Ok(Self {
                    session,
                    _adapter: adapter,
                    stop_event: stop_event as usize,
                    reader_thread: Some(reader_thread),
                    rx_rx: Mutex::new(rx_rx),
                    name: effective_name,
                    auto_route,
                    ipv4_gw,
                    has_v6: !v6_addrs.is_empty(),
                })
            })();

            if res.is_err() && auto_route {
                WIN_OUTBOUND_IF_INDEX.store(0, Ordering::Release);
            }
            res
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut rx = self.rx_rx.lock().await;
            match rx.recv().await {
                Some(pkt) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }

        pub fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
            self.session.send_packet(pkt)
        }
    }

    impl Drop for WinTunDevice {
        fn drop(&mut self) {
            unsafe {
                SetEvent(self.stop_event as Handle);
            }
            if let Some(handle) = self.reader_thread.take() {
                let _ = handle.join();
            }
            if self.auto_route {
                WIN_OUTBOUND_IF_INDEX.store(0, Ordering::Release);
                if let Some(gw) = self.ipv4_gw {
                    let gw_str = gw.to_string();
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "delete",
                        "route",
                        "0.0.0.0/1",
                        &self.name,
                        &gw_str,
                    ]);
                    run_netsh(&[
                        "interface",
                        "ipv4",
                        "delete",
                        "route",
                        "128.0.0.0/1",
                        &self.name,
                        &gw_str,
                    ]);
                }
                if self.has_v6 {
                    run_netsh(&["interface", "ipv6", "delete", "route", "::/1", &self.name]);
                    run_netsh(&[
                        "interface",
                        "ipv6",
                        "delete",
                        "route",
                        "8000::/1",
                        &self.name,
                    ]);
                }
            }
            unsafe {
                CloseHandle(self.stop_event as Handle);
            }
        }
    }
}
