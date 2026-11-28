//! Системный захват трафика уровня L3 через виртуальный сетевой адаптер TUN
//! (`Wintun` через прямые кольцевые буферы `wintun.sys` на Windows, `/dev/net/tun` на Linux),
//! виртуальный стек `smoltcp` для TCP и обработка UDP/DNS с извлечением `IP -> Домен`.

#[cfg(windows)]
use crate::desync::WIN_OUTBOUND_IF_INDEX;
use crate::desync::{
    bind_outbound_socket, extract_hostname, is_quic_dead_for_target, is_quic_long_header,
    report_udp_quic_outcome_with_host, send_udp_fakes_same_tuple_with_host,
};
use crate::lists::{CompiledMatcher, MatchDecision, record_dns_mapping};
use crate::proxy::{LogCallback, TrafficCounters};
use crate::upstream_compat::{
    ACTIVE_QUIC_FAST_FAILOVER, ACTIVE_TUN_IPV6, ACTIVE_TUN_MSS_CLAMP, ACTIVE_TUN_MTU,
    TcpCongestionMode, active_tcp_congestion_mode,
};
use bytes::Bytes;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{
    Device, DeviceCapabilities, Medium, RxToken as PhyRxToken, TxToken as PhyTxToken,
};
use smoltcp::socket::tcp::{
    CongestionControl as SmolCongestionControl, Socket as TcpSocket,
    SocketBuffer as TcpSocketBuffer, State as TcpState,
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock, mpsc};

const TUN_QUEUE_CAP: usize = 512;
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

/// Зажим TCP SYN MSS и обход цепочки расширенных заголовков IPv6 (`0`, `43`, `44`, `51`, `60`)
/// из движка `tachyon-core 0.5.7`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MssClamp {
    enabled: bool,
    maximum_segment_size: u16,
}

impl MssClamp {
    fn for_mtu(mtu: usize) -> Self {
        let ipv4_mss = mtu.saturating_sub(40);
        if ipv4_mss < 536 {
            return Self::default();
        }
        Self {
            enabled: true,
            maximum_segment_size: ipv4_mss.min(u16::MAX as usize) as u16,
        }
    }

    fn apply_in_place(&self, packet: &mut [u8]) -> bool {
        if !self.enabled || !ACTIVE_TUN_MSS_CLAMP.load(Ordering::Relaxed) {
            return false;
        }
        let Some(first) = packet.first().copied() else {
            return false;
        };
        let mut effective = self.maximum_segment_size;
        if (first >> 4) == 6 {
            let Some(adjusted) = effective.checked_sub(20).filter(|&v| v > 0) else {
                return false;
            };
            effective = adjusted;
        }
        let Some(tcp_off) = locate_tcp_syn_segment(packet) else {
            return false;
        };
        clamp_tcp_syn_segment_mss(&mut packet[tcp_off..], effective)
    }
}

fn ipv6_payload_offset_proto(packet: &[u8]) -> Option<(u8, usize)> {
    if packet.len() < 40 || (packet[0] >> 4) != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let end = 40usize.checked_add(payload_len)?;
    if packet.len() < end {
        return None;
    }
    let mut next_header = packet[6];
    let mut offset = 40usize;
    for _ in 0..16 {
        match next_header {
            0 | 43 | 60 => {
                if offset + 8 > end {
                    return None;
                }
                let ext_len = (packet[offset + 1] as usize + 1) * 8;
                if offset + ext_len > end {
                    return None;
                }
                next_header = packet[offset];
                offset += ext_len;
            }
            44 => {
                if offset + 8 > end {
                    return None;
                }
                let frag_off_and_m =
                    u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) & 0xfff9;
                if frag_off_and_m != 0 {
                    return None;
                }
                next_header = packet[offset];
                offset += 8;
            }
            51 => {
                if offset + 8 > end {
                    return None;
                }
                let ext_len = (packet[offset + 1] as usize + 2) * 4;
                if ext_len < 8 || offset + ext_len > end {
                    return None;
                }
                next_header = packet[offset];
                offset += ext_len;
            }
            59 => return None,
            proto => return Some((proto, offset)),
        }
    }
    None
}

fn locate_tcp_syn_segment(packet: &[u8]) -> Option<usize> {
    if packet.is_empty() {
        return None;
    }
    let ip_hdr_len = match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            if u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
                || (u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff) != 0
            {
                return None;
            }
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ihl > packet.len() || packet[9] != 6 {
                return None;
            }
            ihl
        }
        6 => {
            let (proto, off) = ipv6_payload_offset_proto(packet)?;
            if proto != 6 {
                return None;
            }
            off
        }
        _ => return None,
    };
    if packet.len() < ip_hdr_len + 20 {
        return None;
    }
    if (packet[ip_hdr_len + 13] & 0x02) == 0 {
        return None;
    }
    Some(ip_hdr_len)
}

fn clamp_tcp_syn_segment_mss(tcp_segment: &mut [u8], max_mss: u16) -> bool {
    let data_offset = ((tcp_segment[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > tcp_segment.len() {
        return false;
    }
    let mut clamped = false;
    let mut off = 20usize;
    while off < data_offset {
        let kind = tcp_segment[off];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            off += 1;
            continue;
        }
        if off + 1 >= data_offset {
            break;
        }
        let opt_len = tcp_segment[off + 1] as usize;
        if opt_len < 2 || off + opt_len > data_offset {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let val_off = off + 2;
            let advertised = u16::from_be_bytes([tcp_segment[val_off], tcp_segment[val_off + 1]]);
            if advertised > max_mss {
                tcp_segment[val_off..val_off + 2].copy_from_slice(&max_mss.to_be_bytes());
                let (mut prev, mut next) = (advertised, max_mss);
                if !val_off.is_multiple_of(2) {
                    prev = prev.swap_bytes();
                    next = next.swap_bytes();
                }
                let cur_sum = u16::from_be_bytes([tcp_segment[16], tcp_segment[17]]);
                let mut sum = u32::from(!cur_sum) + u32::from(!prev) + u32::from(next);
                while (sum >> 16) != 0 {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                let new_sum = !(sum as u16);
                tcp_segment[16..18].copy_from_slice(&new_sum.to_be_bytes());
                clamped = true;
            }
        }
        off += opt_len;
    }
    clamped
}

/// Виртуальное устройство `smoltcp`, обменивающееся IP-пакетами с платформенным TUN.
struct VirtualTunDevice {
    mtu: usize,
    clamp: MssClamp,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualTunDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            clamp: MssClamp::for_mtu(mtu),
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
    clamp: MssClamp,
}

impl PhyTxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.clamp.apply_in_place(&mut buffer);
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
        let mut packet = self.rx_queue.pop_front()?;
        self.clamp.apply_in_place(&mut packet);
        Some((
            VirtualRxToken { packet },
            VirtualTxToken {
                queue: &mut self.tx_queue,
                clamp: self.clamp,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() >= TUN_QUEUE_CAP {
            return None;
        }
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
            clamp: self.clamp,
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
type TunReserveFut = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    tokio::sync::mpsc::OwnedPermit<bytes::Bytes>,
                    tokio::sync::mpsc::error::SendError<()>,
                >,
            > + Send,
    >,
>;

pub struct TunStream {
    rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<Bytes>,
    notify: Arc<Notify>,
    peer_closed: Arc<AtomicBool>,
    current: Option<(Bytes, usize)>,
    reserve_fut: Option<TunReserveFut>,
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
        mut self: Pin<&mut Self>,
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
        if let Some(mut fut) = self.reserve_fut.take() {
            match std::future::Future::poll(fut.as_mut(), cx) {
                Poll::Ready(Ok(permit)) => {
                    permit.send(Bytes::copy_from_slice(&buf[..take]));
                    self.notify.notify_one();
                    return Poll::Ready(Ok(take));
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
                Poll::Pending => {
                    self.reserve_fut = Some(fut);
                    return Poll::Pending;
                }
            }
        }
        match self.tx.try_send(Bytes::copy_from_slice(&buf[..take])) {
            Ok(()) => {
                self.notify.notify_one();
                Poll::Ready(Ok(take))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.notify.notify_one();
                let mut fut = Box::pin(self.tx.clone().reserve_owned());
                match std::future::Future::poll(fut.as_mut(), cx) {
                    Poll::Ready(Ok(permit)) => {
                        permit.send(Bytes::copy_from_slice(&buf[..take]));
                        self.notify.notify_one();
                        Poll::Ready(Ok(take))
                    }
                    Poll::Ready(Err(_)) => {
                        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                    }
                    Poll::Pending => {
                        self.reserve_fut = Some(fut);
                        Poll::Pending
                    }
                }
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
        let (next_hdr, l4_off) = ipv6_payload_offset_proto(pkt)?;
        if l4_off + 8 > pkt.len() {
            return None;
        }
        let mut s6 = [0u8; 16];
        let mut d6 = [0u8; 16];
        s6.copy_from_slice(&pkt[8..24]);
        d6.copy_from_slice(&pkt[24..40]);
        let src_ip = IpAddr::V6(Ipv6Addr::from(s6));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(d6));
        let src_port = u16::from_be_bytes([pkt[l4_off], pkt[l4_off + 1]]);
        let dst_port = u16::from_be_bytes([pkt[l4_off + 2], pkt[l4_off + 3]]);
        if next_hdr == 6 {
            if l4_off + 20 > pkt.len() {
                return None;
            }
            let tcp_hdr_len = ((pkt[l4_off + 12] >> 4) as usize) * 4;
            let flags = pkt[l4_off + 13];
            Some((
                6,
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
                flags,
                l4_off + tcp_hdr_len,
            ))
        } else if next_hdr == 17 {
            Some((
                17,
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
                0,
                l4_off + 8,
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
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr,
    };
    let udp_repr = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let udp_len = udp_repr.header_len() + payload.len();
    let caps = ChecksumCapabilities::default();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            let ip_repr = Ipv4Repr {
                src_addr: s4,
                dst_addr: d4,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let ip_hdr_len = ip_repr.buffer_len();
            let mut buf = vec![0u8; ip_hdr_len + udp_len];
            {
                let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
                ip_repr.emit(&mut ip_pkt, &caps);
            }
            {
                let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
                udp_repr.emit(
                    &mut udp_pkt,
                    &IpAddress::Ipv4(s4),
                    &IpAddress::Ipv4(d4),
                    payload.len(),
                    |dst_buf| dst_buf.copy_from_slice(payload),
                    &caps,
                );
            }
            Some(buf)
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            let ip_repr = Ipv6Repr {
                src_addr: s6,
                dst_addr: d6,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let ip_hdr_len = ip_repr.buffer_len();
            let mut buf = vec![0u8; ip_hdr_len + udp_len];
            {
                let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
                ip_repr.emit(&mut ip_pkt);
            }
            {
                let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
                udp_repr.emit(
                    &mut udp_pkt,
                    &IpAddress::Ipv6(s6),
                    &IpAddress::Ipv6(d6),
                    payload.len(),
                    |dst_buf| dst_buf.copy_from_slice(payload),
                    &caps,
                );
            }
            Some(buf)
        }
        _ => None,
    }
}

/// Вычислить задержку ожидания пакета TUN на основе таймеров виртуального стека `smoltcp`.
fn compute_tun_poll_timeout(
    poll_delay: Option<smoltcp::time::Duration>,
    has_active_tcp: bool,
) -> Duration {
    const MIN_DELAY: Duration = Duration::from_millis(1);
    const IDLE_MAX_DELAY: Duration = Duration::from_millis(250);
    const ACTIVE_FALLBACK_DELAY: Duration = Duration::from_millis(25);

    match poll_delay {
        Some(delay) => Duration::from_micros(delay.total_micros()).clamp(MIN_DELAY, IDLE_MAX_DELAY),
        None => {
            if has_active_tcp {
                ACTIVE_FALLBACK_DELAY
            } else {
                IDLE_MAX_DELAY
            }
        }
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
    let mtu = (ACTIVE_TUN_MTU.load(Ordering::Relaxed) as usize).clamp(1280, 9000);
    let enable_v6 = ACTIVE_TUN_IPV6.load(Ordering::Relaxed);
    let v4_addrs = [(Ipv4Addr::new(172, 19, 0, 1), 30u8)];
    let v6_addrs_storage = [(Ipv6Addr::new(0xfd00, 0x172, 0x19, 0, 0, 0, 0, 1), 126u8)];
    let v6_addrs: &[(Ipv6Addr, u8)] = if enable_v6 { &v6_addrs_storage } else { &[] };
    let max_tcp_sessions =
        crate::hardware::HardwareProfile::detect().current_tun_max_tcp_sessions();

    let platform_dev = PlatformTunHandle::open(interface_name, mtu, &v4_addrs, v6_addrs, true)?;
    let cc_mode = active_tcp_congestion_mode();
    (log_fn)(
        "info",
        "tun",
        &format!(
            "Системный интерфейс TUN «{}» активирован (MTU {mtu}, IPv4 172.19.0.1/30{}, CC={}, макс. сессий TCP={max_tcp_sessions})",
            platform_dev.name(),
            if enable_v6 {
                ", IPv6 fd00:172:19::1/126"
            } else {
                ""
            },
            cc_mode.as_str(),
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
    let mut udp_sessions: lru::LruCache<(SocketAddr, SocketAddr), Instant> =
        lru::LruCache::new(std::num::NonZeroUsize::new(MAX_UDP_SESSIONS).unwrap());
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
        let wait_timeout = compute_tun_poll_timeout(
            iface.poll_delay(SmolInstant::now(), &sockets),
            !tcp_sessions.is_empty(),
        );
        tokio::select! {
            biased;
            read_res = tokio::time::timeout(wait_timeout, platform_dev.read_packet(&mut pkt_buf)) => {
                if let Ok(Ok(n)) = read_res && n > 0 {
                    let pkt = &pkt_buf[..n];
                    if let Some((proto, src, dst, flags, payload_off)) = parse_ip_packet_meta(pkt) {
                        if !is_routable_tun_destination(dst.ip()) {
                            continue;
                        }
                        if proto == 6 {
                            // TCP-пакет
                            let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
                            if is_syn
                                && !tcp_sessions.contains_key(&(src, dst))
                                && tcp_sessions.len() < max_tcp_sessions
                            {
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
                            let is_first_udp = udp_sessions
                                .get(&(src, dst))
                                .is_none_or(|ts| ts.elapsed() >= Duration::from_secs(60));
                            udp_sessions.put((src, dst), Instant::now());

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

#[inline]
fn active_smoltcp_congestion_control() -> SmolCongestionControl {
    match active_tcp_congestion_mode() {
        TcpCongestionMode::Bbr => SmolCongestionControl::Bbr,
        TcpCongestionMode::Cubic => SmolCongestionControl::Cubic,
        TcpCongestionMode::Reno => SmolCongestionControl::Reno,
        TcpCongestionMode::None => SmolCongestionControl::None,
    }
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
    let init_buf = crate::hardware::smol_tcp_init_buf();
    let active_streams = sessions
        .values()
        .filter(|s| {
            !s.app_closed
                && !s.peer_closed.load(Ordering::Relaxed)
                && s.to_app.as_ref().is_some_and(|tx| !tx.is_closed())
        })
        .count();
    let max_buf = crate::hardware::smol_tcp_fair_max_buf(active_streams + 1);
    if active_streams >= 1 {
        for s in sessions.values().filter(|s| {
            !s.app_closed
                && !s.peer_closed.load(Ordering::Relaxed)
                && s.to_app.as_ref().is_some_and(|tx| !tx.is_closed())
        }) {
            sockets
                .get_mut::<TcpSocket>(s.handle)
                .set_auto_tune_max(max_buf);
        }
    }

    let rx_buf = TcpSocketBuffer::new(vec![0u8; init_buf]);
    let tx_buf = TcpSocketBuffer::new(vec![0u8; init_buf]);
    let mut sock = TcpSocket::new(rx_buf, tx_buf);
    sock.set_auto_tune_max(max_buf);
    sock.set_congestion_control(active_smoltcp_congestion_control());
    sock.set_nagle_enabled(false);
    sock.set_ack_delay(None);
    sock.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));

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
            reserve_fut: None,
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
    crate::proxy::execute_tcp_decision(
        client, dst_addr, first_pkt, sni_host, app_name, decision, "TUN", counters, log_fn,
    )
    .await
}

static TUN_NAT_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

#[inline]
fn nat_now_ms() -> u64 {
    TUN_NAT_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis() as u64
}

const UDP_NAT_IDLE_MS: u64 = 60_000;
const UDP_NAT_MAX_ENTRIES: usize = 1024;

type AdaptiveUdpPeersMap = HashMap<SocketAddr, (u64, bool, Option<String>)>;

#[derive(Clone)]
struct TunUdpNatEntry {
    sock: Arc<UdpSocket>,
    /// Отслеживаемые адаптивные UDP-узлы: `peer -> (rx_bytes, reported_ok, host_opt)`
    adaptive_peers: Arc<std::sync::Mutex<AdaptiveUdpPeersMap>>,
    last_active_ms: Arc<std::sync::atomic::AtomicU64>,
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
    track_adaptive_target: Option<(SocketAddr, Option<String>)>,
    udp_nat: &TunUdpNatTable,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    counters: &Arc<TrafficCounters>,
) -> io::Result<Arc<UdpSocket>> {
    let now_ms = nat_now_ms();
    if let Ok(mut guard) = udp_nat.lock() {
        if let Some(existing) = guard.get(&(src, is_ipv6)) {
            existing.last_active_ms.store(now_ms, Ordering::Relaxed);
            if let Some((dst, ref host)) = track_adaptive_target
                && let Ok(mut peers) = existing.adaptive_peers.lock()
                && peers.len() < 32
            {
                let entry = peers.entry(dst).or_insert((0, false, None));
                if entry.2.is_none() && host.is_some() {
                    entry.2 = host.clone();
                }
            }
            return Ok(existing.sock.clone());
        }
        guard.retain(|_, entry| {
            now_ms.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed)) <= UDP_NAT_IDLE_MS
        });
        if guard.len() >= UDP_NAT_MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP NAT table full",
            ));
        }
    }

    let sock = Arc::new(bind_and_connect_udp(is_ipv6).await?);
    let adaptive_peers = Arc::new(std::sync::Mutex::new(HashMap::new()));
    if let Some((dst, ref host)) = track_adaptive_target
        && let Ok(mut peers) = adaptive_peers.lock()
    {
        peers.insert(dst, (0, false, host.clone()));
    }
    let last_active_ms = Arc::new(std::sync::atomic::AtomicU64::new(nat_now_ms()));

    match udp_nat.lock() {
        Ok(mut guard) => {
            let now_ms = nat_now_ms();
            if let Some(existing) = guard.get(&(src, is_ipv6)) {
                existing.last_active_ms.store(now_ms, Ordering::Relaxed);
                if let Some((dst, host)) = track_adaptive_target
                    && let Ok(mut peers) = existing.adaptive_peers.lock()
                    && peers.len() < 32
                {
                    let entry = peers.entry(dst).or_insert((0, false, None));
                    if entry.2.is_none() && host.is_some() {
                        entry.2 = host;
                    }
                }
                return Ok(existing.sock.clone());
            }
            guard.retain(|_, entry| {
                now_ms.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed))
                    <= UDP_NAT_IDLE_MS
            });
            if guard.len() >= UDP_NAT_MAX_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP NAT table full",
                ));
            }
            guard.insert(
                (src, is_ipv6),
                TunUdpNatEntry {
                    sock: sock.clone(),
                    adaptive_peers: adaptive_peers.clone(),
                    last_active_ms: last_active_ms.clone(),
                },
            );
        }
        Err(_) => {
            return Err(io::Error::other("UDP NAT table lock poisoned"));
        }
    }

    let sock_reader = sock.clone();
    let nat_reader = udp_nat.clone();
    let peers_reader = adaptive_peers;
    let last_active_reader = last_active_ms;
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
                            last_active_reader.store(nat_now_ms(), Ordering::Relaxed);
                            counters_reader
                                .rx_bytes
                                .fetch_add(n as u64, Ordering::Relaxed);
                            let mut promote_host: Option<Option<String>> = None;
                            if let Ok(mut peers) = peers_reader.lock()
                                && let Some((rx_sum, reported, host_opt)) = peers.get_mut(&peer)
                            {
                                *rx_sum = rx_sum.saturating_add(n as u64);
                                // Для UDP 443 (QUIC) закрепляем рецепт только после 256 КиБ (`DESYNC_LIVE_PROMOTE_BYTES`),
                                // чтобы 16 KB QUIC cap не фиксировал мёртвый QUIC-узел как живой.
                                let promote_gate = if peer.port() == 443 {
                                    crate::desync::DESYNC_LIVE_PROMOTE_BYTES
                                } else {
                                    1
                                };
                                if !*reported && *rx_sum >= promote_gate {
                                    *reported = true;
                                    promote_host = Some(host_opt.clone());
                                }
                            }
                            if let Some(host_opt) = promote_host {
                                report_udp_quic_outcome_with_host(Some(peer), host_opt.as_deref(), true);
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
            for (&peer, (rx_sum, reported, host_opt)) in peers.iter() {
                if !*reported && *rx_sum == 0 {
                    report_udp_quic_outcome_with_host(Some(peer), host_opt.as_deref(), false);
                }
            }
        }
        if let Ok(mut guard) = nat_reader.lock()
            && let Some(entry) = guard.get(&(src, is_ipv6))
            && Arc::ptr_eq(&entry.sock, &sock_reader)
        {
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
                && ((config.block_quic && is_quic_long_header(&payload))
                    || (config.auto
                        && ACTIVE_QUIC_FAST_FAILOVER.load(Ordering::Relaxed)
                        && is_quic_dead_for_target(Some(dst), udp_host.as_deref())))
            {
                emit_tun_icmp_port_unreachable(&tun_tx, dst, src, &payload);
                return;
            }
            let track_dst = config.auto.then(|| (dst, udp_host.clone()));
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
                    let quic_mode = dst.port() == 443 && config.quic_desync && !config.block_quic;
                    let quic_rep = if config.quic_repeats > 0 {
                        config.quic_repeats
                    } else if config.udp_repeats > 0 {
                        config.udp_repeats
                    } else {
                        4
                    }
                    .clamp(1, 20);
                    let fg = crate::flows::register_flow(
                        "UDP",
                        app_name.as_deref(),
                        udp_host.as_deref(),
                        dst,
                        if quic_mode {
                            format!("QUIC Desync x{quic_rep}")
                        } else {
                            format!("UDP Fake x{}", config.udp_repeats)
                        },
                        true,
                        true,
                    );
                    fg.record.add_tx(payload.len() as u64);
                    if quic_mode || (dst.port() != 443 && config.udp_fake && config.udp_repeats > 0)
                    {
                        let shown_rep = if quic_mode {
                            quic_rep
                        } else {
                            config.udp_repeats
                        };
                        (log_fn)(
                            "info",
                            "udp_desync",
                            &format!(
                                "UDP{app_tag} {dst} -> [{matched_list}] фейков: {shown_rep}, TTL={}",
                                config.udp_fake_ttl
                            ),
                        );
                        let _ = send_udp_fakes_same_tuple_with_host(
                            &sock,
                            dst,
                            udp_host.as_deref(),
                            &config,
                        )
                        .await;
                    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveTunRoutes {
    adapter_name: String,
    ipv4_gw: Option<Ipv4Addr>,
    has_v6: bool,
}

static ACTIVE_TUN_ROUTES: std::sync::Mutex<Option<ActiveTunRoutes>> = std::sync::Mutex::new(None);

fn register_active_tun_routes(adapter_name: String, ipv4_gw: Option<Ipv4Addr>, has_v6: bool) {
    let mut guard = ACTIVE_TUN_ROUTES
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    *guard = Some(ActiveTunRoutes {
        adapter_name,
        ipv4_gw,
        has_v6,
    });
}

fn clear_active_tun_routes() {
    let mut guard = ACTIVE_TUN_ROUTES
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    *guard = None;
}

fn take_active_tun_routes() -> Option<ActiveTunRoutes> {
    ACTIVE_TUN_ROUTES
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .take()
}

fn cleanup_platform_tun_routes(adapter_name: &str, ipv4_gw: Option<Ipv4Addr>, has_v6: bool) {
    #[cfg(target_os = "windows")]
    windows_tun::cleanup_routes(adapter_name, ipv4_gw, has_v6);
    #[cfg(target_os = "linux")]
    {
        let _ = ipv4_gw;
        linux_tun::cleanup_routes(adapter_name, has_v6);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = ipv4_gw;
        macos_tun::cleanup_routes(adapter_name, has_v6);
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let _ = (adapter_name, ipv4_gw, has_v6);
}

/// Аварийно удалить добавленные маршруты TUN при завершении по сигналу или панике.
pub fn emergency_cleanup_tun_routes() {
    let Some(active) = take_active_tun_routes() else {
        return;
    };
    cleanup_platform_tun_routes(&active.adapter_name, active.ipv4_gw, active.has_v6);
}

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
            let dev = linux_tun::LinuxTunDevice::open(name, mtu, v4_addrs, v6_addrs, auto_route)?;
            Ok(Self::Linux(dev))
        }
        #[cfg(target_os = "macos")]
        {
            let _ = name;
            let dev = macos_tun::MacosTunDevice::open(mtu, v4_addrs, v6_addrs, auto_route)?;
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
        async_fd: AsyncFd<OwnedFd>,
        name: String,
        auto_route: bool,
        has_v6: bool,
    }

    pub(super) fn cleanup_routes(_name: &str, has_v6: bool) {
        crate::upstream_compat::LINUX_TUN_AUTO_ROUTE_ACTIVE
            .store(0, std::sync::atomic::Ordering::Release);
        for mark_arg in ["0x2022/0xffff", "0x2022"] {
            let _ = std::process::Command::new("ip")
                .args([
                    "rule", "del", "not", "fwmark", mark_arg, "lookup", "2022", "pref", "9000",
                ])
                .status();
        }
        let _ = std::process::Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                "0x40000000/0x40000000",
                "lookup",
                "main",
                "pref",
                "8998",
            ])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["route", "flush", "table", "2022"])
            .status();

        if has_v6 {
            for mark_arg in ["0x2022/0xffff", "0x2022"] {
                let _ = std::process::Command::new("ip")
                    .args([
                        "-6", "rule", "del", "not", "fwmark", mark_arg, "lookup", "2022", "pref",
                        "9000",
                    ])
                    .status();
            }
            let _ = std::process::Command::new("ip")
                .args([
                    "-6",
                    "rule",
                    "del",
                    "fwmark",
                    "0x40000000/0x40000000",
                    "lookup",
                    "main",
                    "pref",
                    "8998",
                ])
                .status();
            let _ = std::process::Command::new("ip")
                .args(["-6", "route", "flush", "table", "2022"])
                .status();
        }
    }

    impl LinuxTunDevice {
        pub fn open(
            name: &str,
            mtu: usize,
            v4_addrs: &[(Ipv4Addr, u8)],
            v6_addrs: &[(Ipv6Addr, u8)],
            auto_route: bool,
        ) -> io::Result<Self> {
            let raw_fd =
                unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
            if raw_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let mut ifr = IfReq {
                ifr_name: [0; libc::IFNAMSIZ],
                ifr_flags: IFF_TUN | IFF_NO_PI,
                _pad: [0; 22],
            };
            for (i, b) in name.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
            if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut ifr) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])
                .status();
            for &(ip, prefix) in v4_addrs {
                let _ = std::process::Command::new("ip")
                    .args(["addr", "add", &format!("{ip}/{prefix}"), "dev", name])
                    .status();
            }
            let has_v6 = !v6_addrs.is_empty();
            for &(ip6, prefix6) in v6_addrs {
                let _ = std::process::Command::new("ip")
                    .args([
                        "-6",
                        "addr",
                        "add",
                        &format!("{ip6}/{prefix6}"),
                        "dev",
                        name,
                    ])
                    .status();
            }
            let async_fd = unsafe { AsyncFd::register(fd) }?;
            if auto_route {
                crate::upstream_compat::LINUX_TUN_AUTO_ROUTE_ACTIVE
                    .store(1, std::sync::atomic::Ordering::Release);
                let _ = std::process::Command::new("ip")
                    .args(["route", "replace", "default", "dev", name, "table", "2022"])
                    .status();
                for mark_arg in ["0x2022/0xffff", "0x2022"] {
                    let _ = std::process::Command::new("ip")
                        .args([
                            "rule", "del", "not", "fwmark", mark_arg, "lookup", "2022", "pref",
                            "9000",
                        ])
                        .status();
                }
                let _ = std::process::Command::new("ip")
                    .args([
                        "rule",
                        "del",
                        "fwmark",
                        "0x40000000/0x40000000",
                        "lookup",
                        "main",
                        "pref",
                        "8998",
                    ])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args([
                        "rule",
                        "add",
                        "fwmark",
                        "0x40000000/0x40000000",
                        "lookup",
                        "main",
                        "pref",
                        "8998",
                    ])
                    .status();
                let masked_ok = std::process::Command::new("ip")
                    .args([
                        "rule",
                        "add",
                        "not",
                        "fwmark",
                        "0x2022/0xffff",
                        "lookup",
                        "2022",
                        "pref",
                        "9000",
                    ])
                    .status()
                    .is_ok_and(|s| s.success());
                if !masked_ok {
                    let _ = std::process::Command::new("ip")
                        .args([
                            "rule", "add", "not", "fwmark", "0x2022", "lookup", "2022", "pref",
                            "9000",
                        ])
                        .status();
                }

                if has_v6 {
                    // Не падаем, если IPv6 отключён в ядре/контейнере
                    let _ = std::process::Command::new("ip")
                        .args([
                            "-6", "route", "replace", "::/1", "dev", name, "metric", "10", "table",
                            "2022",
                        ])
                        .status();
                    let _ = std::process::Command::new("ip")
                        .args([
                            "-6", "route", "replace", "8000::/1", "dev", name, "metric", "10",
                            "table", "2022",
                        ])
                        .status();
                    for mark_arg in ["0x2022/0xffff", "0x2022"] {
                        let _ = std::process::Command::new("ip")
                            .args([
                                "-6", "rule", "del", "not", "fwmark", mark_arg, "lookup", "2022",
                                "pref", "9000",
                            ])
                            .status();
                    }
                    let _ = std::process::Command::new("ip")
                        .args([
                            "-6",
                            "rule",
                            "del",
                            "fwmark",
                            "0x40000000/0x40000000",
                            "lookup",
                            "main",
                            "pref",
                            "8998",
                        ])
                        .status();
                    let _ = std::process::Command::new("ip")
                        .args([
                            "-6",
                            "rule",
                            "add",
                            "fwmark",
                            "0x40000000/0x40000000",
                            "lookup",
                            "main",
                            "pref",
                            "8998",
                        ])
                        .status();
                    let v6_masked_ok = std::process::Command::new("ip")
                        .args([
                            "-6",
                            "rule",
                            "add",
                            "not",
                            "fwmark",
                            "0x2022/0xffff",
                            "lookup",
                            "2022",
                            "pref",
                            "9000",
                        ])
                        .status()
                        .is_ok_and(|s| s.success());
                    if !v6_masked_ok {
                        let _ = std::process::Command::new("ip")
                            .args([
                                "-6", "rule", "add", "not", "fwmark", "0x2022", "lookup", "2022",
                                "pref", "9000",
                            ])
                            .status();
                    }
                }

                super::register_active_tun_routes(
                    name.to_string(),
                    v4_addrs.first().map(|&(ip, _)| ip),
                    has_v6,
                );
            }
            Ok(Self {
                async_fd,
                name: name.to_string(),
                auto_route,
                has_v6,
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
                super::clear_active_tun_routes();
                cleanup_routes(&self.name, self.has_v6);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_tun {
    use crate::upstream_compat::MACOS_OUTBOUND_IF_INDEX;
    use std::ffi::CString;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
        async_fd: AsyncFd<OwnedFd>,
        name: String,
        auto_route: bool,
        has_v6: bool,
    }

    pub(super) fn cleanup_routes(name: &str, has_v6: bool) {
        MACOS_OUTBOUND_IF_INDEX.store(0, Ordering::Release);
        let _ = std::process::Command::new("route")
            .args(["-n", "delete", "-net", "0.0.0.0/1", "-interface", name])
            .status();
        let _ = std::process::Command::new("route")
            .args(["-n", "delete", "-net", "128.0.0.0/1", "-interface", name])
            .status();
        if has_v6 {
            let _ = std::process::Command::new("route")
                .args(["-n", "delete", "-inet6", "::/1", "-interface", name])
                .status();
            let _ = std::process::Command::new("route")
                .args(["-n", "delete", "-inet6", "8000::/1", "-interface", name])
                .status();
        }
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
        pub fn open(
            mtu: usize,
            v4_addrs: &[(Ipv4Addr, u8)],
            v6_addrs: &[(Ipv6Addr, u8)],
            auto_route: bool,
        ) -> io::Result<Self> {
            if auto_route && let Some(idx) = detect_macos_default_if_index() {
                MACOS_OUTBOUND_IF_INDEX.store(idx, Ordering::Release);
            }

            let raw_fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if raw_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0u8; 96],
            };
            info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
            if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO as _, &mut info) } < 0 {
                return Err(io::Error::last_os_error());
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
                        fd.as_raw_fd(),
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
                return Err(io::Error::last_os_error());
            };

            unsafe {
                let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL, 0);
                if flags >= 0 {
                    libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
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
            let has_v6 = !v6_addrs.is_empty();
            for &(ip6, prefix6) in v6_addrs {
                let _ = std::process::Command::new("ifconfig")
                    .args([&if_name, "inet6", &format!("{ip6}/{prefix6}"), "up"])
                    .status();
            }

            let async_fd = unsafe { AsyncFd::register(fd) }?;
            if auto_route {
                let _ = std::process::Command::new("route")
                    .args(["-n", "add", "-net", "0.0.0.0/1", "-interface", &if_name])
                    .status();
                let _ = std::process::Command::new("route")
                    .args(["-n", "add", "-net", "128.0.0.0/1", "-interface", &if_name])
                    .status();
                if has_v6 {
                    let _ = std::process::Command::new("route")
                        .args(["-n", "add", "-inet6", "::/1", "-interface", &if_name])
                        .status();
                    let _ = std::process::Command::new("route")
                        .args(["-n", "add", "-inet6", "8000::/1", "-interface", &if_name])
                        .status();
                }
                super::register_active_tun_routes(
                    if_name.clone(),
                    v4_addrs.first().map(|&(ip, _)| ip),
                    has_v6,
                );
            }

            Ok(Self {
                async_fd,
                name: if_name,
                auto_route,
                has_v6,
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
                super::clear_active_tun_routes();
                cleanup_routes(&self.name, self.has_v6);
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

    pub(super) fn cleanup_routes(name: &str, ipv4_gw: Option<Ipv4Addr>, has_v6: bool) {
        WIN_OUTBOUND_IF_INDEX.store(0, Ordering::Release);
        if let Some(gw) = ipv4_gw {
            let gw_str = gw.to_string();
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
        if has_v6 {
            run_netsh(&["interface", "ipv6", "delete", "route", "::/1", name]);
            run_netsh(&["interface", "ipv6", "delete", "route", "8000::/1", name]);
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
                if !v6_addrs.is_empty() {
                    run_netsh(&["interface", "ipv6", "delete", "route", "::/1", name]);
                    run_netsh(&["interface", "ipv6", "delete", "route", "8000::/1", name]);
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

                struct WinTunOpenGuard {
                    stop_event: usize,
                    effective_name: String,
                    routes_added_v4: Option<Ipv4Addr>,
                    routes_added_v6: bool,
                    armed: bool,
                }

                impl Drop for WinTunOpenGuard {
                    fn drop(&mut self) {
                        if !self.armed {
                            return;
                        }
                        if let Some(gw) = self.routes_added_v4 {
                            let gw_str = gw.to_string();
                            run_netsh(&[
                                "interface",
                                "ipv4",
                                "delete",
                                "route",
                                "0.0.0.0/1",
                                &self.effective_name,
                                &gw_str,
                            ]);
                            run_netsh(&[
                                "interface",
                                "ipv4",
                                "delete",
                                "route",
                                "128.0.0.0/1",
                                &self.effective_name,
                                &gw_str,
                            ]);
                        }
                        if self.routes_added_v6 {
                            run_netsh(&[
                                "interface",
                                "ipv6",
                                "delete",
                                "route",
                                "::/1",
                                &self.effective_name,
                            ]);
                            run_netsh(&[
                                "interface",
                                "ipv6",
                                "delete",
                                "route",
                                "8000::/1",
                                &self.effective_name,
                            ]);
                        }
                        if self.stop_event != 0 {
                            unsafe {
                                CloseHandle(self.stop_event as Handle);
                            }
                        }
                    }
                }

                let mut open_guard = WinTunOpenGuard {
                    stop_event: stop_event as usize,
                    effective_name: effective_name.clone(),
                    routes_added_v4: None,
                    routes_added_v6: false,
                    armed: true,
                };

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

                let has_v6 = !v6_addrs.is_empty();
                if has_v6 {
                    for &(ip6, prefix6) in v6_addrs {
                        run_netsh(&[
                            "interface",
                            "ipv6",
                            "delete",
                            "address",
                            &format!("interface={effective_name}"),
                            &format!("address={ip6}"),
                            "store=active",
                        ]);
                        run_netsh(&[
                            "interface",
                            "ipv6",
                            "add",
                            "address",
                            &format!("interface={effective_name}"),
                            &format!("address={ip6}/{prefix6}"),
                            "store=active",
                        ]);
                    }
                    run_netsh(&[
                        "interface",
                        "ipv6",
                        "set",
                        "subinterface",
                        &effective_name,
                        &format!("mtu={mtu}"),
                        "store=active",
                    ]);
                }

                if auto_route {
                    if let Some(gw) = ipv4_gw {
                        let gw_str = gw.to_string();
                        if effective_name != name {
                            run_netsh(&[
                                "interface",
                                "ipv4",
                                "delete",
                                "route",
                                "0.0.0.0/1",
                                &effective_name,
                                &gw_str,
                            ]);
                            run_netsh(&[
                                "interface",
                                "ipv4",
                                "delete",
                                "route",
                                "128.0.0.0/1",
                                &effective_name,
                                &gw_str,
                            ]);
                        }
                        open_guard.routes_added_v4 = Some(gw);
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
                    if has_v6 {
                        if effective_name != name {
                            run_netsh(&[
                                "interface",
                                "ipv6",
                                "delete",
                                "route",
                                "::/1",
                                &effective_name,
                            ]);
                            run_netsh(&[
                                "interface",
                                "ipv6",
                                "delete",
                                "route",
                                "8000::/1",
                                &effective_name,
                            ]);
                        }
                        open_guard.routes_added_v6 = true;
                        run_netsh(&[
                            "interface",
                            "ipv6",
                            "add",
                            "route",
                            "::/1",
                            &effective_name,
                            "metric=1",
                            "store=active",
                        ]);
                        run_netsh(&[
                            "interface",
                            "ipv6",
                            "add",
                            "route",
                            "8000::/1",
                            &effective_name,
                            "metric=1",
                            "store=active",
                        ]);
                    }
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

                open_guard.armed = false;
                if auto_route {
                    super::register_active_tun_routes(effective_name.clone(), ipv4_gw, has_v6);
                }

                Ok(Self {
                    session,
                    _adapter: adapter,
                    stop_event: stop_event as usize,
                    reader_thread: Some(reader_thread),
                    rx_rx: Mutex::new(rx_rx),
                    name: effective_name,
                    auto_route,
                    ipv4_gw,
                    has_v6,
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
            self.rx_rx.get_mut().close();
            unsafe {
                SetEvent(self.stop_event as Handle);
            }
            if let Some(handle) = self.reader_thread.take() {
                let _ = handle.join();
            }
            if self.auto_route {
                super::clear_active_tun_routes();
                cleanup_routes(&self.name, self.ipv4_gw, self.has_v6);
            }
            unsafe {
                CloseHandle(self.stop_event as Handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test(flavor = "current_thread")]
    async fn tun_stream_poll_write_completes_under_saturation() {
        let (_to_app_tx, to_app_rx) = mpsc::channel(1);
        let (from_app_tx, mut from_app_rx) = mpsc::channel(1);
        from_app_tx
            .try_send(Bytes::from_static(b"prefill"))
            .expect("initial slot available");

        let notify = Arc::new(Notify::new());
        let mut stream = TunStream {
            rx: to_app_rx,
            tx: from_app_tx,
            notify: notify.clone(),
            peer_closed: Arc::new(AtomicBool::new(false)),
            current: None,
            reserve_fut: None,
        };

        let drainer = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let first = from_app_rx.recv().await.expect("prefill packet");
            tokio::task::yield_now().await;
            let second = from_app_rx.recv().await.expect("second packet");
            (first, second)
        });

        stream
            .write_all(b"hello world")
            .await
            .expect("write_all under saturated channel must wake via reserve_owned");
        assert!(stream.reserve_fut.is_none());

        let (first, second) = drainer.await.expect("drainer task");
        assert_eq!(&first[..], b"prefill");
        assert_eq!(&second[..], b"hello world");
    }

    #[test]
    fn build_tun_udp_response_ipv4_and_ipv6_valid_checksums() {
        use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};

        let payload = b"\x01\x02hello-quic\xff";
        let src4: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let dst4: SocketAddr = "10.0.0.2:54321".parse().unwrap();
        let raw4 = build_tun_udp_response(src4, dst4, payload).expect("ipv4 udp packet");
        let ip4 = Ipv4Packet::new_checked(&raw4[..]).expect("valid ipv4 packet");
        assert!(ip4.verify_checksum());
        assert_eq!(ip4.next_header(), IpProtocol::Udp);
        assert_eq!(ip4.hop_limit(), 64);
        let udp4 = UdpPacket::new_checked(ip4.payload()).expect("valid udp4 packet");
        assert!(udp4.verify_checksum(
            &IpAddress::Ipv4("1.1.1.1".parse().unwrap()),
            &IpAddress::Ipv4("10.0.0.2".parse().unwrap()),
        ));
        assert_eq!(udp4.src_port(), 53);
        assert_eq!(udp4.dst_port(), 54321);
        assert_eq!(udp4.payload(), payload);

        let src6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let dst6: SocketAddr = "[fd00::2]:40000".parse().unwrap();
        let raw6 = build_tun_udp_response(src6, dst6, payload).expect("ipv6 udp packet");
        let ip6 = Ipv6Packet::new_checked(&raw6[..]).expect("valid ipv6 packet");
        assert_eq!(ip6.next_header(), IpProtocol::Udp);
        assert_eq!(ip6.hop_limit(), 64);
        let udp6 = UdpPacket::new_checked(ip6.payload()).expect("valid udp6 packet");
        assert!(udp6.verify_checksum(
            &IpAddress::Ipv6("2606:4700:4700::1111".parse().unwrap()),
            &IpAddress::Ipv6("fd00::2".parse().unwrap()),
        ));
        assert_eq!(udp6.src_port(), 443);
        assert_eq!(udp6.dst_port(), 40000);
        assert_eq!(udp6.payload(), payload);

        assert!(build_tun_udp_response(src4, dst6, payload).is_none());
    }

    #[test]
    fn ipv6_ext_headers_and_mss_clamp_and_smoltcp_bbr() {
        use smoltcp::wire::{
            IpAddress, IpProtocol, Ipv6Packet, Ipv6Repr, TcpPacket, TcpRepr, TcpSeqNumber,
        };

        // 1. Тест MssClamp на IPv4 + пересчёт TCP чексуммы (RFC 1624)
        let mut syn4 = vec![0u8; 44];
        syn4[0] = 0x45;
        syn4[2..4].copy_from_slice(&44u16.to_be_bytes());
        syn4[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        syn4[8] = 64;
        syn4[9] = 6;
        syn4[12..16].copy_from_slice(&[10, 0, 0, 2]);
        syn4[16..20].copy_from_slice(&[1, 1, 1, 1]);
        syn4[20..22].copy_from_slice(&12345u16.to_be_bytes());
        syn4[22..24].copy_from_slice(&443u16.to_be_bytes());
        syn4[32] = 0x60; // 24 bytes TCP hdr
        syn4[33] = 0x02; // SYN
        syn4[40] = 0x02;
        syn4[41] = 0x04;
        syn4[42..44].copy_from_slice(&1460u16.to_be_bytes());
        {
            let mut tcp = TcpPacket::new_unchecked(&mut syn4[20..44]);
            tcp.fill_checksum(
                &IpAddress::Ipv4("10.0.0.2".parse().unwrap()),
                &IpAddress::Ipv4("1.1.1.1".parse().unwrap()),
            );
        }
        let clamp = MssClamp::for_mtu(1420);
        assert!(clamp.apply_in_place(&mut syn4));
        assert_eq!(u16::from_be_bytes([syn4[42], syn4[43]]), 1380);
        let tcp_checked = TcpPacket::new_checked(&syn4[20..44]).unwrap();
        assert!(tcp_checked.verify_checksum(
            &IpAddress::Ipv4("10.0.0.2".parse().unwrap()),
            &IpAddress::Ipv4("1.1.1.1".parse().unwrap()),
        ));

        // 2. Тест IPv6 с Hop-by-Hop заголовком (next=0) + MssClamp (1420 - 60 = 1360)
        let mut syn6 = vec![0u8; 40 + 8 + 24];
        let v6_src: Ipv6Addr = "fd00::2".parse().unwrap();
        let v6_dst: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let ip6_repr = Ipv6Repr {
            src_addr: v6_src,
            dst_addr: v6_dst,
            next_header: IpProtocol::HopByHop,
            payload_len: 32,
            hop_limit: 64,
        };
        {
            let mut p = Ipv6Packet::new_unchecked(&mut syn6[..40]);
            ip6_repr.emit(&mut p);
        }
        // Hop-by-Hop (8 bytes) -> Next Header = TCP (6)
        syn6[40] = 6;
        syn6[41] = 0;
        let tcp_repr = TcpRepr {
            src_port: 50000,
            dst_port: 443,
            control: smoltcp::wire::TcpControl::Syn,
            seq_number: TcpSeqNumber(1),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1440),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        {
            let mut tcp = TcpPacket::new_unchecked(&mut syn6[48..]);
            tcp_repr.emit(
                &mut tcp,
                &IpAddress::Ipv6(v6_src),
                &IpAddress::Ipv6(v6_dst),
                &smoltcp::phy::ChecksumCapabilities::default(),
            );
        }
        let (proto, src, dst, flags, l4_off) = parse_ip_packet_meta(&syn6).expect("ipv6 ext hdr");
        assert_eq!(proto, 6);
        assert_eq!(src.port(), 50000);
        assert_eq!(dst.port(), 443);
        assert_ne!(flags & 0x02, 0);
        assert_eq!(l4_off, 48 + 24);
        assert!(clamp.apply_in_place(&mut syn6));
        let tcp6_after = TcpPacket::new_checked(&syn6[48..]).unwrap();
        assert_eq!(
            TcpRepr::parse(
                &tcp6_after,
                &IpAddress::Ipv6(v6_src),
                &IpAddress::Ipv6(v6_dst),
                &smoltcp::phy::ChecksumCapabilities::default()
            )
            .unwrap()
            .max_seg_size,
            Some(1360)
        );
        assert!(tcp6_after.verify_checksum(&IpAddress::Ipv6(v6_src), &IpAddress::Ipv6(v6_dst),));

        // 3. Проверка целочисленного BBR в smoltcp
        let mut s = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 4096]),
            TcpSocketBuffer::new(vec![0u8; 4096]),
        );
        s.set_congestion_control(SmolCongestionControl::Bbr);
        assert_eq!(s.congestion_control(), SmolCongestionControl::Bbr);
    }

    #[test]
    fn compute_tun_poll_timeout_clamps_and_adapts_to_idle() {
        assert_eq!(
            compute_tun_poll_timeout(None, false),
            Duration::from_millis(250)
        );
        assert_eq!(
            compute_tun_poll_timeout(None, true),
            Duration::from_millis(25)
        );
        assert_eq!(
            compute_tun_poll_timeout(Some(smoltcp::time::Duration::from_millis(0)), true),
            Duration::from_millis(1)
        );
        assert_eq!(
            compute_tun_poll_timeout(Some(smoltcp::time::Duration::from_micros(500)), false),
            Duration::from_millis(1)
        );
        assert_eq!(
            compute_tun_poll_timeout(Some(smoltcp::time::Duration::from_millis(12)), true),
            Duration::from_millis(12)
        );
        assert_eq!(
            compute_tun_poll_timeout(Some(smoltcp::time::Duration::from_millis(1000)), true),
            Duration::from_millis(250)
        );

        let mut vdev = VirtualTunDevice::new(1500);
        let mut iconfig = IfaceConfig::new(HardwareAddress::Ip);
        iconfig.random_seed = 1;
        let mut iface = Interface::new(iconfig, &mut vdev, SmolInstant::now());
        let sockets = SocketSet::new(Vec::new());
        let delay = iface.poll_delay(SmolInstant::now(), &sockets);
        assert_eq!(
            compute_tun_poll_timeout(delay, false),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn tun_route_tracker_register_clear_and_emergency_take() {
        // Сначала сбрасываем возможный остаток и убеждаемся, что пустой emergency_cleanup безопасен.
        let _ = take_active_tun_routes();
        emergency_cleanup_tun_routes();
        assert!(take_active_tun_routes().is_none());

        let gw = Ipv4Addr::new(172, 19, 0, 1);
        register_active_tun_routes("tachyon-test0".to_string(), Some(gw), true);
        let taken = take_active_tun_routes().expect("registered active routes");
        assert_eq!(
            taken,
            ActiveTunRoutes {
                adapter_name: "tachyon-test0".to_string(),
                ipv4_gw: Some(gw),
                has_v6: true,
            }
        );
        assert!(take_active_tun_routes().is_none());

        register_active_tun_routes("tachyon-test1".to_string(), None, false);
        clear_active_tun_routes();
        assert!(take_active_tun_routes().is_none());
    }
}
