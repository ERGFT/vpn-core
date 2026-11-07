// SPDX-License-Identifier: GPL-3.0-or-later
//! Hysteria 2 unreliable-datagram relay and bounded UDPMessage framing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use quinn::Connection;
use tokio::sync::{mpsc, Mutex};

use crate::app::outbound::{Packet, UdpSession};
use crate::error::{Error, Result};
use crate::vless::Address;

const MAX_ADDRESS: usize = 2048;
const MAX_UDP_PAYLOAD: usize = 4096;
const MAX_FRAGMENTS: usize = 32;
const MAX_IN_FLIGHT_PACKETS: usize = 128;
const MAX_REASSEMBLY_BYTES: usize = 256 * 1024;
const REASSEMBLY_TTL: Duration = Duration::from_secs(5);
const UDP_IDLE: Duration = Duration::from_secs(120);
const UDP_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_QUEUE: usize = 256;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct UdpFragment {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: Address,
    port: u16,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct FragmentSet {
    address: Address,
    port: u16,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
    created_at: Instant,
}

#[derive(Default)]
struct Reassembler {
    pending: HashMap<(u32, u16), FragmentSet>,
    bytes: usize,
}

impl Reassembler {
    fn push(&mut self, fragment: UdpFragment, now: Instant) -> Option<Packet> {
        self.expire(now);
        if fragment.fragment_count == 1 {
            return Some((fragment.address, fragment.port, fragment.payload));
        }

        let key = (fragment.session_id, fragment.packet_id);
        let count = fragment.fragment_count as usize;
        if count > MAX_FRAGMENTS || fragment.fragment_id as usize >= count {
            return None;
        }

        if !self.pending.contains_key(&key) {
            if self.pending.len() >= MAX_IN_FLIGHT_PACKETS {
                self.evict_oldest();
            }
            self.pending.insert(
                key,
                FragmentSet {
                    address: fragment.address.clone(),
                    port: fragment.port,
                    parts: (0..count).map(|_| None).collect(),
                    bytes: 0,
                    created_at: now,
                },
            );
        }

        // A new first fragment with the same 16-bit ID but different bytes
        // marks Packet ID reuse after wrap; discard the stale incomplete set.
        let restart = fragment.fragment_id == 0
            && self
                .pending
                .get(&key)
                .and_then(|set| set.parts.first())
                .and_then(Option::as_ref)
                .is_some_and(|existing| existing != &fragment.payload);
        if restart {
            self.remove(key);
            self.pending.insert(
                key,
                FragmentSet {
                    address: fragment.address.clone(),
                    port: fragment.port,
                    parts: (0..count).map(|_| None).collect(),
                    bytes: 0,
                    created_at: now,
                },
            );
        }

        let Some(set) = self.pending.get_mut(&key) else {
            return None;
        };
        if set.parts.len() != count || set.address != fragment.address || set.port != fragment.port
        {
            self.remove(key);
            return None;
        }

        let part_index = fragment.fragment_id as usize;
        if let Some(existing) = &set.parts[part_index] {
            if existing != &fragment.payload {
                self.remove(key);
            }
            return None;
        }

        if set.bytes.saturating_add(fragment.payload.len()) > MAX_UDP_PAYLOAD
            || self.bytes.saturating_add(fragment.payload.len()) > MAX_REASSEMBLY_BYTES
        {
            self.remove(key);
            return None;
        }

        set.bytes += fragment.payload.len();
        self.bytes += fragment.payload.len();
        set.parts[part_index] = Some(fragment.payload);
        if set.parts.iter().any(Option::is_none) {
            return None;
        }

        let mut set = self.pending.remove(&key)?;
        self.bytes = self.bytes.saturating_sub(set.bytes);
        let mut payload = Vec::with_capacity(set.bytes);
        for part in &mut set.parts {
            payload.extend(part.take()?);
        }
        Some((set.address, set.port, payload))
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(key, set)| {
                (now.saturating_duration_since(set.created_at) >= REASSEMBLY_TTL).then_some(*key)
            })
            .collect();
        for key in expired {
            self.remove(key);
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .pending
            .iter()
            .min_by_key(|(_, set)| set.created_at)
            .map(|(key, _)| *key)
        {
            self.remove(key);
        }
    }

    fn remove(&mut self, key: (u32, u16)) {
        if let Some(set) = self.pending.remove(&key) {
            self.bytes = self.bytes.saturating_sub(set.bytes);
        }
    }
}

/// One QUIC datagram reader demultiplexes replies to bounded per-association queues.
pub(crate) struct UdpDatagramMux {
    connection: Connection,
    routes: Mutex<HashMap<u32, mpsc::Sender<Packet>>>,
    reassembler: StdMutex<Reassembler>,
}

impl UdpDatagramMux {
    pub(crate) fn new(connection: Connection) -> Arc<Self> {
        Arc::new(Self {
            connection,
            routes: Mutex::new(HashMap::new()),
            reassembler: StdMutex::new(Reassembler::default()),
        })
    }

    pub(crate) fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.receive_loop().await })
    }

    pub(crate) async fn open_session(
        self: &Arc<Self>,
        session_id: u32,
    ) -> Result<Arc<dyn UdpSession>> {
        if self.connection.max_datagram_size().is_none() {
            return Err(Error::Protocol(
                "Hysteria 2: QUIC peer does not support unreliable datagrams".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        let mut routes = self.routes.lock().await;
        if routes.contains_key(&session_id) {
            return Err(Error::Protocol(
                "Hysteria 2: duplicate UDP session ID".into(),
            ));
        }
        routes.insert(session_id, tx);
        Ok(Arc::new(Hysteria2UdpSession {
            connection: self.connection.clone(),
            mux: self.clone(),
            session_id,
            next_packet_id: std::sync::atomic::AtomicU16::new(0),
            last_activity: StdMutex::new(Instant::now()),
            rx: Mutex::new(rx),
        }))
    }

    async fn receive_loop(self: Arc<Self>) {
        let mut cleanup = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                datagram = self.connection.read_datagram() => {
                    let Ok(datagram) = datagram else { break };
                    let fragment = match decode_udp_message(&datagram) {
                        Ok(fragment) => fragment,
                        Err(error) => {
                            tracing::debug!(error = %error, "Hysteria 2: discarded malformed UDP datagram");
                            continue;
                        }
                    };
                    let session_id = fragment.session_id;
                    let packet = {
                        let mut reassembler = self.reassembler
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        reassembler.push(fragment, Instant::now())
                    };
                    let Some(packet) = packet else { continue };
                    let mut routes = self.routes.lock().await;
                    routes.retain(|_, sender| !sender.is_closed());
                    if let Some(sender) = routes.get(&session_id) {
                        // A full queue drops this UDP packet; it never blocks QUIC receive.
                        let _ = sender.try_send(packet);
                    }
                }
                _ = cleanup.tick() => {
                    self.routes.lock().await.retain(|_, sender| !sender.is_closed());
                    self.reassembler
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .expire(Instant::now());
                }
            }
        }
        self.routes.lock().await.clear();
        self.reassembler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .clear();
    }

    async fn unregister(&self, session_id: u32) {
        self.routes.lock().await.remove(&session_id);
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys: Vec<_> = reassembler
            .pending
            .keys()
            .filter(|(id, _)| *id == session_id)
            .copied()
            .collect();
        for key in keys {
            reassembler.remove(key);
        }
    }
}

struct Hysteria2UdpSession {
    connection: Connection,
    mux: Arc<UdpDatagramMux>,
    session_id: u32,
    next_packet_id: std::sync::atomic::AtomicU16,
    last_activity: StdMutex<Instant>,
    rx: Mutex<mpsc::Receiver<Packet>>,
}

impl UdpSession for Hysteria2UdpSession {
    fn send(&self, dst: Address, port: u16, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if data.is_empty() || data.len() > MAX_UDP_PAYLOAD {
                // The reference Hysteria client limits one UDP packet to 4096 bytes and
                // its wire parser requires at least one payload byte.
                return Ok(());
            }
            let packet_id = next_packet_id(&self.next_packet_id);
            let max_wire = self.connection.max_datagram_size().ok_or_else(|| {
                Error::Protocol("Hysteria 2: QUIC datagrams are no longer available".into())
            })?;
            let frames =
                encode_udp_fragments(self.session_id, packet_id, &dst, port, &data, max_wire)?;
            *self
                .last_activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();

            for frame in frames {
                match tokio::time::timeout(
                    UDP_SEND_TIMEOUT,
                    self.connection.send_datagram_wait(Bytes::from(frame)),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(quinn::SendDatagramError::ConnectionLost(error))) => {
                        return Err(Error::Protocol(format!(
                            "Hysteria 2: UDP connection lost: {error}"
                        )))
                    }
                    Ok(Err(error)) => {
                        return Err(Error::Protocol(format!(
                            "Hysteria 2: failed to send UDP datagram: {error}"
                        )))
                    }
                    Err(_) => {
                        // Drop the remaining fragments together; incomplete UDP packets
                        // are discarded by the bounded reassembler after its TTL.
                        return Ok(());
                    }
                }
            }
            Ok(())
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Packet>>> {
        Box::pin(async move {
            let mut rx = self.rx.lock().await;
            loop {
                let elapsed = self
                    .last_activity
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .elapsed();
                if elapsed >= UDP_IDLE {
                    drop(rx);
                    self.mux.unregister(self.session_id).await;
                    return Ok(None);
                }
                match tokio::time::timeout(UDP_IDLE - elapsed, rx.recv()).await {
                    Ok(Some(packet)) => {
                        *self
                            .last_activity
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                        return Ok(Some(packet));
                    }
                    Ok(None) => return Ok(None),
                    Err(_) => continue,
                }
            }
        })
    }
}

fn next_packet_id(counter: &std::sync::atomic::AtomicU16) -> u16 {
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn encode_udp_fragments(
    session_id: u32,
    packet_id: u16,
    address: &Address,
    port: u16,
    payload: &[u8],
    max_wire: usize,
) -> Result<Vec<Vec<u8>>> {
    if payload.is_empty() || payload.len() > MAX_UDP_PAYLOAD {
        return Err(Error::Protocol(
            "Hysteria 2: UDP payload is empty or exceeds 4096 bytes".into(),
        ));
    }
    let address = format_authority(address, port);
    if address.is_empty() || address.len() > MAX_ADDRESS {
        return Err(Error::Protocol(
            "Hysteria 2: UDP destination address exceeds the protocol limit".into(),
        ));
    }
    let mut address_len = Vec::new();
    crate::hysteria2_transport::encode_quic_varint(address.len() as u64, &mut address_len);
    let header_len = 8usize
        .checked_add(address_len.len())
        .and_then(|n| n.checked_add(address.len()))
        .ok_or_else(|| Error::Protocol("Hysteria 2: UDP header length overflow".into()))?;
    let fragment_payload = max_wire.checked_sub(header_len).ok_or_else(|| {
        Error::Protocol("Hysteria 2: destination header exceeds QUIC datagram limit".into())
    })?;
    if fragment_payload == 0 {
        return Err(Error::Protocol(
            "Hysteria 2: no payload fits in a QUIC datagram".into(),
        ));
    }
    let fragment_count = payload.len().div_ceil(fragment_payload);
    if fragment_count > MAX_FRAGMENTS {
        return Err(Error::Protocol(
            "Hysteria 2: UDP packet requires too many fragments".into(),
        ));
    }
    let mut frames = Vec::with_capacity(fragment_count);
    for (fragment_id, chunk) in payload.chunks(fragment_payload).enumerate() {
        let mut frame = Vec::with_capacity(header_len + chunk.len());
        frame.extend_from_slice(&session_id.to_be_bytes());
        frame.extend_from_slice(&packet_id.to_be_bytes());
        frame.push(fragment_id as u8);
        frame.push(fragment_count as u8);
        frame.extend_from_slice(&address_len);
        frame.extend_from_slice(address.as_bytes());
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

fn decode_udp_message(bytes: &[u8]) -> Result<UdpFragment> {
    if bytes.len() < 10 {
        return Err(protocol_error("UDP message header is truncated"));
    }
    let session_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let packet_id = u16::from_be_bytes([bytes[4], bytes[5]]);
    let fragment_id = bytes[6];
    let fragment_count = bytes[7];
    if fragment_count == 0
        || fragment_count as usize > MAX_FRAGMENTS
        || fragment_id >= fragment_count
    {
        return Err(protocol_error("UDP fragment index or count is invalid"));
    }
    let (address_len, address_len_bytes) =
        crate::hysteria2_transport::decode_quic_varint(&bytes[8..])?;
    let address_len = usize::try_from(address_len)
        .map_err(|_| protocol_error("UDP address length overflows usize"))?;
    if address_len == 0 || address_len > MAX_ADDRESS {
        return Err(protocol_error("UDP address length is outside the limit"));
    }
    let address_start = 8 + address_len_bytes;
    let payload_start = address_start
        .checked_add(address_len)
        .ok_or_else(|| protocol_error("UDP address length overflow"))?;
    if payload_start >= bytes.len() {
        return Err(protocol_error(
            "UDP payload is empty or address is truncated",
        ));
    }
    let authority = std::str::from_utf8(&bytes[address_start..payload_start])
        .map_err(|_| protocol_error("UDP destination address is not UTF-8"))?;
    let (address, port) = parse_authority(authority)?;
    let payload = bytes[payload_start..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(protocol_error("UDP fragment exceeds the size limit"));
    }
    Ok(UdpFragment {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        port,
        payload,
    })
}

fn format_authority(address: &Address, port: u16) -> String {
    let host = match address {
        Address::Ipv4(ip) => ip.to_string(),
        Address::Domain(domain) => domain.clone(),
        Address::Ipv6(ip) => format!("[{ip}]"),
    };
    format!("{host}:{port}")
}

fn parse_authority(authority: &str) -> Result<(Address, u16)> {
    let (host, port, is_bracketed) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once("]:")
            .ok_or_else(|| protocol_error("invalid bracketed UDP IPv6 destination"))?;
        (host, port, true)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| protocol_error("UDP destination has no port"))?;
        (host, port, false)
    };
    if host.is_empty() || host.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(protocol_error("UDP destination host is invalid"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| protocol_error("UDP destination port is invalid"))?;
    if !is_bracketed && host.contains(':') {
        return Err(protocol_error(
            "unbracketed or invalid UDP IPv6 destination",
        ));
    }
    let address = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Address::Ipv4(ip),
        Ok(IpAddr::V6(ip)) => Address::Ipv6(ip),
        Err(_) if host.contains(':') => {
            return Err(protocol_error(
                "unbracketed or invalid UDP IPv6 destination",
            ))
        }
        Err(_) => Address::Domain(host.to_string()),
    };
    Ok((address, port))
}

fn protocol_error(message: &str) -> Error {
    Error::Protocol(format!("Hysteria 2: {message}"))
}

#[cfg(test)]
mod tests {
    use super::{
        decode_udp_message, encode_udp_fragments, next_packet_id, parse_authority, Address,
        Reassembler, MAX_FRAGMENTS, MAX_IN_FLIGHT_PACKETS, MAX_REASSEMBLY_BYTES, MAX_UDP_PAYLOAD,
    };
    use std::sync::atomic::AtomicU16;
    use std::time::{Duration, Instant};

    #[test]
    fn encodes_and_decodes_udp_messages_with_ipv4_and_ipv6_authorities() {
        let frame = encode_udp_fragments(
            0x1234_5678,
            0xabcd,
            &Address::Domain("dns.example".into()),
            53,
            b"query",
            1200,
        )
        .unwrap()
        .remove(0);
        let parsed = decode_udp_message(&frame).unwrap();
        assert_eq!(parsed.session_id, 0x1234_5678);
        assert_eq!(parsed.packet_id, 0xabcd);
        assert_eq!(parsed.fragment_id, 0);
        assert_eq!(parsed.fragment_count, 1);
        assert_eq!(parsed.address, Address::Domain("dns.example".into()));
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, b"query");

        assert_eq!(
            parse_authority("[2001:db8::1]:443").unwrap(),
            (Address::Ipv6("2001:db8::1".parse().unwrap()), 443)
        );
        assert!(parse_authority("2001:db8::1:443").is_err());
    }

    #[test]
    fn fragments_large_udp_datagrams_under_the_quic_limit() {
        let payload = vec![0x5a; MAX_UDP_PAYLOAD];
        let frames = encode_udp_fragments(
            7,
            u16::MAX,
            &Address::Ipv4("192.0.2.1".parse().unwrap()),
            5353,
            &payload,
            1200,
        )
        .unwrap();
        assert!(frames.len() > 1);
        assert!(frames.len() <= MAX_FRAGMENTS);
        assert!(frames.iter().all(|frame| frame.len() <= 1200));
        let decoded: Vec<_> = frames
            .iter()
            .map(|frame| decode_udp_message(frame).unwrap())
            .collect();
        assert!(decoded
            .iter()
            .all(|fragment| fragment.packet_id == u16::MAX));
        assert!(decoded
            .iter()
            .enumerate()
            .all(|(id, fragment)| fragment.fragment_id as usize == id));
    }

    #[test]
    fn reassembles_fragments_in_order_and_drops_incomplete_or_expired_packets() {
        let now = Instant::now();
        let data = vec![0x33; 2500];
        let frames = encode_udp_fragments(
            4,
            10,
            &Address::Domain("example.org".into()),
            443,
            &data,
            1200,
        )
        .unwrap();
        let mut reassembler = Reassembler::default();
        let fragments: Vec<_> = frames
            .iter()
            .rev()
            .map(|frame| decode_udp_message(frame).unwrap())
            .collect();
        for fragment in fragments.iter().take(fragments.len() - 1) {
            assert!(reassembler.push(fragment.clone_for_test(), now).is_none());
        }
        let complete = reassembler
            .push(fragments.last().unwrap().clone_for_test(), now)
            .unwrap();
        assert_eq!(complete.0, Address::Domain("example.org".into()));
        assert_eq!(complete.1, 443);
        assert_eq!(complete.2, data);

        let mut pending = decode_udp_message(&frames[0]).unwrap();
        pending.fragment_count = 2;
        pending.fragment_id = 0;
        assert!(reassembler.push(pending, now).is_none());
        reassembler.expire(now + Duration::from_secs(6));
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.bytes, 0);
    }

    #[test]
    fn enforces_fragment_and_memory_limits_and_cleans_session_state() {
        let now = Instant::now();
        let data = vec![1; MAX_UDP_PAYLOAD];
        let frame = encode_udp_fragments(
            99,
            12,
            &Address::Domain("a.example".into()),
            53,
            &data,
            1200,
        )
        .unwrap()[0]
            .clone();
        let mut first = decode_udp_message(&frame).unwrap();
        first.fragment_count = (MAX_FRAGMENTS + 1) as u8;
        assert!(Reassembler::default().push(first, now).is_none());

        let mut reassembler = Reassembler::default();
        for id in 0..MAX_IN_FLIGHT_PACKETS {
            let mut fragment = decode_udp_message(&frame).unwrap();
            fragment.session_id = id as u32;
            fragment.fragment_count = 2;
            fragment.fragment_id = 0;
            fragment
                .payload
                .truncate(MAX_REASSEMBLY_BYTES / MAX_IN_FLIGHT_PACKETS);
            assert!(reassembler.push(fragment, now).is_none());
        }
        assert_eq!(reassembler.pending.len(), MAX_IN_FLIGHT_PACKETS);
        assert!(reassembler.bytes <= MAX_REASSEMBLY_BYTES);
        reassembler.expire(now + Duration::from_secs(6));
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.bytes, 0);
    }

    #[test]
    fn reassembly_byte_budget_is_enforced_across_sessions() {
        let now = Instant::now();
        let base = encode_udp_fragments(
            1,
            1,
            &Address::Domain("budget.example".into()),
            53,
            &[1],
            1200,
        )
        .unwrap()
        .remove(0);
        let mut reassembler = Reassembler::default();
        for session_id in 0..=(MAX_REASSEMBLY_BYTES / MAX_UDP_PAYLOAD) as u32 {
            let mut fragment = decode_udp_message(&base).unwrap();
            fragment.session_id = session_id;
            fragment.fragment_count = 2;
            fragment.payload = vec![1; MAX_UDP_PAYLOAD];
            assert!(reassembler.push(fragment, now).is_none());
        }
        assert_eq!(reassembler.bytes, MAX_REASSEMBLY_BYTES);
        assert_eq!(
            reassembler.pending.len(),
            MAX_REASSEMBLY_BYTES / MAX_UDP_PAYLOAD
        );
    }

    #[test]
    fn packet_id_wraps_without_panicking_and_starts_new_reassembly() {
        let packet_id = AtomicU16::new(u16::MAX);
        assert_eq!(next_packet_id(&packet_id), u16::MAX);
        assert_eq!(next_packet_id(&packet_id), 0);

        let now = Instant::now();
        let mut reassembler = Reassembler::default();
        let mut old = decode_udp_message(
            &encode_udp_fragments(
                3,
                u16::MAX,
                &Address::Domain("wrap.example".into()),
                53,
                &[1, 2, 3],
                1200,
            )
            .unwrap()[0],
        )
        .unwrap();
        old.fragment_count = 2;
        assert!(reassembler.push(old, now).is_none());

        let mut wrapped = decode_udp_message(
            &encode_udp_fragments(
                3,
                u16::MAX,
                &Address::Domain("wrap.example".into()),
                53,
                &[9, 8, 7],
                1200,
            )
            .unwrap()[0],
        )
        .unwrap();
        wrapped.fragment_count = 2;
        assert!(reassembler.push(wrapped, now).is_none());
        assert_eq!(reassembler.bytes, 3);
    }

    trait CloneForTest {
        fn clone_for_test(&self) -> Self;
    }

    impl CloneForTest for super::UdpFragment {
        fn clone_for_test(&self) -> Self {
            Self {
                session_id: self.session_id,
                packet_id: self.packet_id,
                fragment_id: self.fragment_id,
                fragment_count: self.fragment_count,
                address: self.address.clone(),
                port: self.port,
                payload: self.payload.clone(),
            }
        }
    }
}
