use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, UdpPoller,
};

const MIN_ELIGIBLE_BYTES: usize = 1000;
const MAX_RECORDS: usize = 128;

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct DropRecord {
    pub(super) peer_port: u16,
    pub(super) len: usize,
    pub(super) stride: usize,
    pub(super) cipher_sha256: String,
    pub(super) eligible_ordinal: usize,
    pub(super) actual_dropped: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct GateSnapshot {
    pub(super) mode: &'static str,
    pub(super) armed: bool,
    pub(super) target_peer_port: Option<u16>,
    pub(super) eligible_datagrams: usize,
    pub(super) dropped_datagrams: usize,
    pub(super) dropped_bytes: usize,
    pub(super) unsupported_datagrams: usize,
    pub(super) unsupported_batches: usize,
    pub(super) record_overflow: usize,
    pub(super) max_transmit_segments: usize,
    pub(super) underlying_max_transmit_segments: Option<usize>,
    pub(super) max_receive_segments: Option<usize>,
    pub(super) records: Vec<DropRecord>,
}

#[derive(Debug)]
struct State {
    peer: Option<SocketAddr>,
    drop_first: bool,
    unsupported: bool,
    snapshot: GateSnapshot,
}

/// One fixture-owned receive omission, selected only by tuple and visible shape.
#[derive(Debug)]
pub(super) struct Gate {
    state: Mutex<State>,
}

impl Gate {
    pub(super) fn new(drop_first: bool) -> Self {
        Self {
            state: Mutex::new(State {
                peer: None,
                drop_first,
                unsupported: false,
                snapshot: GateSnapshot {
                    mode: if drop_first { "drop" } else { "pass" },
                    armed: false,
                    target_peer_port: None,
                    eligible_datagrams: 0,
                    dropped_datagrams: 0,
                    dropped_bytes: 0,
                    unsupported_datagrams: 0,
                    unsupported_batches: 0,
                    record_overflow: 0,
                    max_transmit_segments: 1,
                    underlying_max_transmit_segments: None,
                    max_receive_segments: None,
                    records: Vec::new(),
                },
            }),
        }
    }

    pub(super) fn arm(&self, peer: SocketAddr) -> Result<(), &'static str> {
        let mut state = self.state.lock().unwrap();
        if state.peer.is_some() {
            return Err("ONE_GAP_ALREADY_ARMED");
        }
        if !peer.ip().is_loopback() || peer.port() == 0 {
            return Err("ONE_GAP_INVALID_PEER");
        }
        state.peer = Some(peer);
        state.snapshot.armed = true;
        state.snapshot.target_peer_port = Some(peer.port());
        Ok(())
    }

    pub(super) fn snapshot(&self) -> GateSnapshot {
        self.state.lock().unwrap().snapshot.clone()
    }

    fn unsupported_batch(&self) {
        let mut state = self.state.lock().unwrap();
        state.unsupported = true;
        state.snapshot.unsupported_batches += 1;
    }

    fn select_drop(&self, bufs: &[IoSliceMut<'_>], meta: &[RecvMeta]) -> Option<usize> {
        let mut state = self.state.lock().unwrap();
        let peer = state.peer?;
        for entry in meta.iter().filter(|entry| entry.addr == peer) {
            if entry.stride != entry.len {
                state.unsupported = true;
                state.snapshot.unsupported_datagrams += 1;
            }
        }
        let mut candidate = None;
        let mut candidate_record = None;
        for (index, (entry, buffer)) in meta.iter().zip(bufs).enumerate() {
            if entry.addr != peer || entry.stride != entry.len || entry.len < MIN_ELIGIBLE_BYTES {
                continue;
            }
            let data = &buffer[..entry.len];
            if data[0] & 0x80 != 0 {
                continue;
            }
            state.snapshot.eligible_datagrams += 1;
            let ordinal = state.snapshot.eligible_datagrams;
            let selected = ordinal == 1 && state.drop_first && !state.unsupported;
            if selected {
                candidate = Some(index);
            }
            if state.snapshot.records.len() == MAX_RECORDS {
                state.snapshot.record_overflow += 1;
                continue;
            }
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
            let cipher_sha256 = digest
                .as_ref()
                .iter()
                .map(|value| format!("{value:02x}"))
                .collect();
            if selected {
                candidate_record = Some(state.snapshot.records.len());
            }
            state.snapshot.records.push(DropRecord {
                peer_port: peer.port(),
                len: entry.len,
                stride: entry.stride,
                cipher_sha256,
                eligible_ordinal: ordinal,
                actual_dropped: false,
            });
        }
        let index = candidate?;
        // A dropped slot must not force truncation when the caller supplied
        // differently sized receive buffers. In that case preserve the batch.
        if meta
            .iter()
            .enumerate()
            .skip(index + 1)
            .any(|(read, entry)| bufs[read - 1].len() < entry.len)
        {
            state.unsupported = true;
            state.snapshot.unsupported_batches += 1;
            return None;
        }
        state.snapshot.dropped_datagrams += 1;
        state.snapshot.dropped_bytes += meta[index].len;
        state.snapshot.records[candidate_record.expect("first eligible record")].actual_dropped =
            true;
        Some(index)
    }
}

#[derive(Debug)]
pub(super) struct Socket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Arc<Gate>,
}

impl Socket {
    pub(super) fn new(inner: Arc<dyn AsyncUdpSocket>, gate: Arc<Gate>) -> Self {
        {
            let mut state = gate.state.lock().unwrap();
            state.snapshot.underlying_max_transmit_segments = Some(inner.max_transmit_segments());
            state.snapshot.max_receive_segments = Some(inner.max_receive_segments());
        }
        Self { inner, gate }
    }
}

impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => count,
            result => return result,
        };
        if count > bufs.len() || count > meta.len() {
            self.gate.unsupported_batch();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid receive count",
            )));
        }
        if meta[..count]
            .iter()
            .zip(bufs.iter())
            .any(|(entry, buffer)| entry.len > buffer.len())
        {
            self.gate.unsupported_batch();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid receive length",
            )));
        }
        let Some(drop_index) = self.gate.select_drop(&bufs[..count], &meta[..count]) else {
            return Poll::Ready(Ok(count));
        };
        for read in drop_index + 1..count {
            let length = meta[read].len;
            let (left, right) = bufs.split_at_mut(read);
            left[read - 1][..length].copy_from_slice(&right[0][..length]);
            meta[read - 1] = meta[read];
        }
        if count == 1 {
            // The underlying successful receive did not register readiness.
            // Yield once and arrange another poll instead of spinning here.
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(count - 1))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use quinn::udp::EcnCodepoint;

    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51000);
    const OTHER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51001);

    #[derive(Debug)]
    struct Datagram {
        data: Vec<u8>,
        meta: RecvMeta,
    }

    fn datagram(peer: SocketAddr, length: usize, first: u8) -> Datagram {
        let mut data = vec![0x5a; length];
        if let Some(byte) = data.first_mut() {
            *byte = first;
        }
        Datagram {
            data,
            meta: RecvMeta {
                addr: peer,
                len: length,
                stride: length,
                ecn: Some(EcnCodepoint::Ect0),
                dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            },
        }
    }

    #[derive(Debug)]
    enum Receive {
        Batch(Vec<Datagram>),
        Pending,
        Error(i32),
    }

    #[derive(Debug)]
    struct SendRecord {
        destination: SocketAddr,
        ecn: Option<EcnCodepoint>,
        bytes: Vec<u8>,
        segment_size: Option<usize>,
        src_ip: Option<IpAddr>,
    }

    #[derive(Debug, Default)]
    struct Inner {
        receive: Mutex<VecDeque<Receive>>,
        sends: Mutex<Vec<SendRecord>>,
        send_error: Mutex<Option<i32>>,
        calls: AtomicUsize,
        pollers: AtomicUsize,
    }

    #[derive(Debug)]
    struct Writable;

    impl UdpPoller for Writable {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for Inner {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.pollers.fetch_add(1, Ordering::Relaxed);
            Box::pin(Writable)
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            self.sends.lock().unwrap().push(SendRecord {
                destination: transmit.destination,
                ecn: transmit.ecn,
                bytes: transmit.contents.to_vec(),
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip,
            });
            if let Some(error) = self.send_error.lock().unwrap().take() {
                return Err(io::Error::from_raw_os_error(error));
            }
            Ok(())
        }

        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.receive.lock().unwrap().pop_front() {
                Some(Receive::Batch(batch)) => {
                    assert!(batch.len() <= bufs.len() && batch.len() <= meta.len());
                    for (index, datagram) in batch.iter().enumerate() {
                        bufs[index][..datagram.data.len()].copy_from_slice(&datagram.data);
                        meta[index] = datagram.meta;
                    }
                    Poll::Ready(Ok(batch.len()))
                }
                Some(Receive::Error(error)) => {
                    Poll::Ready(Err(io::Error::from_raw_os_error(error)))
                }
                Some(Receive::Pending) | None => Poll::Pending,
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(([127, 0, 0, 1], 49420).into())
        }

        fn max_transmit_segments(&self) -> usize {
            8
        }

        fn max_receive_segments(&self) -> usize {
            4
        }

        fn may_fragment(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn fixture(
        drop_first: bool,
        batches: impl IntoIterator<Item = Receive>,
    ) -> (Arc<Inner>, Arc<Gate>, Arc<Socket>) {
        let inner = Arc::new(Inner::default());
        inner.receive.lock().unwrap().extend(batches);
        let gate = Arc::new(Gate::new(drop_first));
        let socket = Arc::new(Socket::new(inner.clone(), gate.clone()));
        (inner, gate, socket)
    }

    fn recv(
        socket: &Socket,
        buffers: &mut [Vec<u8>],
        meta: &mut [RecvMeta],
        waker: &Waker,
    ) -> Poll<io::Result<usize>> {
        let mut slices: Vec<_> = buffers
            .iter_mut()
            .map(|buffer| IoSliceMut::new(buffer))
            .collect();
        socket.poll_recv(&mut Context::from_waker(waker), &mut slices, meta)
    }

    fn delivered(result: Poll<io::Result<usize>>, expected: usize) {
        assert!(matches!(result, Poll::Ready(Ok(count)) if count == expected));
    }

    #[test]
    fn one_gap_socket_unarmed_passes_and_arm_cannot_be_reused() {
        let (_, gate, socket) = fixture(true, [Receive::Batch(vec![datagram(PEER, 1200, 0x40)])]);
        let mut buffers = vec![vec![0; 1500]];
        let mut meta = [RecvMeta::default()];
        let wakes = Arc::new(Wakes::default());
        delivered(
            recv(&socket, &mut buffers, &mut meta, &wakes.clone().into()),
            1,
        );
        assert_eq!(gate.snapshot().eligible_datagrams, 0);
        assert!(gate.arm(([192, 0, 2, 1], 51000).into()).is_err());
        assert!(gate.arm(([127, 0, 0, 1], 0).into()).is_err());
        gate.arm(PEER).unwrap();
        assert_eq!(gate.arm(PEER), Err("ONE_GAP_ALREADY_ARMED"));
        assert_eq!(gate.arm(OTHER), Err("ONE_GAP_ALREADY_ARMED"));
        assert_eq!(gate.snapshot().target_peer_port, Some(PEER.port()));
    }

    #[test]
    fn one_gap_socket_ignores_other_peer_long_small_and_empty() {
        let (_, gate, socket) = fixture(
            true,
            [Receive::Batch(vec![
                datagram(OTHER, 1200, 0x40),
                datagram(PEER, 1200, 0xc0),
                datagram(PEER, 999, 0x40),
                datagram(PEER, 0, 0),
            ])],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1500]; 4];
        let mut meta = [RecvMeta::default(); 4];
        let wakes = Arc::new(Wakes::default());
        delivered(recv(&socket, &mut buffers, &mut meta, &wakes.into()), 4);
        assert_eq!(meta[0].addr, OTHER);
        assert_eq!(meta[1].len, 1200);
        assert_eq!(meta[2].len, 999);
        assert_eq!(meta[3].len, 0);
        assert_eq!(gate.snapshot().eligible_datagrams, 0);
        assert_eq!(gate.snapshot().dropped_datagrams, 0);
    }

    #[test]
    fn one_gap_socket_pass_control_records_without_omission() {
        let first = datagram(PEER, 1000, 0x40);
        let expected = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &first.data);
        let (_, gate, socket) = fixture(
            false,
            [Receive::Batch(vec![first, datagram(PEER, 1300, 0x41)])],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1500]; 2];
        let mut meta = [RecvMeta::default(); 2];
        let wakes = Arc::new(Wakes::default());
        delivered(recv(&socket, &mut buffers, &mut meta, &wakes.into()), 2);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.mode, "pass");
        assert_eq!(snapshot.eligible_datagrams, 2);
        assert_eq!(snapshot.dropped_datagrams, 0);
        assert_eq!(snapshot.records[0].eligible_ordinal, 1);
        assert_eq!(snapshot.records[1].eligible_ordinal, 2);
        assert!(snapshot.records.iter().all(|record| !record.actual_dropped));
        let expected: String = expected
            .as_ref()
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect();
        assert_eq!(snapshot.records[0].cipher_sha256, expected);
        let json = serde_json::to_value(snapshot).unwrap();
        assert!(json["records"][0].get("payload").is_none());
        assert!(json["records"][0].get("addr").is_none());
    }

    #[test]
    fn one_gap_socket_exactly_one_drop_yields_then_delivers_following_packet() {
        let (inner, gate, socket) = fixture(
            true,
            [
                Receive::Batch(vec![datagram(PEER, 1200, 0x40)]),
                Receive::Batch(vec![datagram(PEER, 1250, 0x41)]),
            ],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1500]];
        let mut meta = [RecvMeta::default()];
        let wakes = Arc::new(Wakes::default());
        let waker = wakes.clone().into();
        assert!(recv(&socket, &mut buffers, &mut meta, &waker).is_pending());
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        delivered(recv(&socket, &mut buffers, &mut meta, &waker), 1);
        assert_eq!(meta[0].len, 1250);
        assert_eq!(buffers[0][0], 0x41);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.dropped_datagrams, 1);
        assert_eq!(snapshot.dropped_bytes, 1200);
        assert!(snapshot.records[0].actual_dropped);
        assert!(!snapshot.records[1].actual_dropped);
        assert!(gate.arm(PEER).is_err());
    }

    #[test]
    fn one_gap_socket_batch_compaction_keeps_payload_and_all_recv_metadata() {
        let mut last = datagram(PEER, 1250, 0x43);
        last.meta.ecn = Some(EcnCodepoint::Ce);
        last.meta.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        let expected_data = last.data.clone();
        let expected_meta = last.meta;
        let (_, gate, socket) = fixture(
            true,
            [Receive::Batch(vec![
                datagram(OTHER, 1100, 0x42),
                datagram(PEER, 1200, 0x40),
                last,
            ])],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1500]; 3];
        let mut meta = [RecvMeta::default(); 3];
        let wakes = Arc::new(Wakes::default());
        delivered(
            recv(&socket, &mut buffers, &mut meta, &wakes.clone().into()),
            2,
        );
        assert_eq!(meta[0].addr, OTHER);
        assert_eq!(buffers[0][0], 0x42);
        assert_eq!(&buffers[1][..expected_meta.len], expected_data);
        assert_eq!(meta[1].addr, expected_meta.addr);
        assert_eq!(meta[1].len, expected_meta.len);
        assert_eq!(meta[1].stride, expected_meta.stride);
        assert_eq!(meta[1].ecn, expected_meta.ecn);
        assert_eq!(meta[1].dst_ip, expected_meta.dst_ip);
        assert_eq!(gate.snapshot().dropped_datagrams, 1);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn one_gap_socket_drop_then_pending_and_receive_error_do_not_spin() {
        let (inner, gate, socket) = fixture(
            true,
            [
                Receive::Batch(vec![datagram(PEER, 1200, 0x40)]),
                Receive::Pending,
                Receive::Error(10054),
            ],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1500]];
        let mut meta = [RecvMeta::default()];
        let wakes = Arc::new(Wakes::default());
        let waker = wakes.clone().into();
        assert!(recv(&socket, &mut buffers, &mut meta, &waker).is_pending());
        assert!(recv(&socket, &mut buffers, &mut meta, &waker).is_pending());
        assert_eq!(inner.calls.load(Ordering::Relaxed), 2);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert!(matches!(recv(&socket, &mut buffers, &mut meta, &waker),
            Poll::Ready(Err(error)) if error.raw_os_error() == Some(10054)));
        assert_eq!(inner.calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn one_gap_socket_aggregated_target_is_unsupported_and_disables_injection() {
        let mut aggregated = datagram(PEER, 1200, 0x40);
        aggregated.meta.stride = 600;
        let (_, gate, socket) = fixture(
            true,
            [
                Receive::Batch(vec![aggregated]),
                Receive::Batch(vec![datagram(PEER, 1250, 0x41)]),
            ],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1500]];
        let mut meta = [RecvMeta::default()];
        let wakes = Arc::new(Wakes::default());
        let waker = wakes.into();
        delivered(recv(&socket, &mut buffers, &mut meta, &waker), 1);
        assert_eq!(meta[0].stride, 600);
        assert_eq!(meta[0].len, 1200);
        delivered(recv(&socket, &mut buffers, &mut meta, &waker), 1);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.unsupported_datagrams, 1);
        assert_eq!(snapshot.dropped_datagrams, 0);
        assert!(!snapshot.records[0].actual_dropped);
    }

    #[test]
    fn one_gap_socket_small_compaction_slot_preserves_entire_batch() {
        let (_, gate, socket) = fixture(
            true,
            [Receive::Batch(vec![
                datagram(PEER, 1000, 0x40),
                datagram(PEER, 1250, 0x41),
            ])],
        );
        gate.arm(PEER).unwrap();
        let mut buffers = vec![vec![0; 1000], vec![0; 1500]];
        let mut meta = [RecvMeta::default(); 2];
        let wakes = Arc::new(Wakes::default());
        delivered(recv(&socket, &mut buffers, &mut meta, &wakes.into()), 2);
        assert_eq!(buffers[0][0], 0x40);
        assert_eq!(buffers[1][0], 0x41);
        assert_eq!(meta[0].len, 1000);
        assert_eq!(meta[1].len, 1250);
        assert_eq!(gate.snapshot().unsupported_batches, 1);
        assert_eq!(gate.snapshot().dropped_datagrams, 0);
    }

    #[test]
    fn one_gap_socket_send_poller_and_capabilities_are_preserved_or_declared() {
        let (inner, gate, socket) = fixture(true, []);
        gate.arm(PEER).unwrap();
        let contents = vec![0x40; 1200];
        let transmit = Transmit {
            destination: PEER,
            ecn: Some(EcnCodepoint::Ect1),
            contents: &contents,
            segment_size: Some(600),
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        };
        *inner.send_error.lock().unwrap() = Some(10035);
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().raw_os_error(),
            Some(10035)
        );
        socket.try_send(&transmit).unwrap();
        let sends = inner.sends.lock().unwrap();
        assert_eq!(sends.len(), 2);
        for record in sends.iter() {
            assert_eq!(record.destination, transmit.destination);
            assert_eq!(record.ecn, transmit.ecn);
            assert_eq!(record.bytes, contents);
            assert_eq!(record.segment_size, transmit.segment_size);
            assert_eq!(record.src_ip, transmit.src_ip);
        }
        assert_eq!(socket.local_addr().unwrap(), ([127, 0, 0, 1], 49420).into());
        assert_eq!(socket.max_transmit_segments(), 1);
        assert_eq!(socket.max_receive_segments(), 4);
        assert!(!socket.may_fragment());
        let mut poller = socket.clone().create_io_poller();
        let waker: Waker = Arc::new(Wakes::default()).into();
        assert!(poller
            .as_mut()
            .poll_writable(&mut Context::from_waker(&waker))
            .is_ready());
        assert_eq!(inner.pollers.load(Ordering::Relaxed), 1);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.max_transmit_segments, 1);
        assert_eq!(snapshot.underlying_max_transmit_segments, Some(8));
        assert_eq!(snapshot.max_receive_segments, Some(4));
        assert_eq!(snapshot.dropped_datagrams, 0);
    }
}
