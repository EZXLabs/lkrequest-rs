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

/// A fixture-controlled loss phase for short-header-prefixed UDP datagrams.
/// Long-header and empty datagrams pass, including any later coalesced 1-RTT
/// packet in a long-header-prefixed datagram. No encrypted frame is inspected.
/// Use on the current-thread test runtime and queue STOP then release or permit
/// without yielding, so the driver cannot transmit STOP under the old phase.
#[derive(Debug, Default)]
pub(super) struct StopPacketGate {
    state: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    armed: bool,
    permit_peer: Option<SocketAddr>,
    dropped_datagrams: usize,
    dropped_bytes: usize,
}

impl StopPacketGate {
    pub(super) fn arm(&self) {
        *self.state.lock().unwrap() = GateState {
            armed: true,
            ..GateState::default()
        };
    }

    /// Allow one successful short-header datagram to this peer without resetting
    /// phase statistics. Long-header/empty datagrams do not use this allowance.
    pub(super) fn permit_one_to(&self, peer: SocketAddr) {
        let mut state = self.state.lock().unwrap();
        state.armed = true;
        state.permit_peer = Some(peer);
    }

    pub(super) fn release(&self) -> usize {
        let mut state = self.state.lock().unwrap();
        state.armed = false;
        state.permit_peer = None;
        state.dropped_datagrams
    }

    pub(super) fn dropped_count(&self) -> usize {
        self.state.lock().unwrap().dropped_datagrams
    }

    pub(super) fn dropped_bytes(&self) -> usize {
        self.state.lock().unwrap().dropped_bytes
    }

    pub(super) fn is_armed(&self) -> bool {
        self.state.lock().unwrap().armed
    }
}

#[derive(Debug)]
pub(super) struct GatedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Arc<StopPacketGate>,
}

impl GatedSocket {
    pub(super) fn new(inner: Arc<dyn AsyncUdpSocket>, gate: Arc<StopPacketGate>) -> Self {
        Self { inner, gate }
    }
}

impl AsyncUdpSocket for GatedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit
            .contents
            .first()
            .is_some_and(|first| first & 0x80 == 0)
        {
            let mut state = self.gate.state.lock().unwrap();
            if state.armed {
                if state.permit_peer == Some(transmit.destination) {
                    // Serialize the allowance around one nonblocking send. An
                    // error leaves it available for Quinn's buffered retry.
                    let result = self.inner.try_send(transmit);
                    if result.is_ok() {
                        state.permit_peer = None;
                    }
                    return result;
                }
                // Segment metadata counts datagrams, never encrypted frame types.
                state.dropped_datagrams += transmit
                    .segment_size
                    .map_or(1, |size| transmit.contents.len().div_ceil(size));
                state.dropped_bytes += transmit.contents.len();
                return Ok(());
            }
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
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
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, Default)]
    struct SocketProbe {
        sends: AtomicUsize,
        pollers: AtomicUsize,
        failures: Mutex<VecDeque<io::ErrorKind>>,
    }

    #[derive(Debug)]
    struct Writable;

    impl UdpPoller for Writable {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for SocketProbe {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.pollers.fetch_add(1, Ordering::Relaxed);
            Box::pin(Writable)
        }

        fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.failures.lock().unwrap().pop_front() {
                return Err(error.into());
            }
            Ok(())
        }

        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(([127, 0, 0, 1], 0).into())
        }

        fn max_transmit_segments(&self) -> usize {
            32
        }

        fn max_receive_segments(&self) -> usize {
            4
        }

        fn may_fragment(&self) -> bool {
            false
        }
    }

    #[test]
    fn stop_packet_gate_discards_only_inside_explicit_loss_phase() {
        let inner = Arc::new(SocketProbe::default());
        let gate = Arc::new(StopPacketGate::default());
        let socket = GatedSocket::new(inner.clone(), gate.clone());
        let transmit = Transmit {
            destination: ([127, 0, 0, 1], 0).into(),
            ecn: None,
            contents: b"opaque",
            segment_size: None,
            src_ip: None,
        };
        assert!(!gate.is_armed());
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 1);
        gate.arm();
        socket.try_send(&transmit).unwrap();
        socket.try_send(&transmit).unwrap();
        assert_eq!(gate.dropped_count(), 2);
        assert_eq!(gate.dropped_bytes(), 12);
        assert_eq!(inner.sends.load(Ordering::Relaxed), 1);
        assert_eq!(gate.release(), 2);
        assert_eq!(
            inner.sends.load(Ordering::Relaxed),
            1,
            "release must not flush dropped datagrams"
        );
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 2);
        gate.arm();
        assert_eq!(gate.dropped_count(), 0);
        assert_eq!(gate.dropped_bytes(), 0);
        assert_eq!(gate.release(), 0);
    }

    #[test]
    fn stop_packet_gate_passes_long_header_and_empty_datagrams_while_armed() {
        let inner = Arc::new(SocketProbe::default());
        let gate = Arc::new(StopPacketGate::default());
        let socket = GatedSocket::new(inner.clone(), gate.clone());
        let mut transmit = Transmit {
            destination: ([127, 0, 0, 1], 0).into(),
            ecn: None,
            contents: b"",
            segment_size: None,
            src_ip: None,
        };
        gate.arm();
        for contents in [b"\xc0abc".as_slice(), b"\x80abc".as_slice(), b""] {
            transmit.contents = contents;
            socket.try_send(&transmit).unwrap();
        }
        assert_eq!(inner.sends.load(Ordering::Relaxed), 3);
        assert_eq!(gate.dropped_count(), 0);
        for contents in [b"\x40abc".as_slice(), b"\x7fabc".as_slice()] {
            transmit.contents = contents;
            socket.try_send(&transmit).unwrap();
        }
        assert_eq!(inner.sends.load(Ordering::Relaxed), 3);
        assert_eq!(gate.dropped_bytes(), 8);
        assert_eq!(gate.release(), 2);
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn stop_packet_gate_permits_only_one_short_datagram_to_the_case_peer() {
        let inner = Arc::new(SocketProbe::default());
        let gate = Arc::new(StopPacketGate::default());
        let socket = GatedSocket::new(inner.clone(), gate.clone());
        let case_peer = ([127, 0, 0, 1], 1).into();
        let warm_peer = ([127, 0, 0, 1], 2).into();
        let mut transmit = Transmit {
            destination: case_peer,
            ecn: None,
            contents: b"\x40abc",
            segment_size: None,
            src_ip: None,
        };
        gate.arm();
        socket.try_send(&transmit).unwrap();
        gate.permit_one_to(case_peer);
        assert_eq!(
            gate.dropped_count(),
            1,
            "granting a permit keeps phase statistics"
        );
        transmit.destination = warm_peer;
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 0);
        transmit.destination = case_peer;
        for contents in [b"\xc0abc".as_slice(), b""] {
            transmit.contents = contents;
            socket.try_send(&transmit).unwrap();
        }
        assert_eq!(inner.sends.load(Ordering::Relaxed), 2);
        transmit.contents = b"\x40abc";
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 3);
        assert!(gate.is_armed());
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 3);
        assert_eq!(gate.dropped_bytes(), 12);
        assert_eq!(gate.release(), 3);
        assert_eq!(
            inner.sends.load(Ordering::Relaxed),
            3,
            "no dropped packet is flushed"
        );
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 4);
        gate.permit_one_to(case_peer);
        gate.arm();
        socket.try_send(&transmit).unwrap();
        assert_eq!(
            inner.sends.load(Ordering::Relaxed),
            4,
            "arm clears an unused permit"
        );
        assert_eq!(gate.release(), 1);
    }

    #[test]
    fn stop_packet_gate_send_errors_preserve_the_targeted_allowance() {
        let inner = Arc::new(SocketProbe::default());
        inner
            .failures
            .lock()
            .unwrap()
            .extend([io::ErrorKind::WouldBlock, io::ErrorKind::Other]);
        let gate = Arc::new(StopPacketGate::default());
        let socket = GatedSocket::new(inner.clone(), gate.clone());
        let transmit = Transmit {
            destination: ([127, 0, 0, 1], 1).into(),
            ecn: None,
            contents: b"\x40abc",
            segment_size: None,
            src_ip: None,
        };
        gate.permit_one_to(transmit.destination);
        assert!(gate.is_armed());
        for error in [io::ErrorKind::WouldBlock, io::ErrorKind::Other] {
            assert_eq!(socket.try_send(&transmit).unwrap_err().kind(), error);
            assert_eq!(gate.dropped_count(), 0);
        }
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 3);
        socket.try_send(&transmit).unwrap();
        assert_eq!(inner.sends.load(Ordering::Relaxed), 3);
        assert_eq!(gate.release(), 1);
        assert_eq!(gate.dropped_bytes(), 4);
    }

    #[test]
    fn stop_packet_gate_preserves_socket_capabilities_except_gso() {
        let inner = Arc::new(SocketProbe::default());
        let gate = Arc::new(StopPacketGate::default());
        let socket = Arc::new(GatedSocket::new(inner.clone(), gate.clone()));
        assert_eq!(socket.local_addr().unwrap(), inner.local_addr().unwrap());
        assert_eq!(socket.max_transmit_segments(), 1);
        assert_eq!(socket.max_receive_segments(), 4);
        assert!(!socket.may_fragment());
        gate.arm();
        drop(socket.clone().create_io_poller());
        assert_eq!(inner.pollers.load(Ordering::Relaxed), 1);
        assert_eq!(gate.release(), 0);
    }
}
