//! Tier 0: exercise the public adapter across real peer handshakes and bounded
//! transport writes. No network, wall-clock performance assertion or mock crypto.

use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;

use lkrequest::TlsConnector;
use lktls::profile::{presets, types::TlsVersion};
use lktls::session_store::InMemorySessionStore;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

struct FragmentedTransport {
    stream: DuplexStream,
    chunk: usize,
    pending_write: bool,
    pending_flush: bool,
    writes: Arc<AtomicUsize>,
}

impl AsyncRead for FragmentedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let limit = output.remaining().min(self.chunk);
        let mut part = ReadBuf::new(output.initialize_unfilled_to(limit));
        match Pin::new(&mut self.stream).poll_read(cx, &mut part) {
            Poll::Ready(Ok(())) => {
                let count = part.filled().len();
                output.advance(count);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for FragmentedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write {
            self.pending_write = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let limit = bytes.len().min(self.chunk);
        let result = Pin::new(&mut self.stream).poll_write(cx, &bytes[..limit]);
        if let Poll::Ready(Ok(count)) = result {
            assert!(count <= self.chunk);
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.pending_write = true;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_flush {
            self.pending_flush = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = Pin::new(&mut self.stream).poll_flush(cx);
        if result.is_ready() {
            self.pending_flush = true;
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn public_tls_lifecycle_survives_short_writes_and_pending_across_resumption() {
    assert!(
        tokio::time::timeout(Duration::from_secs(30), async {
            for tls12 in [false, true] {
                for chunk in [1, 17, 1024] {
                    run_case(tls12, chunk).await;
                }
            }
        })
        .await
        .is_ok(),
        "bounded in-memory TLS lifecycle must not stall"
    );
}

async fn run_case(tls12: bool, chunk: usize) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let anchor =
        lktls::verify::certchain::parse_trust_anchor_from_der(certificate.cert.der()).unwrap();
    let mut server = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[if tls12 {
        &rustls::version::TLS12
    } else {
        &rustls::version::TLS13
    }])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    server.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
    let server = Arc::new(server);
    let mut profile = presets::chrome_144();
    profile.tls_min_version = if tls12 {
        TlsVersion::Tls12
    } else {
        TlsVersion::Tls13
    };
    profile.tls_max_version = profile.tls_min_version;
    let hellos = Arc::new(AtomicUsize::new(0));
    let hello_count = hellos.clone();
    let connector = TlsConnector::new(profile)
        .custom_ca_anchors(Arc::new(vec![anchor]))
        .session_store(Arc::new(InMemorySessionStore::new()))
        .require_close_notify(true)
        .on_client_hello(Arc::new(move |_| {
            hello_count.fetch_add(1, Ordering::Relaxed);
        }));
    for resumed in [false, true] {
        let payload: Vec<u8> = (0..32791).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        // Leave room for the peer's post-handshake tickets while the application
        // is writing; the wrapper still enforces tiny writes and Pending polls.
        let (client_socket, server_socket) = tokio::io::duplex(4096);
        let acceptor = tokio_rustls::TlsAcceptor::from(server.clone());
        let peer = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_socket).await.unwrap();
            assert_eq!(
                tls.get_ref().1.handshake_kind(),
                Some(if resumed {
                    rustls::HandshakeKind::Resumed
                } else {
                    rustls::HandshakeKind::Full
                })
            );
            let mut received = vec![0; expected.len()];
            tls.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
            tls.write_all(&received).await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let writes = Arc::new(AtomicUsize::new(0));
        let transport = FragmentedTransport {
            stream: client_socket,
            chunk,
            pending_write: true,
            pending_flush: true,
            writes: writes.clone(),
        };
        let mut client = connector
            .connect("localhost", 443, transport)
            .await
            .unwrap();
        eprintln!("tls12={tls12} chunk={chunk} resumed={resumed}: connected");
        assert_eq!(
            client.negotiated_version(),
            Some(if tls12 { 0x0303 } else { 0x0304 })
        );
        assert_eq!(client.peer_certificates().is_empty(), resumed);
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, payload);
        assert!(client.received_close_notify());
        assert!(writes.load(Ordering::Relaxed) > payload.len() / chunk);
        peer.await.unwrap();
        assert_eq!(
            hellos.load(Ordering::Relaxed),
            if resumed { 2 } else { 1 },
            "short writes must not restart ClientHello generation"
        );
    }
}

const INJECTED_WRITE_ERROR: &str = "injected authenticated transport write failure";

struct WriteFault {
    budget: AtomicUsize,
    write_calls: AtomicUsize,
    written_bytes: AtomicUsize,
    read_calls: AtomicUsize,
    flush_calls: AtomicUsize,
}

impl WriteFault {
    fn new() -> Self {
        Self {
            budget: AtomicUsize::new(usize::MAX),
            write_calls: AtomicUsize::new(0),
            written_bytes: AtomicUsize::new(0),
            read_calls: AtomicUsize::new(0),
            flush_calls: AtomicUsize::new(0),
        }
    }

    fn observations(&self) -> [usize; 4] {
        [
            self.write_calls.load(Ordering::Relaxed),
            self.written_bytes.load(Ordering::Relaxed),
            self.read_calls.load(Ordering::Relaxed),
            self.flush_calls.load(Ordering::Relaxed),
        ]
    }
}

struct FailingTransport {
    stream: DuplexStream,
    fault: Arc<WriteFault>,
}

impl AsyncRead for FailingTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.fault.read_calls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut self.stream).poll_read(cx, output)
    }
}

impl AsyncWrite for FailingTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.fault.write_calls.fetch_add(1, Ordering::Relaxed);
        let budget = self.fault.budget.load(Ordering::Relaxed);
        if budget == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                INJECTED_WRITE_ERROR,
            )));
        }
        let result = Pin::new(&mut self.stream).poll_write(cx, &bytes[..bytes.len().min(budget)]);
        if let Poll::Ready(Ok(count)) = result {
            self.fault.written_bytes.fetch_add(count, Ordering::Relaxed);
            if budget != usize::MAX {
                self.fault.budget.fetch_sub(count, Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.fault.flush_calls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn terminal_write_failure_returns_accepted_plaintext_once_and_latches_original_error() {
    assert!(
        tokio::time::timeout(Duration::from_secs(15), async {
            for tls12 in [false, true] {
                for transport_prefix in [0, 7] {
                    terminal_write_case(tls12, transport_prefix).await;
                }
            }
        })
        .await
        .is_ok(),
        "terminal write errors must not stall later reads or flushes"
    );
}

async fn terminal_write_case(tls12: bool, transport_prefix: usize) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let anchor =
        lktls::verify::certchain::parse_trust_anchor_from_der(certificate.cert.der()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[if tls12 {
        &rustls::version::TLS12
    } else {
        &rustls::version::TLS13
    }])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    let mut profile = presets::chrome_144();
    profile.tls_min_version = if tls12 {
        TlsVersion::Tls12
    } else {
        TlsVersion::Tls13
    };
    profile.tls_max_version = profile.tls_min_version;
    let connector = TlsConnector::new(profile).custom_ca_anchors(Arc::new(vec![anchor]));
    let (client_socket, server_socket) = tokio::io::duplex(4096);
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let tls = acceptor.accept(server_socket).await.unwrap();
        accepted_tx.send(()).unwrap();
        let _ = release_rx.await;
        drop(tls);
    });
    let fault = Arc::new(WriteFault::new());
    let transport = FailingTransport {
        stream: client_socket,
        fault: fault.clone(),
    };
    let mut client = connector
        .connect("localhost", 443, transport)
        .await
        .unwrap();
    accepted_rx.await.unwrap();
    assert_eq!(
        client.negotiated_version(),
        Some(if tls12 { 0x0303 } else { 0x0304 })
    );
    let bytes_before = fault.written_bytes.load(Ordering::Relaxed);
    let writes_before = fault.write_calls.load(Ordering::Relaxed);
    fault.budget.store(transport_prefix, Ordering::Relaxed);
    let payload = [0x6d; 2048];
    let accepted = client.write(&payload).await;
    assert!(matches!(accepted, Ok(count) if count > 0 && count <= payload.len()),
        "tls12={tls12} prefix={transport_prefix}: sealed plaintext must be acknowledged once, got {accepted:?}");
    assert_eq!(
        fault.written_bytes.load(Ordering::Relaxed) - bytes_before,
        transport_prefix
    );
    assert!(
        fault.write_calls.load(Ordering::Relaxed) > writes_before,
        "the injected write error must be observed before checking the latch"
    );
    let terminal_observations = fault.observations();

    // Let the underlying stream succeed again. Only the adapter's failure latch
    // can prevent retransmitting queued ciphertext or emitting a fresh alert.
    fault.budget.store(usize::MAX, Ordering::Relaxed);
    let write_error = client.write(b"must not be encoded").await.unwrap_err();
    assert_eq!(write_error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(write_error.to_string(), INJECTED_WRITE_ERROR);
    let flush_error = client.flush().await.unwrap_err();
    assert_eq!(flush_error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(flush_error.to_string(), INJECTED_WRITE_ERROR);
    let read_error = client.read(&mut [0; 16]).await.unwrap_err();
    assert_eq!(read_error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(read_error.to_string(), INJECTED_WRITE_ERROR);
    assert_eq!(
        fault.observations(),
        terminal_observations,
        "terminal TLS must not attempt new transport I/O or send an alert"
    );
    release_tx.send(()).unwrap();
    peer.await.unwrap();
}
