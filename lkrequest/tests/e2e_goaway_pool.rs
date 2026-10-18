//! Concurrent GOAWAY draining and replacement-connection recovery (loopback).

use bytes::{Bytes, BytesMut};
use lkh2::codec::{DecodeResult, H2Codec};
use lkh2::frame::{DataFrame, GoAwayFrame, H2Frame, HeadersFrame, SettingsFrame};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn begin<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) {
    let mut preface = [0; 24];
    io.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, lkh2::CONNECTION_PREFACE);
    send(
        io,
        H2Frame::Settings(SettingsFrame {
            ack: false,
            settings: Vec::new(),
        }),
    )
    .await;
}

async fn send<S: AsyncWrite + Unpin>(io: &mut S, frame: H2Frame) {
    let mut bytes = BytesMut::new();
    H2Codec::new().encode(&frame, &mut bytes);
    io.write_all(&bytes).await.unwrap();
    io.flush().await.unwrap();
}

async fn headers<S: AsyncRead + Unpin>(io: &mut S, input: &mut BytesMut, expected: u32) {
    let mut codec = H2Codec::new();
    loop {
        match codec.decode(input) {
            DecodeResult::Frame(H2Frame::Headers(frame)) => {
                assert_eq!(frame.stream_id, expected);
                assert!(frame.end_headers && frame.end_stream);
                return;
            }
            DecodeResult::Frame(_) => {}
            DecodeResult::NeedMoreData { .. } => {
                assert!(io.read_buf(input).await.unwrap() > 0);
            }
            DecodeResult::Error(error) => panic!("invalid client frame: {error}"),
        }
    }
}

async fn response<S: AsyncWrite + Unpin>(io: &mut S, stream_id: u32, body: Option<&'static [u8]>) {
    send(
        io,
        H2Frame::Headers(HeadersFrame {
            stream_id,
            end_stream: false,
            end_headers: true,
            priority: None,
            padding: None,
            header_block: Bytes::from_static(&[0x88]),
        }),
    )
    .await;
    if let Some(body) = body {
        data(io, stream_id, body).await;
    }
}

async fn data<S: AsyncWrite + Unpin>(io: &mut S, stream_id: u32, body: &'static [u8]) {
    send(
        io,
        H2Frame::Data(DataFrame {
            stream_id,
            end_stream: true,
            padding: None,
            data: Bytes::from_static(body),
        }),
    )
    .await;
}

#[tokio::test]
async fn late_h2_failure_reuses_replacement_and_preserves_accepted_responses() {
    for streaming in [false, true] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let mut config = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
                ),
            )
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];
            config.send_tls13_tickets = 0;
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("https://{}", listener.local_addr().unwrap());
            let (late_seen, late_ready) = tokio::sync::oneshot::channel();
            let (finish_old, old_finished) = tokio::sync::oneshot::channel();
            let (finish_new, new_finished) = tokio::sync::oneshot::channel();
            let (finish_server, server_finished) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (first, _) = listener.accept().await.unwrap();
                let mut first = acceptor.accept(first).await.unwrap();
                let old = tokio::spawn(async move {
                    begin(&mut first).await;
                    let mut input = BytesMut::new();
                    headers(&mut first, &mut input, 1).await;
                    response(&mut first, 1, Some(b"warm")).await;
                    headers(&mut first, &mut input, 3).await;
                    response(&mut first, 3, None).await;
                    headers(&mut first, &mut input, 5).await;
                    late_seen.send(()).unwrap();
                    headers(&mut first, &mut input, 7).await;
                    send(
                        &mut first,
                        H2Frame::GoAway(GoAwayFrame {
                            last_stream_id: 3,
                            error_code: 0,
                            debug_data: Bytes::new(),
                        }),
                    )
                    .await;
                    old_finished.await.unwrap();
                    data(&mut first, 3, b"old-complete").await;
                    let _ = first.read_to_end(&mut Vec::new()).await;
                });
                let (second, _) = listener.accept().await.unwrap();
                let mut second = acceptor.accept(second).await.unwrap();
                begin(&mut second).await;
                let mut input = BytesMut::new();
                headers(&mut second, &mut input, 1).await;
                response(&mut second, 1, Some(b"new")).await;
                headers(&mut second, &mut input, 3).await;
                response(&mut second, 3, None).await;
                headers(&mut second, &mut input, 5).await;
                response(&mut second, 5, Some(b"late")).await;
                new_finished.await.unwrap();
                data(&mut second, 3, b"new-complete").await;
                headers(&mut second, &mut input, 7).await;
                response(&mut second, 7, Some(b"reuse")).await;
                server_finished.await.unwrap();
                old.await.unwrap();
            });
            let client = lkrequest::Client::builder()
                .preset(lkrequest::preset::chrome_155())
                .add_ca_cert_der(cert.cert.der())
                .build();
            let session = client.session().http2_only().max_connections(2).build();
            assert_eq!(
                session
                    .get(&format!("{base}/warm"))
                    .send()
                    .await
                    .unwrap()
                    .bytes(),
                b"warm"
            );
            let old_body = session
                .get(&format!("{base}/old-held"))
                .send_streaming()
                .await
                .unwrap();
            let request = session.post(&format!("{base}/late"));
            let mut late = Box::pin(async move {
                if streaming {
                    request
                        .send_streaming()
                        .await?
                        .bytes()
                        .await
                        .map(|body| body.to_vec())
                } else {
                    request
                        .send()
                        .await
                        .map(|response| response.bytes().to_vec())
                }
            });
            tokio::select! {
                _ = late_ready => {},
                result = &mut late => panic!("late request completed before GOAWAY: {result:?}"),
            }
            // Pause this POST after it acquired the old sender. GOAWAY excludes
            // its stream, so recovery is permitted without an idempotency opt-in.
            assert_eq!(
                session
                    .get(&format!("{base}/trigger"))
                    .send()
                    .await
                    .unwrap()
                    .bytes(),
                b"new"
            );
            let new_body = session
                .get(&format!("{base}/new-held"))
                .send_streaming()
                .await
                .unwrap();
            assert_eq!(session.pool_stats().total, 2);
            let response = late
                .await
                .expect("late failure must reuse the live replacement");
            assert_eq!(response, b"late");
            assert_eq!(session.pool_stats().h2_connections, 1);
            assert_eq!(session.pool_stats().total, 2);
            finish_old.send(()).unwrap();
            finish_new.send(()).unwrap();
            assert_eq!(old_body.bytes().await.unwrap().as_ref(), b"old-complete");
            assert_eq!(new_body.bytes().await.unwrap().as_ref(), b"new-complete");
            tokio::time::timeout(Duration::from_secs(1), async {
                while session.pool_stats().total != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("old draining connection retained its reservation");
            assert_eq!(
                session
                    .get(&format!("{base}/reuse"))
                    .send()
                    .await
                    .unwrap()
                    .bytes(),
                b"reuse"
            );
            finish_server.send(()).unwrap();
            server.await.unwrap();
        })
        .await
        .expect("concurrent GOAWAY recovery did not finish");
    }
}
