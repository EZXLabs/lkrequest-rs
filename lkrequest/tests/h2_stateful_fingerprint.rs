//! Tier-0 Session/TLS/native-H2 wire checks for request priority and reuse.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> ([u8; 9], Vec<u8>) {
    let mut header = [0; 9];
    stream.read_exact(&mut header).await.unwrap();
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    assert!(length <= 16384, "client frame is bounded");
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    (header, payload)
}

async fn response_body(request: lkrequest::session::RequestBuilder, streaming: bool) -> Vec<u8> {
    if streaming {
        let response = request.send_streaming().await.unwrap();
        assert_eq!(response.status(), 200);
        response.bytes().await.unwrap().to_vec()
    } else {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        response.bytes().to_vec()
    }
}

async fn priority_sequence(
    streaming: bool,
    firefox: bool,
    explicit_first: Option<lkh2::RequestPriority>,
    first_weight: Option<u8>,
) -> Vec<(u32, u8, u32, String)> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca = cert.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let mut tls = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut magic = [0; 24];
            stream.read_exact(&mut magic).await.unwrap();
            assert_eq!(&magic, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            stream
                .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let mut decoder = lkh2::hpack::HeaderDecoder::new(4096);
            let mut observed = Vec::new();
            while observed.len() < 3 {
                let (header, payload) = read_frame(&mut stream).await;
                if header[3] == 4 && header[4] & 1 == 0 {
                    stream
                        .write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])
                        .await
                        .unwrap();
                }
                if header[3] != 1 {
                    continue;
                }
                assert_ne!(header[4] & 4, 0, "complete request HEADERS");
                assert_eq!(header[4] & 8, 0, "no header padding in this profile");
                let mut wire = header.to_vec();
                wire.extend_from_slice(&payload);
                let parsed = lkprofile::h2_fingerprint_from_frames_no_preface(&wire).unwrap();
                let priority = parsed
                    .profile
                    .headers_priority
                    .expect("Chrome HEADERS priority");
                let fields = decoder.decode(&payload[5..]).unwrap();
                let http_priority = fields
                    .iter()
                    .find(|(name, _)| name == "priority")
                    .expect("request priority header")
                    .1
                    .clone();
                let stream_id = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
                observed.push((
                    stream_id,
                    priority.weight,
                    priority.stream_dependency,
                    http_priority,
                ));

                let mut response = vec![0, 0, 1, 1, 4, 0, 0, 0, 0, 0x88];
                response[5..9].copy_from_slice(&stream_id.to_be_bytes());
                if observed.len() == 2 {
                    response[4] |= 1; // Exercise HEADERS-only completion too.
                } else {
                    response.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, b'a']);
                    response[15..19].copy_from_slice(&stream_id.to_be_bytes());
                }
                stream.write_all(&response).await.unwrap();
                stream.flush().await.unwrap();
            }
            observed
        });

        let client = lkrequest::Client::builder()
            .preset(if firefox {
                lkrequest::preset::firefox_156()
            } else {
                lkrequest::preset::chrome_155()
            })
            .default_header("sec-fetch-dest", "document")
            .add_ca_cert_der(&ca)
            .build();
        let session = client.session().http2_only().build();
        let origin = format!("https://{address}");
        let mut first = session.get(&format!("{origin}/cdn-cgi/trace"));
        if let Some(priority) = explicit_first {
            first = first.priority(priority);
        }
        if let Some(weight) = first_weight {
            first = first.h2_priority_weight(weight);
        }
        assert_eq!(response_body(first, streaming).await, b"a");
        let mut second = session
            .get(&format!("{origin}/favicon.ico"))
            .header("sec-fetch-dest", "image")
            .header("priority", if firefox { "u=6" } else { "u=1, i" });
        if firefox {
            second = second.h2_priority_weight(21);
        }
        assert!(response_body(second, streaming).await.is_empty());
        assert_eq!(
            response_body(session.get(&format!("{origin}/again")), streaming).await,
            b"a"
        );
        server.await.unwrap()
    })
    .await
    .expect("local stateful H2 fingerprint check completes")
}

#[tokio::test]
async fn firefox_resource_weight_is_independent_for_both_response_modes() {
    for streaming in [false, true] {
        assert_eq!(
            priority_sequence(streaming, true, None, None).await,
            [
                (3, 41, 0, "u=0, i".to_string()),
                (5, 21, 0, "u=6".to_string()),
                (7, 41, 0, "u=0, i".to_string()),
            ]
        );
    }
}

#[tokio::test]
async fn first_h2_request_preserves_raw_weight_override() {
    for weight in [21, 0, 255] {
        assert_eq!(
            priority_sequence(
                false,
                true,
                Some(lkh2::RequestPriority::custom(6, false)),
                Some(weight),
            )
            .await,
            [
                (3, weight, 0, "u=6".to_string()),
                (5, 21, 0, "u=6".to_string()),
                (7, 41, 0, "u=0, i".to_string()),
            ],
            "buffered first-request raw weight {weight}"
        );
    }
}

#[tokio::test]
async fn streaming_first_h2_request_preserves_raw_weight_override() {
    for weight in [21, 0, 255] {
        assert_eq!(
            priority_sequence(
                true,
                true,
                Some(lkh2::RequestPriority::custom(6, false)),
                Some(weight),
            )
            .await,
            [
                (3, weight, 0, "u=6".to_string()),
                (5, 21, 0, "u=6".to_string()),
                (7, 41, 0, "u=0, i".to_string()),
            ],
            "streaming first-request raw weight {weight}"
        );
    }
}

#[tokio::test]
async fn explicit_streaming_priority_overrides_client_destination() {
    assert_eq!(
        priority_sequence(
            true,
            false,
            Some(lkh2::RequestPriority::custom(4, false)),
            None,
        )
        .await,
        [
            (1, 73, 0, "u=4".to_string()),
            (3, 219, 0, "u=1, i".to_string()),
            (5, 255, 0, "u=0, i".to_string()),
        ]
    );
}

#[tokio::test]
async fn navigation_and_reused_requests_match_captured_priorities() {
    assert_eq!(
        priority_sequence(false, false, None, None).await,
        [
            (1, 255, 0, "u=0, i".to_string()),
            (3, 219, 0, "u=1, i".to_string()),
            (5, 255, 0, "u=0, i".to_string()),
        ]
    );
}

#[tokio::test]
async fn streaming_navigation_uses_the_same_wire_priorities() {
    assert_eq!(
        priority_sequence(true, false, None, None).await,
        [
            (1, 255, 0, "u=0, i".to_string()),
            (3, 219, 0, "u=1, i".to_string()),
            (5, 255, 0, "u=0, i".to_string()),
        ]
    );
}
