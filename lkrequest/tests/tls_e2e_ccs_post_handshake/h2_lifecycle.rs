use super::*;
use bytes::{Bytes, BytesMut};
use lkh2::codec::{DecodeResult, H2Codec};
use lkh2::frame::H2Frame;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use tokio::sync::Notify;

const PAGE: &[u8] = b"<!doctype html><html><head><link rel=icon href=data:,></head><body>ccs-control-ok</body></html>";
const ROOT: &[u8] =
    b"<!doctype html><html><head><link rel=icon href=data:,></head><body>root-ready</body></html>";
const FAULT_BODY: &[u8] = b"ccs-control-ok";

#[derive(Clone, Copy, serde::Serialize)]
struct H2Case {
    family: &'static str,
    browser: &'static str,
    scenario: &'static str,
    version: u8,
    port: u16,
}

fn cases() -> Vec<H2Case> {
    let mut cases = Vec::new();
    for browser in ["chrome", "firefox"] {
        for version in [13, 12] {
            for scenario in ["goaway", "close_tls", "close_tcp", "goaway_tls"] {
                cases.push(H2Case {
                    family: "clean",
                    browser,
                    scenario,
                    version,
                    port: 49320 + cases.len() as u16,
                });
            }
        }
    }
    cases
}

fn error_cases() -> Vec<H2Case> {
    let mut cases = Vec::new();
    for browser in ["chrome", "firefox"] {
        for version in [13, 12] {
            for scenario in [
                "error1_after",
                "error2_after",
                "error11_after",
                "error2_partial_fin",
                "truncated_tls",
                "truncated_tcp",
                "goaway_drain",
                "error2_drain",
            ] {
                cases.push(H2Case {
                    family: "errors",
                    browser,
                    scenario,
                    version,
                    port: 49360 + cases.len() as u16,
                });
            }
        }
    }
    cases
}

fn selected_cases() -> Vec<H2Case> {
    if std::env::var("TEST_POST_CCS_SCENARIOS").ok().as_deref() == Some("h2-errors") {
        error_cases()
    } else {
        cases()
    }
}

#[derive(Default)]
struct Keys(Mutex<HashMap<String, Vec<u8>>>);
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys")
    }
}
impl rustls::KeyLog for Keys {
    fn log(&self, label: &str, random: &[u8], secret: &[u8]) {
        let mut keys = self.0.lock().unwrap();
        if matches!(label, "CLIENT_RANDOM" | "CLIENT_TRAFFIC_SECRET_0") {
            keys.insert(label.to_string(), secret.to_vec());
            keys.insert("client_random".into(), random.to_vec());
        }
    }
}

enum ClientCipher {
    Tls13(Aead),
    Tls12(lktls::crypto::tls12_cipher::Tls12GcmCipher),
}
impl ClientCipher {
    fn decode(&self, record: &[u8], sequence: u64) -> (u8, Vec<u8>) {
        match self {
            Self::Tls13(cipher) => {
                let mut inner = cipher
                    .decrypt(sequence, &record[..5], &record[5..])
                    .unwrap();
                while inner.last() == Some(&0) {
                    inner.pop();
                }
                (inner.pop().unwrap(), inner)
            }
            Self::Tls12(cipher) => {
                let mut aad = sequence.to_be_bytes().to_vec();
                aad.extend_from_slice(&record[..3]);
                aad.extend_from_slice(&((record.len() - 5 - 24) as u16).to_be_bytes());
                (record[0], cipher.decrypt(&aad, &record[5..]).unwrap())
            }
        }
    }
}

#[derive(serde::Serialize)]
struct RecordEvent {
    kind: u8,
    sequence: u64,
    alert: Option<[u8; 2]>,
    wire_hex: String,
    goaways: Vec<[u32; 2]>,
    goaway_hex: Vec<String>,
    resets: Vec<[u32; 2]>,
    reset_hex: Vec<String>,
}

#[derive(serde::Serialize)]
struct H2Observation {
    client: &'static str,
    browser: &'static str,
    scenario: &'static str,
    version: u8,
    port: u16,
    finished_verified: bool,
    requests_on_connection: usize,
    response_data_bytes: usize,
    probe_stream_id: u32,
    response_sent: bool,
    goaway_sent: bool,
    close_notify_sent: bool,
    tcp_shutdown_sent: bool,
    server_goaways: Vec<[u32; 2]>,
    events: Vec<RecordEvent>,
    peer_end: &'static str,
    close_ms: u128,
}

fn tls_config(fixture: &Fixture, version: u8, keys: Arc<Keys>) -> rustls::ServerConfig {
    if version == 13 {
        let mut config = fixture.config.clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        config.key_log = keys;
        return config;
    }
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(fixture.config.cert_resolver.clone());
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.key_log = keys;
    config
}

async fn h2_server(
    io: tokio::io::DuplexStream,
    delivered: Arc<Notify>,
    case: H2Case,
    probe_stream: Arc<AtomicU32>,
    requests: Arc<AtomicUsize>,
) {
    let mut connection = h2::server::handshake(io).await.unwrap();
    let (mut request, mut respond) = connection.accept().await.unwrap().unwrap();
    requests.fetch_add(1, Ordering::SeqCst);
    if case.family == "errors" && request.uri().path() == "/" {
        assert_eq!(request.method(), http::Method::GET);
        let root = http::Response::builder()
            .status(200)
            .header("content-type", "text/html")
            .header("content-length", ROOT.len())
            .header("cache-control", "no-store")
            .body(())
            .unwrap();
        respond
            .send_response(root, false)
            .unwrap()
            .send_data(Bytes::from_static(ROOT), true)
            .unwrap();
        drop(request);
        drop(respond);
        (request, respond) = connection.accept().await.unwrap().unwrap();
        requests.fetch_add(1, Ordering::SeqCst);
    }
    if case.family == "errors" {
        assert_eq!(request.uri().path(), "/next");
        assert_eq!(request.method(), http::Method::POST);
    } else {
        assert_eq!(request.uri().path(), "/");
        assert_eq!(request.method(), http::Method::GET);
    }
    probe_stream.store(respond.stream_id().as_u32(), Ordering::SeqCst);
    let body = if case.family == "errors" {
        FAULT_BODY
    } else {
        PAGE
    };
    let partial = matches!(
        case.scenario,
        "error2_partial_fin" | "truncated_tls" | "truncated_tcp" | "goaway_drain" | "error2_drain"
    );
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .header("content-length", body.len())
        .header("cache-control", "no-store")
        .body(())
        .unwrap();
    let mut stream = respond.send_response(response, false).unwrap();
    stream
        .send_data(
            Bytes::from_static(if partial { &body[..7] } else { body }),
            !partial,
        )
        .unwrap();
    let mut stream = Some(stream);
    if !partial {
        drop(stream.take());
    }
    drop(request);
    drop(respond);
    tokio::select! {
        _ = delivered.notified() => {}
        result = std::future::poll_fn(|cx| connection.poll_closed(cx)) => { let _ = result; return; }
    }
    if matches!(case.scenario, "goaway_drain" | "error2_drain") {
        connection.graceful_shutdown();
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            result = std::future::poll_fn(|cx| connection.poll_closed(cx)) => { let _ = result; return; }
        }
        if stream
            .as_mut()
            .unwrap()
            .send_data(Bytes::from_static(&body[7..]), true)
            .is_err()
        {
            return;
        }
        drop(stream.take());
    } else if case.scenario.starts_with("error") {
        let code = match case.scenario {
            "error1_after" => 1,
            "error11_after" => 11,
            _ => 2,
        };
        connection.abrupt_shutdown(h2::Reason::from(code));
    } else if case.scenario.starts_with("goaway") {
        connection.abrupt_shutdown(h2::Reason::NO_ERROR);
    }
    let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
}

async fn buffered_record(
    socket: &mut tokio::net::TcpStream,
    input: &mut BytesMut,
) -> std::io::Result<Vec<u8>> {
    // The select loop may cancel this future when H2 output arrives. Keep
    // partially read TLS records in the caller's buffer across cancellation.
    loop {
        if input.len() >= 5 {
            let length = u16::from_be_bytes([input[3], input[4]]) as usize;
            assert!(length < 18_432);
            if input.len() >= length + 5 {
                return Ok(input.split_to(length + 5).to_vec());
            }
        }
        if socket.read_buf(input).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
    }
}

async fn observe(
    mut socket: tokio::net::TcpStream,
    fixture: &Fixture,
    case: H2Case,
    library: bool,
) -> std::io::Result<H2Observation> {
    let keys = Arc::new(Keys::default());
    let mut tls =
        rustls::ServerConnection::new(Arc::new(tls_config(fixture, case.version, keys.clone())))
            .unwrap();
    let mut server_random = [0; 32];
    while tls.is_handshaking() {
        let record = read_record(&mut socket).await?;
        tls.read_tls(&mut std::io::Cursor::new(record))?;
        tls.process_new_packets().map_err(std::io::Error::other)?;
        let flight = outgoing(&mut tls, true).0;
        if flight.first() == Some(&22) && flight.get(5) == Some(&2) {
            let length =
                ((flight[6] as usize) << 16) | ((flight[7] as usize) << 8) | flight[8] as usize;
            server_random =
                lktls::handshake::server_hello::parse_server_hello(&flight[9..9 + length])
                    .unwrap()
                    .random;
        }
        socket.write_all(&flight).await?;
    }
    assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]));
    let cipher = {
        let keys = keys.0.lock().unwrap();
        if case.version == 13 {
            ClientCipher::Tls13(cipher_from_secret(&keys["CLIENT_TRAFFIC_SECRET_0"]))
        } else {
            let block = lktls::crypto::prf::expand_key_block(
                lktls::crypto::prf::PrfAlgorithm::Sha256,
                &keys["CLIENT_RANDOM"],
                &server_random,
                keys["client_random"].as_slice().try_into().unwrap(),
                0,
                16,
                4,
            )
            .unwrap();
            ClientCipher::Tls12(
                lktls::crypto::tls12_cipher::Tls12GcmCipher::new(
                    &block.client_write_key,
                    block.client_write_iv.as_slice().try_into().unwrap(),
                    false,
                )
                .unwrap(),
            )
        }
    };
    let (engine_io, bridge_io) = tokio::io::duplex(65536);
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge_io);
    let delivered = Arc::new(Notify::new());
    let probe_stream = Arc::new(AtomicU32::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let engine = tokio::spawn(h2_server(
        engine_io,
        delivered.clone(),
        case,
        probe_stream.clone(),
        requests.clone(),
    ));
    let mut output = BytesMut::new();
    let mut codec = H2Codec::new();
    let mut client_codec = H2Codec::new();
    let mut client_frames = BytesMut::new();
    let mut preface_read = false;
    let mut events = Vec::new();
    let mut sequence = u64::from(case.version == 12);
    let mut response_sent = false;
    let mut response_data_bytes = 0;
    let mut goaway_sent = false;
    let mut close_notify_sent = false;
    let mut tcp_shutdown_sent = false;
    let mut server_goaways = Vec::new();
    let mut output_closed = false;
    let mut finished_at = None;
    let mut read_buffer = [0; 16384];
    let mut input = BytesMut::new();
    let peer_end = loop {
        let timeout = async {
            if let Some(instant) = finished_at {
                tokio::time::sleep_until(instant + Duration::from_secs(2)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            record = buffered_record(&mut socket, &mut input) => {
                let record = match record {
                    Ok(record) => record,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break "eof",
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break "reset",
                    Err(error) => return Err(error),
                };
                let (kind, body) = cipher.decode(&record, sequence);
                let mut goaways = Vec::new();
                let mut goaway_hex = Vec::new();
                let mut resets = Vec::new();
                let mut reset_hex = Vec::new();
                if kind == 23 {
                    client_frames.extend_from_slice(&body);
                    if !preface_read && client_frames.len() >= 24 {
                        assert_eq!(&client_frames[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                        let _ = client_frames.split_to(24);
                        preface_read = true;
                    }
                    if preface_read { loop {
                        let encoded = client_frames.clone();
                        match client_codec.decode(&mut client_frames) {
                            DecodeResult::Frame(H2Frame::GoAway(frame)) => {
                                goaways.push([frame.last_stream_id, frame.error_code]);
                                goaway_hex.push(lktls::crypto::to_hex(&encoded[..encoded.len()-client_frames.len()]));
                            },
                            DecodeResult::Frame(H2Frame::RstStream(frame)) => {
                                resets.push([frame.stream_id, frame.error_code]);
                                reset_hex.push(lktls::crypto::to_hex(&encoded[..encoded.len()-client_frames.len()]));
                            },
                            DecodeResult::Frame(_) => {},
                            DecodeResult::NeedMoreData {..} => break,
                            DecodeResult::Error(error) => panic!("invalid client H2 framing: {error}"),
                        }
                    } }
                }
                events.push(RecordEvent { kind, sequence, alert: if kind == 21 {Some(body.as_slice().try_into().unwrap())} else {None}, wire_hex: lktls::crypto::to_hex(&record), goaways, goaway_hex, resets, reset_hex });
                sequence += 1;
                tls.read_tls(&mut std::io::Cursor::new(record))?;
                let state = tls.process_new_packets().map_err(std::io::Error::other)?;
                if kind == 21 { assert!(state.peer_has_closed()); break "alert"; }
                assert_eq!(kind, 23);
                let mut native = vec![0; body.len()];
                tls.reader().read_exact(&mut native)?;
                assert_eq!(native, body);
                if !output_closed { let _ = app_writer.write_all(&native).await; }
            }
            read = app_reader.read(&mut read_buffer), if !output_closed && !close_notify_sent => {
                let count = read?;
                if count == 0 { output_closed = true; continue; }
                output.extend_from_slice(&read_buffer[..count]);
                let mut ended = false;
                let mut data_seen = false;
                let mut goaway = false;
                let mut rewritten = BytesMut::new();
                loop {
                    let mut frame = match codec.decode(&mut output) {
                        DecodeResult::Frame(frame) => frame,
                        DecodeResult::NeedMoreData {..} => break,
                        DecodeResult::Error(error) => panic!("invalid native server frame: {error}"),
                    };
                    match &mut frame {
                        H2Frame::Data(frame) if frame.stream_id == probe_stream.load(Ordering::SeqCst) => {
                            ended |= frame.end_stream;
                            data_seen = true;
                            response_data_bytes += frame.data.len();
                        },
                        H2Frame::GoAway(frame) => {
                            if case.scenario == "error2_drain" { frame.error_code = 2; }
                            server_goaways.push([frame.last_stream_id, frame.error_code]);
                            goaway = true;
                        },
                        _ => {},
                    }
                    if case.scenario == "error2_drain" { codec.encode(&frame, &mut rewritten); }
                }
                let plaintext = if case.scenario == "error2_drain" { &rewritten[..] } else { &read_buffer[..count] };
                tls.writer().write_all(plaintext)?;
                let close_tls = (ended && case.scenario == "close_tls") || (goaway && case.scenario == "goaway_tls") || (data_seen && case.scenario == "truncated_tls");
                if close_tls { tls.send_close_notify(); close_notify_sent = true; }
                socket.write_all(&outgoing(&mut tls, false).0).await?;
                if data_seen {
                    response_sent |= ended;
                    finished_at.get_or_insert_with(tokio::time::Instant::now);
                    delivered.notify_one();
                    if case.scenario == "close_tcp" || case.scenario == "truncated_tcp" { socket.shutdown().await?; output_closed = true; tcp_shutdown_sent = true; }
                }
                if goaway && case.scenario == "error2_partial_fin" { socket.shutdown().await?; output_closed = true; tcp_shutdown_sent = true; }
                goaway_sent |= goaway;
            }
            _ = timeout => break "timeout",
        }
    };
    engine.abort();
    let _ = engine.await;
    Ok(H2Observation {
        client: if library { "library" } else { "browser" },
        browser: case.browser,
        scenario: case.scenario,
        version: case.version,
        port: case.port,
        finished_verified: true,
        requests_on_connection: requests.load(Ordering::SeqCst),
        response_data_bytes,
        probe_stream_id: probe_stream.load(Ordering::SeqCst),
        response_sent,
        goaway_sent,
        close_notify_sent,
        tcp_shutdown_sent,
        server_goaways,
        events,
        peer_end,
        close_ms: finished_at
            .map(|instant| instant.elapsed().as_millis())
            .unwrap_or(0),
    })
}

struct ClientProbe {
    _session: lkrequest::Session,
    body_verified: bool,
    request_failed: bool,
}

async fn library_request(
    address: std::net::SocketAddr,
    case: H2Case,
    certificate: &[u8],
) -> ClientProbe {
    let preset = if case.browser == "chrome" {
        lkrequest::preset::chrome_155()
    } else {
        lkrequest::preset::firefox_156()
    };
    let client = lkrequest::Client::builder()
        .preset(preset)
        .add_ca_cert_der(certificate)
        .build();
    let session = client.session().http2_only().build();
    let response = session
        .get(&format!("https://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.text().unwrap().as_bytes(),
        if case.family == "errors" { ROOT } else { PAGE }
    );
    let (body_verified, request_failed) = if case.family == "errors" {
        let result = session
            .post(&format!("https://{address}/next"))
            .send()
            .await;
        let verified = result.as_ref().is_ok_and(|response| {
            response.status().as_u16() == 200 && response.bytes() == FAULT_BODY
        });
        println!(
            "{}",
            serde_json::json!({"client_result":case.port,"request_failed":result.is_err(),"body_verified":verified,"status":result.as_ref().ok().map(|r|r.status().as_u16())})
        );
        (verified, result.is_err())
    } else {
        (true, false)
    };
    ClientProbe {
        _session: session,
        body_verified,
        request_failed,
    }
}

#[tokio::test]
#[ignore = "Tier-1: isolated browser HTTP/2 shutdown capture"]
async fn local_browser_h2_lifecycle_peer() {
    let fixture = Arc::new(fixture());
    println!(
        "{}",
        serde_json::json!({"fixture":"h2_lifecycle", "spki_pin":fixture.spki_pin, "cases":selected_cases()})
    );
    let library = std::env::var("TEST_BROWSER_ERROR_LIBRARY").ok().as_deref() == Some("1");
    let mut peers = Vec::new();
    for case in selected_cases() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, case.port))
            .await
            .unwrap();
        let fixture = fixture.clone();
        peers.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(240), async {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (socket, _) = accepted.unwrap();
                            let fixture = fixture.clone();
                            connections.spawn(async move { tokio::time::timeout(Duration::from_secs(8), observe(socket, &fixture, case, library)).await });
                        }
                        completed = connections.join_next(), if !connections.is_empty() => {
                            if let Some(Ok(Ok(Ok(observation)))) = completed {
                                if observation.response_data_bytes == 0 {
                                    println!("{}", serde_json::json!({"setup_only":observation}));
                                    continue;
                                }
                                println!("{}", serde_json::to_string(&observation).unwrap());
                                break observation;
                            }
                        }
                    }
                }
            })
            .await
            .unwrap()
        }));
    }
    if library {
        for case in selected_cases() {
            let _session = library_request(
                ([127, 0, 0, 1], case.port).into(),
                case,
                &fixture.certificate,
            )
            .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    for peer in peers {
        let observed = peer.await.unwrap();
        assert!(observed.finished_verified && observed.response_data_bytes > 0);
    }
}

#[tokio::test]
async fn public_h2_sessions_match_browser_shutdown_while_still_alive() {
    let fixture = Arc::new(fixture());
    for mut case in cases() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            case.port = address.port();
            let server_fixture = fixture.clone();
            let peer = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                observe(socket, &server_fixture, case, true).await.unwrap()
            });
            let _session = library_request(address, case, &fixture.certificate).await;
            let observed = peer.await.unwrap();
            assert!(observed.finished_verified && observed.response_sent);
            assert_eq!(observed.goaway_sent, case.scenario.starts_with("goaway"));
            assert_eq!(
                observed.close_notify_sent,
                matches!(case.scenario, "close_tls" | "goaway_tls")
            );
            let alerts: Vec<_> = observed
                .events
                .iter()
                .filter_map(|event| event.alert)
                .collect();
            let goaways: Vec<_> = observed
                .events
                .iter()
                .flat_map(|event| event.goaways.iter().copied())
                .collect();
            if case.browser == "firefox" {
                assert_eq!(alerts, [[1, 0]], "TLS {} {}", case.version, case.scenario);
                assert_eq!(goaways, [[0, 0]], "TLS {} {}", case.version, case.scenario);
                assert_eq!(observed.events.last().unwrap().kind, 21);
                assert_eq!(observed.peer_end, "alert");
            } else {
                assert!(alerts.is_empty() && goaways.is_empty());
                assert_eq!(
                    observed.peer_end, "eof",
                    "TLS {} {} must close while the Session is alive",
                    case.version, case.scenario
                );
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn public_h2_error_flows_match_browser_outcomes_and_close_frames() {
    let fixture = Arc::new(fixture());
    for mut case in error_cases() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            case.port = address.port();
            let server_fixture = fixture.clone();
            let peer = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                observe(socket, &server_fixture, case, true).await.unwrap()
            });
            let client = library_request(address, case, &fixture.certificate).await;
            let observed = peer.await.unwrap();
            let complete = case.scenario.ends_with("_after") || case.scenario.ends_with("_drain");
            assert_eq!(
                client.body_verified, complete,
                "{} TLS {} {}",
                case.browser, case.version, case.scenario
            );
            assert_eq!(client.request_failed, !complete);
            assert_eq!(observed.response_sent, complete);
            assert_eq!(observed.response_data_bytes, if complete { 14 } else { 7 });
            assert_eq!(observed.requests_on_connection, 2);
            assert!(observed.events.iter().all(|event| event.resets.is_empty()));
            let alerts: Vec<_> = observed
                .events
                .iter()
                .filter_map(|event| event.alert)
                .collect();
            let goaways: Vec<_> = observed
                .events
                .iter()
                .flat_map(|event| event.goaways.iter().copied())
                .collect();
            if case.browser == "firefox" {
                assert_eq!(alerts, [[1, 0]]);
                assert_eq!(goaways, [[0, 0]], "TLS {} {}", case.version, case.scenario);
                assert_eq!(observed.peer_end, "alert");
            } else {
                assert!(alerts.is_empty() && goaways.is_empty());
                assert_eq!(observed.peer_end, "eof");
            }
        })
        .await
        .unwrap();
    }
}
