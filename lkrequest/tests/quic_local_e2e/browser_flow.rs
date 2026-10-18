use super::*;
use base64::Engine;
use bytes::Buf;
use rcgen::PublicKeyData;
use std::io::Write;
use std::sync::Mutex;
use std::time::Duration;

#[path = "stop_packet_gate.rs"]
mod stop_packet_gate;
use stop_packet_gate::{GatedSocket, StopPacketGate};

#[path = "one_gap_loss.rs"]
mod one_gap_loss;

const CASES: &[&str] = &[
    "info",
    "early413",
    "cancel",
    "invalid101",
    "trailer_reset",
    "truncated_data",
    "truncated_data_inline",
    "truncated_data_length",
];

const UPLOAD_CASES: &[&str] = &[
    "early413",
    "early413_stop0",
    "early413_stop256",
    "early413_stop268",
    "early200_stop256",
    "early413_reset",
    "early413_cancel",
    "early413_silent",
];

const STOP_ORDER_CASES: &[&str] = &[
    "early413_stop256",
    "early413_fin_then_stop",
    "early413_stop_then_fin",
    "early413_stop_then_reset",
    "early413_stop_then_close",
    "early413_small_stop",
    "early413",
    "early413_cancel400",
];

const RETRY_SESSION_CASES: &[&str] = &[
    "early413_stop_then_reset",
    "early413_stop_then_reset",
    "early413_stop_then_reset",
    "early413",
];

const SMALL_STOP_CASES: &[&str] = &[
    "small_stop0",
    "small_stop256",
    "small_stop268",
    "small_fin_then_stop",
    "early413_small_stop",
];

const SMALL_STOP_NOW_CASES: &[&str] = &[
    "small_stop0_now",
    "small_stop256_now",
    "small_stop268_now",
    "small_stop256",
];

const SMALL_STOP_GATED_CASES: &[&str] = &[
    "small_stop0_gated",
    "small_stop256_gated",
    "small_stop268_gated",
    "small_stop256",
];

const PTO_CASES: &[&str] = &[
    "small_pto120_gated",
    "small_pto400_gated",
    "small_pto900_gated",
    "small_stop256_gated",
];

const PTO_REPEAT_CASES: &[&str] = &[
    "small_pto900_gated",
    "small_pto900_gated",
    "small_pto900_gated",
    "small_stop256_gated",
];

const WRITER_PTO_CASES: &[&str] = &["early_writer_pto_gated"];
const WRITER_PEER_CLOSE_CASES: &[&str] = &["early_writer_peer_close_gated"];
const WRITER_LOCAL_CLOSE_CASES: &[&str] = &["early_writer_local_close_gated"];
const WRITER_UPLOAD_BYTES: usize = 4096;

const FRAMING_CASES: &[&str] = &[
    "frame_complete",
    "frame_data_inline",
    "frame_data_delayed",
    "frame_data_empty",
    "frame_data_length",
    "frame_trailer_partial",
    "frame_unknown_partial",
    "frame_after_trailers",
];

const FRAMING_GUARD_CASES: &[&str] = &[
    "frame_initial_headers_partial",
    "frame_trailer_empty_payload",
    "frame_second_trailer_partial",
    "frame_type_partial",
    "frame_settings_partial",
    "frame_h2_ping_partial",
    "frame_qpack_invalid",
    "frame_after_trailers_partial_data",
];

const FRAMING_EXTENSION_CASES: &[&str] = &[
    "frame_accept_ch_partial",
    "frame_accept_ch_complete",
    "frame_origin_partial",
    "frame_origin_complete",
    "frame_metadata_partial",
    "frame_priority_push_partial",
    "frame_after_trailers_unknown_partial",
    "frame_unknown_complete",
];

const FRAMING_HEADER_WAIT_CASES: &[&str] = &[
    "frame_wait_initial_type",
    "frame_wait_initial_length",
    "frame_wait_body_type",
    "frame_wait_body_length",
    "frame_wait_trailer_type",
    "frame_wait_trailer_length",
    "frame_complete",
    "frame_trailer_partial",
];

fn cases() -> &'static [&'static str] {
    match std::env::var("H3_FLOW_SET").as_deref() {
        Ok("uploads") => UPLOAD_CASES,
        Ok("stop-order") => STOP_ORDER_CASES,
        Ok("retry-session") => RETRY_SESSION_CASES,
        Ok("small-stop") => SMALL_STOP_CASES,
        Ok("small-stop-now") => SMALL_STOP_NOW_CASES,
        Ok("small-stop-gated") => SMALL_STOP_GATED_CASES,
        Ok("pto") => PTO_CASES,
        Ok("pto-repeat") => PTO_REPEAT_CASES,
        Ok("writer-pto") => WRITER_PTO_CASES,
        Ok("writer-peer-close") => WRITER_PEER_CLOSE_CASES,
        Ok("writer-local-close") => WRITER_LOCAL_CLOSE_CASES,
        Ok("cancel-order") => &["early413_cancel", "early413_cancel400", "early413_silent"],
        Ok("framing") => FRAMING_CASES,
        Ok("framing-guards") => FRAMING_GUARD_CASES,
        Ok("framing-tail") => &["frame_after_trailers_unknown_partial"],
        Ok("framing-extensions") => FRAMING_EXTENSION_CASES,
        Ok("framing-header-wait") => FRAMING_HEADER_WAIT_CASES,
        _ => CASES,
    }
}

#[derive(Debug)]
pub(super) struct Keys(pub(super) Mutex<()>);
impl rustls::KeyLog for Keys {
    fn log(&self, label: &str, random: &[u8], secret: &[u8]) {
        let Ok(path) = std::env::var("H3_FLOW_KEYLOG") else {
            return;
        };
        let _guard = self.0.lock().unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        write!(file, "{label} ").unwrap();
        for byte in random {
            write!(file, "{byte:02x}").unwrap();
        }
        write!(file, " ").unwrap();
        for byte in secret {
            write!(file, "{byte:02x}").unwrap();
        }
        writeln!(file).unwrap();
    }
}

fn pool_alias_enabled() -> bool {
    match std::env::var("H3_FLOW_POOL_ALIAS")
        .as_deref()
        .unwrap_or("off")
    {
        "on" => true,
        "off" => false,
        value => panic!("unknown pool alias setting: {value}"),
    }
}

fn server_config() -> (quinn::ServerConfig, String, Vec<u8>) {
    ensure_rustls_provider();
    let mut names = vec!["127.0.0.1".into(), "localhost".into()];
    if pool_alias_enabled() {
        names.extend(["a.fp.test".into(), "b.fp.test".into()]);
    }
    let cert = generate_simple_self_signed(names).unwrap();
    let pin = base64::engine::general_purpose::STANDARD.encode(
        aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            &cert.signing_key.subject_public_key_info(),
        )
        .as_ref(),
    );
    let certificate = cert.cert.der().to_vec();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.key_log = Arc::new(Keys(Mutex::new(())));
    match std::env::var("H3_FLOW_PEER_TICKETS")
        .as_deref()
        .unwrap_or("on")
    {
        "on" => {}
        "off" => tls.send_tls13_tickets = 0,
        value => panic!("unknown peer ticket setting: {value}"),
    }
    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(65_536u32.into())
        .receive_window(262_144u32.into());
    let peer_ecn = std::env::var("H3_FLOW_PEER_ECN").unwrap_or_else(|_| "on".into());
    transport.enable_ecn(match peer_ecn.as_str() {
        "on" => true,
        "off" => false,
        value => panic!("unknown peer ECN setting: {value}"),
    });
    config.transport_config(Arc::new(transport));
    (config, pin, certificate)
}

struct Peers {
    endpoints: Vec<Endpoint>,
    gates: Vec<Arc<StopPacketGate>>,
    tasks: tokio::task::JoinSet<()>,
}
impl Drop for Peers {
    fn drop(&mut self) {
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"fixture complete");
        }
        self.tasks.abort_all();
    }
}

pub(super) fn observe(value: serde_json::Value) {
    println!("{value}");
    std::io::stdout().flush().unwrap();
}

async fn peers(base: u16) -> (Peers, String, Vec<u8>) {
    let (config, pin, certificate) = server_config();
    let pool_alias = pool_alias_enabled();
    let mut peers = Peers {
        endpoints: Vec::new(),
        gates: Vec::new(),
        tasks: tokio::task::JoinSet::new(),
    };
    for (offset, &case) in cases().iter().enumerate() {
        let port = base + offset as u16;
        let gate = Arc::new(StopPacketGate::default());
        let endpoint = if case.ends_with("_gated") {
            let socket = std::net::UdpSocket::bind(localhost_addr(port)).unwrap();
            let socket = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket).unwrap();
            Endpoint::new_with_abstract_socket(
                Default::default(),
                Some(config.clone()),
                Arc::new(GatedSocket::new(socket, gate.clone())),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap()
        } else {
            Endpoint::server(config.clone(), localhost_addr(port)).unwrap()
        };
        peers.gates.push(gate.clone());
        peers.endpoints.push(endpoint.clone());
        peers.tasks.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = endpoint.accept().await {
                let gate = gate.clone();
                connections.spawn(async move {
                    let connection = match incoming.await { Ok(connection) => connection, Err(error) => {
                        observe(serde_json::json!({"case":case,"port":port,"handshake_error":error.to_string()})); return;
                    }};
                    if case.starts_with("truncated_data") || case.starts_with("frame_") {
                        let mut critical = Vec::new();
                        for bytes in [&b"\x00\x04\x00"[..], &b"\x02"[..], &b"\x03"[..]] {
                            let mut stream = connection.open_uni().await.unwrap();
                            stream.write_all(bytes).await.unwrap();
                            critical.push(stream);
                        }
                        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                        recv.read_to_end(65_536).await.unwrap();
                        // Each response starts with stateless QPACK status 200.
                        let response = match case {
                            "frame_wait_initial_type" => b"\x40".as_slice(),
                            "frame_wait_initial_length" => b"\x01\x40".as_slice(),
                            "frame_wait_body_type" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x40".as_slice(),
                            "frame_wait_body_length" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x00\x40".as_slice(),
                            "frame_wait_trailer_type" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x40".as_slice(),
                            "frame_wait_trailer_length" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x01\x40".as_slice(),
                            "frame_accept_ch_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x40\x89\x05x".as_slice(),
                            "frame_accept_ch_complete" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x40\x89\x01x".as_slice(),
                            "frame_origin_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x0c\x05x".as_slice(),
                            "frame_origin_complete" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x0c\x01x".as_slice(),
                            "frame_metadata_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x40\x4d\x05x".as_slice(),
                            "frame_priority_push_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x80\x0f\x07\x01\x05x".as_slice(),
                            "frame_unknown_complete" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x21\x01x".as_slice(),
                            "frame_initial_headers_partial" => b"\x01\x05\x00\x00".as_slice(),
                            "frame_trailer_empty_payload" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x05".as_slice(),
                            "frame_second_trailer_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x01\x05x".as_slice(),
                            "frame_type_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x40".as_slice(),
                            "frame_settings_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x04\x05x".as_slice(),
                            "frame_h2_ping_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x06\x05x".as_slice(),
                            "frame_qpack_invalid" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x03\x00\x00\xff".as_slice(),
                            "frame_after_trailers_partial_data" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x00\x05x".as_slice(),
                            "frame_after_trailers_unknown_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x21\x05x".as_slice(),
                            "frame_complete" => b"\x01\x03\x00\x00\xd9\x00\x05abcde".as_slice(),
                            "frame_data_empty" => b"\x01\x03\x00\x00\xd9\x00\x05".as_slice(),
                            "frame_data_length" => b"\x01\x03\x00\x00\xd9\x00\x40".as_slice(),
                            "frame_trailer_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x05\x00\x00".as_slice(),
                            "frame_unknown_partial" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x21\x05x".as_slice(),
                            "frame_after_trailers" => b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x00\x01x".as_slice(),
                            "truncated_data_length" => b"\x01\x06\x00\x00\xd9\x54\x01\x35\x00\x05abc".as_slice(),
                            _ => b"\x01\x03\x00\x00\xd9\x00\x05abc".as_slice(),
                        };
                        send.write_all(response).await.unwrap();
                        let delayed = matches!(case, "truncated_data" | "truncated_data_length" | "frame_data_delayed");
                        if delayed {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        }
                        send.finish().unwrap();
                        observe(serde_json::json!({"case":case,"port":port,"stream":u64::from(send.id()),"stream_bytes":response.len(),"delayed_fin":delayed,"fin":true}));
                        if case.starts_with("frame_wait_") {
                            let started = std::time::Instant::now();
                            let close = tokio::time::timeout(Duration::from_millis(700), connection.closed()).await;
                            match close {
                                Ok(error) => observe(serde_json::json!({"case":case,"port":port,"peer_closed_first":true,"elapsed_ms":started.elapsed().as_millis(),"close":error.to_string()})),
                                Err(_) => {
                                    connection.close(0x102u32.into(), b"partial header peer close");
                                    observe(serde_json::json!({"case":case,"port":port,"planned_close_code":258,"elapsed_ms":started.elapsed().as_millis()}));
                                    connection.closed().await;
                                }
                            }
                            drop(critical);
                            return;
                        }
                        let hold = if case.starts_with("frame_") { 10 } else { 3 };
                        let close = tokio::time::timeout(Duration::from_secs(hold), connection.closed()).await;
                        observe(serde_json::json!({"case":case,"port":port,"close":close.ok().map(|error|error.to_string())}));
                        drop(critical);
                        return;
                    }
                    let mut h3 = server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(connection.clone())).await.unwrap();
                    let mut requests = tokio::task::JoinSet::new();
                    while let Ok(Some(resolver)) = h3.accept().await {
                        let case_connection = connection.clone();
                        let case_gate = gate.clone();
                        requests.spawn(async move {
                            let Ok((request, mut stream)) = resolver.resolve_request().await else { return; };
                            let path = request.uri().path();
                            if path != "/case" {
                                let body = if path == "/" { b"<!doctype html><title>root-ready</title><body>root-ready</body>".as_slice() } else { b"".as_slice() };
                                let mut response = http::Response::builder().status(200).header("content-type","text/html");
                                if pool_alias {
                                    response = response.header("access-control-allow-origin", format!("https://a.fp.test:{port}"))
                                        .header("access-control-allow-credentials", "true");
                                }
                                let _ = stream.send_response(response.body(()).unwrap()).await;
                                let _ = stream.send_data(bytes::Bytes::copy_from_slice(body)).await;
                                let _ = stream.finish().await;
                                return;
                            }
                            let mut received = 0usize;
                            let start = std::time::Instant::now();
                            if !case.starts_with("small_") {
                                let first = stream.recv_data().await;
                                if let Ok(Some(mut chunk)) = first { received += chunk.copy_to_bytes(chunk.remaining()).len(); }
                            }
                            let mut statuses = Vec::new();
                            let mut stopped = false;
                            if case == "early_writer_local_close_gated" {
                                assert!(received > 0, "local-close fixture requires received STREAM data");
                                let gate_was_armed = case_gate.is_armed();
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_duplicate_control_first_data","request_bytes":received,"gate_was_armed":gate_was_armed,"elapsed_ms":start.elapsed().as_millis()}));
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                let dropped = case_gate.release();
                                let mut duplicate = case_connection.open_uni().await.unwrap();
                                duplicate.write_all(b"\x00\x04\x00").await.unwrap();
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_duplicate_control_written","stream":u64::from(duplicate.id()),"prefix":"000400","request_bytes":received,"gate_was_armed":gate_was_armed,"dropped_datagrams":dropped,"elapsed_ms":start.elapsed().as_millis()}));
                                let closed = tokio::time::timeout(Duration::from_secs(6), case_connection.closed()).await;
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_duplicate_control_peer_result","close_observed":closed.is_ok(),"elapsed_ms":start.elapsed().as_millis()}));
                                drop(duplicate);
                                return;
                            }
                            if case == "early_writer_peer_close_gated" {
                                assert!(received > 0, "peer-close fixture requires received STREAM data");
                                let gate_was_armed = case_gate.is_armed();
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_close_first_data","request_bytes":received,"gate_was_armed":gate_was_armed,"elapsed_ms":start.elapsed().as_millis()}));
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                let dropped = case_gate.release();
                                case_connection.close(258u32.into(), b"writer peer-close fixture");
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_peer_close_called","application_close_code":258,"request_bytes":received,"gate_was_armed":gate_was_armed,"dropped_datagrams":dropped,"elapsed_ms":start.elapsed().as_millis()}));
                                let _ = tokio::time::timeout(Duration::from_secs(2), case_connection.closed()).await;
                                return;
                            }
                            if case == "early_writer_pto_gated" {
                                assert!(case_gate.is_armed(), "writer loss gate armed before POST");
                                assert!(received > 0, "writer fixture requires outstanding STREAM data");
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_first_data","request_bytes":received,"elapsed_ms":start.elapsed().as_millis()}));
                                // Keep the request stream open while ACK loss spans the injected hold.
                                tokio::time::sleep(Duration::from_millis(900)).await;
                                let dropped = case_gate.release();
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_loss_gate_released","dropped_datagrams":dropped,"dropped_bytes":case_gate.dropped_bytes(),"elapsed_ms":start.elapsed().as_millis()}));
                                tokio::time::timeout(Duration::from_secs(6), async {
                                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                                        received += data.copy_to_bytes(data.remaining()).len();
                                    }
                                }).await.expect("finite writer upload must finish after ACK release");
                                assert_eq!(received, WRITER_UPLOAD_BYTES);
                                stream.send_response(http::Response::builder().status(200).body(()).unwrap()).await.unwrap();
                                stream.send_data(bytes::Bytes::from_static(b"writer-complete")).await.unwrap();
                                stream.finish().await.unwrap();
                                observe(serde_json::json!({"case":case,"port":port,"phase":"writer_request_fin","request_bytes":received,"status":200,"elapsed_ms":start.elapsed().as_millis()}));
                                let _ = tokio::time::timeout(Duration::from_secs(6), case_connection.closed()).await;
                                return;
                            }
                            if case.starts_with("small_") {
                                // Reading through transport EOF frees the state needed to send STOP.
                                // The capture must independently establish FIN before the STOP packet.
                                if !case.ends_with("_now") && !case.ends_with("_gated") {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                }
                                let stop_code = match case {
                                    "small_stop0" | "small_stop0_now" | "small_stop0_gated" => 0u64,
                                    "small_stop268" | "small_stop268_now" | "small_stop268_gated" => 268,
                                    _ => 256,
                                };
                                if case != "small_fin_then_stop" {
                                    if case.ends_with("_gated") {
                                        assert!(case_gate.is_armed(), "loss gate armed before POST");
                                    }
                                    stream.stop_sending(stop_code.into());
                                    let post_stop_loss_ms = match case {
                                        "small_pto120_gated" => Some(120u64),
                                        "small_pto400_gated" => Some(400),
                                        "small_pto900_gated" => Some(900),
                                        _ => None,
                                    };
                                    let dropped_before_stop = case_gate.dropped_count();
                                    // Queue STOP and change the gate without yielding on this
                                    // current-thread runtime. Raw capture verifies the permitted packet.
                                    if post_stop_loss_ms.is_some() {
                                        case_gate.permit_one_to(case_connection.remote_address());
                                    } else {
                                        case_gate.release();
                                    }
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"stop_called","stop_code":stop_code,"dropped_pre_stop_datagrams":dropped_before_stop,"dropped_pre_stop_bytes":case_gate.dropped_bytes(),"post_stop_loss_ms":post_stop_loss_ms,"elapsed_ms":start.elapsed().as_millis()}));
                                    if let Some(loss_ms) = post_stop_loss_ms {
                                        tokio::time::sleep(Duration::from_millis(loss_ms)).await;
                                        let dropped = case_gate.release();
                                        observe(serde_json::json!({"case":case,"port":port,"phase":"loss_gate_released","dropped_total_datagrams":dropped,"dropped_post_stop_datagrams":dropped - dropped_before_stop,"elapsed_ms":start.elapsed().as_millis()}));
                                    } else {
                                        tokio::time::sleep(Duration::from_millis(150)).await;
                                    }
                                }
                                let sent = async {
                                    stream.send_response(http::Response::builder().status(413).body(()).unwrap()).await?;
                                    stream.send_data(bytes::Bytes::from_static(b"rejected")).await?;
                                    stream.finish().await?;
                                    Ok::<(), h3::error::StreamError>(())
                                }.await;
                                if let Err(error) = sent {
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"response_send_error","error":error.to_string(),"elapsed_ms":start.elapsed().as_millis()}));
                                    return;
                                }
                                observe(serde_json::json!({"case":case,"port":port,"phase":"final_sent","elapsed_ms":start.elapsed().as_millis(),"request_bytes_read":received,"request_body_read":false}));
                                if case == "small_fin_then_stop" {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                    stream.stop_sending(stop_code.into());
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"stop_called","stop_code":stop_code,"elapsed_ms":start.elapsed().as_millis()}));
                                }
                                let _ = tokio::time::timeout(Duration::from_secs(6), case_connection.closed()).await;
                                return;
                            } else if case == "info" {
                                for status in [100, 103, 200] {
                                    stream.send_response(http::Response::builder().status(status).body(()).unwrap()).await.unwrap();
                                    statuses.push(status);
                                }
                                stream.send_data(bytes::Bytes::from_static(b"ok")).await.unwrap();
                                stream.finish().await.unwrap();
                            } else if case.starts_with("early") {
                                if case == "early413_small_stop" {
                                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                                        received += data.copy_to_bytes(data.remaining()).len();
                                    }
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"request_fin","request_bytes":received,"elapsed_ms":start.elapsed().as_millis()}));
                                }
                                if case == "early413_stop_then_fin" {
                                    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                                    stopped = true;
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"stop_called","stop_code":256,"elapsed_ms":start.elapsed().as_millis()}));
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                }
                                let status = if case.starts_with("early200") { 200 } else { 413 };
                                let sent = async {
                                    stream.send_response(http::Response::builder().status(status).body(()).unwrap()).await?;
                                    stream.send_data(bytes::Bytes::from_static(b"rejected")).await?;
                                    if !matches!(case, "early413_reset" | "early413_stop_then_reset") {
                                        stream.finish().await?;
                                    }
                                    Ok::<(), h3::error::StreamError>(())
                                }.await;
                                if let Err(error) = sent {
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"response_send_error","error":error.to_string(),"elapsed_ms":start.elapsed().as_millis()}));
                                    return;
                                }
                                statuses.push(status);
                                if case == "early413_reset" {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                    stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                                }
                                if case == "early413_fin_then_stop" {
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"finish_returned","elapsed_ms":start.elapsed().as_millis()}));
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                }
                                let stop_code = match case {
                                    "early413_stop0" => Some(0u64),
                                    "early413_stop256" | "early200_stop256" | "early413_fin_then_stop"
                                        | "early413_stop_then_reset" | "early413_stop_then_close"
                                        | "early413_small_stop" => Some(256),
                                    "early413_stop268" => Some(268),
                                    _ => None,
                                };
                                if let Some(code) = stop_code { stream.stop_sending(code.into()); stopped = true; }
                                observe(serde_json::json!({"case":case,"port":port,"phase":"final_sent","elapsed_ms":start.elapsed().as_millis(),"request_bytes":received,"stop_code":stop_code}));
                                if case == "early413_stop_then_reset" {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                    stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"response_reset_called","reset_code":258,"elapsed_ms":start.elapsed().as_millis()}));
                                }
                                if case == "early413_stop_then_close" {
                                    tokio::time::sleep(Duration::from_millis(700)).await;
                                    case_connection.close(258u32.into(), b"STOP completion control");
                                    observe(serde_json::json!({"case":case,"port":port,"phase":"connection_close_called","close_code":258,"elapsed_ms":start.elapsed().as_millis()}));
                                }
                                // The final response arrives while the request window is still bounded.
                                let hold = if matches!(case, "early413_silent" | "early413_cancel400") { 1500 } else { 400 };
                                tokio::time::sleep(Duration::from_millis(hold)).await;
                            } else if case == "invalid101" {
                                stream.send_response(http::Response::builder().status(101).body(()).unwrap()).await.unwrap();
                                statuses.push(101);
                            } else if case == "trailer_reset" {
                                stream.send_response(http::Response::new(())).await.unwrap();
                                statuses.push(200);
                                stream.send_data(bytes::Bytes::from_static(b"body")).await.unwrap();
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("x-trailer", "valid".parse().unwrap());
                                stream.send_trailers(trailers).await.unwrap();
                                tokio::time::sleep(Duration::from_millis(150)).await;
                                stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                            } else {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                            }
                            if stopped {
                                // Reading again after a local STOP would manufacture a frame error.
                                observe(serde_json::json!({"case":case,"port":port,"method":request.method().as_str(),"sent_statuses":statuses,"request_bytes":received,"request_end":"local_stop","elapsed_ms":start.elapsed().as_millis()}));
                                if matches!(case, "early413_fin_then_stop" | "early413_stop_then_fin" | "early413_stop_then_reset" | "early413_stop_then_close" | "early413_small_stop") {
                                    let _ = tokio::time::timeout(Duration::from_secs(6), case_connection.closed()).await;
                                }
                                return;
                            }
                            let result = tokio::time::timeout(Duration::from_secs(4), async {
                                loop {
                                    match stream.recv_data().await {
                                        Ok(Some(mut data)) => received += data.copy_to_bytes(data.remaining()).len(),
                                        Ok(None) => break ("fin", None, None),
                                        Err(h3::error::StreamError::RemoteTerminate { code, .. }) => break ("reset", Some(u64::from(code)), None),
                                        Err(error) => break ("error", None, Some(error.to_string())),
                                    }
                                }
                            }).await;
                            let (end, reset, error) = result.unwrap_or(("timeout",None,None));
                            observe(serde_json::json!({"case":case,"port":port,"method":request.method().as_str(),"sent_statuses":statuses,"request_bytes":received,"request_end":end,"reset_code":reset,"error":error,"elapsed_ms":start.elapsed().as_millis()}));
                        });
                    }
                    while let Some(result) = requests.join_next().await { result.unwrap(); }
                });
            }
        });
    }
    (peers, pin, certificate)
}

#[tokio::test]
#[ignore = "Tier-1: isolated browser H3 flow capture"]
async fn local_browser_h3_flow_peer() {
    match std::env::var("H3_FLOW_SET").as_deref() {
        Ok("one-gap-loss") => {
            one_gap_loss::manual_peer(false).await;
            return;
        }
        Ok("one-gap-time-loss") => {
            one_gap_loss::manual_peer(true).await;
            return;
        }
        _ => {}
    }
    let base = std::env::var("H3_FLOW_PORT")
        .unwrap_or_else(|_| "49420".into())
        .parse()
        .unwrap();
    let (peers, pin, _) = peers(base).await;
    observe(
        serde_json::json!({"fixture":"h3_flow","spki_pin":pin,"base_port":base,"cases":cases(),"pool_alias":pool_alias_enabled()}),
    );
    if let Ok(stop) = std::env::var("H3_FLOW_STOP") {
        tokio::time::timeout(Duration::from_secs(100), async {
            while !std::path::Path::new(&stop).exists() {
                if let Ok(directory) = std::env::var("H3_FLOW_GATE_DIR") {
                    for (offset, case) in cases().iter().enumerate() {
                        if !case.ends_with("_gated") {
                            continue;
                        }
                        let port = base + offset as u16;
                        let directory = std::path::Path::new(&directory);
                        let arm = directory.join(format!("gate-{port}.arm"));
                        let ready = directory.join(format!("gate-{port}.ready"));
                        if arm.exists() && !ready.exists() {
                            peers.gates[offset].arm();
                            std::fs::write(ready, b"ready").unwrap();
                            observe(serde_json::json!({"case":case,"port":port,"phase":"loss_gate_armed"}));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("capture controller must stop peer");
    } else {
        tokio::time::sleep(Duration::from_secs(100)).await;
    }
    assert!(!pin.is_empty());
}

#[tokio::test]
#[ignore = "Tier-1: independent library H3 flow capture"]
async fn local_library_h3_flow_capture() {
    let base = std::env::var("H3_FLOW_PORT")
        .unwrap_or_else(|_| "49420".into())
        .parse()
        .unwrap();
    let (peers, _, certificate) = peers(base).await;
    let profile_name =
        std::env::var("H3_FLOW_LIBRARY_PROFILE").unwrap_or_else(|_| "chrome155".into());
    for (offset, &case) in cases().iter().enumerate() {
        let url = format!("https://127.0.0.1:{}/", base + offset as u16);
        let mut preset = match profile_name.as_str() {
            "chrome155"
            | "chrome155-legacy"
            | "chrome155-ack-legacy"
            | "chrome155-stop-legacy"
            | "chrome155-pto-legacy"
            | "chrome155-timing-legacy" => lkrequest::preset::chrome_155(),
            "chrome154" => lkrequest::preset::chrome_154(),
            value => panic!("unknown capture profile: {value}"),
        };
        if profile_name == "chrome155-legacy" {
            let quic = preset.quic_profile.as_mut().unwrap();
            quic.h3.cancel_response_before_upload = false;
            quic.packetization.stop_before_matching_reset = false;
        }
        if profile_name == "chrome155-ack-legacy" {
            preset
                .quic_profile
                .as_mut()
                .unwrap()
                .packetization
                .ack_obligation_only = false;
        }
        if profile_name == "chrome155-stop-legacy" {
            preset
                .quic_profile
                .as_mut()
                .unwrap()
                .packetization
                .reset_finished_on_stop = false;
        }
        if profile_name == "chrome155-pto-legacy" {
            preset
                .quic_profile
                .as_mut()
                .unwrap()
                .packetization
                .pto_single_probe_with_gap = false;
        }
        if profile_name == "chrome155-timing-legacy" {
            preset
                .quic_profile
                .as_mut()
                .unwrap()
                .packetization
                .chrome_pto_timing = false;
        }
        let retry_mode = match std::env::var("H3_FLOW_LIBRARY_H3_RETRY").as_deref() {
            Ok("chrome155-protocol-errors") => {
                lkrequest::retry::H3RetryMode::Chrome155ProtocolErrors
            }
            Ok("safe") | Err(_) => lkrequest::retry::H3RetryMode::Safe,
            Ok(_) => panic!("invalid H3 flow retry mode"),
        };
        let session = lkrequest::Client::builder()
            .preset(preset)
            .add_ca_cert_der(&certificate)
            .build()
            .session()
            .http3_only()
            .h3_retry_mode(retry_mode)
            .build();
        if !case.starts_with("truncated_data") && !case.starts_with("frame_") {
            let root = session.get(&url).send().await.unwrap();
            assert_eq!(root.version(), lkrequest::HttpVersion::H3);
            assert!(root.text().unwrap().contains("root-ready"));
        }
        if case.ends_with("_gated") {
            peers.gates[offset].arm();
            observe(
                serde_json::json!({"case":case,"port":base + offset as u16,"phase":"loss_gate_armed"}),
            );
        }
        let request = if case.starts_with("truncated_data") || case.starts_with("frame_") {
            session.get(&url)
        } else {
            session.post(&format!("{url}case")).body(vec![
                b'x';
                if matches!(
                    case,
                    "early_writer_pto_gated"
                        | "early_writer_peer_close_gated"
                        | "early_writer_local_close_gated"
                ) {
                    WRITER_UPLOAD_BYTES
                } else if (case.starts_with("early") && case != "early413_small_stop")
                    || case == "cancel"
                {
                    8 * 1024 * 1024
                } else {
                    7
                }
            ])
        };
        let start = std::time::Instant::now();
        let mut future = Box::pin(request.send());
        let deadline = match case {
            "cancel" | "early413_cancel" => Some(150),
            "early413_cancel400" => Some(400),
            "early413_stop0"
            | "early413_stop256"
            | "early413_stop268"
            | "early200_stop256"
            | "early413_fin_then_stop"
            | "early413_stop_then_fin" => Some(4000),
            "early413_silent" => Some(800),
            _ => None,
        };
        let result = if let Some(deadline) = deadline {
            tokio::select! { result = &mut future => Some(result), _ = tokio::time::sleep(Duration::from_millis(deadline)) => None }
        } else {
            Some(
                tokio::time::timeout(Duration::from_secs(6), &mut future)
                    .await
                    .expect("bounded library flow"),
            )
        };
        let report = match result {
            Some(Ok(response)) => {
                serde_json::json!({"status":response.status().as_u16(),"body_len":response.bytes().len(),"ok":true})
            }
            Some(Err(error)) => serde_json::json!({"ok":false,"error":error.to_string()}),
            None => serde_json::json!({"ok":false,"cancelled":true}),
        };
        // Drop the cancellation future before waiting for the peer observation.
        drop(future);
        observe(
            serde_json::json!({"client":"library","profile":profile_name,"h3_retry_mode":format!("{retry_mode:?}"),"case":case,"elapsed_ms":start.elapsed().as_millis(),"result":report}),
        );
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
    assert!((1..=8).contains(&cases().len()));
}
