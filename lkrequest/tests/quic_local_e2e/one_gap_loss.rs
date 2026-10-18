use super::*;
use std::net::SocketAddr;

#[path = "one_gap_socket.rs"]
mod socket;

pub(super) async fn manual_peer(time_loss: bool) {
    assert_eq!(std::env::var("H3_FLOW_PEER_TICKETS").as_deref(), Ok("off"));
    let directory = std::path::PathBuf::from(std::env::var("H3_FLOW_GATE_DIR").unwrap());
    let stop = std::path::PathBuf::from(std::env::var("H3_FLOW_STOP").unwrap());
    let (config, pin, _) = server_config();
    let upload_bytes = if time_loss { 1400 } else { 8192 };
    let mut endpoints = Vec::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut states = Vec::new();
    for (port, drop_first) in [(49420, true), (49423, false)] {
        let gate = Arc::new(socket::Gate::new(drop_first));
        let warm_peer = Arc::new(Mutex::new(None::<SocketAddr>));
        let udp = std::net::UdpSocket::bind(localhost_addr(port)).unwrap();
        let udp = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, udp).unwrap();
        let endpoint = Endpoint::new_with_abstract_socket(
            Default::default(),
            Some(config.clone()),
            Arc::new(socket::Socket::new(udp, gate.clone())),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        states.push((port, gate.clone(), warm_peer.clone()));
        endpoints.push(endpoint.clone());
        tasks.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = endpoint.accept().await {
                let gate = gate.clone();
                let warm_peer = warm_peer.clone();
                connections.spawn(async move {
                    let connection = incoming.await.unwrap();
                    let peer = connection.remote_address();
                    let mut h3 = server::Connection::<_, bytes::Bytes>::new(
                        h3_quinn::Connection::new(connection.clone()),
                    )
                    .await
                    .unwrap();
                    let mut requests = tokio::task::JoinSet::new();
                    while let Ok(Some(resolver)) = h3.accept().await {
                        let warm_peer = warm_peer.clone();
                        let gate = gate.clone();
                        requests.spawn(async move {
                            let (request, mut stream) = resolver.resolve_request().await.unwrap();
                            let path = request.uri().path();
                            if path == "/warm" {
                                *warm_peer.lock().unwrap() = Some(peer);
                            }
                            let mut received = 0;
                            while let Some(data) = stream.recv_data().await.unwrap() {
                                received += data.remaining();
                            }
                            let body = if path == "/case" {
                                assert_eq!(request.method(), http::Method::POST);
                                assert_eq!(received, upload_bytes);
                                b"one-gap-complete".as_slice()
                            } else if path == "/" {
                                b"<!doctype html><title>root-ready</title><body>root-ready</body>"
                                    .as_slice()
                            } else {
                                b"".as_slice()
                            };
                            stream
                                .send_response(
                                    http::Response::builder()
                                        .status(200)
                                        .header("content-type", "text/html")
                                        .body(())
                                        .unwrap(),
                                )
                                .await
                                .unwrap();
                            stream
                                .send_data(bytes::Bytes::copy_from_slice(body))
                                .await
                                .unwrap();
                            stream.finish().await.unwrap();
                            if path == "/case" {
                                observe(serde_json::json!({"fixture":"one_gap_loss","port":port,"phase":"request_fin","client_port":peer.port(),"stream":stream.id().into_inner(),"request_bytes":received,"status":200,"response_bytes":body.len(),"gate":gate.snapshot()}));
                            }
                        });
                    }
                    while let Some(result) = requests.join_next().await {
                        result.unwrap();
                    }
                });
            }
        });
    }
    let cases = if time_loss {
        ["one_gap_time_drop", "unused", "unused", "one_gap_time_pass"]
    } else {
        ["one_gap_drop", "unused", "unused", "one_gap_pass"]
    };
    observe(
        serde_json::json!({"fixture":"h3_flow","spki_pin":pin,"base_port":49420,"cases":cases,"pool_alias":false}),
    );
    tokio::time::timeout(Duration::from_secs(100), async {
        while !stop.exists() {
            for (port, gate, warm_peer) in &states {
                let ready = directory.join(format!("one-gap-{port}.ready.json"));
                if directory.join(format!("one-gap-{port}.arm")).exists() && !ready.exists() {
                    let peer = warm_peer.lock().unwrap().expect("completed warm peer");
                    gate.arm(peer).unwrap();
                    let value = serde_json::json!({"schema":"quic-one-gap-arm-v1","fixture_port":port,"client_port":peer.port(),"ready":true,"gate":gate.snapshot()});
                    let temporary = directory.join(format!("one-gap-{port}.ready.tmp"));
                    std::fs::write(&temporary, serde_json::to_vec(&value).unwrap()).unwrap();
                    std::fs::rename(temporary, ready).unwrap();
                    observe(value);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("capture controller must stop one-gap peer");
    for (port, gate, _) in &states {
        observe(
            serde_json::json!({"fixture":"one_gap_loss","port":port,"phase":"final_gate","gate":gate.snapshot()}),
        );
    }
    for endpoint in endpoints {
        endpoint.close(0u32.into(), b"fixture complete");
    }
    tasks.abort_all();
}
