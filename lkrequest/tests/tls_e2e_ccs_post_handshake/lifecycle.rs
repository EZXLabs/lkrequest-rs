use super::*;

const REUSE_PAGE: &str =
    "<!doctype html><html><head><link rel=icon href=data:,></head><body>root-ready</body></html>";
const CLOSE_PAGE: &str = "<!doctype html><html><head><link rel=icon href=data:,></head><body>ccs-control-ok</body></html>";

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for browser in ["chrome", "firefox"] {
        for scenario in [
            "reuse_plain",
            "reuse_ku_each",
            "reuse_ku_first",
            "close_http_only",
            "close_tls_only",
            "close_tcp_only",
            "close_all",
        ] {
            cases.push(Case {
                port: 49280 + cases.len() as u16,
                browser,
                scenario,
                handshake_ccs: false,
            });
        }
    }
    cases
}

#[derive(serde::Serialize)]
struct Event {
    phase: u8,
    epoch: usize,
    sequence: u64,
    kind: &'static str,
    alert: Option<[u8; 2]>,
    wire_hex: String,
}

#[derive(serde::Serialize)]
struct LifecycleObservation {
    client: &'static str,
    browser: &'static str,
    scenario: &'static str,
    port: u16,
    finished_verified: bool,
    requests_on_connection: usize,
    events: Vec<Event>,
    peer_end: &'static str,
    milliseconds_after_final_response: u128,
}

struct Peer {
    socket: tokio::net::TcpStream,
    tls: rustls::ServerConnection,
    client_secret: Vec<u8>,
    sequence: u64,
    epoch: usize,
    events: Vec<Event>,
}

impl Peer {
    async fn send(
        &mut self,
        body: &[u8],
        close_http: bool,
        close_tls: bool,
        updates: usize,
    ) -> std::io::Result<()> {
        for _ in 0..updates {
            self.tls.refresh_traffic_keys().unwrap();
        }
        let header = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n", body.len(), if close_http { "close" } else { "keep-alive" });
        self.tls.writer().write_all(header.as_bytes())?;
        self.tls.writer().write_all(body)?;
        if close_tls {
            self.tls.send_close_notify();
        }
        self.socket
            .write_all(&outgoing(&mut self.tls, false).0)
            .await
    }

    async fn read_event(&mut self, phase: u8) -> std::io::Result<Option<Vec<u8>>> {
        let record = read_record(&mut self.socket).await?;
        assert_eq!(record[0], 23);
        let mut inner = cipher_from_secret(&self.client_secret)
            .decrypt(self.sequence, &record[..5], &record[5..])
            .unwrap();
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let kind = inner.pop().unwrap();
        let (name, alert) = match kind {
            22 => {
                assert_eq!(inner, [24, 0, 0, 1, 0]);
                ("key_update", None)
            }
            23 => ("application", None),
            21 => {
                assert_eq!(inner.len(), 2);
                ("alert", Some([inner[0], inner[1]]))
            }
            _ => panic!("unexpected client record"),
        };
        self.events.push(Event {
            phase,
            epoch: self.epoch,
            sequence: self.sequence,
            kind: name,
            alert,
            wire_hex: lktls::crypto::to_hex(&record),
        });
        self.sequence += 1;
        self.tls.read_tls(&mut std::io::Cursor::new(&record))?;
        match self.tls.process_new_packets() {
            Ok(state) => {
                if kind == 21 {
                    assert!(state.peer_has_closed());
                }
            }
            Err(rustls::Error::AlertReceived(description)) => {
                assert_eq!(alert.unwrap()[1], u8::from(description));
            }
            Err(error) => panic!("independent TLS decoder failed: {error}"),
        }
        if kind == 22 {
            self.client_secret = next_secret(&self.client_secret);
            self.sequence = 0;
            self.epoch += 1;
        }
        if kind == 23 {
            let mut native = vec![0; inner.len()];
            self.tls.reader().read_exact(&mut native)?;
            assert_eq!(native, inner);
            Ok(Some(inner))
        } else {
            Ok(None)
        }
    }
}

async fn observe(
    mut socket: tokio::net::TcpStream,
    mut config: rustls::ServerConfig,
    case: Case,
    library: bool,
) -> std::io::Result<LifecycleObservation> {
    let ciphers = Arc::new(ApplicationCiphers::default());
    config.key_log = ciphers.clone();
    let mut tls = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut request = Vec::new();
    let mut sequence = 0;
    while !request.ends_with(b"\r\n\r\n") {
        let record = read_record(&mut socket).await?;
        let handshaking = tls.is_handshaking();
        tls.read_tls(&mut std::io::Cursor::new(&record))?;
        tls.process_new_packets().map_err(std::io::Error::other)?;
        if !handshaking && record[0] == 23 {
            sequence += 1;
        }
        socket.write_all(&outgoing(&mut tls, false).0).await?;
        let mut buf = [0; 4096];
        loop {
            match tls.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => request.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
            assert!(request.len() < 16_384);
        }
    }
    assert!(!tls.is_handshaking());
    assert_eq!(tls.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
    let client_secret = std::mem::take(&mut ciphers.0.lock().unwrap().client_secret);
    let mut peer = Peer {
        socket,
        tls,
        client_secret,
        sequence,
        epoch: 0,
        events: Vec::new(),
    };
    let reuse = case.scenario.starts_with("reuse_");
    let mut requests = 1;
    if reuse {
        peer.send(
            REUSE_PAGE.as_bytes(),
            false,
            false,
            if case.scenario == "reuse_plain" { 0 } else { 2 },
        )
        .await?;
        let mut next = Vec::new();
        while !next.ends_with(b"\r\n\r\n") {
            if let Some(data) = peer.read_event(1).await? {
                next.extend_from_slice(&data);
            }
            assert!(next.len() < 16_384);
        }
        assert!(next.starts_with(b"GET /next HTTP/1.1\r\n"));
        requests += 1;
        peer.send(
            b"ccs-control-ok",
            true,
            true,
            if case.scenario == "reuse_ku_each" {
                2
            } else {
                0
            },
        )
        .await?;
    } else {
        peer.send(
            CLOSE_PAGE.as_bytes(),
            matches!(case.scenario, "close_http_only" | "close_all"),
            matches!(case.scenario, "close_tls_only" | "close_all"),
            0,
        )
        .await?;
    }
    if matches!(case.scenario, "close_tcp_only" | "close_all") {
        peer.socket.shutdown().await?;
    }
    let sent = std::time::Instant::now();
    let peer_end = loop {
        match tokio::time::timeout(Duration::from_secs(2), peer.read_event(2)).await {
            Ok(Ok(_)) => {
                if peer
                    .events
                    .last()
                    .is_some_and(|event| event.kind == "alert")
                {
                    break "alert";
                }
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => break "eof",
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => break "reset",
            Ok(Err(error)) => return Err(error),
            Err(_) => break "timeout",
        }
    };
    Ok(LifecycleObservation {
        client: if library { "library" } else { "browser" },
        browser: case.browser,
        scenario: case.scenario,
        port: case.port,
        finished_verified: true,
        requests_on_connection: requests,
        events: peer.events,
        peer_end,
        milliseconds_after_final_response: sent.elapsed().as_millis(),
    })
}

async fn library_request(address: std::net::SocketAddr, case: Case, cert: &[u8]) {
    let preset = if case.browser == "chrome" {
        lkrequest::preset::chrome_155()
    } else {
        lkrequest::preset::firefox_156()
    };
    let client = lkrequest::Client::builder()
        .preset(preset)
        .add_ca_cert_der(cert)
        .build();
    let session = client.session().http1_only().build();
    let response = session
        .get(&format!("https://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.text().unwrap();
    if case.scenario.starts_with("reuse_") {
        assert_eq!(text, REUSE_PAGE);
        let response = session
            .get(&format!("https://{address}/next"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().unwrap(), "ccs-control-ok");
    } else {
        assert_eq!(text, CLOSE_PAGE);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[ignore = "Tier-1: isolated browser connection lifecycle capture"]
async fn local_browser_lifecycle_peer() {
    let fixture = fixture();
    println!(
        "{}",
        serde_json::json!({"fixture":"lifecycle", "spki_pin":fixture.spki_pin})
    );
    let library = std::env::var("TEST_BROWSER_ERROR_LIBRARY").ok().as_deref() == Some("1");
    let mut peers = Vec::new();
    for case in cases() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, case.port))
            .await
            .unwrap();
        let config = fixture.config.clone();
        peers.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(180), async {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    if let Ok(Ok(observation)) = tokio::time::timeout(
                        Duration::from_secs(8),
                        observe(socket, config.clone(), case, library),
                    )
                    .await
                    {
                        println!("{}", serde_json::to_string(&observation).unwrap());
                        break observation;
                    }
                }
            })
            .await
            .unwrap()
        }));
    }
    if library {
        for case in cases() {
            library_request(
                ([127, 0, 0, 1], case.port).into(),
                case,
                &fixture.certificate,
            )
            .await;
        }
    }
    for peer in peers {
        assert!(peer.await.unwrap().finished_verified);
    }
}

#[tokio::test]
async fn public_sessions_match_browser_key_epochs_and_shutdown() {
    let fixture = fixture();
    for mut case in cases() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            case.port = address.port();
            let config = fixture.config.clone();
            let peer = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                observe(socket, config, case, true).await.unwrap()
            });
            library_request(address, case, &fixture.certificate).await;
            let observation = peer.await.unwrap();
            let mut expected = Vec::new();
            if case.scenario.starts_with("reuse_") {
                if case.scenario != "reuse_plain" {
                    expected.push((1, "key_update", 0, 1));
                }
                expected.push((
                    1,
                    "application",
                    usize::from(case.scenario != "reuse_plain"),
                    u64::from(case.scenario == "reuse_plain"),
                ));
            }
            if case.browser == "firefox" {
                if case.scenario == "reuse_ku_each" {
                    expected.push((2, "key_update", 1, 1));
                }
                let (epoch, sequence) = match case.scenario {
                    "reuse_ku_each" => (2, 0),
                    "reuse_ku_first" => (1, 1),
                    "reuse_plain" => (0, 2),
                    _ => (0, 1),
                };
                expected.push((2, "alert", epoch, sequence));
            }
            let actual: Vec<_> = observation
                .events
                .iter()
                .map(|event| (event.phase, event.kind, event.epoch, event.sequence))
                .collect();
            assert_eq!(actual, expected, "{} {}", case.browser, case.scenario);
            assert_eq!(
                observation.requests_on_connection,
                if case.scenario.starts_with("reuse_") {
                    2
                } else {
                    1
                }
            );
            assert!(observation
                .events
                .iter()
                .all(|event| event.alert.is_none() || event.alert == Some([1, 0])));
        })
        .await
        .unwrap();
    }
}
