use super::browser_flow::{observe, Keys};
use super::*;
use base64::Engine;
use bytes::{Buf, Bytes};
use rcgen::PublicKeyData;
use rustls::server::StoresServerSessions;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

const BASE: u16 = 49420;
const CASES: &[&str] = &[
    "resume_accept",
    "resume_reject",
    "resume_accept",
    "resume_reject",
    "resume_accept",
    "resume_reject",
];

struct Store {
    inner: Arc<dyn StoresServerSessions>,
    puts: AtomicUsize,
    get_hits: AtomicUsize,
    take_hits: AtomicUsize,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservedSessionStore")
            .finish_non_exhaustive()
    }
}

impl Store {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: rustls::server::ServerSessionMemoryCache::new(128),
            puts: AtomicUsize::new(0),
            get_hits: AtomicUsize::new(0),
            take_hits: AtomicUsize::new(0),
        })
    }
    fn counts(&self) -> serde_json::Value {
        serde_json::json!({"puts":self.puts.load(Ordering::SeqCst), "get_hits":self.get_hits.load(Ordering::SeqCst), "take_hits":self.take_hits.load(Ordering::SeqCst)})
    }
}

impl StoresServerSessions for Store {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let stored = self.inner.put(key, value);
        if stored {
            self.puts.fetch_add(1, Ordering::SeqCst);
        }
        stored
    }
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.inner.get(key);
        if value.is_some() {
            self.get_hits.fetch_add(1, Ordering::SeqCst);
        }
        value
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.inner.take(key);
        if value.is_some() {
            self.take_hits.fetch_add(1, Ordering::SeqCst);
        }
        value
    }
    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

struct Peer {
    endpoint: Endpoint,
    resume: quinn::ServerConfig,
    generation: Arc<AtomicUsize>,
    store: Arc<Store>,
    warm_connections: Arc<Mutex<Vec<quinn::Connection>>>,
}

struct Peers {
    peers: Vec<Peer>,
    tasks: tokio::task::JoinSet<()>,
    certificate: Vec<u8>,
    pin: String,
}

impl Drop for Peers {
    fn drop(&mut self) {
        for peer in &self.peers {
            peer.endpoint.close(0u32.into(), b"early capture complete");
        }
        self.tasks.abort_all();
    }
}

impl Peers {
    fn new() -> Self {
        assert_eq!(
            std::env::var("H3_FLOW_PEER_TICKETS")
                .as_deref()
                .unwrap_or("on"),
            "on"
        );
        let cert =
            generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
        let certificate = cert.cert.der().to_vec();
        let pin = base64::engine::general_purpose::STANDARD.encode(
            aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                &cert.signing_key.subject_public_key_info(),
            )
            .as_ref(),
        );
        let keys = Arc::new(Keys(Mutex::new(())));
        let mut output = Self {
            peers: Vec::new(),
            tasks: tokio::task::JoinSet::new(),
            certificate,
            pin,
        };
        let started = Instant::now();
        let retire_warm = match std::env::var("H3_FLOW_EARLY_WARM_RETIRE")
            .as_deref()
            .unwrap_or("off")
        {
            "off" => false,
            "on" => true,
            _ => panic!("invalid warm retirement setting"),
        };
        for (offset, &case) in CASES.iter().enumerate() {
            let port = BASE + offset as u16;
            let store = Store::new();
            let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            tls.max_early_data_size = u32::MAX;
            tls.session_storage = store.clone();
            tls.key_log = keys.clone();
            assert!(!tls.ticketer.enabled());
            let mut resumed_tls = tls.clone();
            if case == "resume_reject" {
                resumed_tls.max_early_data_size = 0;
            }
            assert!(Arc::ptr_eq(
                &tls.session_storage,
                &resumed_tls.session_storage
            ));
            assert!(Arc::ptr_eq(&tls.cert_resolver, &resumed_tls.cert_resolver));
            assert!(Arc::ptr_eq(&tls.ticketer, &resumed_tls.ticketer));
            assert!(Arc::ptr_eq(&tls.key_log, &resumed_tls.key_log));
            let mut transport = quinn::TransportConfig::default();
            transport
                .stream_receive_window(65_536u32.into())
                .receive_window(262_144u32.into());
            transport.enable_ecn(
                match std::env::var("H3_FLOW_PEER_ECN").as_deref().unwrap_or("on") {
                    "on" => true,
                    "off" => false,
                    _ => panic!("invalid peer ECN setting"),
                },
            );
            let transport = Arc::new(transport);
            let mut warm = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(tls).unwrap(),
            ));
            warm.transport_config(transport);
            let mut resume = warm.clone();
            resume.crypto = Arc::new(QuicServerConfig::try_from(resumed_tls).unwrap());
            let endpoint = Endpoint::server(warm, localhost_addr(port)).unwrap();
            let generation = Arc::new(AtomicUsize::new(0));
            let warm_connections = Arc::new(Mutex::new(Vec::new()));
            output.peers.push(Peer {
                endpoint: endpoint.clone(),
                resume,
                generation: generation.clone(),
                store: store.clone(),
                warm_connections: warm_connections.clone(),
            });
            output.tasks.spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                let mut next = 0;
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break; };
                            let ordinal = next;
                            next += 1;
                            let generation = generation.load(Ordering::SeqCst);
                            let store = store.clone();
                            let warm_connections = warm_connections.clone();
                            observe(serde_json::json!({"case":case,"port":port,"connection":ordinal,"generation":generation,"phase":"incoming","elapsed_ms":started.elapsed().as_millis()}));
                            connections.spawn(async move {
                                let connection = match incoming.await {
                                    Ok(connection) => connection,
                                    Err(_) => { observe(serde_json::json!({"case":case,"port":port,"connection":ordinal,"phase":"handshake_failed"})); return; }
                                };
                                assert!(connection.remote_address().ip().is_loopback());
                                if generation == 0 && retire_warm {
                                    warm_connections.lock().unwrap().push(connection.clone());
                                }
                                let remote_port = connection.remote_address().port();
                                let alpn_h3 = connection.handshake_data().and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                                    .is_some_and(|data| data.protocol.as_deref() == Some(b"h3"));
                                observe(serde_json::json!({"case":case,"port":port,"remote_port":remote_port,"connection":ordinal,"generation":generation,"phase":"handshake_complete","alpn_h3":alpn_h3,"store":store.counts(),"elapsed_ms":started.elapsed().as_millis()}));
                                assert!(alpn_h3);
                                let Ok(mut h3) = server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone())).await else { return; };
                                while let Ok(Some(resolver)) = h3.accept().await {
                                    let Ok((request, mut stream)) = resolver.resolve_request().await else { break; };
                                    let path = request.uri().path();
                                    assert!(matches!(path, "/" | "/case" | "/favicon.ico"));
                                    assert_eq!(request.method(), http::Method::GET);
                                    let stream_id = stream.id().into_inner();
                                    let mut received = 0;
                                    while let Some(data) = stream.recv_data().await.unwrap() { received += data.remaining(); }
                                    assert_eq!(received, 0);
                                    observe(serde_json::json!({"case":case,"port":port,"remote_port":remote_port,"connection":ordinal,"generation":generation,"phase":"request","path":path,"method":"GET","stream_id":stream_id,"store":store.counts(),"elapsed_ms":started.elapsed().as_millis()}));
                                    let body: &'static [u8] = match path { "/" => b"<!doctype html><body>root-ready</body>", "/case" => b"early-complete", _ => b"" };
                                    stream.send_response(http::Response::builder().status(200)
                                        .header("content-type", if path == "/" { "text/html" } else { "application/octet-stream" })
                                        .header("cache-control", "no-store").body(()).unwrap()).await.unwrap();
                                    if !body.is_empty() { stream.send_data(Bytes::from_static(body)).await.unwrap(); }
                                    stream.finish().await.unwrap();
                                    observe(serde_json::json!({"case":case,"port":port,"connection":ordinal,"phase":"response_complete","path":path,"stream_id":stream_id,"status":200,"body_len":body.len()}));
                                }
                                observe(serde_json::json!({"case":case,"port":port,"connection":ordinal,"phase":"connection_finished","elapsed_ms":started.elapsed().as_millis()}));
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => { result.unwrap().expect("early-data capture connection must not panic"); }
                    }
                }
                connections.shutdown().await;
            });
        }
        output
    }

    fn arm(&self, offset: usize) {
        let peer = &self.peers[offset];
        assert!(
            peer.store.puts.load(Ordering::SeqCst) > 0,
            "warm handshake must issue a stored ticket"
        );
        peer.endpoint.set_server_config(Some(peer.resume.clone()));
        peer.generation.store(1, Ordering::SeqCst);
        observe(
            serde_json::json!({"case":CASES[offset],"port":BASE+offset as u16,"phase":"resume_config_armed","generation":1,"max_early_data_size":if CASES[offset] == "resume_reject" { 0u32 } else { u32::MAX },"store":peer.store.counts(),"shared_store_certificate_ticketer_keylog":true}),
        );
        match std::env::var("H3_FLOW_EARLY_WARM_RETIRE")
            .as_deref()
            .unwrap_or("off")
        {
            "off" => {}
            "on" => {
                let connections = std::mem::take(&mut *peer.warm_connections.lock().unwrap());
                assert_eq!(
                    connections.len(),
                    1,
                    "retirement requires one warm connection"
                );
                for connection in connections {
                    observe(
                        serde_json::json!({"case":CASES[offset],"port":BASE+offset as u16,"remote_port":connection.remote_address().port(),"phase":"warm_retirement_requested","application_close_code":256}),
                    );
                    connection.close(256u32.into(), b"controlled resumption");
                }
            }
            _ => panic!("invalid warm retirement setting"),
        }
    }

    async fn shutdown(&mut self) {
        for peer in &self.peers {
            peer.endpoint.close(0u32.into(), b"early capture complete");
        }
        for peer in &self.peers {
            peer.endpoint.wait_idle().await;
        }
        while let Some(result) = self.tasks.join_next().await {
            result.expect("capture endpoint must not panic");
        }
    }
}

#[tokio::test]
#[ignore = "Tier-1: controlled real-browser early-data rejection capture"]
async fn local_browser_h3_rejection_peer() {
    let mut peers = Peers::new();
    observe(serde_json::json!({"fixture":"h3_flow","cases":CASES,"spki_pin":peers.pin}));
    let stop = std::env::var("H3_FLOW_STOP").unwrap();
    let directory = std::path::PathBuf::from(std::env::var("H3_FLOW_GATE_DIR").unwrap());
    tokio::time::timeout(Duration::from_secs(100), async {
        while !std::path::Path::new(&stop).exists() {
            for offset in 0..CASES.len() {
                let port = BASE + offset as u16;
                let arm = directory.join(format!("resume-{port}.arm"));
                let ready = directory.join(format!("resume-{port}.ready"));
                if arm.exists() && !ready.exists() {
                    peers.arm(offset);
                    std::fs::write(ready, b"ready").unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("controller must stop the rejection peer");
    peers.shutdown().await;
    assert_eq!(peers.peers.len(), 6);
}

#[tokio::test]
#[ignore = "Tier-1: paired library early-data rejection capture"]
async fn local_library_h3_rejection_capture() {
    let mut peers = Peers::new();
    let reuse = match std::env::var("H3_FLOW_LIBRARY_EARLY_REUSE")
        .as_deref()
        .unwrap_or("on")
    {
        "on" => true,
        "off" => false,
        _ => panic!("invalid early reuse mode"),
    };
    for (offset, &case) in CASES.iter().enumerate() {
        let url = format!("https://127.0.0.1:{}/", BASE + offset as u16);
        let mut profile = lkh3::chrome_155_quic();
        profile.packetization.reuse_rejected_0rtt_streams = reuse;
        match std::env::var("H3_FLOW_LIBRARY_DEFER_QPACK")
            .as_deref()
            .unwrap_or("profile")
        {
            "profile" => {}
            "on" => profile.h3.defer_qpack_stream_prefixes = true,
            "off" => profile.h3.defer_qpack_stream_prefixes = false,
            _ => panic!("invalid QPACK prefix policy"),
        }
        let defer_qpack = profile.h3.defer_qpack_stream_prefixes;
        let client = lkrequest::Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .quic_profile(profile)
            .tls_session_cache_partition_policy(
                lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned,
            )
            .add_ca_cert_der(&peers.certificate)
            .build();
        let warm = client.session().http3_only().build();
        assert!(warm
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .unwrap()
            .contains("root-ready"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        peers.arm(offset);
        drop(warm);
        let session = client.session().http3_only().build();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            session.get(&format!("{url}case")).send(),
        )
        .await
        .expect("bounded early-data capture")
        .expect("normal early-data decision must complete");
        assert_eq!(response.bytes(), b"early-complete");
        observe(
            serde_json::json!({"client":"library","case":case,"port":BASE+offset as u16,"profile":"chrome155","h3_retry_mode":"Safe","reuse_rejected_0rtt_streams":reuse,"defer_qpack_stream_prefixes":defer_qpack,"result":{"ok":true,"status":response.status().as_u16(),"body_len":response.bytes().len()},"store":peers.peers[offset].store.counts()}),
        );
        drop(session);
        drop(client);
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
    peers.shutdown().await;
    assert_eq!(CASES.len(), 6);
}
