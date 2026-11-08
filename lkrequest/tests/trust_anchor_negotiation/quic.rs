use super::*;
use quinn_proto::{
    crypto::{self, rustls::QuicServerConfig},
    transport_parameters::TransportParameters,
    ConnectionId, Side, TransportError,
};
use std::any::Any;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct ServerCrypto {
    first: Arc<QuicServerConfig>,
    next: Arc<QuicServerConfig>,
    key: Vec<u8>,
    id: TrustAnchorId,
    attempts: AtomicUsize,
    requests: Arc<Mutex<Vec<Vec<TrustAnchorId>>>>,
    hellos: Arc<Mutex<Vec<Vec<u8>>>>,
    resumed: Arc<Mutex<Vec<bool>>>,
    reject_first: bool,
}

impl crypto::ServerConfig for ServerCrypto {
    fn initial_keys(
        &self,
        version: u32,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.first.initial_keys(version, cid)
    }
    fn retry_tag(&self, version: u32, cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.first.retry_tag(version, cid, packet)
    }
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let first = self.attempts.fetch_add(1, Ordering::SeqCst) == 0 && self.reject_first;
        Box::new(ServerSession {
            inner: if first {
                self.first.clone()
            } else {
                self.next.clone()
            }
            .start_session(version, params),
            key: first.then(|| self.key.clone()),
            id: self.id.clone(),
            incoming: Vec::new(),
            transcript: Vec::new(),
            observed: false,
            requests: self.requests.clone(),
            hellos: self.hellos.clone(),
            resumed: self.resumed.clone(),
        })
    }
}

struct ServerSession {
    inner: Box<dyn crypto::Session>,
    key: Option<Vec<u8>>,
    id: TrustAnchorId,
    incoming: Vec<u8>,
    transcript: Vec<u8>,
    observed: bool,
    requests: Arc<Mutex<Vec<Vec<TrustAnchorId>>>>,
    hellos: Arc<Mutex<Vec<Vec<u8>>>>,
    resumed: Arc<Mutex<Vec<bool>>>,
}

impl crypto::Session for ServerSession {
    fn initial_keys(&self, cid: &ConnectionId, side: Side) -> crypto::Keys {
        self.inner.initial_keys(cid, side)
    }
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }
    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.inner.early_crypto()
    }
    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }
    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }
    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.inner.next_1rtt_keys()
    }
    fn is_valid_retry(&self, cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(cid, header, payload)
    }
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(out, label, context)
    }
    fn read_handshake(&mut self, bytes: &[u8]) -> Result<bool, TransportError> {
        if !self.observed {
            self.incoming.extend_from_slice(bytes);
            if self.incoming.len() >= 4 {
                let len =
                    u32::from_be_bytes([0, self.incoming[1], self.incoming[2], self.incoming[3]])
                        as usize
                        + 4;
                if self.incoming.len() >= len {
                    self.hellos
                        .lock()
                        .unwrap()
                        .push(self.incoming[..len].to_vec());
                    self.requests
                        .lock()
                        .unwrap()
                        .push(ids(&self.incoming[..len]));
                    self.transcript.extend_from_slice(&self.incoming[..len]);
                    self.observed = true;
                }
            }
        }
        self.inner.read_handshake(bytes)
    }
    fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<crypto::Keys> {
        let mut bytes = Vec::new();
        let keys = self.inner.write_handshake(&mut bytes);
        if bytes.first() == Some(&2) {
            let end = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize + 4;
            let mut pos = 44 + usize::from(bytes[38]);
            let mut resumed = false;
            while pos < end {
                let kind = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
                let len = usize::from(u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]));
                resumed |= kind == 41;
                pos += 4 + len;
            }
            self.resumed.lock().unwrap().push(resumed);
        }
        if self.key.is_none() {
            out.extend(bytes);
            return keys;
        }
        // Rustls supplies the QUIC handshake keys. Only the failing first
        // flight is altered; re-sign its transcript so validation reaches PKI.
        let mut remaining = bytes.as_slice();
        while !remaining.is_empty() {
            let len =
                u32::from_be_bytes([0, remaining[1], remaining[2], remaining[3]]) as usize + 4;
            let original = &remaining[..len];
            remaining = &remaining[len..];
            let modified = match original[0] {
                8 => {
                    let mut extensions = original[6..].to_vec();
                    let payload = encode_list(std::slice::from_ref(&self.id)).unwrap();
                    extensions.extend_from_slice(&[0xca, 0x34]);
                    extensions.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                    extensions.extend(payload);
                    let mut body = (extensions.len() as u16).to_be_bytes().to_vec();
                    body.extend(extensions);
                    message(8, &body)
                }
                15 => {
                    let signer = signature::EcdsaKeyPair::from_pkcs8(
                        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        self.key.as_ref().unwrap(),
                    )
                    .unwrap();
                    let mut signed = vec![0x20; 64];
                    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                    signed.extend_from_slice(
                        digest::digest(&digest::SHA256, &self.transcript).as_ref(),
                    );
                    let signature = signer
                        .sign(&aws_lc_rs::rand::SystemRandom::new(), &signed)
                        .unwrap();
                    let mut body = vec![4, 3];
                    body.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
                    body.extend_from_slice(signature.as_ref());
                    message(15, &body)
                }
                20 => continue,
                _ => original.to_vec(),
            };
            self.transcript.extend_from_slice(&modified);
            out.extend(modified);
        }
        keys
    }
}

fn server_tls(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> Arc<QuicServerConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = u32::MAX;
    Arc::new(QuicServerConfig::try_from(config).unwrap())
}

#[tokio::test]
async fn tai_quic_recovers_with_singleton_request() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let trusted = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Untrusted QUIC TAI test CA");
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let untrusted = rcgen::CertifiedKey {
            cert: params.self_signed(&signing_key).unwrap(),
            signing_key,
        };
        let id = TrustAnchorId::from_hex("81fd5901").unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let crypto = Arc::new(ServerCrypto {
            first: server_tls(&untrusted),
            next: server_tls(&trusted),
            key: untrusted.signing_key.serialize_der(),
            id: id.clone(),
            attempts: AtomicUsize::new(0),
            requests: requests.clone(),
            hellos: Arc::new(Mutex::new(Vec::new())),
            resumed: Arc::new(Mutex::new(Vec::new())),
            reject_first: true,
        });
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(crypto.clone()),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            assert!(endpoint.accept().await.unwrap().await.is_err());
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3 =
                h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                use bytes::Buf;
                body.extend_from_slice(data.copy_to_bytes(data.remaining()).as_ref());
            }
            assert_eq!(body, b"payload");
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(bytes::Bytes::from_static(b"ok"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let anchor =
            lktls::verify::certchain::parse_trust_anchor_from_der(trusted.cert.der()).unwrap();
        let mut preset = lkrequest::preset::chrome_157();
        preset.tls_profile.key_share_curves = vec![29];
        if let Some(profile) = &mut preset.quic_tls_profile {
            profile.key_share_curves = vec![29];
        }
        let client = Client::builder()
            .fingerprint(preset.tls_profile)
            .quic_fingerprint(preset.quic_tls_profile.unwrap())
            .quic_profile(preset.quic_profile.unwrap())
            .dns_resolver(Arc::new(LocalDns))
            .add_ca_cert_der(trusted.cert.der())
            .trust_anchor_binding(TrustAnchorBinding {
                anchor_identity: anchor_identity(&anchor),
                id: id.clone(),
            })
            .trust_anchor_policy(TrustAnchorPolicy {
                recovery: TrustAnchorRecovery::Once,
                ..Default::default()
            })
            .try_build()
            .unwrap();
        let result = client
            .session()
            .http3_only()
            .build()
            .post(&format!("https://localhost:{port}/test"))
            .body("payload")
            .collect_diagnostics(true)
            .send()
            .await
            .unwrap();
        assert_eq!(result.version(), lkrequest::HttpVersion::H3);
        assert!(
            result
                .diagnostics()
                .unwrap()
                .trust_anchor
                .as_ref()
                .unwrap()
                .recovered
        );
        assert_eq!(result.text().unwrap(), "ok");
        server.await.unwrap();
        assert_eq!(crypto.attempts.load(Ordering::SeqCst), 2);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0], vec![id.clone()]);
        assert_eq!(requests[1], vec![id]);
    })
    .await
    .unwrap();
}

async fn resumption(recovery: bool) -> bool {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = server_tls(&cert);
        let crypto = Arc::new(ServerCrypto {
            first: tls.clone(),
            next: tls,
            key: Vec::new(),
            id: TrustAnchorId::from_hex("81fd5901").unwrap(),
            attempts: AtomicUsize::new(0),
            requests: Arc::new(Mutex::new(Vec::new())),
            hellos: Arc::new(Mutex::new(Vec::new())),
            resumed: Arc::new(Mutex::new(Vec::new())),
            reject_first: false,
        });
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(crypto.clone()),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let mut h3 =
                    h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                let resolver = h3.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                while stream.recv_data().await.unwrap().is_some() {}
                stream.send_response(http::Response::new(())).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"ok"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let mut preset = lkrequest::preset::chrome_157();
        preset.tls_profile.key_share_curves = vec![29];
        preset.quic_tls_profile.as_mut().unwrap().key_share_curves = vec![29];
        let client = Client::builder()
            .preset(preset)
            .dns_resolver(Arc::new(LocalDns))
            .add_ca_cert_der(cert.cert.der())
            .trust_anchor_policy(TrustAnchorPolicy {
                recovery: if recovery {
                    TrustAnchorRecovery::Once
                } else {
                    TrustAnchorRecovery::Disabled
                },
                ..Default::default()
            })
            .try_build()
            .unwrap();
        let session = client.session().http3_only().build();
        for _ in 0..2 {
            let result = session
                .get(&format!("https://localhost:{port}/"))
                .send()
                .await
                .unwrap();
            assert_eq!(result.text().unwrap(), "ok");
            session.pool_clear();
        }
        server.await.unwrap();
        assert_eq!(crypto.attempts.load(Ordering::SeqCst), 2);
        assert_eq!(*crypto.resumed.lock().unwrap(), vec![false, true]);
        let hellos = crypto.hellos.lock().unwrap();
        assert_eq!(hellos.len(), 2);
        let second = lkprofile::parse_client_hello(&hellos[1]).unwrap();
        assert!(second.extensions.iter().any(|e| e.extension_type == 41));
        second.extensions.iter().any(|e| e.extension_type == 42)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn tai_quic_policy_preserves_psk_and_suppresses_real_zero_rtt() {
    assert!(!resumption(true).await);
}

#[tokio::test]
async fn tai_quic_default_policy_keeps_real_zero_rtt_control() {
    assert!(resumption(false).await);
}
