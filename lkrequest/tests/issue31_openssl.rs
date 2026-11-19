//! Independent P-521 interoperability, including TLS 1.3 HelloRetryRequest.
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server {
    child: Child,
    directory: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
#[ignore = "set TEST_OPENSSL to an OpenSSL executable"]
async fn p521_tls12_tls13_signatures_and_key_exchange() {
    let openssl = std::env::var_os("TEST_OPENSSL").expect("TEST_OPENSSL");
    for (family, profile) in [
        ("firefox", lktls::profile::presets::firefox_156()),
        ("safari18", lktls::profile::presets::safari_18()),
        ("safari26", lktls::profile::presets::safari_26()),
    ] {
        for (case, version, p521_cert, group, sigalg) in [
            (
                "tls13-signature",
                "-tls1_3",
                true,
                "X25519",
                "ecdsa_secp521r1_sha512",
            ),
            (
                "tls12-signature",
                "-tls1_2",
                true,
                "X25519",
                "ecdsa_secp256r1_sha256",
            ),
            (
                "tls13-hrr",
                "-tls1_3",
                false,
                "P-521",
                "ecdsa_secp256r1_sha256",
            ),
            (
                "tls12-group",
                "-tls1_2",
                false,
                "P-521",
                "ecdsa_secp256r1_sha256",
            ),
        ] {
            if family == "safari26" && case == "tls13-signature" {
                continue;
            }
            let key = rcgen::KeyPair::generate_for(if p521_cert {
                &rcgen::PKCS_ECDSA_P521_SHA512
            } else {
                &rcgen::PKCS_ECDSA_P256_SHA256
            })
            .unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let directory = std::env::temp_dir().join(format!(
                "lkrequest-issue31-{}-{family}-{case}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("cert.pem"), cert.pem()).unwrap();
            std::fs::write(directory.join("key.pem"), key.serialize_pem()).unwrap();
            let addr = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let mut command = Command::new(&openssl);
            command
                .args([
                    "s_server",
                    "-accept",
                    &addr.to_string(),
                    "-www",
                    "-quiet",
                    version,
                    "-groups",
                    group,
                    "-sigalgs",
                    sigalg,
                    "-cipher",
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                ])
                .arg("-cert")
                .arg(directory.join("cert.pem"))
                .arg("-key")
                .arg(directory.join("key.pem"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let mut server = Server {
                child: command.spawn().unwrap(),
                directory,
            };
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    assert!(
                        server.child.try_wait().unwrap().is_none(),
                        "OpenSSL exited: {family}/{case}"
                    );
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            let client = lkrequest::Client::builder()
                .fingerprint(profile.clone())
                .add_ca_cert_der(cert.der())
                .total_timeout(Duration::from_secs(5))
                .build();
            let session = client.session().http1_only().build();
            let response = session
                .get(&format!("https://localhost:{}/", addr.port()))
                .send()
                .await
                .unwrap_or_else(|error| panic!("{family}/{case}: {error:?}"));
            assert_eq!(response.status(), http::StatusCode::OK, "{family}/{case}");
        }
    }
}
