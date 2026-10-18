//! Preserve the final CONNECT status after the single Basic-auth retry.

use std::time::Duration;

use lkrequest::dns::SystemDns;
use lkrequest::error::{Error, ProxyErrorKind, Result};
use lkrequest::proxy::ProxyConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const LIMIT: Duration = Duration::from_secs(4);

struct ProxyTask(Option<JoinHandle<usize>>);

impl Drop for ProxyTask {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

async fn answer(stream: &mut TcpStream, status: u16, challenge: bool, credentials: bool) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        assert!(request.len() < 8192, "oversized CONNECT request");
        request.push(stream.read_u8().await.unwrap());
    }
    assert!(request.starts_with(b"CONNECT target.test:443 HTTP/1.1\r\n"));
    let head = std::str::from_utf8(&request).unwrap().to_ascii_lowercase();
    assert_eq!(head.contains("proxy-authorization: basic "), credentials);
    let challenge = if challenge {
        "Proxy-Authenticate: Basic realm=\"fixture\"\r\n"
    } else {
        ""
    };
    let response = format!("HTTP/1.1 {status} Fixture\r\n{challenge}\r\n");
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn connect(status: u16, retry: bool, credentials: bool) -> Result<TcpStream> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let mut server = ProxyTask(Some(tokio::spawn(async move {
        tokio::time::timeout(LIMIT, async {
            let (mut first, _) = listener.accept().await.unwrap();
            if retry {
                answer(&mut first, 407, true, credentials).await;
                drop(first);
                let (mut second, _) = listener.accept().await.unwrap();
                answer(&mut second, status, false, credentials).await;
                2
            } else {
                answer(&mut first, status, status == 407, credentials).await;
                1
            }
        })
        .await
        .expect("CONNECT fixture timeout")
    })));
    let userinfo = if credentials {
        "fixture:FAKE_PASSWORD@"
    } else {
        ""
    };
    let proxy = ProxyConfig::parse(&format!("http://{userinfo}{address}")).unwrap();
    let result =
        tokio::time::timeout(LIMIT, proxy.connect("target.test", 443, None, &SystemDns)).await;
    let requests = tokio::time::timeout(LIMIT, server.0.as_mut().unwrap())
        .await
        .expect("CONNECT fixture completion timeout")
        .expect("CONNECT fixture failed");
    assert_eq!(requests, if retry { 2 } else { 1 });
    result.expect("CONNECT attempt timeout")
}

#[tokio::test]
async fn a_non_auth_rejection_after_407_preserves_the_final_typed_status() {
    for status_code in [402, 503] {
        let error = connect(status_code, true, true).await.unwrap_err();
        assert!(error.is_proxy_tunnel());
        let details = error.as_proxy_error().unwrap();
        assert_eq!(details.kind, ProxyErrorKind::TunnelRefused { status_code });
        assert!(!details.is_auth_error());
    }
}

#[tokio::test]
async fn a_second_407_is_still_an_authentication_failure() {
    let error = connect(407, true, true).await.unwrap_err();
    assert_eq!(
        error.as_proxy_error().unwrap().kind,
        ProxyErrorKind::AuthenticationFailed
    );
    assert!(error.as_proxy_error().unwrap().is_auth_error());
}

#[tokio::test]
async fn a_407_without_credentials_is_still_authentication_required() {
    let error = connect(407, false, false).await.unwrap_err();
    assert_eq!(
        error.as_proxy_error().unwrap().kind,
        ProxyErrorKind::AuthenticationRequired
    );
}

#[tokio::test]
async fn successful_retry_still_accepts_any_2xx_tunnel_status() {
    for status_code in [200, 201, 204, 299] {
        let tunnel = connect(status_code, true, true).await;
        assert!(
            tunnel.is_ok(),
            "2xx CONNECT status {status_code} must establish a tunnel: {tunnel:?}"
        );
    }
}

#[tokio::test]
async fn a_direct_rejection_still_preserves_the_typed_status() {
    let error = connect(503, false, true).await.unwrap_err();
    assert!(matches!(error, Error::Proxy(_)));
    let details = error.as_proxy_error().unwrap();
    assert_eq!(
        details.kind,
        ProxyErrorKind::TunnelRefused { status_code: 503 }
    );
    assert!(!details.is_auth_error());
}
