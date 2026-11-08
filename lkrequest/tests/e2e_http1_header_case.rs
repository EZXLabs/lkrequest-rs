//! HTTP/1.1 casing assertions against raw loopback bytes, before HTTP parsing.

use std::sync::Arc;
use std::time::Duration;

use lkrequest::Client;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const LIMIT: Duration = Duration::from_secs(10);
const BODY: &str = "host: body\r\n\r\nPOST / HTTP/1.1\r\nhost: body\r\n\r\n";

struct Capture {
    url: String,
    ca_der: Option<Vec<u8>>,
    task: JoinHandle<Vec<String>>,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Capture {
    async fn start(tls: bool, streaming: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "{}://{}/headers",
            if tls { "https" } else { "http" },
            listener.local_addr().unwrap()
        );
        let (acceptor, ca_der) = if tls {
            let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let ca_der = key.cert.der().to_vec();
            let mut config = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![key.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            (
                Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
                Some(ca_der),
            )
        } else {
            (None, None)
        };
        let task = tokio::spawn(async move {
            tokio::time::timeout(LIMIT, async move {
                let mut requests = Vec::new();
                let (connections, per_connection) = if streaming { (2, 1) } else { (1, 2) };
                for _ in 0..connections {
                    let (socket, _) = listener.accept().await.unwrap();
                    let heads = if let Some(acceptor) = &acceptor {
                        capture_requests(acceptor.accept(socket).await.unwrap(), per_connection)
                            .await
                    } else {
                        capture_requests(socket, per_connection).await
                    };
                    requests.extend(heads);
                }
                requests
            })
            .await
            .expect("capture timeout")
        });
        Self { url, ca_der, task }
    }

    fn client(&self, title_case: Option<bool>) -> Client {
        let mut builder = Client::builder()
            .default_header("X-Default", "Keep-MiXeD")
            .header_order(vec!["host", "x-default", "x-mixed", "accept", "cookie"]);
        if let Some(ca_der) = &self.ca_der {
            builder = builder.add_ca_cert_der(ca_der);
        }
        if let Some(enabled) = title_case {
            builder = builder.http1_title_case_headers(enabled);
        }
        builder.build()
    }
}

async fn capture_requests<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    count: usize,
) -> Vec<String> {
    let mut requests = Vec::new();
    for index in 0..count {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 16_384, "oversized request head");
            head.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("POST /headers HTTP/1.1\r\n"));
        let length = head
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .unwrap()
            .1
            .trim()
            .parse::<usize>()
            .unwrap();
        assert_eq!(length, BODY.len());
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, BODY.as_bytes());
        requests.push(head);
        let connection = if index + 1 < count {
            "keep-alive"
        } else {
            "close"
        };
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {connection}\r\n\r\nOK"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.flush().await.unwrap();
    }
    requests
}

async fn check_requests(title_case: Option<bool>, preconnect: bool, http1_only: bool) -> usize {
    let mut checked_requests = 0;
    for tls in [false, true] {
        for streaming in [false, true] {
            let mut capture = Capture::start(tls, streaming).await;
            let client = capture.client(title_case);
            let session = if http1_only {
                client.session().http1_only().build()
            } else {
                client.session().build()
            };
            if preconnect {
                session.preconnect(&capture.url).await.unwrap();
            }
            for _ in 0..2 {
                let request = session
                    .post(&capture.url)
                    .header("x-MIXED", "Value-MiXeD")
                    .header("accept", "text/plain")
                    .cookie("test", "Cookie-MiXeD")
                    .body(BODY)
                    .timeout(LIMIT);
                if streaming {
                    let response = request.send_streaming().await.unwrap();
                    assert_eq!(response.bytes().await.unwrap().as_ref(), b"OK");
                } else {
                    let response = request.send().await.unwrap();
                    assert_eq!(response.bytes(), b"OK");
                }
            }
            let requests = (&mut capture.task).await.unwrap();
            for raw in requests {
                let headers: Vec<_> = raw
                    .split("\r\n")
                    .skip(1)
                    .take_while(|line| !line.is_empty())
                    .map(|line| line.split_once(':').unwrap())
                    .collect();
                let expected = if title_case.unwrap_or(true) {
                    ["Host", "X-Default", "X-Mixed", "Accept", "Cookie"]
                } else {
                    ["Host", "x-default", "x-mixed", "accept", "cookie"]
                };
                assert_eq!(
                    headers
                        .iter()
                        .take(5)
                        .map(|(name, _)| *name)
                        .collect::<Vec<_>>(),
                    expected,
                    "tls={tls}, streaming={streaming}, preconnect={preconnect}: {raw}"
                );
                assert!(headers.contains(&(expected[1], " Keep-MiXeD")));
                assert!(headers.contains(&(expected[2], " Value-MiXeD")));
                assert!(headers.contains(&(expected[4], " test=Cookie-MiXeD")));
                let length_name = if title_case.unwrap_or(true) {
                    "Content-Length"
                } else {
                    "content-length"
                };
                assert!(headers.contains(&(length_name, format!(" {}", BODY.len()).as_str())));
                if title_case == Some(false) {
                    assert!(headers
                        .iter()
                        .all(|(name, _)| *name == "Host" || *name == name.to_ascii_lowercase()));
                }
                checked_requests += 1;
            }
        }
    }
    checked_requests
}

#[tokio::test]
async fn lowercase_http1_headers_on_new_and_reused_connections() {
    assert_eq!(check_requests(Some(false), false, true).await, 8);
}

#[tokio::test]
async fn lowercase_http1_headers_on_preconnected_connections() {
    assert_eq!(check_requests(Some(false), true, true).await, 8);
}

#[tokio::test]
async fn title_case_remains_the_default() {
    assert_eq!(check_requests(None, false, true).await, 8);
}

#[tokio::test]
async fn explicit_title_case_applies_to_preconnected_connections() {
    assert_eq!(check_requests(Some(true), true, true).await, 8);
}

#[tokio::test]
async fn lowercase_headers_keep_host_capitalized_after_h2c_rejection() {
    assert_eq!(check_requests(Some(false), false, false).await, 8);
}

#[tokio::test]
async fn lowercase_headers_preserve_chunked_upload_bytes() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;

    for streaming in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/upload", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    assert_eq!(request.headers()["transfer-encoding"], "chunked");
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(body, BODY.as_bytes());
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .header("connection", "close")
                            .body(Full::new(body))
                            .unwrap(),
                    )
                },
            );
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
                .unwrap();
        });
        let session = Client::builder()
            .http1_title_case_headers(false)
            .build()
            .session()
            .http1_only()
            .build();
        let request = session
            .post(&url)
            .body_reader(std::io::Cursor::new(BODY.as_bytes()), None)
            .timeout(LIMIT);
        if streaming {
            assert_eq!(
                request
                    .send_streaming()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
                BODY.as_bytes()
            );
        } else {
            assert_eq!(request.send().await.unwrap().bytes(), BODY.as_bytes());
        }
        server.await.unwrap();
    }
}
