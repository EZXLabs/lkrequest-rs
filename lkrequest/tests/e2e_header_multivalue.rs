//! Public request-builder multi-value header regressions on loopback HTTP/1.

use std::time::Duration;

use http::HeaderMap;
use lkrequest::{Client, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const LIMIT: Duration = Duration::from_secs(4);

struct HeaderCapture {
    url: String,
    task: Option<JoinHandle<Vec<(String, String)>>>,
}

impl HeaderCapture {
    async fn start() -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}/headers", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            tokio::time::timeout(LIMIT, async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 16_384, "oversized request head");
                    head.push(stream.read_u8().await.unwrap());
                }
                let head = std::str::from_utf8(&head).unwrap();
                let mut lines = head.split("\r\n");
                assert_eq!(lines.next(), Some("GET /headers HTTP/1.1"));
                let headers = lines
                    .take_while(|line| !line.is_empty())
                    .map(|line| {
                        let (name, value) = line.split_once(':').unwrap();
                        (name.to_ascii_lowercase(), value.trim().to_owned())
                    })
                    .collect();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
                headers
            })
            .await
            .expect("header fixture timeout")
        });
        Self {
            url,
            task: Some(task),
        }
    }

    async fn finish(mut self) -> Vec<(String, String)> {
        tokio::time::timeout(LIMIT, self.task.as_mut().unwrap())
            .await
            .expect("header fixture completion timeout")
            .expect("header fixture failed")
    }
}

impl Drop for HeaderCapture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn session() -> Session {
    Client::builder()
        .default_header("accept", "application/fixture-default")
        .build()
        .session()
        .http1_only()
        .build()
}

fn accepts() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.append("accept", "text/plain".parse().unwrap());
    headers.append("accept", "application/json".parse().unwrap());
    headers
}

fn values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .collect()
}

async fn send(request: lkrequest::session::RequestBuilder, streaming: bool) {
    tokio::time::timeout(LIMIT, async move {
        if streaming {
            let response = request.send_streaming().await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.bytes().await.unwrap().as_ref(), b"OK");
        } else {
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.bytes(), b"OK");
        }
    })
    .await
    .expect("header request timeout");
}

#[tokio::test]
async fn header_map_retains_values_and_replaces_the_existing_name_group() {
    for streaming in [false, true] {
        let capture = HeaderCapture::start().await;
        let request = session()
            .get(&capture.url)
            .header("accept", "application/previous-request")
            .header("x-keep", "kept")
            .headers(accepts());
        send(request, streaming).await;
        let headers = capture.finish().await;
        assert_eq!(
            values(&headers, "accept"),
            ["text/plain", "application/json"]
        );
        assert_eq!(values(&headers, "x-keep"), ["kept"]);
    }
}

#[tokio::test]
async fn header_map_with_order_retains_each_value_and_name_order() {
    for streaming in [false, true] {
        let capture = HeaderCapture::start().await;
        let mut map = accepts();
        map.insert("x-tail", "tail".parse().unwrap());
        let request = session()
            .get(&capture.url)
            .header("x-prefix", "prefix")
            .headers_with_order(map, &["x-tail", "accept"]);
        send(request, streaming).await;
        let headers = capture.finish().await;
        assert_eq!(
            values(&headers, "accept"),
            ["text/plain", "application/json"]
        );
        let index = |name| headers.iter().position(|(key, _)| key == name).unwrap();
        assert!(index("x-prefix") < index("x-tail"));
        assert!(index("x-tail") < index("accept"));
    }
}

#[tokio::test]
async fn a_later_header_map_replaces_all_values_from_the_earlier_map() {
    for streaming in [false, true] {
        let capture = HeaderCapture::start().await;
        let mut next = HeaderMap::new();
        next.append("accept", "image/png".parse().unwrap());
        next.append("accept", "image/webp".parse().unwrap());
        let request = session().get(&capture.url).headers(accepts()).headers(next);
        send(request, streaming).await;
        assert_eq!(
            values(&capture.finish().await, "accept"),
            ["image/png", "image/webp"]
        );
    }
}

#[tokio::test]
async fn single_header_and_ordered_pair_setters_keep_their_replacement_contract() {
    for streaming in [false, true] {
        for ordered_pairs in [false, true] {
            let capture = HeaderCapture::start().await;
            let request = session().get(&capture.url).headers(accepts());
            let request = if ordered_pairs {
                request.headers_ordered([("accept", "image/png"), ("accept", "image/webp")])
            } else {
                request
                    .header("accept", "image/png")
                    .header("accept", "image/webp")
            };
            send(request, streaming).await;
            assert_eq!(values(&capture.finish().await, "accept"), ["image/webp"]);
        }
    }
}
