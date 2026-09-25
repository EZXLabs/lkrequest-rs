use std::error::Error;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{ACCEPT, USER_AGENT};
use http::{Request, Uri, Version};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use lkrequest::{Client as LkClient, PreferredHttpVersion, Session};
use tokio::net::TcpStream;

use crate::config::ClientName;

const CONNECTION_ID_HEADER: &str = "x-bench-connection-id";

#[derive(Clone)]
pub enum BenchmarkClient {
    Lkrequest(Session),
    LkrequestBatch64(Session),
    LkrequestTransport(Session),
    Lkh2 {
        sender: lkh2::H2Sender,
        _task: Arc<tokio::task::JoinHandle<()>>,
    },
    Hyper(Arc<HyperClient<HttpConnector, Empty<Bytes>>>),
    Reqwest(reqwest::Client),
}

pub struct ResponseSample {
    pub status: u16,
    pub body_bytes: usize,
    pub connection_id: Option<u64>,
    pub is_http2: bool,
}

impl BenchmarkClient {
    pub async fn build(name: ClientName, url: &str) -> Result<Self, Box<dyn Error>> {
        match name {
            ClientName::Lkrequest => {
                let client = LkClient::builder().build();
                Ok(Self::Lkrequest(client.session().http2_only().build()))
            }
            ClientName::LkrequestBatch64 => {
                let client = LkClient::builder().h2_dispatch_batch_size(64).build();
                Ok(Self::LkrequestBatch64(
                    client.session().http2_only().build(),
                ))
            }
            ClientName::LkrequestTransport => {
                let client = LkClient::builder().build();
                Ok(Self::LkrequestTransport(
                    client.session().http2_only().build(),
                ))
            }
            ClientName::Lkh2 | ClientName::Lkh2Drain64 | ClientName::Lkh2Batch64 => {
                let uri: Uri = url.parse()?;
                let authority = uri.authority().ok_or("benchmark URL has no authority")?;
                let port = authority.port_u16().unwrap_or(80);
                let stream = TcpStream::connect((authority.host(), port)).await?;
                stream.set_nodelay(true)?;
                let max_ready_commands_per_turn = match name {
                    ClientName::Lkh2 => 1,
                    ClientName::Lkh2Drain64 | ClientName::Lkh2Batch64 => 64,
                    _ => unreachable!(),
                };
                let max_requests_per_write = match name {
                    ClientName::Lkh2 | ClientName::Lkh2Drain64 => 1,
                    ClientName::Lkh2Batch64 => 64,
                    _ => unreachable!(),
                };
                let connection = lkh2::connect_h2_native_with_config(
                    stream,
                    &lkh2::profile::chrome_144_h2(),
                    None,
                    lkh2::H2DriverConfig {
                        max_ready_commands_per_turn,
                        max_requests_per_write,
                        ..lkh2::H2DriverConfig::default()
                    },
                )
                .await?;
                let sender = connection.clone_sender();
                Ok(Self::Lkh2 {
                    sender,
                    _task: Arc::new(connection.into_task()),
                })
            }
            ClientName::Hyper => {
                let mut connector = HttpConnector::new();
                connector.enforce_http(false);
                connector.set_nodelay(true);
                let mut builder = HyperClient::builder(TokioExecutor::new());
                builder.http2_only(true);
                Ok(Self::Hyper(Arc::new(builder.build(connector))))
            }
            ClientName::Reqwest => Ok(Self::Reqwest(
                reqwest::Client::builder()
                    .http2_prior_knowledge()
                    .tcp_nodelay(true)
                    .build()?,
            )),
        }
    }

    pub async fn get(&self, url: &str) -> Result<ResponseSample, Box<dyn Error + Send + Sync>> {
        match self {
            Self::Lkrequest(session) | Self::LkrequestBatch64(session) => {
                let response = session
                    .get(url)
                    .header(USER_AGENT.as_str(), "http-client-bench")
                    .header(ACCEPT.as_str(), "*/*")
                    .preferred_http_version(PreferredHttpVersion::Http2Only)
                    .send()
                    .await?;
                Ok(ResponseSample {
                    status: response.status().as_u16(),
                    body_bytes: response.bytes().len(),
                    connection_id: connection_id(response.headers()),
                    is_http2: matches!(
                        response.negotiated_version(),
                        lkrequest::NegotiatedHttpVersion::Http2
                    ),
                })
            }
            Self::LkrequestTransport(session) => {
                let response = session
                    .get(url)
                    .header(USER_AGENT.as_str(), "http-client-bench")
                    .header(ACCEPT.as_str(), "*/*")
                    .preferred_http_version(PreferredHttpVersion::Http2Only)
                    .send_transport_only_for_benchmark()
                    .await?;
                Ok(ResponseSample {
                    status: response.status().as_u16(),
                    body_bytes: response.bytes().len(),
                    connection_id: connection_id(response.headers()),
                    is_http2: matches!(
                        response.negotiated_version(),
                        lkrequest::NegotiatedHttpVersion::Http2
                    ),
                })
            }
            Self::Lkh2 { sender, .. } => {
                let uri: Uri = url.parse()?;
                let request = Request::get(uri)
                    .header(USER_AGENT, "http-client-bench")
                    .header(ACCEPT, "*/*")
                    .body(())?;
                let ready = sender.clone().ready().await?;
                let (response_future, _send_stream) = ready.send_request(request, true)?;
                let response = response_future.await_response().await?;
                let status = response.status().as_u16();
                let connection_id = connection_id(response.headers());
                let mut body = response.into_body();
                let mut body_bytes = 0usize;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk?;
                    body_bytes = body_bytes.saturating_add(chunk.len());
                    body.flow_control().release_capacity(chunk.len())?;
                }
                Ok(ResponseSample {
                    status,
                    body_bytes,
                    connection_id,
                    is_http2: true,
                })
            }
            Self::Hyper(client) => {
                let uri: Uri = url.parse()?;
                let request = Request::get(uri)
                    .header(USER_AGENT, "http-client-bench")
                    .header(ACCEPT, "*/*")
                    .body(Empty::new())?;
                let response = client.request(request).await?;
                let status = response.status().as_u16();
                let is_http2 = response.version() == Version::HTTP_2;
                let connection_id = connection_id(response.headers());
                let body = response.into_body().collect().await?.to_bytes();
                Ok(ResponseSample {
                    status,
                    body_bytes: body.len(),
                    connection_id,
                    is_http2,
                })
            }
            Self::Reqwest(client) => {
                let response = client
                    .get(url)
                    .header(USER_AGENT, "http-client-bench")
                    .header(ACCEPT, "*/*")
                    .send()
                    .await?;
                let status = response.status().as_u16();
                let is_http2 = response.version() == Version::HTTP_2;
                let connection_id = connection_id(response.headers());
                let body = response.bytes().await?;
                Ok(ResponseSample {
                    status,
                    body_bytes: body.len(),
                    connection_id,
                    is_http2,
                })
            }
        }
    }
}

fn connection_id(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(CONNECTION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}
