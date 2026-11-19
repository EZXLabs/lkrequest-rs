use std::error::Error;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{ACCEPT, USER_AGENT};
use http::{Request, Uri, Version};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use lkrequest::{Client as LkClient, Session};
use tokio::net::TcpStream;

use crate::config::{ClientName, Lifecycle, Protocol, RunConfig};

const CONNECTION_ID_HEADER: &str = "x-bench-connection-id";
const PROTOCOL_HEADER: &str = "x-bench-protocol";

#[derive(Clone)]
pub enum BenchmarkClient {
    Lkrequest {
        client: LkClient,
        session: Option<Session>,
        protocol: Protocol,
        transport_only: bool,
        streaming: bool,
    },
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
    pub protocol: ObservedProtocol,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservedProtocol {
    H1,
    H2,
    H3,
}

impl BenchmarkClient {
    pub async fn build(config: &RunConfig) -> Result<Self, Box<dyn Error>> {
        let name = config.client;
        let url = &config.url;
        match name {
            ClientName::Lkrequest
            | ClientName::LkrequestBatch64
            | ClientName::LkrequestTransport
            | ClientName::LkrequestStreaming => {
                let mut builder = LkClient::builder();
                if name == ClientName::LkrequestBatch64 {
                    builder = builder.h2_dispatch_batch_size(64);
                }
                #[cfg(feature = "quic-h3")]
                if config.protocol.uses_tls() {
                    let uri: Uri = url.parse()?;
                    let address = crate::config::loopback_address(&uri)
                        .ok_or("TLS benchmark fixture is not loopback")?;
                    builder = builder
                        .preset(lkrequest::preset::chrome_155())
                        .verify(false)
                        .tls_session_resumption_policy(
                            lkrequest::TlsSessionResumptionPolicy::Disabled,
                        )
                        .dns_resolver(Arc::new(FixtureDns { address }));
                }
                let client = builder.build();
                let session = (config.lifecycle == Lifecycle::Warm)
                    .then(|| build_session(&client, config.protocol));
                Ok(Self::Lkrequest {
                    client,
                    session,
                    protocol: config.protocol,
                    transport_only: name == ClientName::LkrequestTransport,
                    streaming: name == ClientName::LkrequestStreaming,
                })
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
            Self::Lkrequest {
                client,
                session,
                protocol,
                transport_only,
                streaming,
            } => {
                let temporary = session.is_none().then(|| build_session(client, *protocol));
                let session = session.as_ref().or(temporary.as_ref()).unwrap();
                let request = session
                    .get(url)
                    .header(USER_AGENT.as_str(), "http-client-bench")
                    .header(ACCEPT.as_str(), "*/*");
                if *streaming {
                    let mut response = request.send_streaming().await?;
                    let status = response.status().as_u16();
                    let connection_id = connection_id(response.headers());
                    let protocol = fixture_protocol(response.headers())?;
                    let mut body_bytes = 0usize;
                    while let Some(chunk) = response.chunk().await? {
                        body_bytes = body_bytes.saturating_add(chunk.len());
                    }
                    return Ok(ResponseSample {
                        status,
                        body_bytes,
                        connection_id,
                        protocol,
                    });
                }
                let response = if *transport_only {
                    request.send_transport_only_for_benchmark().await?
                } else {
                    request.send().await?
                };
                let protocol = match response.negotiated_version() {
                    lkrequest::NegotiatedHttpVersion::Http11 => ObservedProtocol::H1,
                    lkrequest::NegotiatedHttpVersion::Http2 => ObservedProtocol::H2,
                    lkrequest::NegotiatedHttpVersion::Http3 => ObservedProtocol::H3,
                    other => return Err(format!("unexpected negotiated protocol {other:?}").into()),
                };
                Ok(ResponseSample {
                    status: response.status().as_u16(),
                    body_bytes: response.bytes().len(),
                    connection_id: connection_id(response.headers()),
                    protocol,
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
                    protocol: ObservedProtocol::H2,
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
                let protocol = http_protocol(response.version())?;
                let connection_id = connection_id(response.headers());
                let body = response.into_body().collect().await?.to_bytes();
                Ok(ResponseSample {
                    status,
                    body_bytes: body.len(),
                    connection_id,
                    protocol,
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
                let protocol = http_protocol(response.version())?;
                let connection_id = connection_id(response.headers());
                let body = response.bytes().await?;
                Ok(ResponseSample {
                    status,
                    body_bytes: body.len(),
                    connection_id,
                    protocol,
                })
            }
        }
    }
}

fn build_session(client: &LkClient, protocol: Protocol) -> Session {
    let builder = client.session();
    match protocol {
        Protocol::H1 => builder.http1_only().build(),
        Protocol::H2c => builder.http2_only().build(),
        Protocol::H3 => builder.http3_only().build(),
        Protocol::Race => builder
            .protocol_policy(lkrequest::ProtocolPolicy::new(
                lkrequest::HttpIntent::AcquireH3WhenViable,
                lkrequest::AcquisitionPolicy::Race(lkrequest::RacePolicy {
                    enable_tcp: true,
                    enable_quic: true,
                    tcp_delay: std::time::Duration::ZERO,
                    quic_delay: std::time::Duration::ZERO,
                    only_when_h3_advertised: true,
                }),
                lkrequest::UpgradePolicy::Off,
                lkrequest::FallbackPolicy::NoFallback,
            ))
            .chrome_like_protocol_config(lkrequest::ChromeLikeProtocolConfig {
                tcp_main_job_delay: std::time::Duration::ZERO,
                keep_quic_probe_after_tcp_win: false,
                keep_tcp_probe_after_quic_win: false,
            })
            .build(),
    }
}

fn http_protocol(version: Version) -> Result<ObservedProtocol, Box<dyn Error + Send + Sync>> {
    match version {
        Version::HTTP_11 => Ok(ObservedProtocol::H1),
        Version::HTTP_2 => Ok(ObservedProtocol::H2),
        Version::HTTP_3 => Ok(ObservedProtocol::H3),
        other => Err(format!("unexpected HTTP version {other:?}").into()),
    }
}

#[cfg(feature = "quic-h3")]
struct FixtureDns {
    address: std::net::IpAddr,
}

#[cfg(feature = "quic-h3")]
#[async_trait::async_trait]
impl lkrequest::dns::DnsResolver for FixtureDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(vec![std::net::SocketAddr::new(self.address, port)])
    }

    async fn lookup_https(
        &self,
        _host: &str,
    ) -> std::io::Result<Option<lkrequest::dns::HttpsRecord>> {
        Ok(Some(lkrequest::dns::HttpsRecord {
            alpn: vec!["h3".into(), "h2".into()],
            ..Default::default()
        }))
    }
}

fn connection_id(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(CONNECTION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn fixture_protocol(
    headers: &http::HeaderMap,
) -> Result<ObservedProtocol, Box<dyn Error + Send + Sync>> {
    match headers.get(PROTOCOL_HEADER).map(|value| value.as_bytes()) {
        Some(b"h1") => Ok(ObservedProtocol::H1),
        Some(b"h2") => Ok(ObservedProtocol::H2),
        Some(b"h3") => Ok(ObservedProtocol::H3),
        Some(value) => Err(format!("invalid {PROTOCOL_HEADER} fixture header: {value:?}").into()),
        None => {
            Err(format!("streaming benchmark requires the {PROTOCOL_HEADER} fixture header").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_protocol_requires_explicit_fixture_evidence() {
        let mut headers = http::HeaderMap::new();
        assert!(fixture_protocol(&headers).is_err());
        for (value, expected) in [
            ("h1", ObservedProtocol::H1),
            ("h2", ObservedProtocol::H2),
            ("h3", ObservedProtocol::H3),
        ] {
            headers.insert(PROTOCOL_HEADER, value.parse().unwrap());
            assert_eq!(fixture_protocol(&headers).unwrap(), expected);
        }
        for value in ["race", "h2c", "", "H3"] {
            headers.insert(PROTOCOL_HEADER, value.parse().unwrap());
            assert!(fixture_protocol(&headers).is_err());
        }
    }
}
