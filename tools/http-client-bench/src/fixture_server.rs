use std::convert::Infallible;
use std::error::Error;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::config::{Protocol, ServeConfig};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct ServerActivity {
    pub tcp_accepts: u64,
    pub tls_completed: u64,
    pub quic_incoming: u64,
    pub quic_established: u64,
    pub h1_requests: u64,
    pub h2_requests: u64,
    pub h3_requests: u64,
    pub connection_failures: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerSnapshot {
    pub instance_id: String,
    pub sampled_unix_ms: u128,
    pub protocol: Protocol,
    pub address: Option<std::net::SocketAddr>,
    pub activity: ServerActivity,
}

impl ServerSnapshot {
    pub fn since(&self, previous: &Self) -> Result<ServerActivity, String> {
        if self.instance_id != previous.instance_id
            || self.address != previous.address
            || self.protocol != previous.protocol
        {
            return Err("benchmark server restarted during the run".into());
        }
        let delta = |new: u64, old: u64| {
            new.checked_sub(old)
                .ok_or_else(|| "server counters moved backwards".to_string())
        };
        Ok(ServerActivity {
            tcp_accepts: delta(self.activity.tcp_accepts, previous.activity.tcp_accepts)?,
            tls_completed: delta(self.activity.tls_completed, previous.activity.tls_completed)?,
            quic_incoming: delta(self.activity.quic_incoming, previous.activity.quic_incoming)?,
            quic_established: delta(
                self.activity.quic_established,
                previous.activity.quic_established,
            )?,
            h1_requests: delta(self.activity.h1_requests, previous.activity.h1_requests)?,
            h2_requests: delta(self.activity.h2_requests, previous.activity.h2_requests)?,
            h3_requests: delta(self.activity.h3_requests, previous.activity.h3_requests)?,
            connection_failures: delta(
                self.activity.connection_failures,
                previous.activity.connection_failures,
            )?,
        })
    }
}

#[derive(Default)]
pub(crate) struct ServerCounters {
    next_connection: AtomicU64,
    address: OnceLock<std::net::SocketAddr>,
    pub tcp_accepts: AtomicU64,
    pub tls_completed: AtomicU64,
    pub quic_incoming: AtomicU64,
    pub quic_established: AtomicU64,
    pub h1_requests: AtomicU64,
    pub h2_requests: AtomicU64,
    pub h3_requests: AtomicU64,
    pub connection_failures: AtomicU64,
}

impl ServerCounters {
    pub fn connection_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn snapshot(&self, instance_id: &str, protocol: Protocol) -> ServerSnapshot {
        ServerSnapshot {
            instance_id: instance_id.to_string(),
            sampled_unix_ms: crate::metrics::unix_time_ms(),
            protocol,
            address: self.address.get().copied(),
            activity: ServerActivity {
                tcp_accepts: self.tcp_accepts.load(Ordering::Relaxed),
                tls_completed: self.tls_completed.load(Ordering::Relaxed),
                quic_incoming: self.quic_incoming.load(Ordering::Relaxed),
                quic_established: self.quic_established.load(Ordering::Relaxed),
                h1_requests: self.h1_requests.load(Ordering::Relaxed),
                h2_requests: self.h2_requests.load(Ordering::Relaxed),
                h3_requests: self.h3_requests.load(Ordering::Relaxed),
                connection_failures: self.connection_failures.load(Ordering::Relaxed),
            },
        }
    }
}

pub async fn serve(config: ServeConfig) -> Result<(), Box<dyn Error>> {
    let counters = Arc::new(ServerCounters::default());
    let instance_id = format!("{}-{}", std::process::id(), crate::metrics::unix_time_ms());
    let body = Bytes::from(vec![b'x'; config.body_size]);
    let stats_task = config.stats_output.as_ref().map(|path| {
        let path = path.clone();
        let counters = counters.clone();
        let instance_id = instance_id.clone();
        let protocol = config.protocol;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
            loop {
                tick.tick().await;
                if let Err(error) = write_stats(&path, &counters.snapshot(&instance_id, protocol)) {
                    eprintln!("server statistics write failed: {error}");
                }
            }
        })
    });
    let serving = async {
        match config.protocol {
            Protocol::H1 | Protocol::H2c => serve_plain(&config, body, counters.clone()).await,
            #[cfg(feature = "quic-h3")]
            Protocol::H3 | Protocol::Race => {
                crate::tls_server::serve(&config, body, counters.clone()).await
            }
            #[cfg(not(feature = "quic-h3"))]
            _ => Err("h3/race requires the quic-h3 feature".into()),
        }
    };
    let result = tokio::select! {
        result = serving => result,
        result = tokio::signal::ctrl_c() => result.map_err(Into::into),
    };
    if let Some(task) = stats_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(path) = &config.stats_output {
        write_stats(path, &counters.snapshot(&instance_id, config.protocol))?;
    }
    result
}

async fn serve_plain(
    config: &ServeConfig,
    body: Bytes,
    counters: Arc<ServerCounters>,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(config.listen).await?;
    ready(config, listener.local_addr()?, &counters)?;
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        counters.tcp_accepts.fetch_add(1, Ordering::Relaxed);
        let connection_id = counters.connection_id();
        let body = body.clone();
        let counters = counters.clone();
        let protocol = config.protocol;
        tokio::spawn(async move {
            if let Err(error) =
                serve_tcp_connection(stream, body, connection_id, protocol, &counters).await
            {
                counters.connection_failures.fetch_add(1, Ordering::Relaxed);
                eprintln!("connection {connection_id} failed: {error}");
            }
        });
    }
}

pub(crate) async fn serve_tcp_connection<T>(
    stream: T,
    body: Bytes,
    connection_id: u64,
    protocol: Protocol,
    counters: &Arc<ServerCounters>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let counters = counters.clone();
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let body = body.clone();
        let version = request.version();
        if protocol == Protocol::H1 {
            counters.h1_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.h2_requests.fetch_add(1, Ordering::Relaxed);
        }
        async move { Ok::<_, Infallible>(response(body, connection_id, version)) }
    });
    if protocol == Protocol::H1 {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await?;
    } else {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await?;
    }
    Ok(())
}

pub(crate) fn ready(
    config: &ServeConfig,
    address: std::net::SocketAddr,
    counters: &ServerCounters,
) -> io::Result<()> {
    let _ = counters.address.set(address);
    println!(
        "{} benchmark server listening on {address}, body={} bytes",
        config.protocol.report_name(),
        config.body_size
    );
    io::stdout().flush()
}

pub(crate) fn response(
    body: Bytes,
    connection_id: u64,
    version: http::Version,
) -> Response<Full<Bytes>> {
    let body_len = body.len();
    let mut response = Response::new(Full::new(body));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body_len.to_string()).unwrap(),
    );
    response.headers_mut().insert(
        "x-bench-connection-id",
        HeaderValue::from_str(&connection_id.to_string()).unwrap(),
    );
    response
        .headers_mut()
        .insert("x-bench-protocol", crate::server::protocol_header(version));
    response
}

fn write_stats(path: &Path, snapshot: &ServerSnapshot) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("stats-tmp");
    std::fs::write(&temporary, serde_json::to_vec(snapshot)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_delta_rejects_restart_and_counter_regression() {
        let counters = ServerCounters::default();
        let _ = counters.address.set("127.0.0.1:18481".parse().unwrap());
        counters.tcp_accepts.store(4, Ordering::Relaxed);
        let first = counters.snapshot("instance-1", Protocol::Race);
        counters.tcp_accepts.store(7, Ordering::Relaxed);
        counters.quic_incoming.store(2, Ordering::Relaxed);
        let last = counters.snapshot("instance-1", Protocol::Race);
        let delta = last.since(&first).unwrap();
        assert_eq!(delta.tcp_accepts, 3);
        assert_eq!(delta.quic_incoming, 2);
        assert!(first.since(&last).is_err());
        assert!(counters
            .snapshot("instance-2", Protocol::Race)
            .since(&first)
            .is_err());
    }

    #[test]
    fn missing_server_counters_cannot_qualify_as_zero_activity() {
        let counters = ServerCounters::default();
        let snapshot = counters.snapshot("instance", Protocol::Race);
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["activity"]
            .as_object_mut()
            .unwrap()
            .remove("quic_incoming");
        assert!(serde_json::from_value::<ServerSnapshot>(value).is_err());
    }
}
