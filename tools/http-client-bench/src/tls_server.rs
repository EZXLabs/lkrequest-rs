use std::error::Error;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;

use crate::config::{Protocol, ServeConfig};
use crate::fixture_server::{self as server, ServerCounters};

pub async fn serve(
    config: &ServeConfig,
    body: Bytes,
    counters: Arc<ServerCounters>,
) -> Result<(), Box<dyn Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certificate.signing_key.serialize_der(),
            )),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls.clone())?;
    let quic_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let tcp = if config.protocol == Protocol::Race {
        Some(TcpListener::bind(config.listen).await?)
    } else {
        None
    };
    let address = match &tcp {
        Some(tcp) => tcp.local_addr()?,
        None => config.listen,
    };
    let endpoint = quinn::Endpoint::server(quic_config, address)?;
    server::ready(config, endpoint.local_addr()?, &counters)?;
    let quic = serve_quic(endpoint, body.clone(), counters.clone());
    if let Some(tcp) = tcp {
        tokio::select! {
            result = quic => result,
            result = serve_tls(tcp, acceptor, body, counters) => result,
        }
    } else {
        quic.await
    }
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    body: Bytes,
    counters: Arc<ServerCounters>,
) -> Result<(), Box<dyn Error>> {
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        counters.tcp_accepts.fetch_add(1, Ordering::Relaxed);
        let connection_id = counters.connection_id();
        let acceptor = acceptor.clone();
        let body = body.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            let result = async {
                let tls = acceptor.accept(stream).await?;
                counters.tls_completed.fetch_add(1, Ordering::Relaxed);
                server::serve_tcp_connection(tls, body, connection_id, Protocol::Race, &counters)
                    .await
            }
            .await;
            if result.is_err() {
                counters.connection_failures.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

async fn serve_quic(
    endpoint: quinn::Endpoint,
    body: Bytes,
    counters: Arc<ServerCounters>,
) -> Result<(), Box<dyn Error>> {
    while let Some(incoming) = endpoint.accept().await {
        counters.quic_incoming.fetch_add(1, Ordering::Relaxed);
        let connection_id = counters.connection_id();
        let body = body.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            let result = async {
                let connection = incoming.await?;
                counters.quic_established.fetch_add(1, Ordering::Relaxed);
                let mut h3 =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await?;
                while let Some(resolver) = h3.accept().await? {
                    let body = body.clone();
                    let counters = counters.clone();
                    tokio::spawn(async move {
                        let result = async {
                            let (_, mut stream) = resolver.resolve_request().await?;
                            while stream.recv_data().await?.is_some() {}
                            counters.h3_requests.fetch_add(1, Ordering::Relaxed);
                            let (parts, _) = server::response(
                                body.clone(),
                                connection_id,
                                http::Version::HTTP_3,
                            )
                            .into_parts();
                            stream
                                .send_response(http::Response::from_parts(parts, ()))
                                .await?;
                            stream.send_data(body).await?;
                            stream.finish().await?;
                            Ok::<_, Box<dyn Error + Send + Sync>>(())
                        }
                        .await;
                        if result.is_err() {
                            counters.connection_failures.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            }
            .await;
            if result.is_err() {
                counters.connection_failures.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    Ok(())
}
