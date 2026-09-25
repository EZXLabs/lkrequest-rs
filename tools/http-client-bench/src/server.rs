use std::convert::Infallible;
use std::error::Error;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use crate::config::ServeConfig;

pub async fn serve(config: ServeConfig) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(config.listen).await?;
    let body = Bytes::from(vec![b'x'; config.body_size]);
    let next_connection_id = Arc::new(AtomicU64::new(1));
    println!(
        "HTTP/2 prior-knowledge benchmark server listening on {}, body={} bytes",
        listener.local_addr()?,
        config.body_size
    );
    io::stdout().flush()?;

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
        let body = body.clone();
        tokio::spawn(async move {
            let service = service_fn(move |_request: hyper::Request<Incoming>| {
                let body = body.clone();
                async move { Ok::<_, Infallible>(response(body, connection_id)) }
            });
            let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(error) = result {
                eprintln!("connection {connection_id} failed: {error}");
            }
        });
    }
}

fn response(body: Bytes, connection_id: u64) -> Response<Full<Bytes>> {
    let body_len = body.len();
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = StatusCode::OK;
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
}
