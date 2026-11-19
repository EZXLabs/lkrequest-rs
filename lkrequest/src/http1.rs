use std::error::Error;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http_body::Body;
use hyper::client::conn::http1::{Connection, SendRequest};
use hyper::rt::{Read, ReadBufCursor, Write};
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::Client;

#[derive(Clone, Copy)]
enum HostRewrite {
    Idle,
    RequestHead,
    Offset(usize),
}

type HostRewriteState = Option<Arc<Mutex<HostRewrite>>>;

pub(crate) struct Http1Sender<B> {
    inner: SendRequest<B>,
    host_rewrite: HostRewriteState,
    failure: watch::Receiver<Option<Arc<io::Error>>>,
}

#[cfg(test)]
impl<B> From<SendRequest<B>> for Http1Sender<B> {
    fn from(inner: SendRequest<B>) -> Self {
        Self {
            inner,
            host_rewrite: None,
            failure: watch::channel(None).1,
        }
    }
}

impl<B> Http1Sender<B> {
    pub(crate) async fn ready(&mut self) -> crate::error::Result<()> {
        observe_request(self.inner.ready(), &mut self.failure).await
    }
}

impl<B: Body + 'static> Http1Sender<B> {
    pub(crate) async fn send_request(
        &mut self,
        request: http::Request<B>,
    ) -> crate::error::Result<http::Response<hyper::body::Incoming>> {
        self.ready().await?;
        if let Some(state) = &self.host_rewrite {
            *state.lock() = HostRewrite::RequestHead;
        }
        observe_request(self.inner.send_request(request), &mut self.failure).await
    }
}

async fn observe_request<T>(
    future: impl std::future::Future<Output = Result<T, hyper::Error>>,
    failure: &mut watch::Receiver<Option<Arc<io::Error>>>,
) -> crate::error::Result<T> {
    tokio::select! {
        biased;
        result = future => result.map_err(|error| {
            match failure.borrow().as_ref() {
                Some(cause) => crate::error::Error::from_h1_io(cause.clone()),
                None => crate::error::Error::from_h1_error(error, "HTTP/1.1 request failed"),
            }
        }),
        error = async {
            loop {
                let error = failure.borrow().clone();
                if let Some(error) = error { return error; }
                if failure.changed().await.is_err() {
                    return std::future::pending().await;
                }
            }
        } => Err(crate::error::Error::from_h1_io(error)),
    }
}

pub(crate) async fn handshake<T, B>(
    client: &Client,
    io: T,
) -> Result<(Http1Sender<B>, Connection<HostCaseIo<ObservedIo<T>>, B>), hyper::Error>
where
    T: Read + Write + Unpin,
    B: Body + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let host_rewrite =
        (!client.http1_title_case_headers()).then(|| Arc::new(Mutex::new(HostRewrite::Idle)));
    let (failure_tx, failure) = watch::channel(None);
    let io = HostCaseIo {
        inner: ObservedIo {
            inner: io,
            failure: failure_tx,
        },
        host_rewrite: host_rewrite.clone(),
    };
    let (inner, connection) = client.http1_builder().handshake(io).await?;
    Ok((
        Http1Sender {
            inner,
            host_rewrite,
            failure,
        },
        connection,
    ))
}

// Capture the original transport error before Hyper drops it while closing
// its dispatch channel. Wake the request even if driver teardown is pending.
pub(crate) struct ObservedIo<T> {
    inner: T,
    failure: watch::Sender<Option<Arc<io::Error>>>,
}

impl<T> ObservedIo<T> {
    fn observe<V>(&self, result: Poll<io::Result<V>>) -> Poll<io::Result<V>> {
        match result {
            Poll::Ready(Err(error)) => {
                let error = Arc::new(error);
                self.failure.send_if_modified(|failure| {
                    if failure.is_some() {
                        return false;
                    }
                    *failure = Some(error.clone());
                    true
                });
                Poll::Ready(Err(io::Error::new(
                    error.kind(),
                    crate::error::SharedIoError(error),
                )))
            }
            other => other,
        }
    }
}

impl<T: Read + Unpin> Read for ObservedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.observe(result)
    }
}

impl<T: Write + Unpin> Write for ObservedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.observe(result)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.observe(result)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.observe(result)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.observe(result)
    }
}

pub(crate) struct HostCaseIo<T> {
    inner: T,
    host_rewrite: HostRewriteState,
}

impl<T: Read + Unpin> Read for HostCaseIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: Write + Unpin> Write for HostCaseIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(state) = &this.host_rewrite else {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };
        if buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let mut state = state.lock();
        let offset = match *state {
            HostRewrite::Idle => return Pin::new(&mut this.inner).poll_write(cx, buf),
            HostRewrite::Offset(offset) => offset,
            HostRewrite::RequestHead => match host_offset(buf)? {
                Some(offset) => offset,
                None => {
                    *state = HostRewrite::Idle;
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                }
            },
        };

        // Rewrite one byte only. Preserve write boundaries and advance the
        // offset only after the transport accepts bytes, including on reuse.
        let rewritten;
        let outgoing = if offset < buf.len() {
            rewritten = {
                let mut bytes = buf.to_vec();
                bytes[offset] = b'H';
                bytes
            };
            rewritten.as_slice()
        } else {
            buf
        };
        let result = Pin::new(&mut this.inner).poll_write(cx, outgoing);
        if let Poll::Ready(Ok(written)) = result {
            *state = if written > offset {
                HostRewrite::Idle
            } else {
                HostRewrite::Offset(offset - written)
            };
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.host_rewrite.is_none() && self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.host_rewrite.is_none() {
            Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
        } else {
            self.poll_write(
                cx,
                bufs.iter()
                    .find(|buf| !buf.is_empty())
                    .map_or(&[], |buf| buf),
            )
        }
    }
}

fn host_offset(buf: &[u8]) -> io::Result<Option<usize>> {
    // Hyper serializes the complete request head into its first write buffer.
    // Never search the body, WebSocket frames, or the upgraded H2 connection.
    let end = buf
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "incomplete HTTP/1 request head")
        })?;
    let mut offset = 0;
    for line in buf[..end].split_inclusive(|byte| *byte == b'\n') {
        if offset != 0
            && line
                .get(..5)
                .is_some_and(|name| name.eq_ignore_ascii_case(b"host:"))
        {
            return Ok(Some(offset));
        }
        offset += line.len();
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transport_failure_wakes_pending_request_but_preserves_ready_response() {
        let error = lktls::error::TlsError::Alert(lktls::error::TlsAlert {
            level: lktls::error::AlertLevel::Fatal,
            description: lktls::error::AlertDescription::CertificateRequired,
        });
        let (_tx, mut failure) = watch::channel(Some(Arc::new(io::Error::other(error))));
        assert_eq!(
            observe_request(std::future::ready(Ok(200)), &mut failure)
                .await
                .unwrap(),
            200
        );
        let error = observe_request(
            std::future::pending::<Result<(), hyper::Error>>(),
            &mut failure,
        )
        .await
        .unwrap_err();
        assert_eq!(error.as_tls_alert().unwrap().description.as_byte(), 116);
        assert!(!error.is_safe_to_replay());
    }

    struct PartialWriter {
        bytes: Vec<u8>,
        limit: usize,
        pending: bool,
    }

    impl Write for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending = true;
            let written = buf.len().min(self.limit);
            self.bytes.extend_from_slice(&buf[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn write_all(io: &mut HostCaseIo<PartialWriter>, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let written = std::future::poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, bytes))
                .await
                .unwrap();
            assert_ne!(written, 0);
            bytes = &bytes[written..];
        }
    }

    #[tokio::test]
    async fn host_rewrite_survives_pending_partial_writes_and_reuse() {
        let raw = b"POST /host: HTTP/1.1\r\nx-hostile: host: value\r\nhost: MiXeD.test\r\ncontent-length: 30\r\n\r\nGET / HTTP/1.1\r\nhost: body\r\n\r\n";
        let expected = b"POST /host: HTTP/1.1\r\nx-hostile: host: value\r\nHost: MiXeD.test\r\ncontent-length: 30\r\n\r\nGET / HTTP/1.1\r\nhost: body\r\n\r\n";
        for limit in [1, 2, 3, 7, usize::MAX] {
            let state = Arc::new(Mutex::new(HostRewrite::Idle));
            let mut io = HostCaseIo {
                inner: PartialWriter {
                    bytes: Vec::new(),
                    limit,
                    pending: true,
                },
                host_rewrite: Some(state.clone()),
            };
            for _ in 0..2 {
                *state.lock() = HostRewrite::RequestHead;
                write_all(&mut io, raw).await;
            }
            assert_eq!(io.inner.bytes, expected.repeat(2), "write limit {limit}");
        }
    }

    #[tokio::test]
    async fn host_rewrite_does_not_search_a_body_without_host_header() {
        let raw = b"POST / HTTP/1.1\r\nx-hostile: keep\r\n\r\nhost: body\r\n";
        let mut io = HostCaseIo {
            inner: PartialWriter {
                bytes: Vec::new(),
                limit: 1,
                pending: true,
            },
            host_rewrite: Some(Arc::new(Mutex::new(HostRewrite::RequestHead))),
        };
        write_all(&mut io, raw).await;
        assert_eq!(io.inner.bytes, raw);
    }

    #[tokio::test]
    async fn default_casing_passes_writes_through() {
        let raw = b"POST / HTTP/1.1\r\nhost: unchanged\r\n\r\nhost: body";
        let mut io = HostCaseIo {
            inner: PartialWriter {
                bytes: Vec::new(),
                limit: 2,
                pending: true,
            },
            host_rewrite: None,
        };
        write_all(&mut io, raw).await;
        assert_eq!(io.inner.bytes, raw);
    }
}
