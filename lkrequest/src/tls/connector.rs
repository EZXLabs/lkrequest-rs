//! TLS connector — wraps a TCP stream with the lktls TLS engine.
//!
//! This module provides [`TlsConnector`] that:
//! 1. Takes a [`TlsProfile`] and a TCP stream
//! 2. Performs the TLS handshake (TLS 1.3 or 1.2, driven by the profile)
//! 3. Returns a [`TlsStream`] that implements `AsyncRead` + `AsyncWrite`
//!
//! The heavy protocol logic lives in [`lktls::handshake::driver::HandshakeDriver`].
//! This module is a thin async I/O adapter.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::Instrument;

use hyper::rt::{Read as HyperRead, Write as HyperWrite};

use lktls::config::{
    ClientConfigTemplate, ClientHelloOverrides, CompileOptions, CompiledClientConfig,
    ConnectionInputs, Transport,
};
use lktls::connection::{ClientConnection, HandshakeProgress, ReadProgress};
use lktls::error::{Result, TlsError};
use lktls::profile::types::TlsProfile;
use lktls::session_store::SessionStore;
use lktls::verify::policy::VerificationPolicy;
use lktls::{ClientHelloCallback, KeyLogCallback};

/// Trait alias for stream types accepted by [`TlsConnector::connect`].
pub trait TlsTransport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsTransport for T {}

/// Create a [`KeyLogCallback`] that appends lines to the given file path.
pub fn keylog_to_file(path: impl Into<std::path::PathBuf>) -> io::Result<KeyLogCallback> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::Mutex;

    let path = path.into();
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let file = Arc::new(Mutex::new(file));

    Ok(Arc::new(move |line: &str| {
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "{line}");
        }
    }))
}

// ---------------------------------------------------------------------------
// TlsConnector
// ---------------------------------------------------------------------------

/// Connector that establishes TLS connections with a specific fingerprint.
///
/// Shares compiled static configuration across connections and provides the
/// async I/O adapter. Each handshake owns its connection inputs and secrets.
pub struct TlsConnector {
    template: ClientConfigTemplate,
    config: ConnectionInputs,
    require_close_notify: bool,
}

impl From<TlsProfile> for TlsConnector {
    fn from(profile: TlsProfile) -> Self {
        Self::new(profile)
    }
}

impl TlsConnector {
    pub fn new(profile: TlsProfile) -> Self {
        Self::from_template(ClientConfigTemplate::new(
            profile,
            Transport::Tcp,
            CompileOptions::compatibility(),
        ))
    }

    pub fn from_compiled(config: Arc<CompiledClientConfig>) -> Result<Self> {
        if config.transport() != Transport::Tcp {
            return Err(TlsError::InvalidProfile(
                "TCP connector requires a TCP configuration".into(),
            ));
        }
        Ok(Self::from_template(ClientConfigTemplate::from_compiled(
            config,
        )))
    }

    pub(crate) fn from_template(template: ClientConfigTemplate) -> Self {
        Self {
            template,
            config: ConnectionInputs::default(),
            require_close_notify: false,
        }
    }

    pub fn profile(&self) -> &TlsProfile {
        self.template.profile()
    }

    /// Apply generated values per connection without changing the shared profile.
    /// Raw extension conflicts are rejected before selecting a session.
    pub fn client_hello_overrides(mut self, overrides: ClientHelloOverrides) -> Self {
        self.config.hello_overrides = overrides;
        self
    }

    pub(crate) fn require_alpn(mut self, protocols: Option<Vec<String>>) -> Self {
        self.config.required_alpn = protocols;
        self
    }

    pub fn trust_anchor_observer(
        mut self,
        observer: lktls::trust_anchor::TrustAnchorObserver,
    ) -> Self {
        self.config.trust_anchor_observer = Some(observer);
        self
    }

    pub fn full_handshake(mut self) -> Self {
        self.config.session_store = None;
        self
    }

    pub(crate) fn recovery_with_trust_anchor_ids(
        &self,
        ids: Vec<lktls::trust_anchor::TrustAnchorId>,
        observer: lktls::trust_anchor::TrustAnchorObserver,
    ) -> Result<Self> {
        let (template, overrides) = self
            .template
            .trust_anchor_recovery(ids, &self.config.hello_overrides)?;
        let mut config = self.config.clone();
        config.session_store = None;
        config.trust_anchor_observer = Some(observer);
        config.hello_overrides = overrides;
        Ok(Self {
            template,
            config,
            require_close_notify: self.require_close_notify,
        })
    }

    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        self.template = self.template.verification_policy(policy);
        self
    }

    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        if skip {
            self.template = self
                .template
                .verification_policy(VerificationPolicy::Insecure);
        }
        self
    }

    pub fn alps_payload(mut self, payload: Vec<u8>) -> Self {
        self.config.alps_payload = Some(payload);
        self
    }

    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.config.session_store = Some(store);
        self
    }

    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.config.ech_config_list = Some(config_list);
        self
    }

    pub fn ech_config_list(&self) -> Option<&[u8]> {
        self.config.ech_config_list.as_deref()
    }

    pub fn custom_ca_anchors(
        mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) -> Self {
        self.template = self.template.custom_ca_anchors(Some(anchors));
        self
    }

    /// Treat a socket EOF that arrives without a `close_notify` alert as an
    /// error (`io::ErrorKind::UnexpectedEof`) instead of a clean end of stream.
    ///
    /// **Default: off**, which is the behaviour every released version has had.
    /// RFC 8446 §6.1 requires `close_notify`, but a large number of production
    /// servers simply drop the TCP connection, and browsers accept that — so
    /// enforcing it by default would fail requests that Chrome completes.
    ///
    /// Turning it on matters for exactly one case: a response body delimited by
    /// connection close (RFC 9112 §6.3 — neither `Content-Length` nor
    /// `Transfer-Encoding: chunked`). There a network attacker can truncate the
    /// body and the caller cannot tell, because the truncated stream ends the
    /// same way a complete one does. Bodies with a length or chunked framing are
    /// already protected: a short read is reported as an incomplete message
    /// regardless of this setting.
    pub fn require_close_notify(mut self, require: bool) -> Self {
        self.require_close_notify = require;
        self
    }

    /// Whether a socket EOF without `close_notify` will be reported as an error.
    pub fn requires_close_notify(&self) -> bool {
        self.require_close_notify
    }

    pub fn keylog(mut self, callback: KeyLogCallback) -> Self {
        self.config.keylog_callback = Some(callback);
        self
    }

    /// Observes the raw ClientHello bytes about to be sent on the wire (the exact
    /// outbound fingerprint), without affecting the handshake.
    pub fn on_client_hello(mut self, callback: ClientHelloCallback) -> Self {
        self.config.client_hello_callback = Some(callback);
        self
    }

    pub async fn connect_tcp(
        &self,
        hostname: &str,
        port: u16,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>> {
        self.connect(hostname, port, stream).await
    }

    pub async fn connect<S: TlsTransport + 'static>(
        &self,
        hostname: &str,
        port: u16,
        stream: S,
    ) -> Result<TlsStream<S>> {
        let span = tracing::debug_span!("tls.handshake", sni = %hostname);
        let observer = self
            .config
            .trust_anchor_observer
            .clone()
            .unwrap_or_default();
        let result = self
            .connect_inner(hostname, port, stream, observer.clone())
            .instrument(span)
            .await;
        if let Err(error) = &result {
            observer.record_error(error);
        }
        let info = observer.snapshot();
        crate::diagnostics::record_trust_anchor(info.clone());
        result.map_err(|source| {
            if info.available_ids.is_empty() || info.ech_rejected {
                source
            } else {
                TlsError::TrustAnchorFailure {
                    source: Box::new(source),
                    info: Box::new(info),
                }
            }
        })
    }

    /// Perform the TLS handshake using the Sans-I/O [`HandshakeDriver`].
    fn connect_inner<'a, S: TlsTransport + 'static>(
        &'a self,
        hostname: &'a str,
        port: u16,
        mut stream: S,
        observer: lktls::trust_anchor::TrustAnchorObserver,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<TlsStream<S>>> + Send + 'a>> {
        Box::pin(async move {
            let mut config = self.config.clone();
            config.hostname = hostname.to_string();
            config.port = port;
            config.trust_anchor_observer = Some(observer);

            let mut connection = ClientConnection::from_compiled(self.template.compile()?, config)?;
            loop {
                let progress = match connection.progress_handshake() {
                    Ok(progress) => progress,
                    Err(error) => {
                        if !connection.output().is_empty() {
                            if let Err(write_error) = stream.write_all(connection.output()).await {
                                tracing::debug!(error = %write_error, "tls.local_alert_send_failed");
                            } else {
                                let _ = stream.flush().await;
                                let _ = stream.shutdown().await;
                            }
                        }
                        return Err(error);
                    }
                };
                match progress {
                    HandshakeProgress::NeedOutput => {
                        if connection.output().is_empty() {
                            continue;
                        }
                        let written = stream
                            .write(connection.output())
                            .await
                            .map_err(TlsError::Io)?;
                        if written == 0 {
                            return Err(TlsError::Io(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "TLS transport accepted no handshake bytes",
                            )));
                        }
                        connection.consume_output(written);
                    }
                    HandshakeProgress::NeedInput => {
                        let mut bytes = [0; 16384];
                        let capacity = bytes.len().min(connection.input_capacity());
                        if capacity == 0 {
                            return Err(TlsError::HandshakeFailure(
                                "TLS input budget exhausted without progress".into(),
                            ));
                        }
                        let count = stream
                            .read(&mut bytes[..capacity])
                            .await
                            .map_err(TlsError::Io)?;
                        if count == 0 {
                            return Err(TlsError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed during TLS handshake",
                            )));
                        }
                        if connection.feed_bounded(&bytes[..count]) != count {
                            return Err(TlsError::HandshakeFailure(
                                "TLS connection rejected handshake input".into(),
                            ));
                        }
                    }
                    HandshakeProgress::Complete => {
                        return Ok(TlsStream {
                            inner: stream,
                            connection,
                            read_failure: None,
                            require_close_notify: self.require_close_notify,
                        });
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// TlsStream
// ---------------------------------------------------------------------------

struct ReadFailure {
    error: Arc<io::Error>,
    flushed: bool,
    shutdown: bool,
    terminal_io: bool,
}

#[cfg(test)]
thread_local! {
    static PLAINTEXT_TO_CALLER_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub struct TlsStream<S: TlsTransport = TcpStream> {
    inner: S,
    connection: ClientConnection,
    read_failure: Option<ReadFailure>,
    require_close_notify: bool,
}

impl<S: TlsTransport> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("closed", &self.connection.is_closed())
            .finish()
    }
}

impl<S: TlsTransport> TlsStream<S> {
    pub fn inner_stream(&self) -> &S {
        &self.inner
    }
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.connection.negotiated_alpn()
    }
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.connection.negotiated_cipher_suite()
    }
    pub fn negotiated_version(&self) -> Option<u16> {
        self.connection.negotiated_version()
    }
    pub fn received_close_notify(&self) -> bool {
        self.connection.received_close_notify()
    }
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.connection.peer_certificates()
    }

    fn eof_outcome(&self) -> io::Result<()> {
        if self.require_close_notify && !self.received_close_notify() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS connection closed without close_notify (RFC 8446 section 6.1)",
            ));
        }
        Ok(())
    }

    pub(crate) fn poll_browser_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_failure.is_some() {
            return self.poll_read_failure(cx);
        }
        let this = &mut *self;
        if let Err(error) = flush_connection(&mut this.inner, &mut this.connection, true, cx) {
            this.fail_io(error);
            return this.poll_read_failure(cx);
        }
        if !this.connection.idle_output().is_empty() {
            return Poll::Pending;
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => {
                this.fail_io(error);
                this.poll_read_failure(cx)
            }
            result => result,
        }
    }

    pub(crate) fn poll_browser_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_failure.is_some() {
            return AsyncWrite::poll_shutdown(self, cx);
        }
        self.connection.start_browser_close();
        std::task::ready!(AsyncWrite::poll_flush(self.as_mut(), cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_key_update_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = match flush_connection(&mut self.inner, &mut self.connection, false, cx) {
            Err(error) => Err(error),
            Ok(()) if !self.connection.output().is_empty() => return Poll::Pending,
            Ok(()) => match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            },
        };
        self.connection.acknowledge_flush();
        if let Err(error) = result {
            self.connection.discard_output();
            self.fail_read(error);
            self.read_failure.as_mut().unwrap().flushed = true;
            return self.poll_read_failure(cx);
        }
        Poll::Ready(Ok(()))
    }

    fn fail_read(&mut self, error: io::Error) {
        let peer_fatal = error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<TlsError>())
            .is_some_and(|cause| matches!(cause, TlsError::Alert(alert) if alert.is_fatal()));
        self.connection.fail();
        if peer_fatal {
            self.connection.discard_output();
        }
        self.read_failure.get_or_insert_with(|| ReadFailure {
            error: Arc::new(error),
            flushed: peer_fatal,
            shutdown: false,
            terminal_io: peer_fatal,
        });
    }

    fn fail_io(&mut self, error: io::Error) {
        self.connection.discard_output();
        self.fail_read(error);
        // A failed transport cannot carry pending records or another TLS alert.
        self.read_failure.as_mut().unwrap().flushed = true;
        self.read_failure.as_mut().unwrap().terminal_io = true;
    }

    fn poll_read_failure(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.read_failure.as_ref().unwrap().flushed {
            while !self.connection.output().is_empty() {
                let this = &mut *self;
                match Pin::new(&mut this.inner).poll_write(cx, this.connection.output()) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
                        this.connection.discard_output();
                        this.read_failure.as_mut().unwrap().flushed = true;
                        break;
                    }
                    Poll::Ready(Ok(n)) => this.connection.consume_output(n),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if !self.read_failure.as_ref().unwrap().flushed {
                if Pin::new(&mut self.inner).poll_flush(cx).is_pending() {
                    return Poll::Pending;
                }
                self.read_failure.as_mut().unwrap().flushed = true;
            }
        }
        if !self.read_failure.as_ref().unwrap().shutdown {
            if Pin::new(&mut self.inner).poll_shutdown(cx).is_pending()
                && !self.read_failure.as_ref().unwrap().terminal_io
            {
                return Poll::Pending;
            }
            self.read_failure.as_mut().unwrap().shutdown = true;
        }
        let failure = self.read_failure.as_ref().unwrap();
        Poll::Ready(Err(io::Error::new(
            failure.error.kind(),
            crate::error::SharedIoError(failure.error.clone()),
        )))
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut bytes = [0u8; 16384];
        let capacity = self.connection.input_capacity().min(bytes.len());
        if capacity == 0 {
            return Poll::Ready(Err(io::Error::other(
                "TLS input budget exhausted without progress",
            )));
        }
        let mut read_buf = ReadBuf::new(&mut bytes[..capacity]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                let accepted = self.connection.feed_bounded(&bytes[..n]);
                if accepted != n {
                    return Poll::Ready(Err(io::Error::other(
                        "TLS connection rejected transport input",
                    )));
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn connection_io_error(error: TlsError) -> io::Error {
    let kind = match &error {
        TlsError::Alert(_) => io::ErrorKind::ConnectionReset,
        TlsError::LocalAlert { alert, .. }
            if alert.description == lktls::error::AlertDescription::NoRenegotiation =>
        {
            io::ErrorKind::ConnectionAborted
        }
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

impl<S: TlsTransport> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_failure.is_some() {
                return self.poll_read_failure(cx);
            }
            match self.connection.process_read() {
                Ok(ReadProgress::Plaintext) => {
                    let count = self.connection.plaintext().len().min(buf.remaining());
                    buf.put_slice(&self.connection.plaintext()[..count]);
                    #[cfg(test)]
                    PLAINTEXT_TO_CALLER_BYTES.with(|bytes| bytes.set(bytes.get() + count));
                    self.connection.consume_plaintext(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(ReadProgress::PeerClosed) => return Poll::Ready(Ok(())),
                Ok(ReadProgress::Flush) => {
                    std::task::ready!(self.poll_key_update_flush(cx))?;
                }
                Ok(ReadProgress::NeedInput) => match self.poll_read_inner(cx) {
                    Poll::Ready(Ok(0)) => match self.eof_outcome() {
                        Ok(()) => return Poll::Ready(Ok(())),
                        Err(error) => self.fail_io(error),
                    },
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Err(error)) => self.fail_io(error),
                    Poll::Pending => return Poll::Pending,
                },
                Ok(ReadProgress::Yield) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => self.fail_read(connection_io_error(error)),
            }
        }
    }
}

impl<S: TlsTransport> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.connection.take_write_error() {
            self.fail_io(connection_io_error(error));
        }
        if self
            .read_failure
            .as_ref()
            .is_some_and(|failure| failure.terminal_io)
        {
            return self.poll_read_failure(cx).map(|result| result.map(|()| 0));
        }
        if self.connection.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let count = match self.connection.write_application(buf) {
                Ok(count) => count,
                Err(error) => {
                    self.fail_io(connection_io_error(error));
                    return self.poll_read_failure(cx).map(|result| result.map(|()| 0));
                }
            };
            let before = self.connection.output().len();
            let this = &mut *self;
            let failure = this
                .connection
                .take_write_error()
                .map(connection_io_error)
                .or_else(|| {
                    flush_connection(&mut this.inner, &mut this.connection, false, cx).err()
                });
            if let Some(error) = failure {
                self.connection.discard_output();
                self.fail_io(error);
                if count != 0 {
                    return Poll::Ready(Ok(count));
                }
                return self.poll_read_failure(cx).map(|result| result.map(|()| 0));
            }
            if count != 0 {
                return Poll::Ready(Ok(count));
            }
            if self.connection.output().len() == before {
                return Poll::Pending;
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.connection.take_write_error() {
            self.fail_io(connection_io_error(error));
        }
        if self.read_failure.is_some() {
            return self.poll_read_failure(cx);
        }
        let this = &mut *self;
        this.connection.flush_buffered_records();
        if let Some(error) = this
            .connection
            .take_write_error()
            .map(connection_io_error)
            .or_else(|| flush_connection(&mut this.inner, &mut this.connection, false, cx).err())
        {
            this.connection.discard_output();
            this.fail_io(error);
            return this.poll_read_failure(cx);
        }
        if !this.connection.output().is_empty() {
            return Poll::Pending;
        }
        if let Err(error) = std::task::ready!(Pin::new(&mut this.inner).poll_flush(cx)) {
            this.connection.discard_output();
            this.fail_io(error);
            return this.poll_read_failure(cx);
        }
        this.connection.acknowledge_flush();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.read_failure.is_some() {
            if self.poll_read_failure(cx).is_pending() {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(()));
        }
        self.connection.start_close();
        std::task::ready!(AsyncWrite::poll_flush(self.as_mut(), cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Hyper trait adapters
// ---------------------------------------------------------------------------

impl<S: TlsTransport> HyperRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut tokio_buf = ReadBuf::uninit(unsafe { buf.as_mut() });
        match <Self as AsyncRead>::poll_read(self, cx, &mut tokio_buf) {
            Poll::Ready(Ok(())) => {
                let n = tokio_buf.filled().len();
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: TlsTransport> HyperWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        <Self as AsyncWrite>::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWrite>::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWrite>::poll_shutdown(self, cx)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Drain committed output without re-running encoding or protocol transitions.
fn flush_connection<S: TlsTransport>(
    stream: &mut S,
    connection: &mut ClientConnection,
    idle: bool,
    cx: &mut Context<'_>,
) -> io::Result<()> {
    loop {
        let output = if idle {
            connection.idle_output()
        } else {
            connection.output()
        };
        if output.is_empty() {
            return Ok(());
        }
        match Pin::new(&mut *stream).poll_write(cx, output) {
            Poll::Ready(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS transport accepted no queued bytes",
                ))
            }
            Poll::Ready(Ok(n)) => connection.consume_output(n),
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Ok(()),
        }
    }
}

#[cfg(test)]
const MAX_POST_HANDSHAKE_MSG_LEN: usize = 64 * 1024;

#[cfg(test)]
use lktls::handshake::framing::HandshakeDeframer;

/// Drain every *complete* handshake message from `buf`, leaving any partial
/// trailer behind for the next record.
///
/// Post-handshake messages obey handshake framing (RFC 8446 §5.1): a record may
/// carry several coalesced messages, and one message may span several records.
#[cfg(test)]
fn split_post_handshake_messages(buf: &mut Vec<u8>) -> io::Result<Vec<Vec<u8>>> {
    let mut deframer = HandshakeDeframer::new(MAX_POST_HANDSHAKE_MSG_LEN);
    deframer.push(buf).map_err(io::Error::other)?;
    let mut messages = Vec::new();
    while let Some(message) = deframer.take_message().map_err(io::Error::other)? {
        buf.drain(..message.len());
        messages.push(message);
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lktls::handshake::content_type;
    use lktls::handshake::driver::PostHandshakeState;
    use lktls::profile::types::TlsClientHelloStyle;
    use lktls::record::reader::RecordReader;
    use lktls::record::writer::RecordWriter;

    #[test]
    fn generated_alpn_overrides_are_per_connection_and_keep_shared_profile() {
        let compiled = CompiledClientConfig::compile(
            lktls::profile::presets::chrome_155(),
            Transport::Tcp,
            CompileOptions::compatibility(),
        )
        .unwrap();
        let original = compiled.profile().alpn_protocols.clone();
        let connector = TlsConnector::from_compiled(compiled.clone())
            .unwrap()
            .client_hello_overrides(ClientHelloOverrides {
                alpn_protocols: Some(vec!["http/1.1".into()]),
                alps_protocols: Some(Vec::new()),
                ..Default::default()
            });
        assert_eq!(connector.profile().alpn_protocols, original);
        assert!(Arc::ptr_eq(
            &compiled,
            &connector.template.compile().unwrap()
        ));
        let mut inputs = connector.config.clone();
        inputs.hostname = "localhost".into();
        let mut driver =
            lktls::handshake::driver::HandshakeDriver::from_compiled(compiled, inputs).unwrap();
        let wire =
            lktls::handshake::client_hello_wire::ClientHelloWire::parse(&driver.start().unwrap())
                .unwrap();
        let ext = wire
            .extensions
            .iter()
            .find(|e| e.extension_type == 16)
            .unwrap();
        assert_eq!(
            &wire.handshake[ext.payload.clone()],
            &[0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );
    }

    #[test]
    fn generated_tai_recovery_reuses_compilation_and_clears_session_store() {
        use lktls::profile::types::{ExtensionSource, ExtensionSpec};
        use lktls::trust_anchor::{TrustAnchorId, TrustAnchorObserver, EXTENSION_TYPE};
        let mut profile = lktls::profile::presets::chrome_155();
        profile
            .extensions
            .retain(|e| e.extension_type != EXTENSION_TYPE);
        profile.extensions.push(ExtensionSpec {
            extension_type: EXTENSION_TYPE,
            source: ExtensionSource::TrustAnchorIds {
                ids: vec!["01".into()],
                shuffle: false,
            },
        });
        let compiled =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        let connector = TlsConnector::from_compiled(compiled.clone())
            .unwrap()
            .session_store(Arc::new(lktls::session_store::InMemorySessionStore::new()));
        let id = TrustAnchorId::new(vec![2]).unwrap();
        let observer = TrustAnchorObserver::default();
        let retry = connector
            .recovery_with_trust_anchor_ids(vec![id.clone()], observer.clone())
            .unwrap();
        assert!(Arc::ptr_eq(&compiled, &retry.template.compile().unwrap()));
        assert!(retry.config.session_store.is_none());
        let mut inputs = retry.config.clone();
        inputs.hostname = "localhost".into();
        let mut driver = lktls::handshake::driver::HandshakeDriver::from_compiled(
            retry.template.compile().unwrap(),
            inputs,
        )
        .unwrap();
        driver.start().unwrap();
        assert_eq!(observer.snapshot().requested_ids, [id]);
        assert!(connector.config.session_store.is_some());
    }

    #[test]
    fn raw_tai_recovery_retains_profile_replacement_semantics() {
        use lktls::profile::types::{ExtensionSource, ExtensionSpec};
        use lktls::trust_anchor::{TrustAnchorId, TrustAnchorObserver, EXTENSION_TYPE};
        let mut profile = lktls::profile::presets::chrome_155();
        profile
            .extensions
            .retain(|e| e.extension_type != EXTENSION_TYPE);
        profile.extensions.push(ExtensionSpec {
            extension_type: EXTENSION_TYPE,
            source: ExtensionSource::RawBytes {
                data: "00020101".into(),
            },
        });
        let compiled =
            CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility())
                .unwrap();
        let connector = TlsConnector::from_compiled(compiled.clone()).unwrap();
        let retry = connector
            .recovery_with_trust_anchor_ids(
                vec![TrustAnchorId::new(vec![2]).unwrap()],
                TrustAnchorObserver::default(),
            )
            .unwrap();
        assert!(!Arc::ptr_eq(&compiled, &retry.template.compile().unwrap()));
        assert!(retry.config.hello_overrides.trust_anchor_ids.is_none());
        assert!(
            matches!(&retry.profile().extensions.last().unwrap().source, ExtensionSource::TrustAnchorIds { ids, .. } if ids == &["02"])
        );
    }

    const NEW_SESSION_TICKET: u8 = 0x04;
    const KEY_UPDATE: u8 = 0x18;

    /// Build one handshake message: type(1) + length(3) + body.
    fn hs(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut out = vec![msg_type, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        out.extend_from_slice(body);
        out
    }

    /// Regression: a server may put a `KeyUpdate` in the same record as a
    /// `NewSessionTicket`. Treating the record as a single message dispatched
    /// only the ticket and silently dropped the `KeyUpdate` — the read keys
    /// were never rotated and every subsequent record failed to decrypt.
    #[test]
    fn coalesced_key_update_after_ticket_is_not_dropped() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&hs(NEW_SESSION_TICKET, &[0xAA; 32]));
        buf.extend_from_slice(&hs(KEY_UPDATE, &[0x01]));

        let messages = split_post_handshake_messages(&mut buf).unwrap();

        assert_eq!(messages.len(), 2, "both coalesced messages must be yielded");
        assert_eq!(messages[0][0], NEW_SESSION_TICKET);
        assert_eq!(messages[1][0], KEY_UPDATE);
        assert_eq!(
            messages[1][4], 0x01,
            "KeyUpdate body must survive framing (update_requested)"
        );
        assert!(buf.is_empty(), "buffer must be fully drained");
    }

    /// Servers commonly send two tickets back to back in one record.
    #[test]
    fn two_coalesced_tickets_are_both_yielded() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&hs(NEW_SESSION_TICKET, &[0x01; 16]));
        buf.extend_from_slice(&hs(NEW_SESSION_TICKET, &[0x02; 16]));

        let messages = split_post_handshake_messages(&mut buf).unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0][4..], [0x01; 16]);
        assert_eq!(messages[1][4..], [0x02; 16]);
    }

    /// A message split across two records must be reassembled, not truncated.
    #[test]
    fn fragmented_message_is_reassembled_across_records() {
        let message = hs(NEW_SESSION_TICKET, &[0x5A; 300]);
        let (first, second) = message.split_at(100);

        let mut buf = first.to_vec();
        assert!(
            split_post_handshake_messages(&mut buf).unwrap().is_empty(),
            "an incomplete message must not be dispatched"
        );
        assert_eq!(buf.len(), 100, "the partial message stays buffered");

        buf.extend_from_slice(second);
        let messages = split_post_handshake_messages(&mut buf).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], message);
        assert!(buf.is_empty());
    }

    /// A complete message followed by the first bytes of the next one: the
    /// complete one is dispatched, the trailer is carried forward.
    #[test]
    fn partial_trailer_is_retained() {
        let mut buf = hs(KEY_UPDATE, &[0x00]);
        buf.extend_from_slice(&[NEW_SESSION_TICKET, 0x00, 0x00]); // 3-byte trailer

        let messages = split_post_handshake_messages(&mut buf).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0][0], KEY_UPDATE);
        assert_eq!(buf, vec![NEW_SESSION_TICKET, 0x00, 0x00]);
    }

    /// A header shorter than 4 bytes carries no length yet.
    #[test]
    fn header_shorter_than_four_bytes_yields_nothing() {
        let mut buf = vec![NEW_SESSION_TICKET, 0x00];
        assert!(split_post_handshake_messages(&mut buf).unwrap().is_empty());
        assert_eq!(buf.len(), 2);

        let mut empty = Vec::new();
        assert!(split_post_handshake_messages(&mut empty)
            .unwrap()
            .is_empty());
    }

    /// An announced length beyond the cap is rejected instead of buffered.
    #[test]
    fn oversized_announced_length_is_rejected() {
        // length = 0xFFFFFF (16 MiB - 1), body never arrives.
        let mut buf = vec![NEW_SESSION_TICKET, 0xFF, 0xFF, 0xFF];
        let err = split_post_handshake_messages(&mut buf).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );
    }

    /// Exactly at the cap is still accepted.
    #[test]
    fn length_at_the_cap_is_accepted() {
        let message = hs(NEW_SESSION_TICKET, &vec![0u8; MAX_POST_HANDSHAKE_MSG_LEN]);
        let mut buf = message.clone();
        let messages = split_post_handshake_messages(&mut buf).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].len(), 4 + MAX_POST_HANDSHAKE_MSG_LEN);
    }

    // -----------------------------------------------------------------------
    // close_notify vs. bare socket EOF (RFC 8446 section 6.1)
    // -----------------------------------------------------------------------

    /// Transport that hands out pre-canned chunks, then EOFs forever, counting
    /// how many times it was polled so a test can assert the stream stopped
    /// reading.
    enum WriteAction {
        Pending,
        Limit(usize),
        Fail,
    }

    #[derive(Default)]
    struct MockTransport {
        handshake_writer: Option<RecordWriter>,
        handshake_keys: Option<PostHandshakeState>,
        chunks: std::collections::VecDeque<Vec<u8>>,
        read_error: Option<io::ErrorKind>,
        pending_reads: usize,
        polls: usize,
        /// Everything the stream wrote, so a test can inspect the wire.
        written: Vec<u8>,
        write_actions: std::collections::VecDeque<WriteAction>,
        write_calls: usize,
        pending_flushes: usize,
        flush_calls: usize,
        pending_shutdowns: usize,
        shutdown_calls: usize,
    }

    impl AsyncRead for MockTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls += 1;
            if self.pending_reads != 0 {
                self.pending_reads -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(kind) = self.read_error.take() {
                return Poll::Ready(Err(io::Error::new(kind, "scripted read failure")));
            }
            if let Some(chunk) = self.chunks.pop_front() {
                buf.put_slice(&chunk);
            }
            // Nothing left: fill nothing, which the caller reads as EOF.
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockTransport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_calls += 1;
            let length = match self.write_actions.pop_front() {
                Some(WriteAction::Pending) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(WriteAction::Limit(n)) => n.min(buf.len()),
                Some(WriteAction::Fail) => {
                    return Poll::Ready(Err(io::Error::other("scripted write failure")))
                }
                None => buf.len(),
            };
            self.written.extend_from_slice(&buf[..length]);
            Poll::Ready(Ok(length))
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_calls += 1;
            if self.pending_flushes > 0 {
                self.pending_flushes -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_calls += 1;
            if self.pending_shutdowns > 0 {
                self.pending_shutdowns -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }
    }

    /// One plaintext TLS record (the reader is in plaintext mode here).
    fn record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = vec![content_type, 0x03, 0x03, (len >> 8) as u8, len as u8];
        out.extend_from_slice(payload);
        out
    }

    fn close_notify_record() -> Vec<u8> {
        // level = warning(1), description = close_notify(0)
        record(content_type::ALERT, &[0x01, 0x00])
    }

    #[tokio::test]
    async fn received_fatal_alert_does_not_wait_for_transport_cleanup() {
        let mut stream = mock_stream(vec![record(content_type::ALERT, &[2, 116])], false);
        stream.inner.pending_flushes = usize::MAX;
        stream.inner.pending_shutdowns = usize::MAX;
        let mut buf = [0; 1];
        for _ in 0..2 {
            let error =
                tokio::time::timeout(std::time::Duration::from_millis(100), stream.read(&mut buf))
                    .await
                    .expect("fatal alert must be returned before teardown finishes")
                    .unwrap_err();
            let error = crate::error::Error::from_h1_io(Arc::new(error));
            assert_eq!(error.as_tls_alert().unwrap().description.as_byte(), 116);
            assert!(!error.is_safe_to_replay());
        }
        assert_eq!(stream.inner.shutdown_calls, 1);
        assert_eq!(stream.inner.flush_calls, 0);
    }

    fn app_data_record(body: &[u8]) -> Vec<u8> {
        record(content_type::APPLICATION_DATA, body)
    }

    fn mock_stream(chunks: Vec<Vec<u8>>, require_close_notify: bool) -> TlsStream<MockTransport> {
        let mut stream = TlsStream {
            inner: MockTransport {
                chunks: chunks.into(),
                ..MockTransport::default()
            },
            connection: mock_connection(TlsClientHelloStyle::Generic, None, false),
            read_failure: None,
            require_close_notify,
        };
        stream.inner.handshake_writer = Some(RecordWriter::new());
        stream
    }

    fn mock_connection(
        style: TlsClientHelloStyle,
        version: Option<u16>,
        keys: bool,
    ) -> ClientConnection {
        ClientConnection::from_handshake(
            lktls::handshake::driver::HandshakeResult {
                reader: RecordReader::new(),
                writer: RecordWriter::new(),
                negotiated_alpn: None,
                negotiated_cipher_suite: None,
                negotiated_version: version,
                peer_certificates: Vec::new(),
                post_handshake: keys.then(mock_post_handshake_state),
                session_ticket_ctx: None,
            },
            style,
        )
    }

    fn configure_mock(
        stream: &mut TlsStream<MockTransport>,
        style: TlsClientHelloStyle,
        version: Option<u16>,
        keys: bool,
    ) {
        stream.connection = mock_connection(style, version, keys);
    }

    impl TlsStream<MockTransport> {
        fn handle_post_handshake_record(&mut self, payload: &[u8]) -> io::Result<()> {
            let record = self
                .inner
                .handshake_writer
                .as_mut()
                .unwrap()
                .write_record(content_type::HANDSHAKE, payload)
                .unwrap();
            self.connection.feed(&record);
            let result = self.connection.process_read().map_err(connection_io_error);
            if result.is_ok() && payload.len() == 5 && payload[0] == 24 && payload[4] <= 1 {
                let keys = self
                    .inner
                    .handshake_keys
                    .get_or_insert_with(mock_post_handshake_state);
                let cipher = keys.process_key_update().unwrap();
                self.inner
                    .handshake_writer
                    .as_mut()
                    .unwrap()
                    .set_keys(cipher);
            }
            result.map(|_| ())
        }
    }

    fn mock_post_handshake_state() -> PostHandshakeState {
        PostHandshakeState {
            server_app_secret: vec![0x22; 32],
            client_app_secret: vec![0x33; 32],
            hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: lktls::crypto::aead::AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x44; 32],
        }
    }

    #[tokio::test]
    async fn chromium_reply_suppression_ends_at_the_ku_record_not_the_entire_write_queue() {
        let mut stream = mock_stream(Vec::new(), false);
        configure_mock(
            &mut stream,
            TlsClientHelloStyle::ChromiumBoringssl,
            None,
            true,
        );
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        let first_secret = lktls::crypto::hkdf::hkdf_expand_label(
            lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            &[0x33; 32],
            "traffic upd",
            &[],
            32,
        )
        .unwrap();
        stream.inner.write_actions = [WriteAction::Limit(3), WriteAction::Pending].into();
        stream.write_all(b"queued").await.unwrap();
        assert_eq!(stream.inner.written.len(), 3);
        let queued = stream.connection.output().to_vec();
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert_eq!(stream.connection.output(), queued);
        stream.inner.write_actions = [WriteAction::Limit(7), WriteAction::Pending].into();
        let pending = std::future::poll_fn(|cx| {
            Poll::Ready(AsyncWrite::poll_flush(Pin::new(&mut stream), cx))
        })
        .await;
        assert!(pending.is_pending());
        assert_eq!(stream.inner.written.len(), 10);
        assert!(!stream.connection.output().is_empty());
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert_eq!(stream.connection.output().len(), 28 + 27);
        stream.flush().await.unwrap();
        assert!(stream.connection.output().is_empty());
        let key = lktls::crypto::hkdf::hkdf_expand_label(
            lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            &first_secret,
            "key",
            &[],
            16,
        )
        .unwrap();
        let iv = lktls::crypto::hkdf::hkdf_expand_label(
            lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            &first_secret,
            "iv",
            &[],
            12,
        )
        .unwrap();
        let cipher = lktls::crypto::aead::Aead::new(
            lktls::crypto::aead::AeadAlgorithm::Aes128Gcm,
            &key,
            &iv,
        )
        .unwrap();
        let wire = &stream.inner.written;
        assert_eq!(
            cipher.decrypt(0, &wire[10..15], &wire[15..38]).unwrap(),
            b"queued\x17"
        );
        assert_eq!(
            cipher.decrypt(1, &wire[38..43], &wire[43..]).unwrap(),
            [24, 0, 0, 1, 0, 22]
        );
    }

    #[tokio::test]
    async fn firefox_reply_suppression_survives_flush_until_application_write() {
        let mut stream = mock_stream(Vec::new(), false);
        configure_mock(&mut stream, TlsClientHelloStyle::FirefoxNss, None, true);
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        stream.flush().await.unwrap();
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert!(stream.connection.output().is_empty());
        assert_eq!(stream.inner.written.len(), 10);
        stream.write_all(b"next").await.unwrap();
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert!(stream.connection.flush_required());
        assert_eq!(stream.connection.output().len(), 27);
        let mut peer = mock_post_handshake_state();
        let (_, cipher) = peer.build_key_update_response().unwrap();
        let response = stream.connection.output();
        assert_eq!(
            cipher.decrypt(1, &response[..5], &response[5..]).unwrap(),
            [24, 0, 0, 1, 0, 22]
        );
    }

    #[tokio::test]
    async fn chromium_browser_flush_keeps_idle_ku_but_flushes_accepted_application_prefix() {
        for prefix in [
            Vec::new(),
            RecordWriter::new()
                .write_record(content_type::APPLICATION_DATA, b"accepted")
                .unwrap(),
        ] {
            let mut stream = mock_stream(Vec::new(), false);
            configure_mock(
                &mut stream,
                TlsClientHelloStyle::ChromiumBoringssl,
                None,
                true,
            );
            if !prefix.is_empty() {
                stream.connection.write_application(b"accepted").unwrap();
            }
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 1])
                .unwrap();
            stream.inner.write_actions = [WriteAction::Limit(2), WriteAction::Pending].into();
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_flush(cx))
                .await
                .unwrap();
            assert_eq!(stream.inner.written, prefix);
            assert!(stream.connection.idle_output().is_empty());
            assert_eq!(stream.connection.output().len(), 10);
            stream.flush().await.unwrap();
            assert_eq!(&stream.inner.written[prefix.len() + 5..], &[24, 0, 0, 1, 0]);
        }
    }

    #[tokio::test]
    async fn chromium_browser_shutdown_discards_only_an_unsent_trailing_key_update() {
        for prefix in [
            Vec::new(),
            RecordWriter::new()
                .write_record(content_type::APPLICATION_DATA, b"accepted")
                .unwrap(),
        ] {
            let mut stream = mock_stream(Vec::new(), false);
            configure_mock(
                &mut stream,
                TlsClientHelloStyle::ChromiumBoringssl,
                None,
                true,
            );
            if !prefix.is_empty() {
                stream.connection.write_application(b"accepted").unwrap();
            }
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 1])
                .unwrap();
            stream.inner.write_actions = [
                WriteAction::Pending,
                WriteAction::Limit(2),
                WriteAction::Pending,
            ]
            .into();
            stream.inner.pending_flushes = 1;
            stream.inner.pending_shutdowns = 1;
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_shutdown(cx))
                .await
                .unwrap();
            assert_eq!(stream.inner.written, prefix);
            assert!(stream.connection.is_closed() && stream.connection.output().is_empty());
            assert!(stream.connection.idle_output().is_empty());
            assert_eq!(
                stream.write(b"late").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        let mut explicit = mock_stream(Vec::new(), false);
        configure_mock(
            &mut explicit,
            TlsClientHelloStyle::ChromiumBoringssl,
            None,
            false,
        );
        explicit.shutdown().await.unwrap();
        assert_eq!(&explicit.inner.written[5..], &[1, 0]);
    }

    #[tokio::test]
    async fn chromium_browser_shutdown_preserves_partial_ku_and_dependent_application_data() {
        for partial in [false, true] {
            let mut stream = mock_stream(Vec::new(), false);
            configure_mock(
                &mut stream,
                TlsClientHelloStyle::ChromiumBoringssl,
                None,
                true,
            );
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 1])
                .unwrap();
            if partial {
                stream.inner.write_actions = [WriteAction::Limit(3), WriteAction::Pending].into();
                let pending = std::future::poll_fn(|cx| {
                    Poll::Ready(AsyncWrite::poll_flush(Pin::new(&mut stream), cx))
                })
                .await;
                assert!(pending.is_pending());
                assert_eq!(stream.inner.written.len(), 3);
            } else {
                stream.inner.write_actions = [WriteAction::Pending].into();
                stream.write_all(b"after").await.unwrap();
            }
            let expected = [stream.inner.written.as_slice(), stream.connection.output()].concat();
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_shutdown(cx))
                .await
                .unwrap();
            assert_eq!(stream.inner.written, expected);
            assert!(stream.connection.output().is_empty());
            assert!(stream.connection.is_closed());
        }
    }

    #[tokio::test]
    async fn browser_shutdown_still_flushes_terminal_alerts() {
        let mut stream = mock_stream(Vec::new(), false);
        configure_mock(
            &mut stream,
            TlsClientHelloStyle::ChromiumBoringssl,
            None,
            true,
        );
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        stream.connection.feed(&[22, 3, 3, 0xff, 0xff]);
        let error = stream.connection.process_read().unwrap_err();
        stream.fail_read(connection_io_error(error));
        let expected = stream.connection.output().to_vec();
        std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_shutdown(cx))
            .await
            .unwrap();
        assert_eq!(stream.inner.written, expected);
        assert_eq!(stream.inner.shutdown_calls, 1);
        assert!(stream.read(&mut [0; 1]).await.is_err());
    }

    #[tokio::test]
    async fn key_update_response_flush_timing_and_next_write_epoch_match_profiles() {
        use lktls::crypto::hkdf::{hkdf_expand_label, HkdfAlgorithm};
        for style in [
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            let mut stream = mock_stream(
                vec![record(content_type::HANDSHAKE, &[24, 0, 0, 1, 1])],
                false,
            );
            configure_mock(&mut stream, style, None, true);
            stream.inner.write_actions = [
                WriteAction::Pending,
                WriteAction::Limit(2),
                WriteAction::Pending,
            ]
            .into();
            stream.inner.pending_flushes = 1;
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            let response = [22, 3, 1, 0, 5, 24, 0, 0, 1, 0];
            if style == TlsClientHelloStyle::FirefoxNss {
                assert_eq!(stream.inner.written, response);
                assert!(stream.connection.output().is_empty());
                assert!(!stream.connection.flush_required());
            } else {
                assert!(stream.inner.written.is_empty());
                assert_eq!(stream.connection.output(), response);
            }
            stream.write_all(b"next").await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(&stream.inner.written[..10], &response);
            let secret =
                hkdf_expand_label(HkdfAlgorithm::Sha256, &[0x33; 32], "traffic upd", &[], 32)
                    .unwrap();
            let key = hkdf_expand_label(HkdfAlgorithm::Sha256, &secret, "key", &[], 16).unwrap();
            let iv = hkdf_expand_label(HkdfAlgorithm::Sha256, &secret, "iv", &[], 12).unwrap();
            let cipher = lktls::crypto::aead::Aead::new(
                lktls::crypto::aead::AeadAlgorithm::Aes128Gcm,
                &key,
                &iv,
            )
            .unwrap();
            assert_eq!(
                cipher
                    .decrypt(
                        0,
                        &stream.inner.written[10..15],
                        &stream.inner.written[15..]
                    )
                    .unwrap(),
                b"next\x17"
            );
        }
    }

    #[tokio::test]
    async fn key_update_response_write_zero_is_terminal() {
        let mut stream = mock_stream(
            vec![record(content_type::HANDSHAKE, &[24, 0, 0, 1, 1])],
            false,
        );
        configure_mock(&mut stream, TlsClientHelloStyle::FirefoxNss, None, true);
        stream.inner.write_actions = [WriteAction::Limit(0)].into();
        let error =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert!(stream.connection.is_closed() && stream.connection.output().is_empty());
        assert_eq!(
            stream.read(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(stream.inner.write_calls, 1);
    }

    #[tokio::test]
    async fn cancelled_key_update_flush_reports_write_zero() {
        for shutdown in [false, true] {
            let mut stream = mock_stream(
                vec![record(content_type::HANDSHAKE, &[24, 0, 0, 1, 1])],
                false,
            );
            configure_mock(&mut stream, TlsClientHelloStyle::FirefoxNss, None, true);
            stream.inner.write_actions = [WriteAction::Pending].into();
            let pending = std::future::poll_fn(|cx| {
                let mut bytes = [0; 1];
                let mut buffer = ReadBuf::new(&mut bytes);
                Poll::Ready(AsyncRead::poll_read(Pin::new(&mut stream), cx, &mut buffer))
            })
            .await;
            assert!(pending.is_pending());
            assert!(stream.connection.flush_required());
            stream.inner.write_actions.push_back(WriteAction::Limit(0));
            let error = if shutdown {
                stream.shutdown().await.unwrap_err()
            } else {
                stream.flush().await.unwrap_err()
            };
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
            assert_eq!(stream.inner.write_calls, 2);
            assert!(stream.inner.written.is_empty());
        }
    }

    #[tokio::test]
    async fn empty_application_record_does_not_signal_end_of_stream() {
        let mut stream = mock_stream(
            vec![
                app_data_record(b""),
                app_data_record(b"body"),
                close_notify_record(),
            ],
            false,
        );
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"body");
        assert!(stream.received_close_notify());
    }

    #[tokio::test]
    async fn handshake_fatal_alert_is_flushed_before_transport_shutdown() {
        #[derive(Default)]
        struct Snapshot {
            wire: Vec<u8>,
            flushes: usize,
            shutdowns: usize,
        }
        struct BufferedFailure {
            input: Option<Vec<u8>>,
            pending: Vec<u8>,
            state: Arc<std::sync::Mutex<Snapshot>>,
        }
        impl AsyncRead for BufferedFailure {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if let Some(input) = self.input.take() {
                    buf.put_slice(&input);
                }
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for BufferedFailure {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.pending.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                let pending = std::mem::take(&mut self.pending);
                let mut state = self.state.lock().unwrap();
                state.wire.extend(pending);
                state.flushes += 1;
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                assert!(
                    self.pending.is_empty(),
                    "fatal flight must be flushed before shutdown"
                );
                self.state.lock().unwrap().shutdowns += 1;
                Poll::Ready(Ok(()))
            }
        }
        let state = Arc::new(std::sync::Mutex::new(Snapshot::default()));
        let transport = BufferedFailure {
            input: Some(record(0x18, &[1])),
            pending: Vec::new(),
            state: Arc::clone(&state),
        };
        let result = TlsConnector::new(lktls::profile::presets::chrome_155())
            .connect("localhost", 443, transport)
            .await;
        assert!(
            matches!(result, Err(TlsError::LocalAlert { alert, .. }) if alert.description == lktls::error::AlertDescription::UnexpectedMessage)
        );
        let state = state.lock().unwrap();
        assert!(state.wire.ends_with(&[21, 3, 1, 0, 2, 2, 10]));
        assert_eq!((state.flushes, state.shutdowns), (1, 1));
    }

    #[tokio::test]
    async fn adapter_copies_authenticated_plaintext_once_into_fragmented_caller_buffers() {
        use lktls::crypto::aead::{Aead, AeadAlgorithm};
        use lktls::crypto::tls12_cipher::{Tls12GcmCipher, Tls12RecordCipher};

        for tls12 in [false, true] {
            for size in [1, 1024, 16384, 32791] {
                for caller_capacity in [1, 17, 1024] {
                    let mut reader = RecordReader::new();
                    let mut peer = RecordWriter::new();
                    if tls12 {
                        let cipher = || {
                            Tls12RecordCipher::Gcm(
                                Tls12GcmCipher::new(&[0x41; 16], &[0x32; 4], false).unwrap(),
                            )
                        };
                        reader.set_tls12_keys(cipher());
                        peer.set_tls12_keys(cipher());
                    } else {
                        let cipher = || {
                            Aead::new(AeadAlgorithm::Aes128Gcm, &[0x41; 16], &[0x32; 12]).unwrap()
                        };
                        reader.set_keys(cipher());
                        peer.set_keys(cipher());
                    }
                    let expected = vec![0x53; size];
                    let mut records = peer
                        .write_record(content_type::APPLICATION_DATA, &expected)
                        .unwrap();
                    records.extend(peer.write_record(content_type::ALERT, &[1, 0]).unwrap());
                    let mut stream =
                        mock_stream(records.chunks(1024).map(<[u8]>::to_vec).collect(), true);
                    stream.connection = ClientConnection::from_handshake(
                        lktls::handshake::driver::HandshakeResult {
                            reader,
                            writer: RecordWriter::new(),
                            negotiated_alpn: None,
                            negotiated_cipher_suite: None,
                            negotiated_version: Some(if tls12 { 0x0303 } else { 0x0304 }),
                            peer_certificates: Vec::new(),
                            post_handshake: None,
                            session_ticket_ctx: None,
                        },
                        TlsClientHelloStyle::Generic,
                    );
                    stream.inner.pending_reads = 1;
                    let mut caller = vec![0; caller_capacity];
                    let mut received = Vec::with_capacity(size);
                    PLAINTEXT_TO_CALLER_BYTES.with(|bytes| bytes.set(0));
                    loop {
                        let count = stream.read(&mut caller).await.unwrap();
                        if count == 0 {
                            break;
                        }
                        received.extend_from_slice(&caller[..count]);
                    }
                    assert_eq!(received, expected);
                    assert_eq!(PLAINTEXT_TO_CALLER_BYTES.with(|bytes| bytes.get()), size);
                    assert!(stream.received_close_notify());
                    assert!(stream.inner.polls > 1);
                    assert!(stream.inner.written.is_empty());
                }
            }
        }
    }

    #[tokio::test]
    async fn interrupted_transport_read_can_be_retried() {
        let mut stream = mock_stream(vec![app_data_record(b"ok")], false);
        stream.inner.read_error = Some(io::ErrorKind::Interrupted);
        assert_eq!(
            stream.read(&mut [0; 2]).await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!stream.connection.is_closed());
        let mut bytes = [0; 2];
        assert_eq!(stream.read(&mut bytes).await.unwrap(), 2);
        assert_eq!(&bytes, b"ok");
        assert_eq!(stream.inner.polls, 2);
    }

    #[tokio::test]
    async fn terminal_transport_read_errors_and_strict_eof_latch_both_directions() {
        for kind in [
            Some(io::ErrorKind::ConnectionReset),
            Some(io::ErrorKind::TimedOut),
            None,
        ] {
            let mut stream = mock_stream(vec![], kind.is_none());
            stream.inner.read_error = kind;
            stream
                .connection
                .write_application(b"unsent prefix")
                .unwrap();
            let error = stream.read(&mut [0; 16]).await.unwrap_err();
            assert_eq!(error.kind(), kind.unwrap_or(io::ErrorKind::UnexpectedEof));
            assert!(stream.connection.is_closed());
            assert!(stream.connection.output().is_empty());
            assert!(stream.inner.written.is_empty());
            assert_eq!(stream.inner.polls, 1);
            assert_eq!((stream.inner.write_calls, stream.inner.flush_calls), (0, 0));
            assert_eq!(stream.inner.shutdown_calls, 1);

            stream.inner.chunks.push_back(app_data_record(b"late data"));
            for later in [
                stream.read(&mut [0; 16]).await.map(|_| ()),
                stream.write(b"late write").await.map(|_| ()),
                stream.flush().await,
            ] {
                let later = later.unwrap_err();
                assert_eq!(later.kind(), error.kind());
                assert_eq!(later.to_string(), error.to_string());
            }
            stream.shutdown().await.unwrap();
            assert_eq!(stream.inner.polls, 1);
            assert_eq!((stream.inner.write_calls, stream.inner.flush_calls), (0, 0));
            assert_eq!(stream.inner.shutdown_calls, 1);
        }
    }

    #[tokio::test]
    async fn fatal_read_flushes_partial_alert_writes_before_returning_and_stays_terminal() {
        let mut stream = mock_stream(
            vec![record(0x18, &[1]), app_data_record(b"late data")],
            false,
        );
        stream.inner.write_actions = [
            WriteAction::Pending,
            WriteAction::Limit(2),
            WriteAction::Pending,
            WriteAction::Limit(1),
        ]
        .into();
        stream.inner.pending_flushes = 1;
        stream.inner.pending_shutdowns = 1;
        let mut buffer = [0; 16];
        let error =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buffer))
                .await
                .expect("fatal alert write stalled")
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown TLS record content type"));
        assert_eq!(stream.inner.written, [21, 3, 1, 0, 2, 2, 10]);
        assert_eq!((stream.inner.write_calls, stream.inner.flush_calls), (5, 2));
        assert_eq!(stream.inner.shutdown_calls, 2);
        assert!(stream.connection.output().is_empty());
        let polls = stream.inner.polls;
        assert_eq!(
            stream.read(&mut buffer).await.unwrap_err().to_string(),
            error.to_string()
        );
        assert_eq!(stream.inner.polls, polls);
        assert_eq!((stream.inner.write_calls, stream.inner.flush_calls), (5, 2));
        assert_eq!(
            stream.write_all(b"late write").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        stream.shutdown().await.unwrap();
        assert_eq!(stream.inner.shutdown_calls, 2);
        assert_eq!(stream.inner.written, [21, 3, 1, 0, 2, 2, 10]);
    }

    #[tokio::test]
    async fn fatal_read_does_not_spin_or_retry_when_alert_transport_fails() {
        for actions in [
            vec![WriteAction::Limit(0)],
            vec![WriteAction::Limit(2), WriteAction::Fail],
        ] {
            let expected_writes = actions.len();
            let mut stream = mock_stream(vec![record(0x18, &[1])], false);
            stream.inner.write_actions = actions.into();
            let error =
                tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
                    .await
                    .expect("zero/error write must not spin")
                    .unwrap_err();
            assert!(error
                .to_string()
                .contains("unknown TLS record content type"));
            assert_eq!(stream.inner.write_calls, expected_writes);
            assert_eq!(
                stream.inner.written.len(),
                if expected_writes == 1 { 0 } else { 2 }
            );
            assert!(stream.connection.output().is_empty());
            assert_eq!(
                stream.read(&mut [0; 1]).await.unwrap_err().to_string(),
                error.to_string()
            );
            assert_eq!(stream.inner.write_calls, expected_writes);
        }
    }

    #[tokio::test]
    async fn cancelled_fatal_read_can_finish_through_flush_or_shutdown() {
        for shutdown in [false, true] {
            let mut stream = mock_stream(vec![record(0x18, &[1])], false);
            stream.inner.write_actions = [
                WriteAction::Pending,
                WriteAction::Limit(2),
                WriteAction::Pending,
                WriteAction::Limit(0),
            ]
            .into();
            let first_poll = std::future::poll_fn(|cx| {
                let mut bytes = [0; 1];
                let mut buffer = ReadBuf::new(&mut bytes);
                Poll::Ready(AsyncRead::poll_read(Pin::new(&mut stream), cx, &mut buffer))
            })
            .await;
            assert!(first_poll.is_pending());
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                if shutdown {
                    stream.shutdown().await
                } else {
                    stream.flush().await
                }
            })
            .await
            .expect("cancelled fatal read must not spin on WriteZero");
            assert_eq!(result.is_ok(), shutdown);
            assert_eq!(stream.inner.written, [21, 3]);
            assert!(stream.connection.output().is_empty());
            assert!(stream
                .read(&mut [0; 1])
                .await
                .unwrap_err()
                .to_string()
                .contains("unknown TLS record content type"));
            assert_eq!(stream.inner.polls, 1);
            assert_eq!(stream.inner.write_calls, 4);
        }
    }

    #[tokio::test]
    async fn fatal_read_preserves_queued_record_order() {
        let mut stream = mock_stream(vec![record(0x18, &[1])], false);
        stream.connection.write_application(b"queued").unwrap();
        stream.inner.write_actions = [WriteAction::Limit(3), WriteAction::Pending].into();
        assert!(stream.read(&mut [0; 1]).await.is_err());
        assert_eq!(&stream.inner.written[..5], &[23, 3, 1, 0, 6]);
        assert_eq!(&stream.inner.written[5..11], b"queued");
        assert_eq!(&stream.inner.written[11..], &[21, 3, 3, 0, 2, 2, 10]);
        assert!(stream.connection.output().is_empty());
    }

    #[tokio::test]
    async fn peer_fatal_alert_is_not_echoed_or_followed_by_application_reads() {
        let mut stream = mock_stream(
            vec![
                record(content_type::ALERT, &[2, 40]),
                app_data_record(b"late"),
            ],
            false,
        );
        assert_eq!(
            stream.read(&mut [0; 4]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert!(stream.inner.written.is_empty());
        assert_eq!(
            stream.read(&mut [0; 4]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(stream.inner.polls, 1);
        assert_eq!(stream.inner.write_calls, 0);
    }

    /// A peer that shuts down properly is recorded as such, and the body is
    /// delivered intact.
    #[tokio::test]
    async fn close_notify_is_recorded_and_ends_the_stream_cleanly() {
        let mut stream = mock_stream(
            vec![app_data_record(b"hello"), close_notify_record()],
            false,
        );

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.expect("clean shutdown");

        assert_eq!(body, b"hello");
        assert!(
            stream.received_close_notify(),
            "close_notify must be recorded"
        );
    }

    /// The gap this closes: a peer that drops the TCP connection produces a
    /// byte-identical EOF, so the two cases must be distinguishable after the
    /// fact even though both still succeed by default.
    #[tokio::test]
    async fn bare_eof_is_distinguishable_from_a_clean_shutdown() {
        let mut stream = mock_stream(vec![app_data_record(b"hello")], false);

        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .expect("default behaviour must stay tolerant");

        assert_eq!(body, b"hello", "the truncated body still reads as success");
        assert!(
            !stream.received_close_notify(),
            "a bare EOF must not look like a clean shutdown"
        );
    }

    /// With enforcement on, the same truncation becomes an error instead of a
    /// silently short body.
    #[tokio::test]
    async fn require_close_notify_turns_a_bare_eof_into_an_error() {
        let mut stream = mock_stream(vec![app_data_record(b"hello")], true);

        let mut body = Vec::new();
        let err = stream
            .read_to_end(&mut body)
            .await
            .expect_err("truncation must be reported");

        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            err.to_string().contains("close_notify"),
            "unexpected error: {err}"
        );
    }

    /// Enforcement must not fire on a properly closed connection.
    #[tokio::test]
    async fn require_close_notify_accepts_a_clean_shutdown() {
        let mut stream = mock_stream(vec![app_data_record(b"hello"), close_notify_record()], true);

        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .expect("close_notify was sent, so this must succeed");
        assert_eq!(body, b"hello");
    }

    /// RFC 8446 section 6.1: nothing arriving after `close_notify` came from the
    /// peer. The read loop used to keep polling the socket past the alert, so
    /// bytes appended by anyone able to write to the connection were delivered
    /// to the caller as body data.
    #[tokio::test]
    async fn data_injected_after_close_notify_is_not_delivered() {
        let mut stream = mock_stream(
            vec![
                app_data_record(b"hello"),
                close_notify_record(),
                app_data_record(b"INJECTED"),
            ],
            false,
        );

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.expect("clean shutdown");

        assert_eq!(body, b"hello", "post-close_notify bytes must be ignored");
    }

    /// Once `close_notify` has been seen the socket must not be polled again —
    /// otherwise a peer that keeps the connection open stalls the reader.
    #[tokio::test]
    async fn socket_is_not_polled_after_close_notify() {
        let mut stream = mock_stream(
            vec![app_data_record(b"hello"), close_notify_record()],
            false,
        );

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.expect("clean shutdown");
        let polls_at_eof = stream.inner_stream().polls;

        // Reading again at EOF must be answered from the recorded state alone.
        let mut extra = [0u8; 8];
        let n = stream.read(&mut extra).await.expect("EOF is not an error");

        assert_eq!(n, 0);
        assert_eq!(
            stream.inner_stream().polls,
            polls_at_eof,
            "no further socket reads are allowed after close_notify"
        );
    }

    // -----------------------------------------------------------------------
    // TLS 1.2 HelloRequest (RFC 5246 §7.4.1.1)
    // -----------------------------------------------------------------------

    /// One plaintext handshake record carrying a single message.
    fn handshake_record(msg: &[u8]) -> Vec<u8> {
        record(content_type::HANDSHAKE, msg)
    }

    fn stream_at_version(version: u16, chunks: Vec<Vec<u8>>) -> TlsStream<MockTransport> {
        let mut stream = mock_stream(chunks, false);
        configure_mock(
            &mut stream,
            TlsClientHelloStyle::Generic,
            Some(version),
            false,
        );
        stream
    }

    /// Read whatever the stream queued for the peer.
    /// Everything that actually reached the peer, plus anything still queued.
    fn written_bytes(stream: &TlsStream<MockTransport>) -> Vec<u8> {
        let mut out = stream.inner_stream().written.clone();
        out.extend_from_slice(stream.connection.output());
        out
    }

    /// BoringSSL answers a TLS 1.2 `HelloRequest` with a **fatal**
    /// `no_renegotiation` and aborts. Silently ignoring it — what this used to
    /// do — is something no browser does, so a server could probe for it.
    #[tokio::test]
    async fn tls12_hello_request_is_refused_with_a_fatal_alert() {
        // HelloRequest: type 0x00, length 0.
        let hello_request = handshake_record(&[0x00, 0x00, 0x00, 0x00]);
        let mut stream = stream_at_version(0x0303, vec![hello_request]);

        let mut body = Vec::new();
        let err = stream
            .read_to_end(&mut body)
            .await
            .expect_err("a HelloRequest must fail the connection, not be ignored");

        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            err.to_string().contains("no_renegotiation"),
            "unexpected error: {err}"
        );

        // level = fatal(2), description = no_renegotiation(100). The record is
        // plaintext here because the mock writer has no keys installed.
        let written = written_bytes(&stream);
        assert!(
            written.ends_with(&[0x02, 0x64]),
            "expected a fatal no_renegotiation alert on the wire, got {written:02x?}"
        );
        assert_eq!(
            written.first(),
            Some(&content_type::ALERT),
            "the queued record must be an alert: {written:02x?}"
        );
    }

    /// RFC 5246 §7.2.2 calls `no_renegotiation` a *warning*; BoringSSL sends it
    /// fatal. We follow BoringSSL — matching the browser is the point — so this
    /// pins the level against a well-meaning "fix" toward the RFC.
    #[tokio::test]
    async fn the_refusal_alert_is_fatal_not_a_warning() {
        let hello_request = handshake_record(&[0x00, 0x00, 0x00, 0x00]);
        let mut stream = stream_at_version(0x0303, vec![hello_request]);
        let _ = stream.read_to_end(&mut Vec::new()).await;

        let written = written_bytes(&stream);
        let level = written[written.len() - 2];
        assert_eq!(
            level, 0x02,
            "BoringSSL sends this fatal (2), not warning (1), despite RFC 5246 §7.2.2"
        );
    }

    /// TLS 1.3 rejects HelloRequest as an unexpected handshake message.
    #[tokio::test]
    async fn tls13_does_not_take_the_renegotiation_path() {
        let hello_request = handshake_record(&[0x00, 0x00, 0x00, 0x00]);
        let mut stream = stream_at_version(0x0304, vec![hello_request]);

        let mut body = Vec::new();
        let error = stream
            .read_to_end(&mut body)
            .await
            .expect_err("TLS 1.3 must reject HelloRequest");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(written_bytes(&stream), &[21, 3, 1, 0, 2, 2, 10]);
    }

    /// A HelloRequest arriving before a version is known must not trip the
    /// refusal either — `negotiated_version` is `None` only if the handshake
    /// never recorded one.
    #[tokio::test]
    async fn unknown_version_keeps_the_previous_behaviour() {
        let hello_request = handshake_record(&[0x00, 0x00, 0x00, 0x00]);
        let mut stream = mock_stream(vec![hello_request], false);
        assert!(stream.negotiated_version().is_none());

        stream
            .read_to_end(&mut Vec::new())
            .await
            .expect("an unknown version must not abort");
        assert!(written_bytes(&stream).is_empty());
    }
}
