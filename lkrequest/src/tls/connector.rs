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

use lktls::error::{Result, TlsError};
use lktls::handshake::content_type;
use lktls::handshake::driver::{
    HandshakeConfig, HandshakeDriver, HandshakeOutput, PostHandshakeState, SessionTicketContext,
};
use lktls::profile::types::{TlsClientHelloStyle, TlsProfile};
use lktls::record::reader::RecordReader;
use lktls::record::writer::RecordWriter;
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
/// Wraps an [`lktls::handshake::driver::HandshakeConfig`] with a builder
/// API and provides the async I/O adapter for the TLS handshake.
pub struct TlsConnector {
    config: HandshakeConfig,
    require_close_notify: bool,
}

impl TlsConnector {
    pub fn new(profile: TlsProfile) -> Self {
        Self {
            config: HandshakeConfig {
                profile,
                hostname: String::new(),
                port: 0,
                verification_policy: VerificationPolicy::default(),
                alps_payload: None,
                session_store: None,
                ech_config_list: None,
                custom_ca_anchors: None,
                keylog_callback: None,
                client_hello_callback: None,
            },
            require_close_notify: false,
        }
    }

    pub fn profile(&self) -> &TlsProfile {
        &self.config.profile
    }

    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        self.config.verification_policy = policy;
        self
    }

    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        if skip {
            self.config.verification_policy = VerificationPolicy::Insecure;
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
        self.config.custom_ca_anchors = Some(anchors);
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
        self.connect_inner(hostname, port, stream)
            .instrument(span)
            .await
    }

    /// Perform the TLS handshake using the Sans-I/O [`HandshakeDriver`].
    fn connect_inner<'a, S: TlsTransport + 'static>(
        &'a self,
        hostname: &'a str,
        port: u16,
        mut stream: S,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<TlsStream<S>>> + Send + 'a>> {
        Box::pin(async move {
            let mut config = self.config.clone();
            config.hostname = hostname.to_string();
            config.port = port;

            let mut driver = HandshakeDriver::new(config);

            // `driver.start()` fires `client_hello_callback` (set via
            // `on_client_hello`) internally, so the same hook works for direct
            // lktls users — see `HandshakeDriver::start`.
            let ch_bytes = driver.start()?;
            stream.write_all(&ch_bytes).await.map_err(TlsError::Io)?;

            loop {
                let output = match driver.progress() {
                    Ok(output) => output,
                    Err(error) => {
                        if let Some(alert) = driver.take_pending_alert() {
                            if let Err(write_error) = stream.write_all(&alert).await {
                                tracing::debug!(
                                    error = %write_error,
                                    "tls.local_alert_send_failed"
                                );
                            } else {
                                let _ = stream.flush().await;
                                let _ = stream.shutdown().await;
                            }
                        }
                        return Err(error);
                    }
                };

                match output {
                    HandshakeOutput::SendData(data) => {
                        stream.write_all(&data).await.map_err(TlsError::Io)?;
                    }
                    HandshakeOutput::NeedData => {
                        let mut buf = [0u8; 16384];
                        let n = stream.read(&mut buf).await.map_err(TlsError::Io)?;
                        if n == 0 {
                            return Err(TlsError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed during TLS handshake",
                            )));
                        }
                        driver.feed(&buf[..n]);
                    }
                    HandshakeOutput::Done { to_send, result } => {
                        if !to_send.is_empty() {
                            stream.write_all(&to_send).await.map_err(TlsError::Io)?;
                        }
                        return Ok(TlsStream::from_handshake(
                            stream,
                            *result,
                            self.require_close_notify,
                            self.config.profile.tls_client_hello_style,
                        ));
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
    kind: io::ErrorKind,
    message: String,
    flushed: bool,
    shutdown: bool,
}

pub struct TlsStream<S: TlsTransport = TcpStream> {
    inner: S,
    reader: RecordReader,
    writer: RecordWriter,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
    closed: bool,
    read_failure: Option<ReadFailure>,
    client_style: TlsClientHelloStyle,
    key_update_flush_pending: bool,
    consecutive_key_updates: u8,
    // Bytes through the queued KU record, including any preceding records.
    pending_key_update_bytes: usize,
    pending_key_update_record_len: usize,
    key_update_without_application_write: bool,
    negotiated_alpn: Option<String>,
    negotiated_cipher_suite: Option<u16>,
    negotiated_version: Option<u16>,
    peer_certificates: Vec<Vec<u8>>,
    post_handshake: Option<PostHandshakeState>,
    session_ticket_ctx: Option<SessionTicketContext>,
    /// Reassembly buffer for post-handshake handshake messages.
    ///
    /// Post-handshake messages obey the same framing as the handshake itself
    /// (RFC 8446 §5.1): several MAY be coalesced into one record, and one MAY
    /// be fragmented across several records. Servers routinely coalesce two
    /// `NewSessionTicket`s, and a `KeyUpdate` may share a record with them.
    /// Decrypted handshake bytes are appended here and only *complete* messages
    /// are dispatched, with any partial trailer carried to the next record —
    /// the same buffering `HandshakeDriver::hs_buffer` does during the
    /// handshake.
    post_handshake_buf: Vec<u8>,
    /// Whether the peer's `close_notify` was seen before the stream ended.
    ///
    /// RFC 8446 §6.1 requires each side to send `close_notify` before closing.
    /// A peer that just drops the TCP connection produces a byte-identical EOF,
    /// so without this flag a truncation attack is indistinguishable from a
    /// clean shutdown on any body framed by connection close.
    received_close_notify: bool,
    /// Whether a socket EOF with no preceding `close_notify` is an error.
    ///
    /// Off by default: plenty of real servers close without the alert, and
    /// erroring by default would break requests that browsers accept.
    require_close_notify: bool,
}

impl<S: TlsTransport> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("closed", &self.closed)
            .finish()
    }
}

impl<S: TlsTransport> TlsStream<S> {
    /// Construct a `TlsStream` from a completed handshake result and the
    /// underlying transport stream.
    fn from_handshake(
        inner: S,
        result: lktls::handshake::driver::HandshakeResult,
        require_close_notify: bool,
        client_style: TlsClientHelloStyle,
    ) -> Self {
        Self {
            inner,
            reader: result.reader,
            writer: result.writer,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            closed: false,
            read_failure: None,
            client_style,
            key_update_flush_pending: false,
            consecutive_key_updates: 0,
            pending_key_update_bytes: 0,
            pending_key_update_record_len: 0,
            key_update_without_application_write: false,
            negotiated_alpn: result.negotiated_alpn,
            negotiated_cipher_suite: result.negotiated_cipher_suite,
            negotiated_version: result.negotiated_version,
            peer_certificates: result.peer_certificates,
            post_handshake: result.post_handshake,
            session_ticket_ctx: result.session_ticket_ctx,
            post_handshake_buf: Vec::new(),
            received_close_notify: false,
            require_close_notify,
        }
    }

    pub fn inner_stream(&self) -> &S {
        &self.inner
    }

    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.negotiated_cipher_suite
    }

    /// Negotiated TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3), if known.
    pub fn negotiated_version(&self) -> Option<u16> {
        self.negotiated_version
    }

    /// Whether the peer sent `close_notify` (RFC 8446 §6.1) before the stream
    /// ended.
    ///
    /// Only meaningful once reading has reached EOF. `false` at that point means
    /// the peer closed the TCP connection without a TLS-level shutdown, so a
    /// body delimited by connection close may have been truncated in transit.
    pub fn received_close_notify(&self) -> bool {
        self.received_close_notify
    }

    /// Outcome to report when the socket reaches EOF.
    fn eof_outcome(&self) -> io::Result<()> {
        if self.require_close_notify && !self.received_close_notify {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS connection closed without close_notify (RFC 8446 §6.1);                  a body delimited by connection close may be truncated",
            ));
        }
        Ok(())
    }

    /// The server's certificate chain (DER, leaf first). Empty on a resumed
    /// handshake that carried no Certificate message.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }

    /// Feed one decrypted handshake *record* payload into the post-handshake
    /// reassembly buffer and dispatch every complete message it yields.
    ///
    /// Processing a record as if it were exactly one message loses coalesced
    /// messages (a `KeyUpdate` sharing a record with a `NewSessionTicket` would
    /// never rotate the read keys, breaking every subsequent record) and
    /// mis-parses fragmented ones.
    fn handle_post_handshake_record(&mut self, payload: &[u8]) -> io::Result<()> {
        self.post_handshake_buf.extend_from_slice(payload);
        while let Some(message) = take_post_handshake_message(&mut self.post_handshake_buf)? {
            self.handle_post_handshake_message(&message, self.post_handshake_buf.is_empty())?;
        }
        Ok(())
    }

    /// Dispatch exactly one complete post-handshake handshake message
    /// (4-byte header included).
    fn handle_post_handshake_message(
        &mut self,
        payload: &[u8],
        at_record_end: bool,
    ) -> io::Result<()> {
        let Some(&msg_type) = payload.first() else {
            return Ok(());
        };
        match msg_type {
            0x18 => {
                if self.post_handshake.is_some() {
                    if self.client_style == TlsClientHelloStyle::ChromiumBoringssl {
                        if self.consecutive_key_updates == 32 {
                            return Err(self.post_handshake_alert(
                                lktls::error::AlertDescription::UnexpectedMessage,
                                "too many consecutive KeyUpdate messages",
                            ));
                        }
                        self.consecutive_key_updates += 1;
                    }
                    if payload.len() != 5 {
                        return Err(self.post_handshake_alert(
                            lktls::error::AlertDescription::DecodeError,
                            "KeyUpdate must contain exactly one request byte",
                        ));
                    }
                    if payload[4] > 1 {
                        let description = if matches!(
                            self.client_style,
                            TlsClientHelloStyle::ChromiumBoringssl
                                | TlsClientHelloStyle::FirefoxNss
                        ) {
                            lktls::error::AlertDescription::DecodeError
                        } else {
                            lktls::error::AlertDescription::IllegalParameter
                        };
                        return Err(self
                            .post_handshake_alert(description, "invalid KeyUpdate request value"));
                    }
                    if !at_record_end {
                        return Err(self.post_handshake_alert(
                            lktls::error::AlertDescription::UnexpectedMessage,
                            "KeyUpdate must end at a record boundary",
                        ));
                    }
                }
                if let Some(ref mut ph) = self.post_handshake {
                    // Update read-side keys (server's new key).
                    let new_read_aead = ph
                        .process_key_update()
                        .map_err(|e| io::Error::other(format!("KeyUpdate failed: {e}")))?;
                    self.reader.set_keys(new_read_aead);

                    // Check if the server requested us to update our keys too.
                    // KeyUpdate body: update_requested(1 byte).
                    // 0x00 = update_not_requested, 0x01 = update_requested
                    let update_requested = payload[4] == 0x01;
                    let can_respond = match self.client_style {
                        TlsClientHelloStyle::ChromiumBoringssl => {
                            self.pending_key_update_bytes == 0
                        }
                        TlsClientHelloStyle::FirefoxNss => {
                            !self.key_update_without_application_write
                        }
                        _ => true,
                    };
                    if update_requested && can_respond {
                        let (ku_msg, new_write_aead) =
                            ph.build_key_update_response().map_err(|e| {
                                io::Error::other(format!("KeyUpdate response failed: {e}"))
                            })?;
                        // Encrypt the KeyUpdate message with the current write key,
                        // then install the new write key.
                        let record = self
                            .writer
                            .write_record(lktls::handshake::content_type::HANDSHAKE, &ku_msg)
                            .map_err(|e| {
                                io::Error::other(format!("KeyUpdate write failed: {e}"))
                            })?;
                        self.write_buf.extend_from_slice(&record);
                        self.pending_key_update_bytes = self.write_buf.len();
                        self.pending_key_update_record_len = record.len();
                        self.key_update_without_application_write = true;
                        self.writer.set_keys(new_write_aead);
                        self.key_update_flush_pending =
                            self.client_style == TlsClientHelloStyle::FirefoxNss;
                    }
                }
            }
            0x04 => {
                if let Some(ref ctx) = self.session_ticket_ctx {
                    ctx.process_new_session_ticket(payload);
                } else {
                    tracing::trace!("tls.session_ticket_received_no_store");
                }
            }
            HELLO_REQUEST if self.negotiated_version.is_some_and(|v| v < TLS13_VERSION) => {
                return Err(self.refuse_renegotiation());
            }
            other => {
                tracing::trace!(
                    msg_type = format_args!("0x{:02x}", other),
                    "tls.post_handshake_ignored"
                );
            }
        }
        Ok(())
    }

    fn post_handshake_alert(
        &mut self,
        description: lktls::error::AlertDescription,
        message: &str,
    ) -> io::Error {
        let error = TlsError::local_alert(description, message);
        if let Ok(record) = self
            .writer
            .write_record(content_type::ALERT, &[2, description.as_byte()])
        {
            self.write_buf.extend_from_slice(&record);
        }
        io::Error::other(error.to_string())
    }

    fn unsent_trailing_key_update_len(&self) -> usize {
        if self.pending_key_update_bytes == self.write_buf.len()
            && self.pending_key_update_bytes >= self.pending_key_update_record_len
        {
            self.pending_key_update_record_len
        } else {
            0
        }
    }

    pub(crate) fn poll_browser_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.client_style != TlsClientHelloStyle::ChromiumBoringssl
            || self.read_failure.is_some()
        {
            return AsyncWrite::poll_flush(self, cx);
        }
        // An HTTP driver's idle flush does not initiate Chromium's queued KU.
        // Already accepted application records must still reach the transport.
        let retained_tail = self.unsent_trailing_key_update_len();
        let this = &mut *self;
        flush_write_buf_prefix(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.pending_key_update_bytes,
            retained_tail,
            cx,
        )?;
        if this.write_buf.len() > retained_tail {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    pub(crate) fn poll_browser_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.client_style != TlsClientHelloStyle::ChromiumBoringssl
            || self.read_failure.is_some()
        {
            return AsyncWrite::poll_shutdown(self, cx);
        }
        if !self.closed {
            self.closed = true;
            // Chromium disconnects without close_notify. A trailing unsent KU
            // can be dropped only when no accepted data depends on its epoch.
            let discard = self.unsent_trailing_key_update_len();
            if discard > 0 {
                let keep = self.write_buf.len() - discard;
                self.write_buf.truncate(keep);
                self.pending_key_update_bytes = 0;
            }
        }
        std::task::ready!(AsyncWrite::poll_flush(self.as_mut(), cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_key_update_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = match flush_write_buf(
            &mut self.inner,
            &mut self.write_buf,
            &mut self.pending_key_update_bytes,
            cx,
        ) {
            Err(error) => Err(error),
            Ok(()) if !self.write_buf.is_empty() => return Poll::Pending,
            Ok(()) => match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            },
        };
        self.key_update_flush_pending = false;
        if let Err(error) = result {
            self.write_buf.clear();
            self.pending_key_update_bytes = 0;
            self.fail_read(error);
            self.read_failure.as_mut().unwrap().flushed = true;
            return self.poll_read_failure(cx);
        }
        Poll::Ready(Ok(()))
    }

    fn fail_read(&mut self, error: io::Error) {
        self.closed = true;
        self.read_failure.get_or_insert_with(|| ReadFailure {
            kind: error.kind(),
            message: error.to_string(),
            flushed: false,
            shutdown: false,
        });
    }

    /// Keep a fatal read pending until its queued records reach the transport.
    /// If the transport fails, retain the original TLS error and stop retrying.
    fn poll_read_failure(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.read_failure.as_ref().unwrap().flushed {
            while !self.write_buf.is_empty() {
                match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
                        self.write_buf.clear();
                        self.read_failure.as_mut().unwrap().flushed = true;
                        break;
                    }
                    Poll::Ready(Ok(n)) => {
                        self.write_buf.drain(..n);
                        self.pending_key_update_bytes =
                            self.pending_key_update_bytes.saturating_sub(n);
                    }
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
            if Pin::new(&mut self.inner).poll_shutdown(cx).is_pending() {
                return Poll::Pending;
            }
            self.read_failure.as_mut().unwrap().shutdown = true;
        }
        let failure = self.read_failure.as_ref().unwrap();
        Poll::Ready(Err(io::Error::new(failure.kind, failure.message.clone())))
    }

    /// Answer a TLS 1.2 `HelloRequest` the way BoringSSL does: a **fatal**
    /// `no_renegotiation` alert, then fail the connection.
    ///
    /// This client never renegotiates, and the previous behaviour — dropping the
    /// message into `post_handshake_ignored` — is something no browser does, so
    /// it was a behavioural tell to any server willing to probe with a
    /// `HelloRequest`.
    ///
    /// The BoringSSL path (`ssl/ssl_lib.cc`, `ssl_do_post_handshake`) for a
    /// client below TLS 1.3: the default `renegotiate_mode` is
    /// `ssl_renegotiate_never`, so the message falls through to
    /// `SSL_renegotiate`, `ssl_can_renegotiate` returns false for that mode, and
    /// the caller sends `SSL3_AL_FATAL` / `SSL_AD_NO_RENEGOTIATION` and aborts.
    /// Chrome reaches the same place: `SSLClientSocketImpl` arms
    /// `ssl_renegotiate_explicit` for the handshake and then drops to
    /// `ssl_renegotiate_never` unless the negotiated ALPN is in
    /// `renego_allowed_for_protos`, which is empty by default and can never
    /// contain h2 (RFC 9113 §9.2.1 forbids renegotiation outright).
    ///
    /// Note the alert is **fatal**, even though RFC 5246 §7.2.2 classifies
    /// `no_renegotiation` as a warning. That deviation is BoringSSL's, and
    /// matching the browser is what this crate is for.
    fn refuse_renegotiation(&mut self) -> io::Error {
        // level = fatal(2), description = no_renegotiation(100)
        let alert: &[u8] = &[0x02, 0x64];
        if let Ok(record) = self.writer.write_record(content_type::ALERT, alert) {
            self.write_buf.extend_from_slice(&record);
        }
        tracing::debug!("tls.renegotiation_refused");
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "server requested TLS 1.2 renegotiation (HelloRequest); refused with no_renegotiation",
        )
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut buf = [0u8; 16384];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    Poll::Ready(Ok(0))
                } else {
                    self.reader.feed(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn try_read_app_data(&mut self) -> io::Result<bool> {
        loop {
            match self.reader.next_record() {
                Ok(Some(record)) => {
                    if record.content_type == content_type::APPLICATION_DATA {
                        if !record.payload.is_empty() {
                            self.consecutive_key_updates = 0;
                        }
                        self.read_buf = record.payload;
                        self.read_pos = 0;
                        return Ok(true);
                    } else if record.content_type == content_type::ALERT {
                        let level = record.payload.first().copied().unwrap_or(0);
                        let desc = record.payload.get(1).copied().unwrap_or(0);
                        let alert = lktls::error::TlsAlert::from_bytes(level, desc);
                        if alert.is_close_notify() {
                            self.received_close_notify = true;
                            return Ok(false);
                        } else if alert.level == lktls::error::AlertLevel::Warning {
                            continue;
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!("TLS {}", alert),
                            ));
                        }
                    } else if record.content_type == content_type::HANDSHAKE {
                        self.handle_post_handshake_record(&record.payload)?;
                        if self.key_update_flush_pending {
                            return Ok(false);
                        }
                        continue;
                    } else {
                        continue;
                    }
                }
                Ok(None) => return Ok(false),
                Err(e) => {
                    if let TlsError::LocalAlert { alert, .. } = &e {
                        let bytes = [alert.level.as_byte(), alert.description.as_byte()];
                        if let Ok(record) = self.writer.write_record(content_type::ALERT, &bytes) {
                            self.write_buf.extend_from_slice(&record);
                        }
                    }
                    return Err(io::Error::other(e.to_string()));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncRead / AsyncWrite for TlsStream
// ---------------------------------------------------------------------------

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
            if self.key_update_flush_pending {
                match self.poll_key_update_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    other => return other,
                }
            }
            if self.read_pos < self.read_buf.len() {
                let available = &self.read_buf[self.read_pos..];
                let to_copy = available.len().min(buf.remaining());
                buf.put_slice(&available[..to_copy]);
                self.read_pos += to_copy;
                return Poll::Ready(Ok(()));
            }
            // No records after close_notify may be exposed to the caller.
            if self.received_close_notify {
                return Poll::Ready(Ok(()));
            }
            match self.try_read_app_data() {
                Ok(true) => continue,
                Err(error) => {
                    self.fail_read(error);
                    continue;
                }
                Ok(false) => {
                    if self.key_update_flush_pending || self.received_close_notify {
                        continue;
                    }
                }
            }
            match self.poll_read_inner(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(self.eof_outcome()),
                Poll::Ready(Ok(_)) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Maximum write buffer size before applying back-pressure (256 KB).
const MAX_WRITE_BUF: usize = 256 * 1024;

impl<S: TlsTransport> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS stream is closed",
            )));
        }

        // Back-pressure: if the write buffer is already large, try to drain
        // it first before accepting more data.
        if self.write_buf.len() >= MAX_WRITE_BUF {
            let this = &mut *self;
            flush_write_buf(
                &mut this.inner,
                &mut this.write_buf,
                &mut this.pending_key_update_bytes,
                cx,
            )?;
            if self.write_buf.len() >= MAX_WRITE_BUF {
                return Poll::Pending;
            }
        }

        let records = self
            .writer
            .write_record(content_type::APPLICATION_DATA, buf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.key_update_without_application_write = false;

        if records.is_empty() {
            return Poll::Ready(Ok(buf.len()));
        }

        self.write_buf.extend_from_slice(&records);

        let this = &mut *self;
        flush_write_buf(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.pending_key_update_bytes,
            cx,
        )?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.read_failure.is_some() {
            return self.poll_read_failure(cx);
        }
        let coalesced = self.writer.flush();
        if !coalesced.is_empty() {
            self.write_buf.extend_from_slice(&coalesced);
        }

        let this = &mut *self;
        flush_write_buf(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.pending_key_update_bytes,
            cx,
        )?;
        if !this.write_buf.is_empty() {
            return Poll::Pending;
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.read_failure.is_some() {
            if self.poll_read_failure(cx).is_pending() {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(()));
        }
        if !self.closed {
            self.closed = true;
            let close_notify: &[u8] = &[0x01, 0x00];
            if let Ok(alert_record) = self.writer.write_record(content_type::ALERT, close_notify) {
                self.write_buf.extend_from_slice(&alert_record);
            }
        }

        let coalesced = self.writer.flush();
        if !coalesced.is_empty() {
            self.write_buf.extend_from_slice(&coalesced);
        }

        let this = &mut *self;
        flush_write_buf(
            &mut this.inner,
            &mut this.write_buf,
            &mut this.pending_key_update_bytes,
            cx,
        )?;
        if !this.write_buf.is_empty() {
            return Poll::Pending;
        }

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

/// Try to flush a write buffer to a transport stream.
fn flush_write_buf<S: TlsTransport>(
    stream: &mut S,
    write_buf: &mut Vec<u8>,
    pending_key_update_bytes: &mut usize,
    cx: &mut Context<'_>,
) -> io::Result<()> {
    flush_write_buf_prefix(stream, write_buf, pending_key_update_bytes, 0, cx)
}

fn flush_write_buf_prefix<S: TlsTransport>(
    stream: &mut S,
    write_buf: &mut Vec<u8>,
    pending_key_update_bytes: &mut usize,
    retained_tail: usize,
    cx: &mut Context<'_>,
) -> io::Result<()> {
    while write_buf.len() > retained_tail {
        let end = write_buf.len() - retained_tail;
        match Pin::new(&mut *stream).poll_write(cx, &write_buf[..end]) {
            Poll::Ready(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS transport accepted no queued bytes",
                ))
            }
            Poll::Ready(Ok(n)) => {
                write_buf.drain(..n);
                *pending_key_update_bytes = pending_key_update_bytes.saturating_sub(n);
            }
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => break,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-handshake message framing
// ---------------------------------------------------------------------------

/// `HelloRequest` (RFC 5246 §7.4.1.1). TLS 1.2 only; TLS 1.3 has no such
/// post-handshake message.
const HELLO_REQUEST: u8 = 0x00;

/// `legacy_version` for TLS 1.3; anything below it takes the TLS 1.2 path.
const TLS13_VERSION: u16 = 0x0304;

/// Upper bound on a partially-received post-handshake handshake message.
///
/// `NewSessionTicket` and `KeyUpdate` are small — even a large ticket is a few
/// KiB. The 3-byte handshake length field allows up to 16 MiB, so without a cap
/// a peer could pin that much memory per connection by announcing a huge
/// message and then dribbling bytes.
const MAX_POST_HANDSHAKE_MSG_LEN: usize = 64 * 1024;

fn take_post_handshake_message(buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let length = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    if length > MAX_POST_HANDSHAKE_MSG_LEN {
        return Err(io::Error::other(format!("post-handshake message length {length} exceeds the {MAX_POST_HANDSHAKE_MSG_LEN} byte limit")));
    }
    let end = 4 + length;
    if end > buf.len() {
        return Ok(None);
    }
    Ok(Some(buf.drain(..end).collect()))
}

/// Drain every *complete* handshake message from `buf`, leaving any partial
/// trailer behind for the next record.
///
/// Post-handshake messages obey handshake framing (RFC 8446 §5.1): a record may
/// carry several coalesced messages, and one message may span several records.
#[cfg(test)]
fn split_post_handshake_messages(buf: &mut Vec<u8>) -> io::Result<Vec<Vec<u8>>> {
    let mut messages = Vec::new();
    while let Some(message) = take_post_handshake_message(buf)? {
        messages.push(message);
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        chunks: std::collections::VecDeque<Vec<u8>>,
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
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls += 1;
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

    fn app_data_record(body: &[u8]) -> Vec<u8> {
        record(content_type::APPLICATION_DATA, body)
    }

    fn mock_stream(chunks: Vec<Vec<u8>>, require_close_notify: bool) -> TlsStream<MockTransport> {
        TlsStream {
            inner: MockTransport {
                chunks: chunks.into(),
                polls: 0,
                written: Vec::new(),
                ..MockTransport::default()
            },
            reader: RecordReader::new(),
            writer: RecordWriter::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            closed: false,
            read_failure: None,
            client_style: TlsClientHelloStyle::Generic,
            key_update_flush_pending: false,
            consecutive_key_updates: 0,
            pending_key_update_bytes: 0,
            pending_key_update_record_len: 0,
            key_update_without_application_write: false,
            negotiated_alpn: None,
            negotiated_cipher_suite: None,
            negotiated_version: None,
            peer_certificates: Vec::new(),
            post_handshake: None,
            session_ticket_ctx: None,
            post_handshake_buf: Vec::new(),
            received_close_notify: false,
            require_close_notify,
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

    #[test]
    fn repeated_requests_do_not_rotate_an_unused_browser_write_key() {
        for style in [
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            let mut stream = mock_stream(Vec::new(), false);
            stream.client_style = style;
            stream.post_handshake = Some(mock_post_handshake_state());
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 1])
                .unwrap();
            let first_secret = stream
                .post_handshake
                .as_ref()
                .unwrap()
                .client_app_secret
                .clone();
            let first_reply = stream.write_buf.clone();
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 1])
                .unwrap();
            assert_eq!(
                stream.post_handshake.as_ref().unwrap().client_app_secret,
                first_secret
            );
            assert_eq!(stream.write_buf, first_reply);
        }
    }

    #[test]
    fn chromium_key_update_limit_precedes_validation_without_rotating_rejected_keys() {
        let mut stream = mock_stream(Vec::new(), false);
        stream.client_style = TlsClientHelloStyle::ChromiumBoringssl;
        stream.post_handshake = Some(mock_post_handshake_state());
        for _ in 0..32 {
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 0])
                .unwrap();
        }
        let secret = stream
            .post_handshake
            .as_ref()
            .unwrap()
            .server_app_secret
            .clone();
        assert!(stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 2])
            .is_err());
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().server_app_secret,
            secret
        );
        assert_eq!(stream.consecutive_key_updates, 32);
        assert!(stream.write_buf.ends_with(&[2, 10]));
    }

    #[tokio::test]
    async fn chromium_reply_suppression_ends_at_the_ku_record_not_the_entire_write_queue() {
        let mut stream = mock_stream(Vec::new(), false);
        stream.client_style = TlsClientHelloStyle::ChromiumBoringssl;
        stream.post_handshake = Some(mock_post_handshake_state());
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        let first_secret = stream
            .post_handshake
            .as_ref()
            .unwrap()
            .client_app_secret
            .clone();
        stream.inner.write_actions = [WriteAction::Limit(3), WriteAction::Pending].into();
        stream.write_all(b"queued").await.unwrap();
        assert_eq!(stream.pending_key_update_bytes, 7);
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().client_app_secret,
            first_secret
        );
        stream.inner.write_actions = [WriteAction::Limit(7), WriteAction::Pending].into();
        let pending = std::future::poll_fn(|cx| {
            Poll::Ready(AsyncWrite::poll_flush(Pin::new(&mut stream), cx))
        })
        .await;
        assert!(pending.is_pending());
        assert_eq!(stream.pending_key_update_bytes, 0);
        assert!(!stream.write_buf.is_empty());
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert_ne!(
            stream.post_handshake.as_ref().unwrap().client_app_secret,
            first_secret
        );
        assert_eq!(stream.pending_key_update_bytes, stream.write_buf.len());
        stream.flush().await.unwrap();
        assert_eq!(stream.pending_key_update_bytes, 0);
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
        stream.client_style = TlsClientHelloStyle::FirefoxNss;
        stream.post_handshake = Some(mock_post_handshake_state());
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        stream.flush().await.unwrap();
        let first_secret = stream
            .post_handshake
            .as_ref()
            .unwrap()
            .client_app_secret
            .clone();
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert!(stream.write_buf.is_empty());
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().client_app_secret,
            first_secret
        );
        assert_eq!(stream.inner.written.len(), 10);
        stream.write_all(b"next").await.unwrap();
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        assert_ne!(
            stream.post_handshake.as_ref().unwrap().client_app_secret,
            first_secret
        );
        assert!(stream.key_update_flush_pending);
        assert_eq!(stream.write_buf.len(), 27);
    }

    #[test]
    fn malformed_key_update_does_not_change_either_traffic_secret() {
        for style in [
            TlsClientHelloStyle::Generic,
            TlsClientHelloStyle::ChromiumBoringssl,
            TlsClientHelloStyle::FirefoxNss,
        ] {
            let enum_alert = if style == TlsClientHelloStyle::Generic {
                47
            } else {
                50
            };
            let cases = [
                (vec![24, 0, 0, 0], 50),
                (vec![24, 0, 0, 2, 1, 0], 50),
                (vec![24, 0, 0, 1, 2], enum_alert),
                (vec![24, 0, 0, 1, 0, 24, 0, 0, 1, 0], 10),
                (vec![24, 0, 0, 1, 0, 4], 10),
                (vec![24, 0, 0, 1, 0, 4, 0xff, 0xff, 0xff], 10),
                (vec![24, 0, 0, 1, 2, 24, 0, 0, 1, 0], enum_alert),
            ];
            for (message, expected) in cases {
                let mut stream = mock_stream(Vec::new(), false);
                stream.client_style = style;
                stream.post_handshake = Some(mock_post_handshake_state());
                assert!(stream.handle_post_handshake_record(&message).is_err());
                assert_eq!(
                    stream.post_handshake.as_ref().unwrap().server_app_secret,
                    vec![0x22; 32]
                );
                assert_eq!(
                    stream.post_handshake.as_ref().unwrap().client_app_secret,
                    vec![0x33; 32]
                );
                assert!(stream.write_buf.ends_with(&[2, expected]));
                assert!(!stream.key_update_flush_pending);
            }
        }
    }

    #[tokio::test]
    async fn chromium_browser_flush_keeps_idle_ku_but_flushes_accepted_application_prefix() {
        for prefix in [Vec::new(), app_data_record(b"accepted")] {
            let mut stream = mock_stream(Vec::new(), false);
            stream.client_style = TlsClientHelloStyle::ChromiumBoringssl;
            stream.post_handshake = Some(mock_post_handshake_state());
            stream.write_buf = prefix.clone();
            stream
                .handle_post_handshake_record(&[24, 0, 0, 1, 1])
                .unwrap();
            stream.inner.write_actions = [WriteAction::Limit(2), WriteAction::Pending].into();
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_flush(cx))
                .await
                .unwrap();
            assert_eq!(stream.inner.written, prefix);
            assert_eq!(stream.pending_key_update_bytes, 10);
            assert_eq!(stream.write_buf.len(), 10);
            stream.flush().await.unwrap();
            assert_eq!(&stream.inner.written[prefix.len() + 5..], &[24, 0, 0, 1, 0]);
        }
    }

    #[tokio::test]
    async fn chromium_browser_shutdown_discards_only_an_unsent_trailing_key_update() {
        for prefix in [Vec::new(), app_data_record(b"accepted")] {
            let mut stream = mock_stream(Vec::new(), false);
            stream.client_style = TlsClientHelloStyle::ChromiumBoringssl;
            stream.post_handshake = Some(mock_post_handshake_state());
            stream.write_buf = prefix.clone();
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
            assert!(stream.closed && stream.write_buf.is_empty());
            assert_eq!(stream.pending_key_update_bytes, 0);
            assert_eq!(
                stream.write(b"late").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        let mut explicit = mock_stream(Vec::new(), false);
        explicit.client_style = TlsClientHelloStyle::ChromiumBoringssl;
        explicit.shutdown().await.unwrap();
        assert_eq!(&explicit.inner.written[5..], &[1, 0]);
    }

    #[tokio::test]
    async fn chromium_browser_shutdown_preserves_partial_ku_and_dependent_application_data() {
        for partial in [false, true] {
            let mut stream = mock_stream(Vec::new(), false);
            stream.client_style = TlsClientHelloStyle::ChromiumBoringssl;
            stream.post_handshake = Some(mock_post_handshake_state());
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
                assert_eq!(stream.pending_key_update_bytes, 7);
            } else {
                stream.inner.write_actions = [WriteAction::Pending].into();
                stream.write_all(b"after").await.unwrap();
            }
            let expected = [stream.inner.written.as_slice(), stream.write_buf.as_slice()].concat();
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_shutdown(cx))
                .await
                .unwrap();
            assert_eq!(stream.inner.written, expected);
            assert_eq!(stream.pending_key_update_bytes, 0);
            assert!(stream.closed);
        }
    }

    #[tokio::test]
    async fn browser_shutdown_still_flushes_terminal_alerts() {
        let mut stream = mock_stream(Vec::new(), false);
        stream.client_style = TlsClientHelloStyle::ChromiumBoringssl;
        stream.post_handshake = Some(mock_post_handshake_state());
        stream
            .handle_post_handshake_record(&[24, 0, 0, 1, 1])
            .unwrap();
        let error = stream.post_handshake_alert(
            lktls::error::AlertDescription::RecordOverflow,
            "oversized record",
        );
        stream.fail_read(error);
        let expected = stream.write_buf.clone();
        std::future::poll_fn(|cx| Pin::new(&mut stream).poll_browser_shutdown(cx))
            .await
            .unwrap();
        assert_eq!(stream.inner.written, expected);
        assert_eq!(stream.inner.shutdown_calls, 1);
        assert!(stream.read(&mut [0; 1]).await.is_err());
    }

    #[test]
    fn fragmented_key_update_changes_keys_only_at_the_completed_record_boundary() {
        let mut stream = mock_stream(Vec::new(), false);
        stream.post_handshake = Some(mock_post_handshake_state());
        stream.handle_post_handshake_record(&[24, 0]).unwrap();
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().server_app_secret,
            vec![0x22; 32]
        );
        stream.handle_post_handshake_record(&[0, 1, 0]).unwrap();
        let expected = lktls::crypto::hkdf::hkdf_expand_label(
            lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            &[0x22; 32],
            "traffic upd",
            &[],
            32,
        )
        .unwrap();
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().server_app_secret,
            expected
        );
        assert_eq!(
            stream.post_handshake.as_ref().unwrap().client_app_secret,
            vec![0x33; 32]
        );
        assert!(stream.post_handshake_buf.is_empty());
        assert!(stream.write_buf.is_empty());
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
            stream.client_style = style;
            stream.post_handshake = Some(mock_post_handshake_state());
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
                assert!(stream.write_buf.is_empty());
                assert!(!stream.key_update_flush_pending);
            } else {
                assert!(stream.inner.written.is_empty());
                assert_eq!(stream.write_buf, response);
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
        stream.client_style = TlsClientHelloStyle::FirefoxNss;
        stream.post_handshake = Some(mock_post_handshake_state());
        stream.inner.write_actions = [WriteAction::Limit(0)].into();
        let error =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert!(stream.closed && stream.write_buf.is_empty());
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
            stream.client_style = TlsClientHelloStyle::FirefoxNss;
            stream.post_handshake = Some(mock_post_handshake_state());
            stream.inner.write_actions = [WriteAction::Pending].into();
            let pending = std::future::poll_fn(|cx| {
                let mut bytes = [0; 1];
                let mut buffer = ReadBuf::new(&mut bytes);
                Poll::Ready(AsyncRead::poll_read(Pin::new(&mut stream), cx, &mut buffer))
            })
            .await;
            assert!(pending.is_pending());
            assert!(stream.key_update_flush_pending);
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
        assert!(stream.received_close_notify);
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
        assert!(stream.write_buf.is_empty());
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
            assert!(stream.write_buf.is_empty());
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
            assert!(stream.write_buf.is_empty());
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
        stream.write_buf = stream
            .writer
            .write_record(content_type::APPLICATION_DATA, b"queued")
            .unwrap();
        stream.inner.write_actions = [WriteAction::Limit(3), WriteAction::Pending].into();
        assert!(stream.read(&mut [0; 1]).await.is_err());
        assert_eq!(&stream.inner.written[..5], &[23, 3, 1, 0, 6]);
        assert_eq!(&stream.inner.written[5..11], b"queued");
        assert_eq!(&stream.inner.written[11..], &[21, 3, 3, 0, 2, 2, 10]);
        assert!(stream.write_buf.is_empty());
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
        stream.negotiated_version = Some(version);
        stream
    }

    /// Read whatever the stream queued for the peer.
    /// Everything that actually reached the peer, plus anything still queued.
    fn written_bytes(stream: &TlsStream<MockTransport>) -> Vec<u8> {
        let mut out = stream.inner_stream().written.clone();
        out.extend_from_slice(&stream.write_buf);
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

    /// TLS 1.3 has no `HelloRequest`, and BoringSSL routes >= 1.3 to a different
    /// post-handshake path entirely. Leave that path alone rather than guessing
    /// at an alert we have not verified.
    #[tokio::test]
    async fn tls13_does_not_take_the_renegotiation_path() {
        let hello_request = handshake_record(&[0x00, 0x00, 0x00, 0x00]);
        let mut stream = stream_at_version(0x0304, vec![hello_request]);

        let mut body = Vec::new();
        stream
            .read_to_end(&mut body)
            .await
            .expect("TLS 1.3 keeps the previous ignore behaviour");

        assert!(
            written_bytes(&stream).is_empty(),
            "no alert should be queued on the TLS 1.3 path"
        );
    }

    /// A HelloRequest arriving before a version is known must not trip the
    /// refusal either — `negotiated_version` is `None` only if the handshake
    /// never recorded one.
    #[tokio::test]
    async fn unknown_version_keeps_the_previous_behaviour() {
        let hello_request = handshake_record(&[0x00, 0x00, 0x00, 0x00]);
        let mut stream = mock_stream(vec![hello_request], false);
        assert!(stream.negotiated_version.is_none());

        stream
            .read_to_end(&mut Vec::new())
            .await
            .expect("an unknown version must not abort");
        assert!(written_bytes(&stream).is_empty());
    }
}
