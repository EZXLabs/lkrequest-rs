//! Async connection driver — bridges the Sans-I/O `H2Engine` with Tokio I/O.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐    mpsc     ┌─────────────────────┐
//! │NativeSendReq │ ──────────► │  ConnectionDriver   │
//! │  (cloneable) │    cmds     │  ┌───────────────┐  │ ◄── TLS read
//! └──────────────┘             │  │   H2Engine    │  │ ──► TLS write
//!                              │  └───────────────┘  │
//!                              └─────────────────────┘
//! ```

use crate::engine::{H2Engine, H2Event};
use crate::frame::H2Frame;
use crate::policy::{FrameWritePolicy, H2Behavior};
use crate::profile::H2Profile;
use bytes::{Buf, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

// ─── Channel messages ────────────────────────────────────────────────────────

/// Command sent from NativeSendRequest to the driver task.
#[derive(Debug)]
pub(crate) enum DriverCommand {
    SendRequest {
        request_id: u64,
        request: Box<http::Request<Option<Bytes>>>,
        /// Sends back the response headers.
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        /// Sends body chunks as they arrive; dropped when stream ends.
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
    #[allow(dead_code)]
    SendNativeRequest {
        request_id: u64,
        request: Box<crate::adapter::NativeH2Request>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
    #[allow(dead_code)]
    Shutdown,
}

/// Response headers from the native engine.
#[derive(Debug, Clone)]
pub struct NativeResponseHeaders {
    pub status: u16,
    pub headers: http::HeaderMap,
}

// ─── First Request (piggybacked on connection setup) ─────────────────────────

/// First request to send immediately after the connection preface.
///
/// By passing this into the driver at spawn time, the HEADERS frame is
/// written in the same async task as the preface — back-to-back,
/// guaranteeing they land in separate TLS records (matching Chrome).
pub struct FirstRequest {
    pub request: http::Request<Option<Bytes>>,
    pub headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
    pub body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
}

/// Channels returned to the caller for the piggybacked first request.
pub struct FirstRequestResponse {
    pub headers_rx: oneshot::Receiver<Result<NativeResponseHeaders, DriverError>>,
    pub body_rx: mpsc::UnboundedReceiver<Result<Bytes, DriverError>>,
}

impl FirstRequest {
    /// Build a `FirstRequest` + `FirstRequestResponse` pair from an
    /// `http::Request<Option<Bytes>>`.
    pub fn new(request: http::Request<Option<Bytes>>) -> (Self, FirstRequestResponse) {
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        (
            Self {
                request,
                headers_tx,
                body_tx,
            },
            FirstRequestResponse {
                headers_rx,
                body_rx,
            },
        )
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DriverError {
    Io(String),
    Protocol(String),
    StreamReset(u32),
    GoAway(String),
    Shutdown,
    ChannelClosed,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::StreamReset(code) => write!(f, "stream reset: error_code={code}"),
            Self::GoAway(msg) => write!(f, "GOAWAY: {msg}"),
            Self::Shutdown => write!(f, "connection shut down"),
            Self::ChannelClosed => write!(f, "channel closed"),
        }
    }
}

impl std::error::Error for DriverError {}

impl From<std::io::Error> for DriverError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── NativeSendRequest ───────────────────────────────────────────────────────

/// Runtime controls for the native HTTP/2 connection driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2DriverConfig {
    /// Maximum requests that may wait for a remote stream slot.
    ///
    /// None keeps the default unbounded queue. A positive value applies
    /// asynchronous backpressure before additional requests enter the driver.
    pub max_pending_requests: Option<usize>,

    /// Maximum ready request commands drained before dispatching writes.
    ///
    /// The default of one preserves the existing fingerprint-sensitive
    /// scheduling. Larger values reduce driver wakeups without changing frame
    /// grouping or explicitly concatenating writes.
    pub max_ready_commands_per_turn: usize,

    /// Maximum requests encoded into one socket write.
    ///
    /// The default of one preserves frame-group write boundaries. Values above
    /// one are an explicit throughput mode and may change TLS record and TCP
    /// segmentation behavior.
    pub max_requests_per_write: usize,

    /// Maximum encoded bytes accumulated for one socket write.
    pub max_write_batch_bytes: usize,
}

impl Default for H2DriverConfig {
    fn default() -> Self {
        Self {
            max_pending_requests: None,
            max_ready_commands_per_turn: 1,
            max_requests_per_write: 1,
            max_write_batch_bytes: 64 * 1024,
        }
    }
}

/// Cloneable handle to send HTTP/2 requests through a native H2 connection.
#[derive(Clone)]
pub struct NativeSendRequest {
    cmd_tx: mpsc::Sender<DriverCommand>,
    cancel_tx: mpsc::UnboundedSender<u64>,
    next_request_id: Arc<AtomicU64>,
    pending_slots: Option<Arc<Semaphore>>,
}

struct RequestCancelGuard {
    request_id: u64,
    cancel_tx: mpsc::UnboundedSender<u64>,
    armed: bool,
}

impl RequestCancelGuard {
    fn new(request_id: u64, cancel_tx: mpsc::UnboundedSender<u64>) -> Self {
        Self {
            request_id,
            cancel_tx,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RequestCancelGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cancel_tx.send(self.request_id);
        }
    }
}

impl NativeSendRequest {
    async fn acquire_pending_permit(&self) -> Result<Option<OwnedSemaphorePermit>, DriverError> {
        match &self.pending_slots {
            Some(slots) => Arc::clone(slots)
                .acquire_owned()
                .await
                .map(Some)
                .map_err(|_| DriverError::Shutdown),
            None => Ok(None),
        }
    }

    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Check that the connection is alive.
    pub async fn ready(&mut self) -> Result<(), DriverError> {
        if self.cmd_tx.is_closed() {
            return Err(DriverError::Shutdown);
        }
        Ok(())
    }

    /// Send a request and receive a streaming response.
    ///
    /// Returns `(NativeResponseHeaders, mpsc::UnboundedReceiver<Result<Bytes, DriverError>>)`.
    /// The receiver yields body chunks; when it returns `None` the body is complete.
    pub async fn send_request(
        &mut self,
        request: http::Request<Option<Bytes>>,
    ) -> Result<
        (
            NativeResponseHeaders,
            mpsc::UnboundedReceiver<Result<Bytes, DriverError>>,
        ),
        DriverError,
    > {
        let pending_permit = self.acquire_pending_permit().await?;
        let request_id = self.next_request_id();
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();

        let cmd = DriverCommand::SendRequest {
            request_id,
            request: Box::new(request),
            headers_tx,
            body_tx,
            pending_permit,
        };

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| DriverError::ChannelClosed)?;

        let mut cancel_guard = RequestCancelGuard::new(request_id, self.cancel_tx.clone());
        let response = headers_rx.await.map_err(|_| DriverError::ChannelClosed)?;
        cancel_guard.disarm();
        let resp_headers = response?;

        Ok((resp_headers, body_rx))
    }

    /// Send a request using a pre-ordered `NativeH2Request` and receive a streaming response.
    pub(crate) async fn send_native_request(
        &mut self,
        request: crate::adapter::NativeH2Request,
    ) -> Result<
        (
            NativeResponseHeaders,
            mpsc::UnboundedReceiver<Result<Bytes, DriverError>>,
        ),
        DriverError,
    > {
        let pending_permit = self.acquire_pending_permit().await?;
        let request_id = self.next_request_id();
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();

        let cmd = DriverCommand::SendNativeRequest {
            request_id,
            request: Box::new(request),
            headers_tx,
            body_tx,
            pending_permit,
        };

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| DriverError::ChannelClosed)?;

        let mut cancel_guard = RequestCancelGuard::new(request_id, self.cancel_tx.clone());
        let response = headers_rx.await.map_err(|_| DriverError::ChannelClosed)?;
        cancel_guard.disarm();
        let resp_headers = response?;

        Ok((resp_headers, body_rx))
    }
}

impl fmt::Debug for NativeSendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSendRequest").finish()
    }
}

// ─── Pending response state ─────────────────────────────────────────────────

struct PendingStream {
    upload: Option<PendingUpload>,
    // Keep cancellation alive after upload EOF, until the response is released.
    cancelled: Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>,
    /// Sends response headers (used once, then becomes None).
    headers_tx: Option<oneshot::Sender<Result<NativeResponseHeaders, DriverError>>>,
    /// Streams body data chunks to the consumer.
    body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
    /// Method of the request this stream carries. Decides whether the response
    /// is defined to have content (RFC 9110 §6.4.1), which in turn decides
    /// whether the RFC 9113 §8.1.1 content-length check applies.
    method: http::Method,
    /// `content-length` bookkeeping, populated once the final response headers
    /// declare one for a response that is defined to have content.
    content_length: Option<ContentLengthCheck>,
}

impl PendingStream {
    fn new(
        method: http::Method,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
    ) -> Self {
        Self {
            upload: None,
            cancelled: None,
            headers_tx: Some(headers_tx),
            body_tx,
            method,
            content_length: None,
        }
    }
}

pub(crate) struct PendingUpload {
    source: crate::adapter::UploadStream,
    chunk: Bytes,
}

impl PendingUpload {
    pub(crate) fn new(source: crate::adapter::UploadStream) -> Self {
        Self {
            source,
            chunk: Bytes::new(),
        }
    }
}

impl fmt::Debug for PendingUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingUpload")
            .field("buffered_bytes", &self.chunk.len())
            .finish_non_exhaustive()
    }
}

enum UploadAction {
    Data(Bytes),
    End,
    Failed(DriverError),
    Cancel,
}

fn poll_uploads(
    pending: &mut HashMap<u32, PendingStream>,
    engine: &H2Engine,
    context: &mut Context<'_>,
    allow_data: bool,
) -> Poll<(u32, UploadAction)> {
    // Cancellation must progress even with no peer window or a blocked writer.
    for (&stream_id, response) in pending.iter_mut() {
        let Some(cancelled) = response.cancelled.as_mut() else {
            continue;
        };
        if response.body_tx.is_closed() || cancelled.as_mut().poll(context).is_ready() {
            return Poll::Ready((stream_id, UploadAction::Cancel));
        }
    }
    if !allow_data {
        return Poll::Pending;
    }
    for (&stream_id, response) in pending.iter_mut() {
        let Some(upload) = response.upload.as_mut() else {
            continue;
        };
        let capacity = engine.upload_capacity(stream_id);
        if upload.chunk.is_empty() {
            match upload.source.as_mut().poll_next(context) {
                Poll::Pending => continue,
                Poll::Ready(None) => return Poll::Ready((stream_id, UploadAction::End)),
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready((stream_id, UploadAction::Failed(error.into())))
                }
                Poll::Ready(Some(Ok(chunk))) => upload.chunk = chunk,
            }
        }
        if capacity == 0 && !upload.chunk.is_empty() {
            continue;
        }
        let count = capacity.min(upload.chunk.len());
        return Poll::Ready((stream_id, UploadAction::Data(upload.chunk.split_to(count))));
    }
    Poll::Pending
}

/// Running comparison of a response's declared `content-length` against the
/// sum of its DATA frame payload lengths (RFC 9113 §8.1.1).
struct ContentLengthCheck {
    expected: u64,
    received: u64,
}

impl ContentLengthCheck {
    fn mismatch_reason(&self) -> String {
        format!(
            "content-length {} does not match the {} DATA byte(s) received (RFC 9113 §8.1.1)",
            self.expected, self.received
        )
    }
}

#[derive(Debug)]
enum QueuedRequest {
    Request {
        request_id: u64,
        request: Box<http::Request<Option<Bytes>>>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
    NativeRequest {
        request_id: u64,
        request: Box<crate::adapter::NativeH2Request>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
}

impl QueuedRequest {
    fn is_canceled(&self) -> bool {
        match self {
            Self::Request {
                headers_tx,
                body_tx,
                ..
            }
            | Self::NativeRequest {
                headers_tx,
                body_tx,
                ..
            } => headers_tx.is_closed() && body_tx.is_closed(),
        }
    }

    fn request_id(&self) -> u64 {
        match self {
            Self::Request { request_id, .. } | Self::NativeRequest { request_id, .. } => {
                *request_id
            }
        }
    }
}

// ─── Driver ──────────────────────────────────────────────────────────────────

/// Spawn the connection driver task with default behaviour.
pub async fn spawn_driver<S>(
    stream: S,
    profile: &H2Profile,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_config(stream, profile, H2DriverConfig::default()).await
}

/// Spawn the connection driver task with runtime queue configuration.
pub async fn spawn_driver_with_config<S>(
    stream: S,
    profile: &H2Profile,
    config: H2DriverConfig,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request_and_config(stream, profile, None, None, config).await
}

/// Spawn the connection driver task with custom behaviour.
pub async fn spawn_driver_with_behavior<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request_and_config(
        stream,
        profile,
        behavior,
        None,
        H2DriverConfig::default(),
    )
    .await
}

/// Spawn the connection driver with an optional first request that is
/// written back-to-back with the connection preface (matching Chrome).
///
/// The caller creates a FirstRequest via FirstRequest::new() and keeps the
/// corresponding FirstRequestResponse to await the result.
pub async fn spawn_driver_with_first_request<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
    first_request: Option<FirstRequest>,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request_and_config(
        stream,
        profile,
        behavior,
        first_request,
        H2DriverConfig::default(),
    )
    .await
}

/// Spawn the connection driver with fingerprint behaviour, an optional first
/// request, and runtime pending-request backpressure configuration.
pub async fn spawn_driver_with_first_request_and_config<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
    first_request: Option<FirstRequest>,
    config: H2DriverConfig,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if config.max_pending_requests == Some(0) {
        return Err(DriverError::Protocol(
            "max_pending_requests must be greater than zero".into(),
        ));
    }
    if config.max_ready_commands_per_turn == 0 {
        return Err(DriverError::Protocol(
            "max_ready_commands_per_turn must be greater than zero".into(),
        ));
    }
    if config.max_requests_per_write == 0 {
        return Err(DriverError::Protocol(
            "max_requests_per_write must be greater than zero".into(),
        ));
    }
    if config.max_write_batch_bytes == 0 {
        return Err(DriverError::Protocol(
            "max_write_batch_bytes must be greater than zero".into(),
        ));
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<DriverCommand>(64);
    let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();
    let pending_slots = config
        .max_pending_requests
        .map(|max| Arc::new(Semaphore::new(max)));

    let behavior = behavior.unwrap_or_else(H2Behavior::default_behavior);
    let max_data_frame_payload = behavior.write_policy.max_data_frame_payload();

    tracing::info!(
        write_policy = ?behavior.write_policy,
        flow_control = ?behavior.flow_control,
        hpack_policy = ?behavior.hpack_policy,
        max_data_frame_payload = ?max_data_frame_payload,
        max_pending_requests = ?config.max_pending_requests,
        max_ready_commands_per_turn = config.max_ready_commands_per_turn,
        max_requests_per_write = config.max_requests_per_write,
        max_write_batch_bytes = config.max_write_batch_bytes,
        "h2.native.behavior_applied"
    );

    let (engine, preface_frames) = H2Engine::client_with_policies(
        profile,
        behavior.flow_control.box_clone(),
        Some(behavior.hpack_policy.box_clone()),
        max_data_frame_payload,
    );

    let write_policy = behavior.write_policy;
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), DriverError>>();

    let handle = tokio::spawn(driver_loop(
        stream,
        engine,
        preface_frames,
        DriverRuntime {
            cmd_rx,
            cancel_rx,
            write_policy,
            ready_tx,
            first_request,
            pending_slots: pending_slots.clone(),
            max_ready_commands_per_turn: config.max_ready_commands_per_turn,
            max_requests_per_write: config.max_requests_per_write,
            max_write_batch_bytes: config.max_write_batch_bytes,
        },
    ));

    ready_rx
        .await
        .map_err(|_| DriverError::ChannelClosed)?
        .map_err(|e| DriverError::Io(e.to_string()))?;

    Ok((
        NativeSendRequest {
            cmd_tx,
            cancel_tx,
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending_slots,
        },
        handle,
    ))
}

struct DriverRuntime {
    cmd_rx: mpsc::Receiver<DriverCommand>,
    cancel_rx: mpsc::UnboundedReceiver<u64>,
    write_policy: Box<dyn FrameWritePolicy>,
    ready_tx: oneshot::Sender<Result<(), DriverError>>,
    first_request: Option<FirstRequest>,
    pending_slots: Option<Arc<Semaphore>>,
    max_ready_commands_per_turn: usize,
    max_requests_per_write: usize,
    max_write_batch_bytes: usize,
}

struct PendingSlotsCloseGuard(Option<Arc<Semaphore>>);

/// Queues encoded writes so socket backpressure cannot block reads or cancellation.
/// Original buffered request batches remain intact; streaming admission waits for
/// pending writes to drain rather than collecting the producer's entire body.
#[derive(Default)]
struct PendingWrites {
    buffers: VecDeque<Bytes>,
    buffered_bytes: usize,
    flushing: bool,
    admitting_buffered_batch: bool,
    control_limit: usize,
}

impl PendingWrites {
    const LIMIT: usize = 1024 * 1024;

    fn is_empty(&self) -> bool {
        self.buffers.is_empty() && !self.flushing
    }

    fn poll_drain<S: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut S,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.flushing {
            std::task::ready!(std::pin::Pin::new(&mut *writer).poll_flush(context))?;
            self.flushing = false;
            if self.buffers.is_empty() {
                self.control_limit = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let Some(buffer) = self.buffers.front_mut() else {
            return Poll::Pending;
        };
        let count = std::task::ready!(std::pin::Pin::new(writer).poll_write(context, buffer))?;
        if count == 0 {
            return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
        }
        buffer.advance(count);
        self.buffered_bytes -= count;
        if buffer.is_empty() {
            self.buffers.pop_front();
            self.flushing = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PendingWrites {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.admitting_buffered_batch
            && self.buffered_bytes.saturating_add(data.len()) > self.control_limit.max(Self::LIMIT)
        {
            return Poll::Ready(Err(std::io::Error::other(
                "H2 pending write limit exceeded",
            )));
        }
        if !data.is_empty() {
            self.buffers.push_back(Bytes::copy_from_slice(data));
            self.buffered_bytes += data.len();
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for PendingSlotsCloseGuard {
    fn drop(&mut self) {
        if let Some(slots) = &self.0 {
            slots.close();
        }
    }
}

async fn driver_loop<S>(
    mut stream: S,
    mut engine: H2Engine,
    preface_frames: Vec<H2Frame>,
    runtime: DriverRuntime,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let DriverRuntime {
        mut cmd_rx,
        mut cancel_rx,
        write_policy,
        ready_tx,
        first_request,
        pending_slots,
        max_ready_commands_per_turn,
        max_requests_per_write,
        max_write_batch_bytes,
    } = runtime;
    let _pending_slots_guard = PendingSlotsCloseGuard(pending_slots);

    // ── Send connection preface ──────────────────────────────────────
    // The 24-byte connection magic is always the first thing on the wire,
    // written together with the first frame group to form a single TLS record
    // (matching Chrome's observed behavior: magic + SETTINGS + WINDOW_UPDATE
    // in one record).
    //
    // Subsequent groups (e.g. PRIORITY frames) get their own TLS records,
    // controlled by the FrameWritePolicy.
    {
        let groups = write_policy.group_frames(preface_frames);
        for (i, group) in groups.into_iter().enumerate() {
            let mut buf = BytesMut::new();
            if i == 0 {
                buf.extend_from_slice(crate::CONNECTION_PREFACE);
            }
            engine.encode_frames(&group, &mut buf);
            if let Err(e) = stream.write_all(&buf).await {
                tracing::error!(error = %e, "h2.native.write_preface_failed");
                let _ = ready_tx.send(Err(DriverError::Io(e.to_string())));
                return;
            }
            if let Err(e) = stream.flush().await {
                tracing::error!(error = %e, "h2.native.flush_preface_failed");
                let _ = ready_tx.send(Err(DriverError::Io(e.to_string())));
                return;
            }
        }
    }
    tracing::debug!("h2.native.preface_sent");

    let mut read_buf = BytesMut::with_capacity(16384);
    let mut pending: HashMap<u32, PendingStream> = HashMap::new();
    let mut waiting: VecDeque<QueuedRequest> = VecDeque::new();

    // ── Write the first request directly after the preface ───────────
    // Real browsers (Chrome) send HEADERS ~40μs after the preface as a
    // separate TLS record, without waiting for the server's SETTINGS.
    //
    // After flush(), the preface TLS record has been written to the OS
    // TCP send buffer. The write_all(HEADERS) below creates a separate
    // TLS record. With TCP_NODELAY enabled (set via TcpFingerprint),
    // the OS sends the preface segment immediately, and HEADERS follows
    // as an independent TCP segment — matching Chrome's behavior.
    if let Some(first_req) = first_request {
        if let Err(e) = write_first_request(
            &mut stream,
            &mut engine,
            &*write_policy,
            &mut pending,
            first_req,
        )
        .await
        {
            let _ = ready_tx.send(Err(e));
            return;
        }
    }

    let _ = ready_tx.send(Ok(()));

    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut stream = PendingWrites::default();

    // ── Main loop ────────────────────────────────────────────────────
    let mut shutdown = false;
    let mut terminating = false;
    let mut cancel_rx_open = true;
    let mut shutdown_deadline: Option<tokio::time::Instant> = None;

    loop {
        let allow_upload_data = stream.is_empty();
        let sleep_fut = async {
            if let Some(deadline) = shutdown_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {

            cancelled = cancel_rx.recv(), if cancel_rx_open => {
                match cancelled {
                    Some(request_id) => {
                        remove_waiting_request(&mut waiting, request_id);
                    }
                    None => cancel_rx_open = false,
                }
            }

            result = reader.read_buf(&mut read_buf), if !terminating => {
                match result {
                    Ok(0) => {
                        let error = DriverError::Io("connection closed".into());
                        notify_all_error(&mut pending, error.clone());
                        notify_waiting_error(&mut waiting, error);
                        break;
                    }
                    Ok(_n) => {
                        let (mut events, outbound_frames) = engine.process(&mut read_buf);
                        let connection_error = events.iter().find_map(|event| match event {
                            H2Event::Error(message) => Some(DriverError::Protocol(format!(
                                "connection error: {message}"
                            ))),
                            _ => None,
                        });

                        if !outbound_frames.is_empty() {
                            let buffered_data = outbound_frames.iter().any(|frame| matches!(frame, H2Frame::Data(_)));
                            stream.admitting_buffered_batch = buffered_data;
                            if let Err(e) = encode_and_write_frames(
                                &mut stream, &engine, &*write_policy, outbound_frames,
                            ).await {
                                let error = DriverError::Io(e.to_string());
                                tracing::error!(error = %error, "h2.native.write_error");
                                notify_all_error(&mut pending, error.clone());
                                notify_waiting_error(&mut waiting, error);
                                break;
                            }
                            stream.admitting_buffered_batch = false;
                            if buffered_data {
                                stream.control_limit = stream.buffered_bytes.saturating_add(PendingWrites::LIMIT);
                            }
                        }

                        let mut resets = Vec::new();
                        let mut completed_uploads = Vec::new();
                        for event in events.drain(..) {
                            let ended_upload = match &event {
                                H2Event::ResponseHeaders { stream_id, end_stream: true, .. }
                                | H2Event::ResponseData { stream_id, end_stream: true, .. }
                                    if pending.get(stream_id).is_some_and(|response| response.upload.is_some()) => Some(*stream_id),
                                _ => None,
                            };
                            handle_event_inner(event, &mut pending, &mut resets);
                            if let Some(stream_id) = ended_upload {
                                if !pending.contains_key(&stream_id) && !resets.contains(&stream_id) {
                                    completed_uploads.push(stream_id);
                                }
                            }
                        }

                        let mut output = BytesMut::new();
                        for stream_id in completed_uploads {
                            engine.send_rst_stream(stream_id, 0, &mut output);
                        }
                        if let Err(error) = write_encoded_buffer(&mut stream, &mut output).await {
                            notify_all_error(&mut pending, error.clone());
                            notify_waiting_error(&mut waiting, error);
                            break;
                        }

                        // RFC 9113 §8.1.1: a malformed response is a stream
                        // error of type PROTOCOL_ERROR, and the RST_STREAM has
                        // to reach the server or it may keep sending DATA on a
                        // stream we have already torn down.
                        if let Err(e) = write_stream_resets(&mut stream, &mut engine, &resets).await
                        {
                            let error = DriverError::Io(e.to_string());
                            tracing::error!(error = %error, "h2.native.rst_stream_write_error");
                            notify_all_error(&mut pending, error.clone());
                            notify_waiting_error(&mut waiting, error);
                            break;
                        }

                        engine.recycle_buffers(events, Vec::new());

                        if let Some(error) = connection_error {
                            tracing::error!(error = %error, "h2.native.connection_error");
                            notify_all_error(&mut pending, error.clone());
                            notify_waiting_error(&mut waiting, error);
                            terminating = true;
                            shutdown = true;
                            shutdown_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
                        }
                    }
                    Err(e) => {
                        let error = DriverError::Io(e.to_string());
                        notify_all_error(&mut pending, error.clone());
                        notify_waiting_error(&mut waiting, error);
                        break;
                    }
                }
            }

            cmd = cmd_rx.recv(), if !shutdown && allow_upload_data => {
                match cmd {
                    Some(command) => {
                        shutdown = queue_driver_command(command, &mut waiting);
                        if !shutdown && max_ready_commands_per_turn > 1 {
                            if !pending.is_empty() {
                                tokio::task::yield_now().await;
                            }
                            for _ in 1..max_ready_commands_per_turn {
                                match cmd_rx.try_recv() {
                                    Ok(command) => {
                                        if queue_driver_command(command, &mut waiting) {
                                            shutdown = true;
                                            break;
                                        }
                                    }
                                    Err(mpsc::error::TryRecvError::Empty) => break,
                                    Err(mpsc::error::TryRecvError::Disconnected) => {
                                        shutdown = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        shutdown = true;
                    }
                }
                if shutdown {
                    if pending.is_empty() && waiting.is_empty() {
                        break;
                    }
                    if shutdown_deadline.is_none() {
                        shutdown_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
                    }
                }
            }

            _ = sleep_fut, if shutdown_deadline.is_some() => {
                tracing::warn!(pending = pending.len(), "h2.native.shutdown_timeout");
                notify_all_error(&mut pending, DriverError::Shutdown);
                notify_waiting_error(&mut waiting, DriverError::Shutdown);
                break;
            }

            (stream_id, action) = std::future::poll_fn(|context| poll_uploads(&mut pending, &engine, context, allow_upload_data)) => {
                let mut output = BytesMut::new();
                match action {
                    UploadAction::Data(data) => engine.send_data(stream_id, data, false, &mut output),
                    UploadAction::End => {
                        if let Some(response) = pending.get_mut(&stream_id) { response.upload = None; }
                        engine.send_data(stream_id, Bytes::new(), true, &mut output);
                    }
                    UploadAction::Failed(error) => {
                        if let Some(response) = pending.remove(&stream_id) {
                            if let Some(headers) = response.headers_tx { let _ = headers.send(Err(error.clone())); }
                            let _ = response.body_tx.send(Err(error));
                        }
                        engine.send_rst_stream(stream_id, 2, &mut output);
                    }
                    UploadAction::Cancel => {
                        pending.remove(&stream_id);
                        engine.send_rst_stream(stream_id, 8, &mut output);
                    }
                }
                if let Err(error) = write_encoded_buffer(&mut stream, &mut output).await {
                    notify_all_error(&mut pending, error.clone());
                    notify_waiting_error(&mut waiting, error);
                    break;
                }
                tokio::task::yield_now().await;
            }

            result = std::future::poll_fn(|context| stream.poll_drain(&mut writer, context)), if !allow_upload_data => {
                if let Err(error) = result {
                    let error = DriverError::Io(error.to_string());
                    notify_all_error(&mut pending, error.clone());
                    notify_waiting_error(&mut waiting, error);
                    break;
                }
            }
        }

        if !stream.is_empty() {
            continue;
        }

        if let Err(error) = dispatch_waiting_requests(
            &mut stream,
            &mut engine,
            &*write_policy,
            &mut pending,
            &mut waiting,
            max_requests_per_write,
            max_write_batch_bytes,
        )
        .await
        {
            tracing::error!(error = %error, "h2.native.write_error");
            notify_all_error(&mut pending, error.clone());
            notify_waiting_error(&mut waiting, error);
            break;
        }

        if !shutdown && max_ready_commands_per_turn > 1 && stream.is_empty() {
            let mut received_request = false;
            for _ in 0..max_ready_commands_per_turn {
                match cmd_rx.try_recv() {
                    Ok(command) => {
                        let waiting_before = waiting.len();
                        if queue_driver_command(command, &mut waiting) {
                            shutdown = true;
                            break;
                        }
                        received_request |= waiting.len() > waiting_before;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        shutdown = true;
                        break;
                    }
                }
            }

            if received_request {
                if let Err(error) = dispatch_waiting_requests(
                    &mut stream,
                    &mut engine,
                    &*write_policy,
                    &mut pending,
                    &mut waiting,
                    max_requests_per_write,
                    max_write_batch_bytes,
                )
                .await
                {
                    tracing::error!(error = %error, "h2.native.write_error");
                    notify_all_error(&mut pending, error.clone());
                    notify_waiting_error(&mut waiting, error);
                    break;
                }
            }

            if shutdown && shutdown_deadline.is_none() {
                shutdown_deadline =
                    Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
            }
        }

        if shutdown && pending.is_empty() && waiting.is_empty() {
            break;
        }
    }

    tracing::debug!("h2.native.driver_exited");
}

fn queue_driver_command(command: DriverCommand, waiting: &mut VecDeque<QueuedRequest>) -> bool {
    let request = match command {
        DriverCommand::SendRequest {
            request_id,
            request,
            headers_tx,
            body_tx,
            pending_permit,
        } => QueuedRequest::Request {
            request_id,
            request,
            headers_tx,
            body_tx,
            pending_permit,
        },
        DriverCommand::SendNativeRequest {
            request_id,
            request,
            headers_tx,
            body_tx,
            pending_permit,
        } => QueuedRequest::NativeRequest {
            request_id,
            request,
            headers_tx,
            body_tx,
            pending_permit,
        },
        DriverCommand::Shutdown => return true,
    };

    if !request.is_canceled() {
        waiting.push_back(request);
    }
    false
}

async fn dispatch_waiting_requests(
    stream: &mut PendingWrites,
    engine: &mut H2Engine,
    write_policy: &dyn FrameWritePolicy,
    pending: &mut HashMap<u32, PendingStream>,
    waiting: &mut VecDeque<QueuedRequest>,
    max_requests_per_write: usize,
    max_write_batch_bytes: usize,
) -> Result<(), DriverError> {
    if engine.is_goaway() {
        notify_waiting_error(
            waiting,
            DriverError::GoAway("connection is draining".into()),
        );
        return Ok(());
    }

    let mut batched_output = BytesMut::new();
    stream.admitting_buffered_batch = true;
    let mut batched_requests = 0usize;
    let mut dispatched_requests = 0usize;

    while engine.can_open_stream() && dispatched_requests < max_requests_per_write {
        let Some(request) = waiting.pop_front() else {
            break;
        };
        if request.is_canceled() {
            continue;
        }

        let stream_id = engine.open_stream();
        dispatched_requests += 1;
        let mut upload = None;
        let (frames, headers_tx, body_tx, pending_permit, method) = match request {
            QueuedRequest::Request {
                request,
                headers_tx,
                body_tx,
                pending_permit,
                ..
            } => {
                let method = request.method().clone();
                (
                    engine.build_request(stream_id, *request),
                    headers_tx,
                    body_tx,
                    pending_permit,
                    method,
                )
            }
            QueuedRequest::NativeRequest {
                mut request,
                headers_tx,
                body_tx,
                pending_permit,
                ..
            } => {
                let method = request.method.clone();
                upload = request.upload.take();
                (
                    engine.build_native_request(stream_id, *request),
                    headers_tx,
                    body_tx,
                    pending_permit,
                    method,
                )
            }
        };
        drop(pending_permit);

        let mut response = PendingStream::new(method, headers_tx, body_tx);
        if upload.is_some() {
            let body_tx = response.body_tx.clone();
            response.cancelled = Some(Box::pin(async move { body_tx.closed().await }));
        }
        response.upload = upload;
        pending.insert(stream_id, response);

        if max_requests_per_write == 1 {
            if let Err(error) = encode_and_write_frames(stream, engine, write_policy, frames).await
            {
                let error = DriverError::Io(error.to_string());
                if let Some(pending_stream) = pending.remove(&stream_id) {
                    if let Some(headers_tx) = pending_stream.headers_tx {
                        let _ = headers_tx.send(Err(error.clone()));
                    }
                    let _ = pending_stream.body_tx.send(Err(error.clone()));
                }
                return Err(error);
            }
            continue;
        }

        for group in write_policy.group_frames(frames) {
            engine.encode_frames(&group, &mut batched_output);
        }
        batched_requests += 1;
        if batched_requests >= max_requests_per_write
            || batched_output.len() >= max_write_batch_bytes
        {
            write_encoded_buffer(stream, &mut batched_output).await?;
            batched_requests = 0;
        }
    }

    write_encoded_buffer(stream, &mut batched_output).await?;

    stream.admitting_buffered_batch = false;
    stream.control_limit = stream.buffered_bytes.saturating_add(PendingWrites::LIMIT);

    Ok(())
}

async fn write_encoded_buffer<S>(stream: &mut S, output: &mut BytesMut) -> Result<(), DriverError>
where
    S: AsyncWrite + Unpin,
{
    if output.is_empty() {
        return Ok(());
    }
    stream
        .write_all(output)
        .await
        .map_err(|error| DriverError::Io(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| DriverError::Io(error.to_string()))?;
    output.clear();
    Ok(())
}

/// Group, encode, and flush frames via write policy.
///
/// Each group returned by `FrameWritePolicy::group_frames` is encoded
/// into a single buffer and issued as one `AsyncWrite` call. The TLS layer
/// may split that write into multiple records when it exceeds its record cap.
async fn encode_and_write_frames<S>(
    stream: &mut S,
    engine: &H2Engine,
    write_policy: &dyn FrameWritePolicy,
    frames: Vec<H2Frame>,
) -> Result<(), std::io::Error>
where
    S: AsyncWrite + Unpin,
{
    let groups = write_policy.group_frames(frames);
    for group in groups {
        let mut output = BytesMut::new();
        engine.encode_frames(&group, &mut output);
        if !output.is_empty() {
            stream.write_all(&output).await?;
            stream.flush().await?;
        }
    }
    Ok(())
}

/// Write the piggybacked first request directly to the stream.
async fn write_first_request<S>(
    stream: &mut S,
    engine: &mut H2Engine,
    write_policy: &dyn FrameWritePolicy,
    pending: &mut HashMap<u32, PendingStream>,
    first_req: FirstRequest,
) -> Result<(), DriverError>
where
    S: AsyncWrite + Unpin,
{
    let stream_id = engine.open_stream();
    let (parts, body) = first_req.request.into_parts();
    let method = parts.method.clone();
    let priority = parts
        .extensions
        .get::<crate::profile::RequestPriority>()
        .copied();
    let native_req = crate::adapter::NativeH2Request::new(
        parts.method,
        parts.uri,
        parts.headers,
        body,
        priority,
    );
    let frames = engine.build_native_request(stream_id, native_req);

    pending.insert(
        stream_id,
        PendingStream::new(method, first_req.headers_tx, first_req.body_tx),
    );

    if let Err(e) = encode_and_write_frames(stream, engine, write_policy, frames).await {
        tracing::error!(error = %e, "h2.native.write_first_request_failed");
        if let Some(ps) = pending.remove(&stream_id) {
            if let Some(tx) = ps.headers_tx {
                let _ = tx.send(Err(DriverError::Io(e.to_string())));
            }
        }
        return Err(DriverError::Io(e.to_string()));
    }

    tracing::debug!(stream_id, "h2.native.first_request_sent");
    Ok(())
}

/// Whether `status` is a 1xx informational (interim) status code.
///
/// Per RFC 9110 §15.2 / RFC 9113 §8.1 an informational response
/// (100 Continue, 103 Early Hints, …) is one or more HEADERS blocks that
/// *precede* the final response — it is never the final response itself. A
/// conforming client must keep reading until a final (non-1xx) HEADERS block
/// arrives.
fn is_interim_status(status: u16) -> bool {
    (100..200).contains(&status)
}

/// Whether a response to `method` with `status` is defined to carry content
/// (RFC 9110 §6.4.1).
///
/// RFC 9113 §8.1.1 exempts these responses from the content-length ↔ DATA-sum
/// equality: a 204, a 304 or the response to a HEAD may legally declare a
/// non-zero `content-length` while sending no DATA at all.
fn response_has_content(method: &http::Method, status: u16) -> bool {
    if method == http::Method::HEAD {
        return false;
    }
    if method == http::Method::CONNECT && (200..300).contains(&status) {
        return false;
    }
    !matches!(status, 204 | 304)
}

/// Fail one stream with a malformed-response protocol error.
///
/// RFC 9113 §8.1.1 makes a malformed response a **stream** error of type
/// PROTOCOL_ERROR, so only this stream is torn down — the connection and every
/// other stream on it keep running. The caller receives
/// `DriverError::Protocol` (never a synthesized status), which is what lets it
/// tell a protocol violation apart from a status the server really sent.
///
/// The stream id is pushed onto `resets` so the driver loop can emit the
/// RST_STREAM §8.1.1 also calls for. This used to write nothing to the wire, on
/// the theory that sending the frame would diverge from the fingerprint. That
/// was backwards: Chromium's netlog runs
/// `HTTP2_SESSION_RECV_INVALID_HEADER` → `HTTP2_SESSION_SEND_RST_STREAM` with
/// PROTOCOL_ERROR, so staying silent is the divergence. Staying silent also
/// leaks: the server may keep sending DATA on a stream we have already torn
/// down, and that stream's flow-control window is never returned.
fn fail_malformed(
    pending: &mut HashMap<u32, PendingStream>,
    stream_id: u32,
    reason: String,
    resets: &mut Vec<u32>,
) {
    let Some(ps) = pending.remove(&stream_id) else {
        return;
    };
    resets.push(stream_id);
    let error = DriverError::Protocol(format!("{}: {reason}", crate::adapter::MALFORMED_PREFIX));
    tracing::debug!(stream_id, error = %error, "h2.native.malformed_response");
    if let Some(tx) = ps.headers_tx {
        let _ = tx.send(Err(error.clone()));
    }
    let _ = ps.body_tx.send(Err(error));
}

/// Encode and write one RST_STREAM(PROTOCOL_ERROR) per malformed stream.
async fn write_stream_resets<S>(
    stream: &mut S,
    engine: &mut H2Engine,
    resets: &[u32],
) -> Result<(), std::io::Error>
where
    S: AsyncWrite + Unpin,
{
    if resets.is_empty() {
        return Ok(());
    }
    let mut output = BytesMut::new();
    for &stream_id in resets {
        engine.send_rst_stream(
            stream_id,
            crate::conn_state::H2ErrorCode::ProtocolError.as_u32(),
            &mut output,
        );
    }
    if !output.is_empty() {
        stream.write_all(&output).await?;
        stream.flush().await?;
    }
    Ok(())
}

/// End-of-stream bookkeeping: enforce RFC 9113 §8.1.1's content-length ↔
/// DATA-sum equality, then drop the stream (dropping `body_tx` signals EOF).
fn finish_stream(pending: &mut HashMap<u32, PendingStream>, stream_id: u32, resets: &mut Vec<u32>) {
    let mismatch = pending.get(&stream_id).and_then(|ps| {
        ps.content_length
            .as_ref()
            .filter(|check| check.received != check.expected)
            .map(ContentLengthCheck::mismatch_reason)
    });
    match mismatch {
        Some(reason) => fail_malformed(pending, stream_id, reason, resets),
        None => {
            pending.remove(&stream_id);
        }
    }
}

/// Dispatch one engine event.
///
/// Returns the streams that need a RST_STREAM(PROTOCOL_ERROR) — normally
/// empty. The driver loop calls [`handle_event_inner`] directly with a shared
/// buffer; this wrapper exists so tests can dispatch a single event without
/// threading one through.
#[cfg(test)]
fn handle_event(event: H2Event, pending: &mut HashMap<u32, PendingStream>) -> Vec<u32> {
    let mut resets = Vec::new();
    handle_event_inner(event, pending, &mut resets);
    resets
}

fn handle_event_inner(
    event: H2Event,
    pending: &mut HashMap<u32, PendingStream>,
    resets: &mut Vec<u32>,
) {
    match event {
        H2Event::ResponseHeaders {
            stream_id,
            headers,
            end_stream,
        } => {
            // A field section that arrives once the response headers have
            // already been handed to the caller is the trailer section.
            let Some(is_trailers) = pending.get(&stream_id).map(|ps| ps.headers_tx.is_none())
            else {
                return;
            };

            // RFC 9113 §8.3 (only `:status`, exactly once, ahead of every
            // regular field) and §8.1 (no pseudo-header at all in a trailer
            // section). Checked first: a section whose *shape* is wrong is
            // malformed regardless of what its regular fields look like.
            if let Err(reason) =
                crate::adapter::validate_response_pseudo_headers(&headers, is_trailers)
            {
                fail_malformed(pending, stream_id, reason, resets);
                return;
            }

            // RFC 9113 §8.2.1/§8.2.2 apply to every received field section,
            // response and trailer sections alike.
            let parsed_headers = match crate::adapter::parse_response_fields(&headers) {
                Ok(headers) => headers,
                Err(reason) => {
                    fail_malformed(pending, stream_id, reason, resets);
                    return;
                }
            };

            if is_trailers {
                if end_stream {
                    finish_stream(pending, stream_id, resets);
                }
                return;
            }

            // RFC 9113 §8.3.2: a missing or unusable `:status` is a protocol
            // error. Reporting it as a synthesized status would be
            // indistinguishable from a server that really sent that status.
            let status = match crate::adapter::validate_response_status(
                crate::hpack::get_pseudo_header(&headers, ":status"),
            ) {
                Ok(status) => status,
                Err(reason) => {
                    fail_malformed(pending, stream_id, reason, resets);
                    return;
                }
            };

            // 1xx interim responses (e.g. 103 Early Hints, which servers like
            // Cloudflare send ahead of the final 200) are NOT the final
            // response. Skip the interim HEADERS block and keep `headers_tx`
            // in place so the subsequent final (non-1xx) HEADERS is delivered
            // to the caller instead.
            if is_interim_status(status) {
                // RFC 9113 §8.5: HTTP/2 has no upgrade mechanism, so 101 is
                // never a valid HTTP/2 response. Parking the stream as if a
                // final response were still coming would hang it forever.
                if status == 101 {
                    fail_malformed(
                        pending,
                        stream_id,
                        "101 (Switching Protocols) is not used in HTTP/2 (RFC 9113 §8.5)"
                            .to_string(),
                        resets,
                    );
                    return;
                }
                // RFC 9113 §8.1: an interim response is never the end of the
                // stream. If the server ends it here, no final response can
                // ever arrive — surface the protocol error rather than leaving
                // the request to hang until it times out.
                if end_stream {
                    fail_malformed(
                        pending,
                        stream_id,
                        format!(
                            "interim {status} response carried END_STREAM, so no final response can follow (RFC 9113 §8.1)"
                        ),
                        resets,
                    );
                    return;
                }
                tracing::debug!(stream_id, status, "h2.native.interim_response_skipped");
                return;
            }

            // RFC 9113 §8.1.1: `content-length`, when the response is defined
            // to have content, must equal the sum of the DATA payload lengths.
            let declared_length = match crate::adapter::response_content_length(&headers) {
                Ok(length) => length,
                Err(reason) => {
                    fail_malformed(pending, stream_id, reason, resets);
                    return;
                }
            };

            let empty_body_mismatch = {
                let Some(ps) = pending.get_mut(&stream_id) else {
                    return;
                };
                if let Some(expected) = declared_length {
                    if response_has_content(&ps.method, status) {
                        ps.content_length = Some(ContentLengthCheck {
                            expected,
                            received: 0,
                        });
                    }
                }
                // END_STREAM here means the whole content is zero bytes.
                match (&ps.content_length, end_stream) {
                    (Some(check), true) if check.expected != 0 => Some(check.mismatch_reason()),
                    _ => None,
                }
            };
            if let Some(reason) = empty_body_mismatch {
                fail_malformed(pending, stream_id, reason, resets);
                return;
            }

            let Some(ps) = pending.get_mut(&stream_id) else {
                return;
            };
            if let Some(tx) = ps.headers_tx.take() {
                let _ = tx.send(Ok(NativeResponseHeaders {
                    status,
                    headers: parsed_headers,
                }));
            }
            if end_stream {
                // No body — drop body_tx to signal EOF.
                pending.remove(&stream_id);
            }
        }
        H2Event::ResponseData {
            stream_id,
            data,
            end_stream,
        } => {
            let overflow = {
                let Some(ps) = pending.get_mut(&stream_id) else {
                    return;
                };
                match ps.content_length.as_mut() {
                    Some(check) => {
                        check.received = check.received.saturating_add(data.len() as u64);
                        (check.received > check.expected).then(|| check.mismatch_reason())
                    }
                    None => None,
                }
            };
            if let Some(reason) = overflow {
                fail_malformed(pending, stream_id, reason, resets);
                return;
            }

            if let Some(ps) = pending.get_mut(&stream_id) {
                if !data.is_empty() {
                    if let Err(e) = ps.body_tx.send(Ok(data)) {
                        tracing::warn!(stream_id, error = %e, "h2.native.body_receiver_dropped");
                    }
                }
                if end_stream {
                    finish_stream(pending, stream_id, resets);
                }
            }
        }
        H2Event::StreamReset {
            stream_id,
            error_code,
        } => {
            if let Some(ps) = pending.remove(&stream_id) {
                let err = DriverError::StreamReset(error_code);
                if let Some(tx) = ps.headers_tx {
                    let _ = tx.send(Err(err.clone()));
                }
                let _ = ps.body_tx.send(Err(err));
            }
        }
        H2Event::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            if error_code != 0 {
                let msg = format!(
                    "error_code={error_code}, debug={}",
                    String::from_utf8_lossy(&debug_data)
                );
                notify_all_error(pending, DriverError::GoAway(msg));
            } else {
                // Graceful GOAWAY (error_code=0): only fail streams that
                // the server will NOT process (stream_id > last_stream_id).
                let stale: Vec<u32> = pending
                    .keys()
                    .filter(|&&sid| sid > last_stream_id)
                    .copied()
                    .collect();
                for sid in stale {
                    if let Some(ps) = pending.remove(&sid) {
                        if let Some(tx) = ps.headers_tx {
                            let _ = tx
                                .send(Err(DriverError::GoAway("stream rejected by GOAWAY".into())));
                        }
                    }
                }
            }
        }
        H2Event::Error(msg) => {
            tracing::error!(msg = %msg, "h2.native.engine_error");
        }
        _ => {}
    }
}

fn remove_waiting_request(waiting: &mut VecDeque<QueuedRequest>, request_id: u64) -> bool {
    let Some(index) = waiting
        .iter()
        .position(|request| request.request_id() == request_id)
    else {
        return false;
    };
    waiting.remove(index);
    true
}

fn notify_waiting_error(waiting: &mut VecDeque<QueuedRequest>, err: DriverError) {
    for request in waiting.drain(..) {
        match request {
            QueuedRequest::Request {
                headers_tx,
                body_tx,
                ..
            }
            | QueuedRequest::NativeRequest {
                headers_tx,
                body_tx,
                ..
            } => {
                let _ = headers_tx.send(Err(err.clone()));
                let _ = body_tx.send(Err(err.clone()));
            }
        }
    }
}

fn notify_all_error(pending: &mut HashMap<u32, PendingStream>, err: DriverError) {
    for (_, ps) in pending.drain() {
        if let Some(tx) = ps.headers_tx {
            let _ = tx.send(Err(err.clone()));
        }
        let _ = ps.body_tx.send(Err(err.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct WriteTrace(Vec<Option<Vec<u8>>>);

    impl AsyncWrite for WriteTrace {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.push(Some(data.to_vec()));
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.0.push(None);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn queued_buffered_writes_preserve_direct_bytes_and_flush_boundaries() {
        for profile in [
            crate::profile::chrome_146_h2(),
            crate::profile::safari_26_h2(),
        ] {
            let behavior = profile.behavior();
            let (mut engine, _) = H2Engine::client(&profile);
            let stream_id = engine.open_stream();
            let frames = engine.build_request(
                stream_id,
                http::Request::builder()
                    .method("POST")
                    .uri("https://example.test/upload")
                    .body(Some(Bytes::from(vec![7; 32768])))
                    .unwrap(),
            );
            let mut direct = WriteTrace::default();
            encode_and_write_frames(
                &mut direct,
                &engine,
                &*behavior.write_policy,
                frames.clone(),
            )
            .await
            .unwrap();
            let mut queued = PendingWrites::default();
            encode_and_write_frames(&mut queued, &engine, &*behavior.write_policy, frames)
                .await
                .unwrap();
            let mut actual = WriteTrace::default();
            while !queued.is_empty() {
                std::future::poll_fn(|context| queued.poll_drain(&mut actual, context))
                    .await
                    .unwrap();
            }
            assert_eq!(actual.0, direct.0);
        }
    }
    use std::time::Duration;

    fn test_sender(
        cmd_tx: mpsc::Sender<DriverCommand>,
        max_pending_requests: Option<usize>,
    ) -> NativeSendRequest {
        let (cancel_tx, _cancel_rx) = mpsc::unbounded_channel();
        NativeSendRequest {
            cmd_tx,
            cancel_tx,
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending_slots: max_pending_requests.map(|max| Arc::new(Semaphore::new(max))),
        }
    }

    fn request(path: &str) -> http::Request<Option<Bytes>> {
        http::Request::builder()
            .uri(format!("https://example.test/{path}"))
            .body(None)
            .unwrap()
    }

    fn has_frame(wire: &[u8], frame_type: u8, stream_id: u32) -> bool {
        let mut offset = 0;
        while offset + 9 <= wire.len() {
            let length =
                u32::from_be_bytes([0, wire[offset], wire[offset + 1], wire[offset + 2]]) as usize;
            let end = offset + 9 + length;
            if end > wire.len() {
                return false;
            }
            let current_type = wire[offset + 3];
            let current_stream_id = u32::from_be_bytes([
                wire[offset + 5] & 0x7f,
                wire[offset + 6],
                wire[offset + 7],
                wire[offset + 8],
            ]);
            if current_type == frame_type && current_stream_id == stream_id {
                return true;
            }
            offset = end;
        }
        false
    }

    // ====================================================================
    // DriverError — user-facing error messages
    // ====================================================================

    #[test]
    fn io_error_message() {
        let err = DriverError::Io("connection reset".to_string());
        assert_eq!(err.to_string(), "I/O error: connection reset");
    }

    #[test]
    fn protocol_error_message() {
        let err = DriverError::Protocol("invalid frame".to_string());
        assert_eq!(err.to_string(), "protocol error: invalid frame");
    }

    #[test]
    fn stream_reset_shows_error_code() {
        let err = DriverError::StreamReset(8); // CANCEL
        assert!(err.to_string().contains("error_code=8"));
    }

    #[test]
    fn goaway_message() {
        let err = DriverError::GoAway("server shutting down".to_string());
        assert!(err.to_string().contains("server shutting down"));
    }

    #[test]
    fn shutdown_and_channel_closed_messages() {
        assert_eq!(DriverError::Shutdown.to_string(), "connection shut down");
        assert_eq!(DriverError::ChannelClosed.to_string(), "channel closed");
    }

    #[test]
    fn io_error_converts_from_std() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let driver_err: DriverError = io_err.into();
        assert!(driver_err.to_string().contains("pipe broken"));
    }

    #[test]
    fn driver_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(DriverError::Shutdown);
        assert_eq!(err.to_string(), "connection shut down");
    }

    // ====================================================================
    // NativeSendRequest — connection readiness check
    // ====================================================================

    #[tokio::test]
    async fn ready_returns_ok_when_channel_open() {
        let (tx, _rx) = mpsc::channel::<DriverCommand>(1);
        let mut sender = test_sender(tx, None);
        assert!(sender.ready().await.is_ok());
    }

    #[tokio::test]
    async fn ready_returns_err_when_connection_dropped() {
        let (tx, rx) = mpsc::channel::<DriverCommand>(1);
        drop(rx);
        let mut sender = test_sender(tx, None);
        assert!(sender.ready().await.is_err());
    }

    #[tokio::test]
    async fn send_request_fails_when_driver_gone() {
        let (tx, rx) = mpsc::channel::<DriverCommand>(1);
        drop(rx);
        let mut sender = test_sender(tx, None);
        let req = http::Request::builder()
            .uri("https://example.com/")
            .body(None)
            .unwrap();
        let result = sender.send_request(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn driver_config_defaults_to_unbounded_pending_requests() {
        assert_eq!(H2DriverConfig::default().max_pending_requests, None);
        assert_eq!(H2DriverConfig::default().max_ready_commands_per_turn, 1);
        assert_eq!(H2DriverConfig::default().max_requests_per_write, 1);
        assert_eq!(H2DriverConfig::default().max_write_batch_bytes, 64 * 1024);
    }

    #[tokio::test]
    async fn zero_pending_request_limit_is_rejected() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let result = spawn_driver_with_config(
            client_io,
            &crate::profile::chrome_146_h2(),
            H2DriverConfig {
                max_pending_requests: Some(0),
                ..H2DriverConfig::default()
            },
        )
        .await;
        assert!(matches!(result, Err(DriverError::Protocol(_))));
    }

    #[tokio::test]
    async fn zero_ready_command_batch_is_rejected() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let result = spawn_driver_with_config(
            client_io,
            &crate::profile::chrome_146_h2(),
            H2DriverConfig {
                max_ready_commands_per_turn: 0,
                ..H2DriverConfig::default()
            },
        )
        .await;
        assert!(matches!(result, Err(DriverError::Protocol(_))));
    }

    #[tokio::test]
    async fn zero_requests_per_write_is_rejected() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let result = spawn_driver_with_config(
            client_io,
            &crate::profile::chrome_146_h2(),
            H2DriverConfig {
                max_requests_per_write: 0,
                ..H2DriverConfig::default()
            },
        )
        .await;
        assert!(matches!(result, Err(DriverError::Protocol(_))));
    }

    #[tokio::test]
    async fn zero_write_batch_bytes_is_rejected() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let result = spawn_driver_with_config(
            client_io,
            &crate::profile::chrome_146_h2(),
            H2DriverConfig {
                max_write_batch_bytes: 0,
                ..H2DriverConfig::default()
            },
        )
        .await;
        assert!(matches!(result, Err(DriverError::Protocol(_))));
    }

    #[tokio::test]
    async fn bounded_pending_requests_apply_async_backpressure() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<DriverCommand>(4);
        let sender = test_sender(cmd_tx, Some(1));

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("first")).await }
        });
        let first_command = tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("second")).await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), cmd_rx.recv())
                .await
                .is_err(),
            "second request entered the driver before a pending permit was released"
        );

        drop(first_command);
        let second_command = tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();
        drop(second_command);

        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn cancellation_removes_waiting_request_and_releases_backpressure() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_ready_tx, server_ready_rx) = oneshot::channel();
        let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
        let (release_first_tx, release_first_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.max_concurrent_streams(1);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
            let mut ping_pong = connection.ping_pong().unwrap();
            let ping = ping_pong.ping(h2::Ping::opaque());
            tokio::pin!(ping);
            tokio::select! {
                result = &mut ping => { result.unwrap(); }
                request = connection.accept() => {
                    panic!("request arrived before server SETTINGS were observed: {request:?}");
                }
            }
            let _ = server_ready_tx.send(());

            let (_first_request, mut first_response) = connection.accept().await.unwrap().unwrap();
            let _ = first_accepted_tx.send(());
            let _ = release_first_rx.await;
            first_response
                .send_response(http::Response::new(()), true)
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(50), connection.accept()).await;
        });

        let profile = crate::profile::chrome_146_h2();
        let (sender, driver_task) = spawn_driver_with_config(
            client_io,
            &profile,
            H2DriverConfig {
                max_pending_requests: Some(1),
                ..H2DriverConfig::default()
            },
        )
        .await
        .unwrap();
        let pending_slots = sender.pending_slots.as_ref().unwrap().clone();
        server_ready_rx.await.unwrap();

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("first")).await }
        });
        first_accepted_rx.await.unwrap();

        let second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("second")).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pending_slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        second_task.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while pending_slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled queued request did not release its pending permit");

        release_first_tx.send(()).unwrap();
        first_task.await.unwrap().unwrap();
        server_task.await.unwrap();
        driver_task.abort();
    }

    #[tokio::test]
    async fn requests_wait_for_remote_stream_capacity() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_ready_tx, server_ready_rx) = oneshot::channel();
        let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
        let (release_first_tx, release_first_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.max_concurrent_streams(1);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
            let mut ping_pong = connection.ping_pong().unwrap();
            let ping = ping_pong.ping(h2::Ping::opaque());
            tokio::pin!(ping);
            tokio::select! {
                result = &mut ping => { result.unwrap(); }
                request = connection.accept() => {
                    panic!("request arrived before server SETTINGS were observed: {request:?}");
                }
            }
            let _ = server_ready_tx.send(());

            let (_first_request, mut first_response) = connection.accept().await.unwrap().unwrap();
            let _ = first_accepted_tx.send(());
            let _ = release_first_rx.await;
            first_response
                .send_response(http::Response::new(()), true)
                .unwrap();

            let (_second_request, mut second_response) =
                connection.accept().await.unwrap().unwrap();
            second_response
                .send_response(http::Response::new(()), true)
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(50), connection.accept()).await;
        });

        let profile = crate::profile::chrome_146_h2();
        let (sender, driver_task) = spawn_driver(client_io, &profile).await.unwrap();
        server_ready_rx.await.unwrap();

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move {
                sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://example.test/first")
                            .body(None)
                            .unwrap(),
                    )
                    .await
            }
        });
        first_accepted_rx.await.unwrap();

        let mut second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move {
                sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://example.test/second")
                            .body(None)
                            .unwrap(),
                    )
                    .await
            }
        });

        if let Ok(result) = tokio::time::timeout(Duration::from_millis(50), &mut second_task).await
        {
            panic!(
                "second request must wait while the only remote stream slot is occupied: {result:?}"
            );
        }

        release_first_tx.send(()).unwrap();
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
        server_task.await.unwrap();
        driver_task.abort();
    }
    // ====================================================================
    // Local connection errors — the driver must close the transport and
    // fail both active and queued requests after writing error GOAWAY.
    // ====================================================================

    #[tokio::test]
    async fn local_connection_error_closes_driver_and_notifies_pending_and_waiting() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let (server_ready_tx, server_ready_rx) = oneshot::channel();
        let (first_request_tx, first_request_rx) = oneshot::channel();
        let (inject_error_tx, inject_error_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut preface = [0u8; crate::CONNECTION_PREFACE.len()];
            server_io.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, crate::CONNECTION_PREFACE);

            let settings = [
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                0x01,
            ];
            server_io.write_all(&settings).await.unwrap();

            let mut wire = BytesMut::new();
            loop {
                let read = server_io.read_buf(&mut wire).await.unwrap();
                assert!(read > 0, "client closed before acknowledging SETTINGS");
                if has_frame(&wire, 0x04, 0)
                    && wire.windows(9).any(|window| {
                        window == [0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]
                    })
                {
                    break;
                }
            }
            let _ = server_ready_tx.send(());

            loop {
                let read = server_io.read_buf(&mut wire).await.unwrap();
                assert!(read > 0, "client closed before sending the first request");
                if has_frame(&wire, 0x01, 1) {
                    let _ = first_request_tx.send(());
                    break;
                }
            }

            inject_error_rx.await.unwrap();
            let malformed_data = [0x00, 0x4e, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
            server_io.write_all(&malformed_data).await.unwrap();

            let mut tail = [0u8; 1024];
            loop {
                if server_io.read(&mut tail).await.unwrap() == 0 {
                    break;
                }
            }
            has_frame(&wire, 0x01, 3)
        });

        let profile = crate::profile::chrome_146_h2();
        let (sender, driver_task) = spawn_driver(client_io, &profile).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), server_ready_rx)
            .await
            .unwrap()
            .unwrap();

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("first")).await }
        });

        tokio::time::timeout(Duration::from_secs(1), first_request_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !first_task.is_finished(),
            "first request completed before the server injected an error"
        );

        let second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("second")).await }
        });
        tokio::task::yield_now().await;
        inject_error_tx.send(()).unwrap();

        let first_result = tokio::time::timeout(Duration::from_secs(1), first_task)
            .await
            .unwrap()
            .unwrap();
        let second_result = tokio::time::timeout(Duration::from_secs(1), second_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(first_result, Err(DriverError::Protocol(ref message)) if message.contains("connection error")),
            "pending request should receive the connection error: {first_result:?}"
        );
        assert!(
            matches!(second_result, Err(DriverError::Protocol(ref message)) if message.contains("connection error")),
            "waiting request should receive the connection error: {second_result:?}"
        );

        tokio::time::timeout(Duration::from_secs(1), driver_task)
            .await
            .unwrap()
            .unwrap();
        let second_dispatched = tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !second_dispatched,
            "the second request must remain waiting while the peer allows one stream"
        );
    }
    // ====================================================================
    // FirstRequest — channel pair creation
    // ====================================================================

    #[test]
    fn first_request_creates_channel_pair() {
        let req = http::Request::builder()
            .uri("https://example.com/")
            .body(None)
            .unwrap();
        let (first_req, mut response) = FirstRequest::new(req);
        assert!(!first_req.headers_tx.is_closed());
        drop(first_req);
        assert!(response.headers_rx.try_recv().is_err());
    }

    // ====================================================================
    // NativeSendRequest — debug formatting
    // ====================================================================

    #[test]
    fn native_send_request_debug() {
        let (tx, _rx) = mpsc::channel::<DriverCommand>(1);
        let sender = test_sender(tx, None);
        let debug = format!("{:?}", sender);
        assert!(debug.contains("NativeSendRequest"));
    }

    // ====================================================================
    // notify_all_error — notifying all pending streams on failure
    // ====================================================================

    #[test]
    fn notify_all_error_sends_to_all_pending() {
        let (h_tx, mut h_rx) = oneshot::channel();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();

        let mut pending = HashMap::new();
        pending.insert(1, PendingStream::new(http::Method::GET, h_tx, b_tx));

        notify_all_error(&mut pending, DriverError::Shutdown);

        assert!(pending.is_empty());
        let header_result = h_rx.try_recv().unwrap();
        assert!(header_result.is_err());
        let body_result = b_rx.try_recv().unwrap();
        assert!(body_result.is_err());
    }

    // ====================================================================
    // handle_event — 1xx interim responses (100 Continue / 103 Early Hints)
    // must be skipped; the final (non-1xx) response is what reaches the caller.
    // Regression: Cloudflare emits 103 Early Hints before its 200, and the
    // native driver used to surface the 103 as the final response.
    // ====================================================================

    fn status_headers_event(stream_id: u32, status: u16, end_stream: bool) -> H2Event {
        H2Event::ResponseHeaders {
            stream_id,
            headers: vec![(":status".to_string(), status.to_string())],
            end_stream,
        }
    }

    type HeadersRx = oneshot::Receiver<Result<NativeResponseHeaders, DriverError>>;
    type BodyRx = mpsc::UnboundedReceiver<Result<Bytes, DriverError>>;

    fn pending_with_channels() -> (HashMap<u32, PendingStream>, HeadersRx, BodyRx) {
        pending_with_channels_for(http::Method::GET)
    }

    fn pending_with_channels_for(
        method: http::Method,
    ) -> (HashMap<u32, PendingStream>, HeadersRx, BodyRx) {
        let (h_tx, h_rx) = oneshot::channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let mut pending = HashMap::new();
        pending.insert(1, PendingStream::new(method, h_tx, b_tx));
        (pending, h_rx, b_rx)
    }

    #[test]
    fn is_interim_status_classifies_1xx_only() {
        assert!(is_interim_status(100));
        assert!(is_interim_status(103));
        assert!(is_interim_status(199));
        assert!(!is_interim_status(200));
        assert!(!is_interim_status(204));
        assert!(!is_interim_status(304));
        assert!(!is_interim_status(500));
        // Missing/unparsed :status maps to 0 upstream — not interim.
        assert!(!is_interim_status(0));
    }

    #[test]
    fn interim_103_is_skipped_and_final_200_delivered() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();

        // 103 Early Hints arrives first — must NOT be delivered as the
        // response, and the stream must stay pending awaiting the final one.
        handle_event(status_headers_event(1, 103, false), &mut pending);
        assert!(
            h_rx.try_recv().is_err(),
            "103 interim response must not be surfaced as the final response"
        );
        assert!(
            pending.contains_key(&1),
            "stream must remain pending after an interim 103"
        );

        // Final 200 arrives — this is what the caller receives.
        handle_event(status_headers_event(1, 200, false), &mut pending);
        let delivered = h_rx
            .try_recv()
            .expect("final 200 headers must be delivered")
            .expect("delivered headers must be Ok");
        assert_eq!(delivered.status, 200);
    }

    #[test]
    fn multiple_interim_blocks_then_final() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();

        // A server may emit several 1xx blocks (100 Continue + repeated
        // 103 Early Hints) before the final response.
        handle_event(status_headers_event(1, 100, false), &mut pending);
        handle_event(status_headers_event(1, 103, false), &mut pending);
        handle_event(status_headers_event(1, 103, false), &mut pending);
        assert!(h_rx.try_recv().is_err());
        assert!(pending.contains_key(&1));

        // Final 204 with END_STREAM (no body) — delivered and stream removed.
        handle_event(status_headers_event(1, 204, true), &mut pending);
        let delivered = h_rx.try_recv().unwrap().unwrap();
        assert_eq!(delivered.status, 204);
        assert!(
            !pending.contains_key(&1),
            "END_STREAM on the final headers must remove the pending stream"
        );
    }

    #[test]
    fn trailing_headers_after_final_are_ignored() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();

        // Final headers (body follows).
        handle_event(status_headers_event(1, 200, false), &mut pending);
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        // HTTP trailers arrive as a HEADERS block with no :status and
        // END_STREAM set. They must not re-deliver headers or panic, and the
        // stream is cleaned up.
        let trailers = H2Event::ResponseHeaders {
            stream_id: 1,
            headers: vec![("grpc-status".to_string(), "0".to_string())],
            end_stream: true,
        };
        handle_event(trailers, &mut pending);
        assert!(!pending.contains_key(&1));
    }

    // ====================================================================
    // Malformed responses (RFC 9113 §8.1.1) — receive-side validation.
    //
    // Each of these must fail the *stream* with `DriverError::Protocol`
    // (message prefixed "malformed response") so the caller can tell a
    // protocol violation apart from a status the server really sent, and the
    // stream must not be left pending (which used to hang the request until
    // its timeout).
    // ====================================================================

    fn headers_event(stream_id: u32, headers: &[(&str, &str)], end_stream: bool) -> H2Event {
        H2Event::ResponseHeaders {
            stream_id,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
            end_stream,
        }
    }

    fn data_event(stream_id: u32, data: &[u8], end_stream: bool) -> H2Event {
        H2Event::ResponseData {
            stream_id,
            data: Bytes::copy_from_slice(data),
            end_stream,
        }
    }

    /// Return the protocol-error text a channel result carries, or `None` when
    /// it is not a `DriverError::Protocol`.
    fn protocol_error_text<T>(result: Result<T, DriverError>) -> Option<String> {
        match result {
            Err(DriverError::Protocol(msg)) => Some(msg),
            _ => None,
        }
    }

    /// Drive a single response HEADERS block through `handle_event` and report
    /// the protocol error the headers channel received, if any.
    fn malformed_headers_reason(headers: &[(&str, &str)], end_stream: bool) -> Option<String> {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();
        handle_event(headers_event(1, headers, end_stream), &mut pending);
        let still_pending = pending.contains_key(&1);
        let reason = h_rx.try_recv().ok().and_then(protocol_error_text);
        if reason.is_some() && still_pending {
            return Some(format!("{reason:?} but the stream was left pending"));
        }
        reason
    }

    // ── H-04: an invalid :status must not be disguised as a status code ──

    #[test]
    fn missing_status_is_a_protocol_error_not_a_500() {
        let reason = malformed_headers_reason(&[("content-type", "text/plain")], false);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("malformed response") && r.contains(":status")),
            "a response with no :status must fail the stream, got {reason:?}"
        );
    }

    #[test]
    fn non_numeric_status_is_a_protocol_error() {
        let reason = malformed_headers_reason(&[(":status", "abc")], false);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains(":status")),
            "an unparsable :status must fail the stream, got {reason:?}"
        );
    }

    #[test]
    fn out_of_range_status_is_a_protocol_error() {
        for bad in [":status-099", ":status-1000", ":status-20", ":status-0200"] {
            let value = bad.trim_start_matches(":status-");
            let reason = malformed_headers_reason(&[(":status", value)], false);
            assert!(
                reason.is_some(),
                ":status {value:?} must fail the stream, got {reason:?}"
            );
        }
    }

    #[test]
    fn valid_status_still_reaches_the_caller() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();
        handle_event(headers_event(1, &[(":status", "500")], true), &mut pending);
        let delivered = h_rx.try_recv().unwrap().unwrap();
        assert_eq!(
            delivered.status, 500,
            "a server-sent 500 must still be delivered as an ordinary response"
        );
    }

    // ── H-02: malformed field names/values must be rejected, not dropped ──

    #[test]
    fn uppercase_field_name_is_a_protocol_error() {
        let reason = malformed_headers_reason(&[(":status", "200"), ("X-Trace", "abc")], false);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("X-Trace") && r.contains("§8.2.1")),
            "an uppercase field name must fail the stream instead of being lowercased, got {reason:?}"
        );
    }

    #[test]
    fn invalid_field_name_and_value_bytes_are_protocol_errors() {
        let cases: &[(&str, &str)] = &[
            ("x bad", "v"),        // space in the name
            ("x\u{7f}bad", "v"),   // DEL in the name
            ("", "v"),             // empty name
            ("x-nul", "a\u{0}b"),  // NUL in the value
            ("x-cr", "a\rb"),      // CR in the value
            ("x-lf", "a\nb"),      // LF in the value
            ("x-pad", " padded"),  // leading whitespace
            ("x-pad", "padded\t"), // trailing whitespace
        ];
        for (name, value) in cases {
            let reason = malformed_headers_reason(&[(":status", "200"), (name, value)], false);
            assert!(
                reason.is_some(),
                "field ({name:?}, {value:?}) must fail the stream, got {reason:?}"
            );
        }
    }

    #[test]
    fn well_formed_fields_are_delivered_untouched() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();
        handle_event(
            headers_event(1, &[(":status", "200"), ("x-trace", "abc")], true),
            &mut pending,
        );
        let delivered = h_rx.try_recv().unwrap().unwrap();
        assert!(
            delivered
                .headers
                .iter()
                .any(|(n, v)| n == "x-trace" && v == "abc"),
            "well-formed fields must pass through: {:?}",
            delivered.headers
        );
    }

    // ── H-03: connection-specific fields make the response malformed ──

    #[test]
    fn connection_specific_fields_are_protocol_errors() {
        let cases: &[(&str, &str)] = &[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
        ];
        for (name, value) in cases {
            let reason = malformed_headers_reason(&[(":status", "200"), (name, value)], false);
            assert!(
                reason.as_deref().is_some_and(|r| r.contains("§8.2.2")),
                "connection-specific field {name:?} must fail the stream, got {reason:?}"
            );
        }
    }

    #[test]
    fn te_is_only_allowed_with_the_value_trailers() {
        let allowed = malformed_headers_reason(&[(":status", "200"), ("te", "trailers")], false);
        assert!(
            allowed.is_none(),
            "te: trailers is explicitly permitted, got {allowed:?}"
        );
        let rejected = malformed_headers_reason(&[(":status", "200"), ("te", "gzip")], false);
        assert!(
            rejected.is_some(),
            "any other te value must fail the stream, got {rejected:?}"
        );
    }

    #[test]
    fn connection_specific_field_in_trailers_is_a_protocol_error() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(headers_event(1, &[(":status", "200")], false), &mut pending);
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        handle_event(
            headers_event(1, &[("transfer-encoding", "chunked")], true),
            &mut pending,
        );
        let body_error = b_rx.try_recv().ok().and_then(protocol_error_text);
        assert!(
            body_error.as_deref().is_some_and(|r| r.contains("§8.2.2")),
            "a malformed trailer section must fail the body stream, got {body_error:?}"
        );
    }

    // ── N-03: response pseudo-header rules (RFC 9113 §8.3, §8.1) ──
    //
    // Only `:status` is defined for a response, it may appear exactly once, no
    // pseudo-header may follow a regular field, and a trailer section carries
    // none at all. Each violation makes the response malformed, which §8.1.1
    // makes a stream error of type PROTOCOL_ERROR.

    #[test]
    fn duplicate_status_is_a_protocol_error() {
        let reason = malformed_headers_reason(&[(":status", "200"), (":status", "404")], false);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("more than one :status")),
            "a second :status must fail the stream instead of being ignored, got {reason:?}"
        );
    }

    #[test]
    fn malformed_response_schedules_rst_stream_and_removes_pending_request() {
        let (mut pending, mut headers_rx, mut body_rx) = pending_with_channels();

        let resets = handle_event(
            headers_event(1, &[(":status", "200"), (":status", "204")], false),
            &mut pending,
        );

        assert_eq!(
            resets,
            vec![1],
            "malformed response must be reset on the wire"
        );
        assert!(
            !pending.contains_key(&1),
            "a reset stream must not remain pending"
        );
        assert!(
            headers_rx
                .try_recv()
                .ok()
                .and_then(protocol_error_text)
                .is_some_and(|reason| reason.contains("malformed response")),
            "the headers waiter must receive the protocol error"
        );
        assert!(
            body_rx
                .try_recv()
                .ok()
                .and_then(protocol_error_text)
                .is_some_and(|reason| reason.contains("malformed response")),
            "the body waiter must receive the protocol error"
        );
    }
    #[test]
    fn unknown_pseudo_header_in_a_response_is_a_protocol_error() {
        // Request pseudo-headers and anything invented: §8.3 defines exactly
        // one pseudo-header for responses.
        for name in [":method", ":path", ":authority", ":scheme", ":protocol"] {
            let reason = malformed_headers_reason(&[(":status", "200"), (name, "x")], false);
            assert!(
                reason
                    .as_deref()
                    .is_some_and(|r| r.contains(name) && r.contains("§8.3")),
                "{name} is not defined for responses and must fail the stream, got {reason:?}"
            );
        }
    }

    #[test]
    fn pseudo_header_after_a_regular_field_is_a_protocol_error() {
        let reason = malformed_headers_reason(&[("x-trace", "abc"), (":status", "200")], false);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("after a regular field")),
            "every pseudo-header must precede the regular fields, got {reason:?}"
        );
    }

    #[test]
    fn pseudo_header_in_a_trailer_section_is_a_protocol_error() {
        for (name, value) in [(":status", "200"), (":method", "GET")] {
            let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
            handle_event(headers_event(1, &[(":status", "200")], false), &mut pending);
            assert_eq!(
                h_rx.try_recv().unwrap().unwrap().status,
                200,
                "the final response must be delivered before the trailers"
            );

            handle_event(headers_event(1, &[(name, value)], true), &mut pending);
            let body_error = b_rx.try_recv().ok().and_then(protocol_error_text);
            assert!(
                body_error
                    .as_deref()
                    .is_some_and(|r| r.contains("trailer section")),
                "{name} in a trailer section must fail the body stream, got {body_error:?}"
            );
        }
    }

    // N-03 counter-cases: the rules above must not reject conforming sections.

    #[test]
    fn a_response_with_status_first_is_still_delivered() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();
        handle_event(
            headers_event(
                1,
                &[
                    (":status", "200"),
                    ("content-type", "text/plain"),
                    ("x-trace", "abc"),
                ],
                true,
            ),
            &mut pending,
        );
        let delivered = h_rx.try_recv().unwrap().unwrap();
        assert_eq!(
            delivered.status, 200,
            "a conforming field section must still reach the caller"
        );
        assert!(
            delivered
                .headers
                .iter()
                .any(|(n, v)| n == "x-trace" && v == "abc"),
            "the regular fields after :status must survive: {:?}",
            delivered.headers
        );
    }

    #[test]
    fn legitimate_trailers_after_data_are_still_accepted() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(headers_event(1, &[(":status", "200")], false), &mut pending);
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);
        handle_event(data_event(1, b"chunk", false), &mut pending);
        handle_event(
            headers_event(1, &[("grpc-status", "0"), ("x-checksum", "deadbeef")], true),
            &mut pending,
        );

        let mut chunks = 0usize;
        let mut errors = 0usize;
        while let Ok(message) = b_rx.try_recv() {
            match message {
                Ok(_) => chunks += 1,
                Err(_) => errors += 1,
            }
        }
        assert_eq!(
            errors, 0,
            "a trailer section of regular fields is legal (RFC 9113 §8.1) and must not fail"
        );
        assert_eq!(chunks, 1, "the body chunk must still have been delivered");
        assert!(
            !pending.contains_key(&1),
            "END_STREAM on the trailers must complete the stream"
        );
    }

    // ── H-06: the 1xx state machine ──

    #[test]
    fn status_101_is_a_protocol_error_not_an_interim_response() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();
        handle_event(headers_event(1, &[(":status", "101")], false), &mut pending);
        let reason = h_rx.try_recv().ok().and_then(protocol_error_text);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("101")),
            "101 has no meaning in HTTP/2 and must fail the stream, got {reason:?}"
        );
        assert!(
            !pending.contains_key(&1),
            "a 101 response must not leave the stream waiting for a final response"
        );
    }

    #[test]
    fn interim_response_with_end_stream_is_a_protocol_error() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();
        handle_event(headers_event(1, &[(":status", "103")], true), &mut pending);
        let reason = h_rx.try_recv().ok().and_then(protocol_error_text);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("END_STREAM")),
            "an interim response ending the stream must fail it, got {reason:?}"
        );
        assert!(
            !pending.contains_key(&1),
            "an interim END_STREAM must not leave the request hanging until its timeout"
        );
    }

    // ── H-01: content-length must equal the DATA payload sum ──

    #[test]
    fn content_length_shorter_than_the_data_sum_is_a_protocol_error() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(
            headers_event(1, &[(":status", "200"), ("content-length", "2")], false),
            &mut pending,
        );
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        handle_event(data_event(1, b"toolong", true), &mut pending);
        let body_error = b_rx.try_recv().ok().and_then(protocol_error_text);
        assert!(
            body_error
                .as_deref()
                .is_some_and(|r| r.contains("content-length")),
            "more DATA than content-length declares must fail the stream, got {body_error:?}"
        );
    }

    #[test]
    fn content_length_longer_than_the_data_sum_is_a_protocol_error() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(
            headers_event(1, &[(":status", "200"), ("content-length", "10")], false),
            &mut pending,
        );
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        handle_event(data_event(1, b"short", true), &mut pending);
        // The truncated chunk is delivered first, then the desync surfaces.
        let chunk = b_rx.try_recv().unwrap().unwrap();
        assert_eq!(&chunk[..], b"short");
        let body_error = b_rx.try_recv().ok().and_then(protocol_error_text);
        assert!(
            body_error
                .as_deref()
                .is_some_and(|r| r.contains("content-length")),
            "a short body must not be reported as a clean EOF, got {body_error:?}"
        );
    }

    #[test]
    fn non_zero_content_length_with_end_stream_on_headers_is_a_protocol_error() {
        let reason = malformed_headers_reason(
            &[(":status", "200"), ("content-length", "5")],
            /* end_stream */ true,
        );
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("content-length")),
            "a bodiless response declaring content-length: 5 must fail the stream, got {reason:?}"
        );
    }

    #[test]
    fn matching_content_length_delivers_the_body_and_a_clean_eof() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(
            headers_event(1, &[(":status", "200"), ("content-length", "2")], false),
            &mut pending,
        );
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        handle_event(data_event(1, b"ok", true), &mut pending);
        let chunk = b_rx.try_recv().unwrap().unwrap();
        assert_eq!(&chunk[..], b"ok");
        assert!(
            b_rx.try_recv().is_err() && !pending.contains_key(&1),
            "a matching content-length must end the stream cleanly"
        );
    }

    #[test]
    fn split_data_frames_are_summed_not_compared_individually() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(
            headers_event(1, &[(":status", "200"), ("content-length", "4")], false),
            &mut pending,
        );
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        handle_event(data_event(1, b"ab", false), &mut pending);
        handle_event(data_event(1, b"", false), &mut pending);
        handle_event(data_event(1, b"cd", true), &mut pending);
        let mut body = Vec::new();
        while let Ok(Ok(chunk)) = b_rx.try_recv() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(&body[..], b"abcd");
    }

    #[test]
    fn content_length_is_also_checked_when_the_stream_ends_in_trailers() {
        let (mut pending, mut h_rx, mut b_rx) = pending_with_channels();
        handle_event(
            headers_event(1, &[(":status", "200"), ("content-length", "9")], false),
            &mut pending,
        );
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        handle_event(data_event(1, b"ab", false), &mut pending);
        let _ = b_rx.try_recv();
        handle_event(
            headers_event(1, &[("grpc-status", "0")], true),
            &mut pending,
        );
        let body_error = b_rx.try_recv().ok().and_then(protocol_error_text);
        assert!(
            body_error
                .as_deref()
                .is_some_and(|r| r.contains("content-length")),
            "the sum check must also run when the stream ends on trailers, got {body_error:?}"
        );
    }

    #[test]
    fn conflicting_or_unparsable_content_length_is_a_protocol_error() {
        let conflicting = malformed_headers_reason(
            &[
                (":status", "200"),
                ("content-length", "3"),
                ("content-length", "5"),
            ],
            false,
        );
        assert!(
            conflicting
                .as_deref()
                .is_some_and(|r| r.contains("content-length")),
            "conflicting content-length values must fail the stream, got {conflicting:?}"
        );
        for bad in ["", "abc", "-1", "+5", "0x10", "5 "] {
            let reason =
                malformed_headers_reason(&[(":status", "200"), ("content-length", bad)], false);
            assert!(
                reason.is_some(),
                "content-length {bad:?} must fail the stream, got {reason:?}"
            );
        }
    }

    #[test]
    fn responses_defined_to_have_no_content_skip_the_sum_check() {
        // RFC 9113 §8.1.1 explicitly permits a non-zero content-length with no
        // DATA on 204/304 and on the response to a HEAD request.
        for status in ["204", "304"] {
            let reason =
                malformed_headers_reason(&[(":status", status), ("content-length", "42")], true);
            assert!(
                reason.is_none(),
                "a {status} declaring content-length: 42 is legal, got {reason:?}"
            );
        }

        let (mut pending, mut h_rx, _b_rx) = pending_with_channels_for(http::Method::HEAD);
        handle_event(
            headers_event(1, &[(":status", "200"), ("content-length", "42")], true),
            &mut pending,
        );
        let delivered = h_rx.try_recv().unwrap().unwrap();
        assert_eq!(
            delivered.status, 200,
            "a HEAD response may declare a content-length it does not send"
        );
    }

    #[test]
    fn response_has_content_follows_rfc_9110_6_4_1() {
        assert!(response_has_content(&http::Method::GET, 200));
        assert!(!response_has_content(&http::Method::HEAD, 200));
        assert!(!response_has_content(&http::Method::GET, 204));
        assert!(!response_has_content(&http::Method::GET, 304));
        assert!(!response_has_content(&http::Method::CONNECT, 200));
        assert!(response_has_content(&http::Method::CONNECT, 407));
    }

    #[test]
    fn malformed_response_is_a_stream_error_not_a_connection_error() {
        // Two concurrent streams; only the malformed one must be torn down.
        let (h_tx1, mut h_rx1) = oneshot::channel();
        let (b_tx1, _b_rx1) = mpsc::unbounded_channel();
        let (h_tx2, mut h_rx2) = oneshot::channel();
        let (b_tx2, _b_rx2) = mpsc::unbounded_channel();
        let mut pending = HashMap::new();
        pending.insert(1, PendingStream::new(http::Method::GET, h_tx1, b_tx1));
        pending.insert(3, PendingStream::new(http::Method::GET, h_tx2, b_tx2));

        handle_event(
            headers_event(1, &[("x-no-status", "1")], false),
            &mut pending,
        );

        assert!(
            h_rx1
                .try_recv()
                .ok()
                .and_then(protocol_error_text)
                .is_some(),
            "the malformed stream must fail"
        );
        assert!(
            pending.contains_key(&3) && h_rx2.try_recv().is_err(),
            "the sibling stream must be untouched by another stream's malformed response"
        );
    }

    // ====================================================================
    // Full-stack regression: a local H2 server that emits 103 then 200.
    // Drives the real client driver against a hand-rolled server over an
    // in-memory duplex stream and asserts the caller sees the final 200.
    // ====================================================================

    /// Frame a raw HTTP/2 frame (9-byte header + payload).
    fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut buf = Vec::with_capacity(9 + len);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
        buf.push(frame_type);
        buf.push(flags);
        buf.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// HPACK "Literal Header Field without Indexing — Indexed Name" (`0000 NNNN`).
    /// `:status` is static-table index 8; values here are short (<128, no Huffman).
    fn hpack_indexed_name(name_index: u8, value: &str) -> Vec<u8> {
        let mut out = vec![name_index & 0x0f];
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
        out
    }

    /// HPACK "Literal Header Field without Indexing — New Name" (`0000 0000`).
    fn hpack_new_name(name: &str, value: &str) -> Vec<u8> {
        let mut out = vec![0x00];
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
        out
    }

    /// Minimal fake H2 server: sends SETTINGS, waits for the client's request
    /// HEADERS, then replies 103 Early Hints (with a preload Link header)
    /// followed by the final 200 + "ok" body. Keeps reading until the client
    /// closes so all client-side outbound writes succeed.
    async fn fake_server_103_then_200<S>(mut server: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const HEADERS: u8 = 0x1;
        const SETTINGS: u8 = 0x4;
        const DATA: u8 = 0x0;
        const END_STREAM: u8 = 0x1;
        const END_HEADERS: u8 = 0x4;

        // Our (empty) SETTINGS is the server's first frame.
        server
            .write_all(&h2_frame(SETTINGS, 0, 0, &[]))
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Skip the 24-byte client connection preface.
        let mut preface = [0u8; 24];
        server.read_exact(&mut preface).await.unwrap();

        // Read frames until the client's request HEADERS; capture its stream id.
        // Frame header layout (RFC 9113 §4.1): [0..3] length, [3] type,
        // [4] flags, [5..9] R-bit + 31-bit stream id.
        let sid = loop {
            let mut hdr = [0u8; 9];
            server.read_exact(&mut hdr).await.unwrap();
            let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
            let ftype = hdr[3];
            let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
            let mut payload = vec![0u8; len];
            server.read_exact(&mut payload).await.unwrap();
            if ftype == HEADERS {
                break sid;
            }
        };

        // 103 Early Hints (interim) carrying a preload Link header.
        let mut block_103 = hpack_indexed_name(8, "103");
        block_103.extend(hpack_new_name("link", "</s.css>; rel=preload"));
        server
            .write_all(&h2_frame(HEADERS, END_HEADERS, sid, &block_103))
            .await
            .unwrap();

        // Final 200 with a marker header.
        let mut block_200 = hpack_indexed_name(8, "200");
        block_200.extend(hpack_new_name("x-final", "yes"));
        server
            .write_all(&h2_frame(HEADERS, END_HEADERS, sid, &block_200))
            .await
            .unwrap();

        // Body + END_STREAM.
        server
            .write_all(&h2_frame(DATA, END_STREAM, sid, b"ok"))
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Keep the connection open (draining client frames) until the client
        // shuts the connection down, so client-side writes never hit a broken
        // pipe before its read loop dispatches our response events.
        let mut scratch = [0u8; 512];
        while let Ok(n) = server.read(&mut scratch).await {
            if n == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn early_hints_103_skipped_end_to_end() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_server_103_then_200(server_io));

        let profile = crate::profile::chrome_144_h2();
        let (mut sender, task) = spawn_driver(client_io, &profile).await.unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(None)
            .unwrap();

        // Timeout guards so a future regression fails fast instead of hanging CI.
        let (headers, mut body_rx) =
            tokio::time::timeout(std::time::Duration::from_secs(10), sender.send_request(req))
                .await
                .expect("send_request timed out — final response was never delivered")
                .unwrap();

        // The caller must see the final 200, not the interim 103.
        assert_eq!(
            headers.status, 200,
            "expected final 200, got interim status {}",
            headers.status
        );
        // Final response headers pass through; interim Link header does not leak.
        assert!(
            headers
                .headers
                .iter()
                .any(|(n, v)| n == "x-final" && v == "yes"),
            "final response headers should be present"
        );
        assert!(
            !headers.headers.iter().any(|(n, _)| n == "link"),
            "interim 103 Early Hints headers must not leak into the final response"
        );

        // Body reads "ok" then EOF.
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), body_rx.recv())
            .await
            .expect("body recv timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&chunk[..], b"ok");
        assert!(body_rx.recv().await.is_none());

        // Shut the client driver down so the server task can finish.
        drop(sender);
        let _ = task.await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server task timed out");
    }

    /// Minimal fake H2 server that answers with a response whose declared
    /// `content-length` is larger than the DATA it actually sends — the
    /// response-length desync of RFC 9113 §8.1.1.
    async fn fake_server_short_body<S>(mut server: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const HEADERS: u8 = 0x1;
        const SETTINGS: u8 = 0x4;
        const DATA: u8 = 0x0;
        const END_STREAM: u8 = 0x1;
        const END_HEADERS: u8 = 0x4;

        server
            .write_all(&h2_frame(SETTINGS, 0, 0, &[]))
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut preface = [0u8; 24];
        server.read_exact(&mut preface).await.unwrap();

        let sid = loop {
            let mut hdr = [0u8; 9];
            server.read_exact(&mut hdr).await.unwrap();
            let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
            let ftype = hdr[3];
            let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
            let mut payload = vec![0u8; len];
            server.read_exact(&mut payload).await.unwrap();
            if ftype == HEADERS {
                break sid;
            }
        };

        // 200 promising 100 bytes …
        let mut block = hpack_indexed_name(8, "200");
        block.extend(hpack_new_name("content-length", "100"));
        server
            .write_all(&h2_frame(HEADERS, END_HEADERS, sid, &block))
            .await
            .unwrap();
        // … then delivering 2 and closing the stream.
        server
            .write_all(&h2_frame(DATA, END_STREAM, sid, b"ok"))
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut scratch = [0u8; 512];
        while let Ok(n) = server.read(&mut scratch).await {
            if n == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn short_body_against_content_length_surfaces_end_to_end() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_server_short_body(server_io));

        let profile = crate::profile::chrome_144_h2();
        let (mut sender, task) = spawn_driver(client_io, &profile).await.unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(None)
            .unwrap();

        let (headers, mut body_rx) =
            tokio::time::timeout(std::time::Duration::from_secs(10), sender.send_request(req))
                .await
                .expect("send_request timed out")
                .unwrap();
        assert_eq!(headers.status, 200);

        // The two bytes the server did send arrive normally …
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), body_rx.recv())
            .await
            .expect("body recv timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&chunk[..], b"ok");

        // … and the truncation is then reported instead of a clean EOF.
        let tail = tokio::time::timeout(std::time::Duration::from_secs(10), body_rx.recv())
            .await
            .expect("body recv timed out");
        let reason = tail.and_then(protocol_error_text);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("malformed response") && r.contains("content-length")),
            "a truncated body must not be handed to the caller as a complete one, got {reason:?}"
        );

        drop(sender);
        let _ = task.await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server task timed out");
    }

    /// Like [`fake_server_short_body`], but it keeps reading afterwards and
    /// reports the first RST_STREAM the client sends (stream id, error code).
    async fn fake_server_short_body_watching_for_rst<S>(
        mut server: S,
        rst_tx: tokio::sync::oneshot::Sender<Option<(u32, u32)>>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const HEADERS: u8 = 0x1;
        const SETTINGS: u8 = 0x4;
        const DATA: u8 = 0x0;
        const RST_STREAM: u8 = 0x3;
        const END_STREAM: u8 = 0x1;
        const END_HEADERS: u8 = 0x4;

        server
            .write_all(&h2_frame(SETTINGS, 0, 0, &[]))
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut preface = [0u8; 24];
        server.read_exact(&mut preface).await.unwrap();

        let sid = loop {
            let mut hdr = [0u8; 9];
            server.read_exact(&mut hdr).await.unwrap();
            let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
            let ftype = hdr[3];
            let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
            let mut payload = vec![0u8; len];
            server.read_exact(&mut payload).await.unwrap();
            if ftype == HEADERS {
                break sid;
            }
        };

        // Promise 100 bytes, deliver 2, close the stream: RFC 9113 §8.1.1
        // response-length desync.
        let mut block = hpack_indexed_name(8, "200");
        block.extend(hpack_new_name("content-length", "100"));
        server
            .write_all(&h2_frame(HEADERS, END_HEADERS, sid, &block))
            .await
            .unwrap();
        server
            .write_all(&h2_frame(DATA, END_STREAM, sid, b"ok"))
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Now watch for the client's RST_STREAM.
        let mut found = None;
        loop {
            let mut hdr = [0u8; 9];
            if server.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
            let ftype = hdr[3];
            let frame_sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
            let mut payload = vec![0u8; len];
            if server.read_exact(&mut payload).await.is_err() {
                break;
            }
            if ftype == RST_STREAM && payload.len() == 4 {
                let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                found = Some((frame_sid, code));
                break;
            }
        }
        let _ = rst_tx.send(found);

        let mut scratch = [0u8; 512];
        while let Ok(n) = server.read(&mut scratch).await {
            if n == 0 {
                break;
            }
        }
    }

    /// RFC 9113 §8.1.1 makes a malformed response a stream error of type
    /// PROTOCOL_ERROR, which means an actual RST_STREAM on the wire.
    ///
    /// This used to be suppressed on the theory that any extra frame would
    /// diverge from the browser fingerprint. That was backwards — Chromium's
    /// netlog goes `HTTP2_SESSION_RECV_INVALID_HEADER` →
    /// `HTTP2_SESSION_SEND_RST_STREAM` with PROTOCOL_ERROR, so *not* sending it
    /// was the divergence. Staying silent also let the server keep sending DATA
    /// on a stream we had already torn down, with its flow-control window never
    /// returned.
    #[tokio::test]
    async fn malformed_response_sends_rst_stream_protocol_error() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (rst_tx, rst_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(fake_server_short_body_watching_for_rst(server_io, rst_tx));

        let profile = crate::profile::chrome_144_h2();
        let (mut sender, task) = spawn_driver(client_io, &profile).await.unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(None)
            .unwrap();

        let (_headers, mut body_rx) =
            tokio::time::timeout(std::time::Duration::from_secs(10), sender.send_request(req))
                .await
                .expect("send_request timed out")
                .unwrap();

        // Drain until the stream ends, which is what triggers the check.
        while let Ok(Some(_)) =
            tokio::time::timeout(std::time::Duration::from_secs(10), body_rx.recv()).await
        {}

        let observed = tokio::time::timeout(std::time::Duration::from_secs(10), rst_rx)
            .await
            .expect("timed out waiting for the client's RST_STREAM")
            .expect("server task dropped the channel");

        const PROTOCOL_ERROR: u32 = 0x1;
        assert_eq!(
            observed,
            Some((1, PROTOCOL_ERROR)),
            "the malformed stream must be reset with PROTOCOL_ERROR on the wire",
        );

        drop(sender);
        let _ = task.await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server task timed out");
    }
}
