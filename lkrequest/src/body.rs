//! Internal request bodies: replayable buffered bytes or a single-use upload source.
//!
//! Attempt clones share only the right to claim a stream, not a replayable copy.
//! Framing is checked after header merging; source polling happens outside locks.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, ReadBuf};

use crate::error::{Error, Result};

pub(crate) type UploadStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

/// Runs at most one blocking read per poll-driven chunk; never drains ahead.
/// Dropping it cannot interrupt a `Read` already executing on a blocking worker.
pub(crate) struct BlockingReaderStream<Reader> {
    reader: Option<Reader>,
    pending: Option<tokio::task::JoinHandle<(Reader, io::Result<Bytes>)>>,
    done: bool,
}

impl<Reader> BlockingReaderStream<Reader> {
    pub(crate) fn new(reader: Reader) -> Self {
        Self {
            reader: Some(reader),
            pending: None,
            done: false,
        }
    }
}

impl<Reader: io::Read + Send + Unpin + 'static> Stream for BlockingReaderStream<Reader> {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use std::future::Future;
        if self.done {
            return Poll::Ready(None);
        }
        if self.pending.is_none() {
            let Some(mut reader) = self.reader.take() else {
                return Poll::Ready(None);
            };
            self.pending = Some(tokio::task::spawn_blocking(move || {
                let mut buffer = vec![0; 16 * 1024];
                let result = loop {
                    match reader.read(&mut buffer) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => break result,
                    }
                }
                .map(|count| {
                    buffer.truncate(count);
                    Bytes::from(buffer)
                });
                (reader, result)
            }));
        }
        match Pin::new(self.pending.as_mut().unwrap()).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                match result {
                    Ok((reader, Ok(bytes))) if !bytes.is_empty() => {
                        self.reader = Some(reader);
                        Poll::Ready(Some(Ok(bytes)))
                    }
                    Ok((_, Ok(_))) => {
                        self.done = true;
                        Poll::Ready(None)
                    }
                    Ok((_, Err(error))) => {
                        self.done = true;
                        Poll::Ready(Some(Err(error)))
                    }
                    Err(error) => {
                        self.done = true;
                        Poll::Ready(Some(Err(io::Error::other(error))))
                    }
                }
            }
        }
    }
}

/// Cloning preserves buffered bytes or shares a single claimable streaming source.
#[derive(Clone)]
pub(crate) struct RequestBody {
    inner: BodySource,
}

#[derive(Clone)]
enum BodySource {
    Buffered(Bytes),
    Stream(Arc<Mutex<StreamSource>>),
}

struct StreamSource {
    stream: Option<UploadStream>,
    length: Option<u64>,
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestBody")
            .field("streaming", &self.is_streaming())
            .field("length", &self.len())
            .finish()
    }
}

impl Default for RequestBody {
    fn default() -> Self {
        Bytes::new().into()
    }
}

impl From<Bytes> for RequestBody {
    fn from(bytes: Bytes) -> Self {
        Self {
            inner: BodySource::Buffered(bytes),
        }
    }
}

impl RequestBody {
    pub(crate) fn stream(stream: UploadStream, length: Option<u64>) -> Self {
        Self {
            inner: BodySource::Stream(Arc::new(Mutex::new(StreamSource {
                stream: Some(stream),
                length,
            }))),
        }
    }

    pub(crate) fn reader(reader: impl AsyncRead + Send + 'static, length: Option<u64>) -> Self {
        Self::stream(
            Box::pin(ReaderStream {
                reader: Box::pin(reader),
                buffer: vec![0; 16 * 1024],
            }),
            length,
        )
    }

    pub(crate) fn buffered(&self) -> Option<&Bytes> {
        match &self.inner {
            BodySource::Buffered(bytes) => Some(bytes),
            BodySource::Stream(_) => None,
        }
    }

    pub(crate) fn is_streaming(&self) -> bool {
        matches!(self.inner, BodySource::Stream(_))
    }

    /// Body availability only; method/idempotency policy is checked separately.
    pub(crate) fn can_replay(&self) -> bool {
        match &self.inner {
            BodySource::Buffered(_) => true,
            BodySource::Stream(source) => source.lock().stream.is_some(),
        }
    }

    pub(crate) fn len(&self) -> Option<u64> {
        match &self.inner {
            BodySource::Buffered(bytes) => Some(bytes.len() as u64),
            BodySource::Stream(source) => source.lock().length,
        }
    }

    /// Validate effective headers before claiming the source, after all merges.
    /// An explicit length also constrains a previously unknown-length source.
    pub(crate) fn prepare_headers(&self, headers: &mut http::HeaderMap) -> Result<()> {
        let BodySource::Stream(source) = &self.inner else {
            return Ok(());
        };
        if headers.contains_key(http::header::TRANSFER_ENCODING) {
            return Err(Error::Http("streaming uploads must not set Transfer-Encoding; framing is selected by the transport".into()));
        }
        let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
        let length = values
            .next()
            .map(|value| {
                let text = value
                    .to_str()
                    .map_err(|_| Error::Http("invalid upload Content-Length".into()))?;
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(Error::Http("invalid upload Content-Length".into()));
                }
                text.parse::<u64>()
                    .map_err(|_| Error::Http("invalid upload Content-Length".into()))
            })
            .transpose()?;
        if values.next().is_some() {
            return Err(Error::Http("multiple upload Content-Length headers".into()));
        }
        let mut source = source.lock();
        if let Some(length) = length {
            if source.length.is_some_and(|expected| expected != length) {
                return Err(Error::Http(
                    "upload length does not match Content-Length".into(),
                ));
            }
            source.length = Some(length);
        } else if let Some(length) = source.length {
            headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from(length),
            );
        }
        Ok(())
    }

    pub(crate) fn into_upload(self) -> Result<UploadStream> {
        match self.inner {
            BodySource::Buffered(bytes) => Ok(Box::pin(OneChunk(Some(bytes)))),
            BodySource::Stream(source) => {
                let mut source = source.lock();
                // Every attempt shares this slot. Claiming it prevents even an
                // idempotent retry from sending a partially consumed source.
                let stream = source.stream.take().ok_or_else(|| {
                    Error::Http(
                        "streaming upload body has already been consumed and cannot be replayed"
                            .into(),
                    )
                })?;
                Ok(Box::pin(CheckedStream {
                    stream,
                    remaining: source.length,
                    final_chunk: None,
                    done: false,
                }))
            }
        }
    }

    pub(crate) fn into_http_body(self) -> Result<WireBody> {
        if let Some(bytes) = self.buffered() {
            return Ok(WireBody::Buffered(Full::new(bytes.clone())));
        }
        let remaining = self.len();
        Ok(WireBody::Stream {
            stream: self.into_upload()?,
            remaining,
            done: false,
            completion: Arc::new(AtomicBool::new(false)),
        })
    }
}

struct OneChunk(Option<Bytes>);

impl Stream for OneChunk {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.take().filter(|bytes| !bytes.is_empty()).map(Ok))
    }
}

struct ReaderStream {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    buffer: Vec<u8>,
}

impl Stream for ReaderStream {
    type Item = io::Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buffer = ReadBuf::new(&mut this.buffer);
        match this.reader.as_mut().poll_read(context, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => Poll::Ready(None),
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(Bytes::copy_from_slice(buffer.filled())))),
        }
    }
}

struct CheckedStream {
    stream: UploadStream,
    remaining: Option<u64>,
    final_chunk: Option<Bytes>,
    done: bool,
}

impl Stream for CheckedStream {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        for _ in 0..32 {
            match self.stream.as_mut().poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    if self.remaining.is_some_and(|remaining| remaining != 0) {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "upload body is shorter than Content-Length",
                        ))));
                    }
                    return Poll::Ready(self.final_chunk.take().map(Ok));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    if let Some(remaining) = self.remaining {
                        if bytes.len() as u64 > remaining {
                            self.done = true;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "upload body exceeds Content-Length",
                            ))));
                        }
                        self.remaining = Some(remaining - bytes.len() as u64);
                        if self.remaining == Some(0) {
                            // Hyper may stop polling at Content-Length. Hold the
                            // final chunk until EOF proves there are no extra bytes.
                            self.final_chunk = Some(bytes);
                            continue;
                        }
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }
            }
        }
        // Empty ready chunks must not monopolize the executor.
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

pub(crate) enum WireBody {
    Buffered(Full<Bytes>),
    Stream {
        stream: UploadStream,
        remaining: Option<u64>,
        done: bool,
        completion: Arc<AtomicBool>,
    },
}

impl WireBody {
    /// Tracks validated source completion, not acknowledgement by the peer.
    /// H1 uses this to avoid pooling a connection with an unfinished upload.
    pub(crate) fn upload_completion(&self) -> Option<Arc<AtomicBool>> {
        match self {
            Self::Buffered(_) => None,
            Self::Stream { completion, .. } => Some(completion.clone()),
        }
    }

    /// Hyper can skip polling a zero-length body; check its source before sending.
    pub(crate) async fn validate_empty(&mut self) -> Result<()> {
        if let Self::Stream {
            stream,
            remaining: Some(0),
            done,
            completion,
        } = self
        {
            if let Some(result) =
                std::future::poll_fn(|context| stream.as_mut().poll_next(context)).await
            {
                result.map_err(|error| Error::Http(format!("upload body: {error}")))?;
                return Err(Error::Http(
                    "nonempty upload with zero Content-Length".into(),
                ));
            }
            *done = true;
            completion.store(true, Ordering::Release);
        }
        Ok(())
    }
}

impl Body for WireBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        match self.get_mut() {
            Self::Buffered(body) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(|never| match never {}))),
            Self::Stream {
                stream,
                remaining,
                done,
                completion,
            } => match stream.as_mut().poll_next(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => {
                    if let Some(remaining) = remaining {
                        *remaining -= bytes.len() as u64;
                        if *remaining == 0 {
                            completion.store(true, Ordering::Release);
                        }
                    }
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
                Poll::Ready(Some(Err(error))) => {
                    *done = true;
                    Poll::Ready(Some(Err(error)))
                }
                Poll::Ready(None) => {
                    *done = true;
                    completion.store(true, Ordering::Release);
                    Poll::Ready(None)
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Buffered(body) => body.is_end_stream(),
            Self::Stream { done, .. } => *done,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Buffered(body) => body.size_hint(),
            Self::Stream {
                remaining: Some(length),
                ..
            } => SizeHint::with_exact(*length),
            Self::Stream { .. } => SizeHint::default(),
        }
    }
}
