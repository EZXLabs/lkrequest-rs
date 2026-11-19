//! Negotiated RFC 7692 connections use an extension-aware, bounded frame engine.

use super::WsMessage;
use crate::error::{Error, Result};
use futures_util::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream, StreamExt,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};
use yawc::{
    frame::{Frame, OpCode},
    WebSocket,
};

const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

// Preserve protocol errors: yawc's ordinary Stream adapter converts them to EOF.
struct Socket<S> {
    ws: WebSocket<S>,
    pending: Option<yawc::Result<Frame>>,
    close_sent: bool,
    terminal: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for Socket<S> {
    type Item = yawc::Result<Frame>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminal {
            return Poll::Ready(Some(Err(yawc::WebSocketError::ConnectionClosed)));
        }
        if self.pending.is_none() {
            self.pending = Some(std::task::ready!(self.ws.poll_next_frame(cx)));
        }
        let close_received = self.pending.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .is_ok_and(|frame| frame.opcode() == OpCode::Close)
        });
        // Flush automatic Pong/Close replies before returning the received
        // frame, even when the caller never polls recv again.
        if !(close_received && self.close_sent) {
            if let Err(error) = std::task::ready!(Pin::new(&mut self.ws).poll_ready(cx)) {
                if self.pending.as_ref().is_some_and(|result| result.is_ok()) {
                    self.pending = Some(Err(error));
                }
            }
        }
        self.terminal =
            close_received || self.pending.as_ref().is_some_and(|result| result.is_err());
        Poll::Ready(self.pending.take())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Frame> for Socket<S> {
    type Error = yawc::WebSocketError;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<yawc::Result<()>> {
        if self.close_sent || self.terminal {
            return Poll::Ready(Err(yawc::WebSocketError::ConnectionClosed));
        }
        Pin::new(&mut self.ws).poll_ready(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, frame: Frame) -> yawc::Result<()> {
        if self.close_sent || self.terminal {
            return Err(yawc::WebSocketError::ConnectionClosed);
        }
        self.close_sent = frame.opcode() == OpCode::Close;
        Pin::new(&mut self.ws).start_send(frame)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<yawc::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<yawc::Result<()>> {
        Pin::new(&mut self.ws).poll_close(cx)
    }
}

pub(super) struct Connection<S: AsyncRead + AsyncWrite + Unpin> {
    reader: Mutex<SplitStream<Socket<S>>>,
    writer: Mutex<SplitSink<Socket<S>, Frame>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub(super) fn new(stream: S, negotiated: &str) -> Result<Self> {
        Self::with_limit(stream, negotiated, MAX_MESSAGE_BYTES)
    }

    fn with_limit(stream: S, negotiated: &str, limit: usize) -> Result<Self> {
        let options = yawc::Options::default()
            .with_limits(limit + 1, limit + 1)
            .with_balanced_compression()
            .with_utf8();
        let ws = WebSocket::from_stream_with_extensions(
            stream,
            yawc::Role::Client,
            Some(negotiated),
            options,
        )
        .map_err(ws_error)?;
        let (writer, reader) = Socket {
            ws,
            pending: None,
            close_sent: false,
            terminal: false,
        }
        .split();
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    }

    pub(super) async fn recv(&self) -> Result<WsMessage> {
        let frame = self
            .reader
            .lock()
            .await
            .next()
            .await
            .ok_or_else(|| Error::Http("WebSocket connection closed".into()))?
            .map_err(ws_error)?;
        let payload = frame.payload();
        match frame.opcode() {
            OpCode::Text => Ok(WsMessage::Text(
                String::from_utf8(payload.to_vec())
                    .map_err(|e| Error::Http(format!("WebSocket invalid UTF-8: {e}")))?,
            )),
            OpCode::Binary => Ok(WsMessage::Binary(payload.to_vec())),
            OpCode::Ping => Ok(WsMessage::Ping(payload.to_vec())),
            OpCode::Pong => Ok(WsMessage::Pong(payload.to_vec())),
            OpCode::Close => {
                let code =
                    (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]]));
                let reason = if code.is_some() {
                    String::from_utf8_lossy(&payload[2..]).into_owned()
                } else {
                    String::new()
                };
                Ok(WsMessage::Close(code, reason))
            }
            OpCode::Continuation => Err(Error::Http(
                "WebSocket incomplete fragmented message".into(),
            )),
        }
    }

    pub(super) async fn send(&self, frame: fastwebsockets::Frame<'_>) -> Result<()> {
        use fastwebsockets::OpCode as Code;
        let data = bytes::Bytes::copy_from_slice(&frame.payload);
        let frame = match frame.opcode {
            Code::Text => Frame::text(data),
            Code::Binary => Frame::binary(data),
            Code::Ping => Frame::ping(data),
            Code::Pong => Frame::pong(data),
            Code::Close => Frame::close(u16::from_be_bytes([data[0], data[1]]).into(), &data[2..]),
            Code::Continuation => {
                return Err(Error::Http(
                    "WebSocket unexpected outgoing continuation".into(),
                ))
            }
        };
        self.writer.lock().await.send(frame).await.map_err(ws_error)
    }
}

fn ws_error(error: yawc::WebSocketError) -> Error {
    Error::Http(format!("WebSocket compression/frame error: {error}"))
}

#[derive(Default)]
struct Parameters {
    server_bits: Option<u8>,
    client_bits: Option<Option<u8>>,
    server_reset: bool,
    client_reset: bool,
}

fn parameters(value: &str, response: bool) -> Result<Parameters> {
    let mut parts = value.split(';');
    if parts.next().map(str::trim) != Some("permessage-deflate") {
        return Err(Error::Http(
            "unsupported negotiated WebSocket extension".into(),
        ));
    }
    let mut result = Parameters::default();
    let mut seen = std::collections::HashSet::new();
    for part in parts {
        let (name, value) = part
            .trim()
            .split_once('=')
            .map_or((part.trim(), None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        if !seen.insert(name) {
            return Err(Error::Http("duplicate permessage-deflate parameter".into()));
        }
        let bits = || -> Result<u8> {
            let raw = value.ok_or_else(|| Error::Http("missing deflate window size".into()))?;
            let raw = if let Some(raw) = raw.strip_prefix('"') {
                raw.strip_suffix('"').unwrap_or("")
            } else {
                raw
            };
            let bits = (!raw.starts_with('0') && raw.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| raw.parse::<u8>().ok())
                .flatten()
                .filter(|n| (8..=15).contains(n));
            bits.ok_or_else(|| Error::Http("invalid deflate window size".into()))
        };
        match name {
            "server_max_window_bits" => result.server_bits = Some(bits()?),
            "client_max_window_bits" => {
                result.client_bits = Some(if value.is_some() || response {
                    Some(bits()?)
                } else {
                    None
                })
            }
            "server_no_context_takeover" if value.is_none() => result.server_reset = true,
            "client_no_context_takeover" if value.is_none() => result.client_reset = true,
            _ => {
                return Err(Error::Http(
                    "unsupported permessage-deflate parameter".into(),
                ))
            }
        }
    }
    Ok(result)
}

/// Validate against the actual emitted headers, including caller overrides.
pub(super) fn negotiate(
    offers: &http::HeaderMap,
    response: &http::HeaderMap,
) -> Result<Option<String>> {
    let mut accepted = Vec::new();
    for value in response.get_all("sec-websocket-extensions") {
        let value = value
            .to_str()
            .map_err(|_| Error::Http("invalid WebSocket extension header".into()))?;
        accepted.extend(value.split(',').map(str::trim));
    }
    if accepted.is_empty() {
        return Ok(None);
    }
    if accepted.len() != 1 {
        return Err(Error::Http(
            "multiple negotiated WebSocket extensions are unsupported".into(),
        ));
    }
    let mut selected = parameters(accepted[0], true)?;
    let matched = offers
        .get_all("sec-websocket-extensions")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| parameters(value.trim(), false).ok())
        .find(|offer| {
            (!offer.server_reset || selected.server_reset)
                && offer
                    .server_bits
                    .is_none_or(|limit| selected.server_bits.is_some_and(|bits| bits <= limit))
                && (selected.client_bits.is_none() || offer.client_bits.is_some())
        });
    let offer = matched
        .ok_or_else(|| Error::Http("WebSocket deflate response does not match an offer".into()))?;
    // RFC 7692 client_* offers are promises even when the server omits them
    // or accepts a larger window; server_* offers constrain the response.
    selected.client_reset |= offer.client_reset;
    if let Some(bits) = offer.client_bits.flatten() {
        selected.client_bits = Some(Some(bits.min(selected.client_bits.flatten().unwrap_or(15))));
    }
    if selected.client_bits == Some(Some(8)) {
        return Err(Error::Http(
            "8-bit client compression windows are unsupported".into(),
        ));
    }
    // Normalize only the internal engine input; the captured request bytes stay intact.
    let mut normalized = "permessage-deflate".to_owned();
    if selected.server_reset {
        normalized.push_str("; server_no_context_takeover");
    }
    if selected.client_reset {
        normalized.push_str("; client_no_context_takeover");
    }
    if let Some(bits) = selected.server_bits {
        normalized.push_str(&format!("; server_max_window_bits={bits}"));
    }
    if let Some(Some(bits)) = selected.client_bits {
        normalized.push_str(&format!("; client_max_window_bits={bits}"));
    }
    Ok(Some(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn headers(value: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("sec-websocket-extensions", value.parse().unwrap());
        headers
    }

    #[test]
    fn negotiation_checks_parameters_and_actual_offer() {
        let offer = headers("permessage-deflate; client_max_window_bits; server_max_window_bits=12; server_no_context_takeover");
        let accepted = "permessage-deflate; client_max_window_bits=10; server_max_window_bits=11; server_no_context_takeover";
        assert!(negotiate(&offer, &headers(accepted)).unwrap().is_some());
        for invalid in [
            "permessage-deflate",
            "permessage-deflate; server_max_window_bits=13; server_no_context_takeover",
            "permessage-deflate; client_max_window_bits=8; server_max_window_bits=12; server_no_context_takeover",
            "permessage-deflate; server_max_window_bits=7",
            "permessage-deflate; server_max_window_bits=012",
            "permessage-deflate; server_max_window_bits=+12",
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; client_no_context_takeover=1",
            "permessage-deflate; client_max_window_bits=10; client_max_window_bits=11",
            "permessage-deflate; unknown=1",
            "permessage-deflate, permessage-deflate",
            "x-unknown",
        ] {
            assert!(negotiate(&offer, &headers(invalid)).is_err(), "{invalid}");
        }
        assert!(negotiate(&http::HeaderMap::new(), &headers("permessage-deflate")).is_err());
        assert!(negotiate(&offer, &http::HeaderMap::new())
            .unwrap()
            .is_none());
        assert!(negotiate(
            &headers("permessage-deflate"),
            &headers("permessage-deflate; client_max_window_bits=10")
        )
        .is_err());
        let mut repeated = headers("permessage-deflate");
        repeated.append(
            "sec-websocket-extensions",
            "permessage-deflate".parse().unwrap(),
        );
        assert!(negotiate(&offer, &repeated).is_err());
    }

    #[test]
    fn local_compression_promises_survive_server_omission_or_larger_window() {
        let offer =
            headers("permessage-deflate; client_max_window_bits=10; client_no_context_takeover");
        for response in [
            "permessage-deflate",
            "permessage-deflate; client_max_window_bits=12",
        ] {
            let normalized = negotiate(&offer, &headers(response)).unwrap().unwrap();
            assert!(normalized.contains("client_max_window_bits=10"));
            assert!(normalized.contains("client_no_context_takeover"));
        }
        assert!(negotiate(
            &headers("permessage-deflate; server_max_window_bits=15"),
            &headers("permessage-deflate")
        )
        .is_err());
    }

    fn compress(compressor: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::with_capacity(data.len() * 2 + 64);
        compressor
            .compress_vec(data, &mut compressed, FlushCompress::Sync)
            .unwrap();
        assert!(compressed.ends_with(&[0, 0, 255, 255]));
        compressed.truncate(compressed.len() - 4);
        compressed
    }

    async fn server_frame(peer: &mut DuplexStream, opcode: u8, payload: &[u8]) {
        peer.write_u8(opcode).await.unwrap();
        if payload.len() < 126 {
            peer.write_u8(payload.len() as u8).await.unwrap();
        } else {
            peer.write_u8(126).await.unwrap();
            peer.write_u16(payload.len() as u16).await.unwrap();
        }
        peer.write_all(payload).await.unwrap();
    }

    async fn client_frame(peer: &mut DuplexStream) -> (u8, Vec<u8>) {
        let opcode = peer.read_u8().await.unwrap();
        let length = peer.read_u8().await.unwrap();
        assert_ne!(length & 128, 0, "client frames must be masked");
        let length = match length & 127 {
            126 => peer.read_u16().await.unwrap() as usize,
            127 => peer.read_u64().await.unwrap() as usize,
            length => length as usize,
        };
        let mut mask = [0; 4];
        peer.read_exact(&mut mask).await.unwrap();
        let mut data = vec![0; length];
        peer.read_exact(&mut data).await.unwrap();
        for (index, byte) in data.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        (opcode, data)
    }

    #[tokio::test]
    async fn both_directions_honor_windows_and_context_takeover() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for reset in [false, true] {
                for bits in [9, 12, 15] {
                    let mut negotiated = format!("permessage-deflate; client_max_window_bits={bits}; server_max_window_bits={bits}");
                    if reset { negotiated.push_str("; client_no_context_takeover; server_no_context_takeover"); }
                    let (stream, mut peer) = tokio::io::duplex(16384);
                    let connection = Connection::new(stream, &negotiated).unwrap();
                    let mut encoder = Compress::new_with_window_bits(Compression::default(), false, bits);
                    let mut decoder = Decompress::new_with_window_bits(false, bits);
                    for _ in 0..3 {
                        let message = "WebSocket compression context ".repeat(100);
                        let encoded = compress(&mut encoder, message.as_bytes());
                        server_frame(&mut peer, 0xc1, &encoded).await;
                        assert!(matches!(connection.recv().await.unwrap(), WsMessage::Text(text) if text == message));
                        connection.send(fastwebsockets::Frame::text(fastwebsockets::Payload::Borrowed(message.as_bytes()))).await.unwrap();
                        let (opcode, mut payload) = client_frame(&mut peer).await;
                        assert_eq!(opcode, 0xc1, "outgoing text must be compressed");
                        payload.extend_from_slice(&[0, 0, 255, 255]);
                        let mut plain = Vec::with_capacity(message.len() + 128);
                        decoder.decompress_vec(&payload, &mut plain, FlushDecompress::Sync).unwrap();
                        assert_eq!(plain, message.as_bytes());
                        if reset { encoder.reset(); decoder.reset(false); }
                    }
                }
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn inflation_and_fragment_aggregation_are_bounded() {
        for fragmented in [false, true] {
            let (stream, mut peer) = tokio::io::duplex(4096);
            let connection = Connection::with_limit(stream, "permessage-deflate", 1024).unwrap();
            let mut encoder = Compress::new(Compression::default(), false);
            let encoded = compress(&mut encoder, &vec![b'x'; 2048]);
            if fragmented {
                server_frame(&mut peer, 0x41, &encoded[..encoded.len() / 2]).await;
                server_frame(&mut peer, 0x80, &encoded[encoded.len() / 2..]).await;
            } else {
                server_frame(&mut peer, 0xc1, &encoded).await;
            }
            let error = tokio::time::timeout(std::time::Duration::from_secs(2), connection.recv())
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                error.to_string().to_lowercase().contains("large"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn pending_receive_does_not_block_send_and_control_replies_are_flushed() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (stream, mut peer) = tokio::io::duplex(4096);
            let connection = Connection::new(stream, "permessage-deflate").unwrap();
            let mut recv = Box::pin(connection.recv());
            assert!(futures_util::poll!(&mut recv).is_pending());
            connection
                .send(fastwebsockets::Frame::text(
                    fastwebsockets::Payload::Borrowed(b"hello"),
                ))
                .await
                .unwrap();
            let _ = client_frame(&mut peer).await;
            server_frame(&mut peer, 0x89, b"ping").await;
            assert!(matches!(recv.await.unwrap(), WsMessage::Ping(_)));
            assert_eq!(client_frame(&mut peer).await, (0x8a, b"ping".to_vec()));
            server_frame(&mut peer, 0x88, &[3, 232]).await;
            assert!(matches!(
                connection.recv().await.unwrap(),
                WsMessage::Close(Some(1000), _)
            ));
            assert_eq!(client_frame(&mut peer).await, (0x88, vec![3, 232]));
            assert!(connection.recv().await.is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn locally_initiated_close_is_not_echoed_twice() {
        let (stream, mut peer) = tokio::io::duplex(4096);
        let connection = Connection::new(stream, "permessage-deflate").unwrap();
        connection
            .send(fastwebsockets::Frame::close(1000, b""))
            .await
            .unwrap();
        assert_eq!(client_frame(&mut peer).await, (0x88, vec![3, 232]));
        server_frame(&mut peer, 0x88, &[3, 232]).await;
        assert!(matches!(
            connection.recv().await.unwrap(),
            WsMessage::Close(..)
        ));
        assert!(connection.recv().await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), peer.read_u8())
                .await
                .is_err()
        );
    }
}
