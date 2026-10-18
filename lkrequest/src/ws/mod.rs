//! WebSocket support — fingerprint-consistent WebSocket connections.
//!
//! Provides WebSocket connectivity through HTTP/1.1 Upgrade with full TLS
//! fingerprint control.
//!
//! # Usage
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! use lkrequest::Client;
//! use lktls::profile::presets;
//!
//! let client = Client::builder()
//!     .fingerprint(presets::chrome_144())
//!     .build();
//! let session = client.session().build();
//!
//! let ws = session.websocket("wss://echo.websocket.events")
//!     .header("Origin", "https://echo.websocket.events")
//!     .connect()
//!     .await?;
//!
//! ws.send_text("hello").await?;
//! let msg = ws.recv().await?;
//! ws.close(None).await?;
//! # Ok(())
//! # }
//! ```

pub mod builder;
pub(crate) mod upgrade;

use std::sync::atomic::{AtomicBool, Ordering};

use fastwebsockets::{
    FragmentCollectorRead, Frame, OpCode, Payload, Role, WebSocket, WebSocketWrite,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::error::{Error, Result};

/// A WebSocket message received from or sent to the peer.
#[derive(Debug, Clone)]
pub enum WsMessage {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping frame with optional payload.
    Ping(Vec<u8>),
    /// A pong frame with optional payload.
    Pong(Vec<u8>),
    /// A close frame with optional (code, reason).
    Close(Option<u16>, String),
}

/// An active WebSocket connection.
///
/// Wraps an HTTP/1.1 upgraded stream with independent reader and writer state.
/// The existing `send_text`, `send_binary`, `recv`, and `close` methods accept
/// shared references, so a pending receive does not prevent sending or closing.
/// Multiple receives and multiple writes are serialized within each direction.
///
/// By default, incoming Ping frames are automatically answered with Pong
/// (`auto_pong` is enabled).
pub struct WsConnection<S: AsyncRead + AsyncWrite + Unpin> {
    reader: Mutex<FragmentCollectorRead<ReadHalf<S>>>,
    writer: Mutex<WebSocketWrite<WriteHalf<S>>>,
    closed: AtomicBool,
    url: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsConnection<S> {
    /// Create a new WsConnection wrapping a stream that has already completed
    /// the WebSocket handshake.
    pub(crate) fn new(stream: S, url: String) -> Self {
        let mut ws = WebSocket::after_handshake(stream, Role::Client);
        ws.set_auto_pong(true);
        ws.set_auto_close(true);
        ws.set_writev(false);
        let (reader, writer) = ws.split(tokio::io::split);
        Self {
            reader: Mutex::new(FragmentCollectorRead::new(reader)),
            writer: Mutex::new(writer),
            closed: AtomicBool::new(false),
            url,
        }
    }

    /// Returns the URL of this WebSocket connection.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send a text message.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        let frame = Frame::text(Payload::Borrowed(text.as_bytes()));
        self.write_frame(frame)
            .await
            .map_err(|e| Error::Http(format!("WebSocket send_text error: {e}")))?;
        Ok(())
    }

    /// Send a binary message.
    pub async fn send_binary(&self, data: &[u8]) -> Result<()> {
        let frame = Frame::binary(Payload::Borrowed(data));
        self.write_frame(frame)
            .await
            .map_err(|e| Error::Http(format!("WebSocket send_binary error: {e}")))?;
        Ok(())
    }

    /// Send a raw [`WsMessage`].
    pub async fn send(&self, msg: WsMessage) -> Result<()> {
        match msg {
            WsMessage::Text(s) => self.send_text(&s).await,
            WsMessage::Binary(b) => self.send_binary(&b).await,
            WsMessage::Ping(data) => {
                let frame = Frame::new(true, OpCode::Ping, None, Payload::Owned(data));
                self.write_frame(frame)
                    .await
                    .map_err(|e| Error::Http(format!("WebSocket send ping error: {e}")))?;
                Ok(())
            }
            WsMessage::Pong(data) => {
                let frame = Frame::new(true, OpCode::Pong, None, Payload::Owned(data));
                self.write_frame(frame)
                    .await
                    .map_err(|e| Error::Http(format!("WebSocket send pong error: {e}")))?;
                Ok(())
            }
            WsMessage::Close(code, reason) => self.close(code.map(|c| (c, reason.as_str()))).await,
        }
    }

    /// Receive the next message from the WebSocket.
    ///
    /// Ping frames are automatically answered with Pong when `auto_pong` is
    /// enabled (default). This method blocks until a data or close frame is
    /// received.
    /// The underlying frame parser is not cancellation safe after receiving a
    /// partial frame. Keep an in-flight receive alive while sending concurrently;
    /// dropping and restarting it may lose framing state.
    pub async fn recv(&self) -> Result<WsMessage> {
        let mut reader = self.reader.lock().await;
        loop {
            let frame = reader
                .read_frame(&mut |frame| async move {
                    let mut writer = self.writer.lock().await;
                    if writer.is_closed() {
                        return Ok(());
                    }
                    if frame.opcode == OpCode::Close {
                        self.closed.store(true, Ordering::Release);
                    }
                    writer.write_frame(frame).await
                })
                .await
                .map_err(|e| Error::Http(format!("WebSocket recv error: {e}")))?;

            if self.closed.load(Ordering::Acquire) && frame.opcode != OpCode::Close {
                return Err(Error::Http(format!(
                    "WebSocket recv error: {}",
                    fastwebsockets::WebSocketError::ConnectionClosed
                )));
            }

            match frame.opcode {
                OpCode::Text => {
                    let text = String::from_utf8(frame.payload.to_vec())
                        .map_err(|e| Error::Http(format!("WebSocket invalid UTF-8: {e}")))?;
                    return Ok(WsMessage::Text(text));
                }
                OpCode::Binary => {
                    return Ok(WsMessage::Binary(frame.payload.to_vec()));
                }
                OpCode::Close => {
                    let (code, reason) = if frame.payload.len() >= 2 {
                        let code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                        let reason = String::from_utf8_lossy(&frame.payload[2..]).into_owned();
                        (Some(code), reason)
                    } else {
                        (None, String::new())
                    };
                    return Ok(WsMessage::Close(code, reason));
                }
                OpCode::Ping => {
                    // auto_pong handles this; yield Ping to caller anyway
                    return Ok(WsMessage::Ping(frame.payload.to_vec()));
                }
                OpCode::Pong => {
                    return Ok(WsMessage::Pong(frame.payload.to_vec()));
                }
                OpCode::Continuation => {
                    // FragmentCollector should reassemble; skip if leaked
                    continue;
                }
            }
        }
    }

    /// Close the WebSocket connection.
    ///
    /// Optionally send a close code and reason string. If `None`, sends a
    /// normal close (code 1000).
    ///
    /// # Errors
    ///
    /// Returns an error *without writing anything to the wire* if `code` is one
    /// an endpoint may not send (see [`validate_close_code`]) or if `reason`
    /// does not fit in a control frame (RFC 6455 §5.5 caps the whole payload at
    /// 125 bytes, of which the code takes 2).
    ///
    /// # Closing handshake
    ///
    /// This sends the close frame and returns; it does not wait for the peer's
    /// close frame (RFC 6455 §7.1.1). `fastwebsockets`' `auto_close` only
    /// covers the mirror-image case — a close frame *received* by
    /// [`recv`](Self::recv) is echoed back automatically. To complete the
    /// handshake as the initiator, call [`recv`](Self::recv) after `close` and
    /// wait for the [`WsMessage::Close`] reply; dropping the `WsConnection`
    /// then closes the underlying transport. Waiting here instead would block
    /// indefinitely against a peer that never replies.
    pub async fn close(&self, close_info: Option<(u16, &str)>) -> Result<()> {
        let frame = if let Some((code, reason)) = close_info {
            validate_close_code(code)?;
            let reason = reason.as_bytes();
            if reason.len() > MAX_CLOSE_REASON_LEN {
                return Err(Error::Http(format!(
                    "WebSocket close reason is {} bytes; RFC 6455 §5.5 limits a control \
                     frame payload to 125 bytes, leaving {MAX_CLOSE_REASON_LEN} for the reason",
                    reason.len(),
                )));
            }
            Frame::close(code, reason)
        } else {
            Frame::close(1000, b"")
        };
        self.write_frame(frame)
            .await
            .map_err(|e| Error::Http(format!("WebSocket close error: {e}")))?;
        Ok(())
    }

    async fn write_frame(
        &self,
        frame: Frame<'_>,
    ) -> std::result::Result<(), fastwebsockets::WebSocketError> {
        let mut writer = self.writer.lock().await;
        if frame.opcode == OpCode::Close {
            self.closed.store(true, Ordering::Release);
        }
        writer.write_frame(frame).await
    }
}

/// Longest close reason that still fits in a control frame: RFC 6455 §5.5
/// caps a control frame payload at 125 bytes, and the status code takes 2.
const MAX_CLOSE_REASON_LEN: usize = 123;

/// Validate a WebSocket close status code before it goes on the wire.
///
/// `fastwebsockets::Frame::close` documents that it "does not check if `code`
/// is a valid close code", so the check has to happen here — otherwise a
/// reserved code such as 1006 is framed and sent, and a conformant peer fails
/// the connection with 1002 (protocol error).
///
/// Per RFC 6455 §7.4.1 and §7.4.2:
///
/// - `0`–`999` — "not used".
/// - `1000`–`2999` — "reserved for definition by this protocol, its future
///   revisions, and extensions specified in a permanent and readily available
///   public specification", i.e. only codes that are actually defined may be
///   sent. Defined and sendable: 1000–1003 and 1007–1011 from §7.4.1, plus
///   1012 (Service Restart), 1013 (Try Again Later) and 1014 (Bad Gateway)
///   from the IANA WebSocket Close Code Number Registry. Not sendable:
///   - `1004` — "Reserved. The specific meaning might be defined in the
///     future", so it carries no meaning to send.
///   - `1005` and `1006` — each "is a reserved value and MUST NOT be set as a
///     status code in a Close control frame by an endpoint"; they exist so an
///     application can report "no code present" / "closed abnormally".
///   - `1015` — same MUST NOT, for a failed TLS handshake.
///   - `1016`–`2999` — unassigned; an endpoint may not invent one.
/// - `3000`–`3999` — registered with IANA by libraries/frameworks: sendable.
/// - `4000`–`4999` — private use: sendable.
/// - `5000` and above — outside every defined range.
pub fn validate_close_code(code: u16) -> Result<()> {
    let reason = match code {
        1000..=1003 | 1007..=1014 | 3000..=4999 => return Ok(()),
        0..=999 => "status codes below 1000 are not used",
        1004 => "1004 is reserved with no defined meaning",
        1005 => "1005 is reserved for \"no status code present\" and MUST NOT be sent",
        1006 => "1006 is reserved for \"closed abnormally\" and MUST NOT be sent",
        1015 => "1015 is reserved for \"TLS handshake failure\" and MUST NOT be sent",
        1016..=2999 => "unassigned in the protocol-reserved 1000-2999 range",
        _ => "status codes above 4999 are outside every defined range",
    };
    Err(Error::Http(format!(
        "WebSocket close code {code} may not be sent (RFC 6455 §7.4): {reason}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn split_receiver_preserves_fragments_auto_pong_and_auto_close() {
        let (client, server) = tokio::io::duplex(4096);
        let ws = WsConnection::new(client, "wss://local.test/".into());
        let peer = tokio::spawn(async move {
            let mut server = WebSocket::after_handshake(server, Role::Server);
            server.set_auto_close(false);
            server.set_auto_pong(false);
            server
                .write_frame(Frame::new(
                    false,
                    OpCode::Text,
                    None,
                    Payload::Borrowed(b"hel"),
                ))
                .await
                .unwrap();
            server
                .write_frame(Frame::new(
                    true,
                    OpCode::Ping,
                    None,
                    Payload::Borrowed(b"ping"),
                ))
                .await
                .unwrap();
            let pong = server.read_frame().await.unwrap();
            assert_eq!(pong.opcode, OpCode::Pong);
            assert_eq!(&*pong.payload, b"ping");
            server
                .write_frame(Frame::new(
                    true,
                    OpCode::Continuation,
                    None,
                    Payload::Borrowed(b"lo"),
                ))
                .await
                .unwrap();
            server
                .write_frame(Frame::close(1000, b"done"))
                .await
                .unwrap();
            let close = server.read_frame().await.unwrap();
            assert_eq!(close.opcode, OpCode::Close);
            assert_eq!(&close.payload[2..], b"done");
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            assert!(matches!(ws.recv().await.unwrap(), WsMessage::Text(text) if text == "hello"));
            assert!(matches!(ws.recv().await.unwrap(), WsMessage::Close(Some(1000), reason) if reason == "done"));
            assert!(ws.send_text("after close").await.is_err());
            peer.await.unwrap();
        })
        .await
        .expect("split control frames must progress");
    }

    #[tokio::test]
    async fn split_receiver_does_not_echo_close_twice() {
        let (client, server) = tokio::io::duplex(4096);
        let ws = WsConnection::new(client, "wss://local.test/".into());
        let (check_tx, check_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut server = WebSocket::after_handshake(server, Role::Server);
            server.set_auto_close(false);
            let close = server.read_frame().await.unwrap();
            assert_eq!(close.opcode, OpCode::Close);
            server.write_frame(Frame::close(1000, b"")).await.unwrap();
            check_rx.await.unwrap();
            let second = server.read_frame();
            tokio::pin!(second);
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(second.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            ws.close(None).await.unwrap();
            assert!(matches!(
                ws.recv().await.unwrap(),
                WsMessage::Close(Some(1000), _)
            ));
            check_tx.send(()).unwrap();
            peer.await.unwrap();
        })
        .await
        .expect("close exchange must progress");
    }

    /// RFC 6455 §7.4.1 defines these, and §7.4.2 reserves 3000-4999 for IANA
    /// registration and private use. All are sendable by an endpoint.
    #[test]
    fn sendable_close_codes_are_accepted() {
        for code in [
            1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999,
            4000, 4999,
        ] {
            assert!(
                validate_close_code(code).is_ok(),
                "close code {code} must be sendable"
            );
        }
    }

    /// The codes RFC 6455 §7.4.1 says MUST NOT be set in a Close frame, plus
    /// 1004 ("Reserved", no defined meaning).
    #[test]
    fn reserved_close_codes_are_rejected() {
        for code in [1004, 1005, 1006, 1015] {
            let err = validate_close_code(code)
                .expect_err("reserved close code must be rejected before it is framed");
            let msg = err.to_string();
            assert!(
                msg.contains(&code.to_string()) && msg.contains("6455"),
                "error should name the code and the RFC, got: {msg}"
            );
        }
    }

    /// §7.4.2 range rules: 0-999 unused, 1016-2999 unassigned, 5000+ undefined.
    #[test]
    fn out_of_range_close_codes_are_rejected() {
        for code in [0u16, 1, 999, 1016, 1100, 2000, 2999, 5000, 9999, 65535] {
            assert!(
                validate_close_code(code).is_err(),
                "close code {code} is outside every sendable range and must be rejected"
            );
        }
    }

    /// RFC 6455 §5.5: a control frame payload is at most 125 bytes, so the
    /// reason gets 123 after the 2-byte status code.
    #[test]
    fn close_reason_budget_matches_control_frame_limit() {
        assert_eq!(MAX_CLOSE_REASON_LEN, 125 - 2);
    }
}
