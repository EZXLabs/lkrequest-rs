use crate::error::{AlertDescription, TlsError};
use crate::handshake::driver::SessionTicketContext;
use crate::handshake::framing::{FramingError, HandshakeDeframer, INPUT_FRAGMENT};
use crate::session_store::ticket::Tls13Ticket;

const MAX_POST_HANDSHAKE_MESSAGE: usize = 256 * 1024;

/// Protocol failures for the QUIC adapter to map to transport error codes.
#[derive(Debug, thiserror::Error)]
pub enum QuicControlError {
    #[error("{0}")]
    Tls(#[from] TlsError),
    #[error("{0}")]
    BufferLimit(String),
    #[error("NewSessionTicket early_data max_early_data_size is {0:#010x}, but QUIC permits only 0xffffffff (RFC 9001 section 4.6.1)")]
    EarlyDataLimit(u32),
    #[error("QUIC TLS post-handshake control has failed")]
    Failed,
}

impl From<FramingError> for QuicControlError {
    fn from(error: FramingError) -> Self {
        match error {
            FramingError::Truncated => Self::Tls(error.into()),
            _ => Self::BufferLimit(error.to_string()),
        }
    }
}

/// QUIC TLS ticket control. Packet key updates remain with the QUIC endpoint.
pub struct QuicPostHandshake {
    input: HandshakeDeframer,
    tickets: Option<SessionTicketContext>,
    failed: bool,
}

impl QuicPostHandshake {
    pub fn new(tickets: Option<SessionTicketContext>) -> Self {
        Self {
            input: HandshakeDeframer::new(MAX_POST_HANDSHAKE_MESSAGE - 4),
            tickets,
            failed: false,
        }
    }

    pub fn has_pending_message(&self) -> bool {
        !self.input.is_empty()
    }

    /// Accept a CRYPTO delivery in bounded chunks, including large valid batches.
    pub fn read(&mut self, bytes: &[u8]) -> Result<(), QuicControlError> {
        if self.failed {
            return Err(QuicControlError::Failed);
        }
        let result = self.process(bytes);
        self.failed = result.is_err();
        result
    }

    fn process(&mut self, bytes: &[u8]) -> Result<(), QuicControlError> {
        for fragment in bytes.chunks(INPUT_FRAGMENT) {
            self.input.push(fragment)?;
            loop {
                if let Some(kind) = self.input.message_type() {
                    if kind != 4 {
                        return Err(TlsError::local_alert(
                            AlertDescription::UnexpectedMessage,
                            format!("unexpected QUIC post-handshake TLS message {kind:#04x}"),
                        )
                        .into());
                    }
                }
                let Some(message) = self.input.take_message()? else {
                    break;
                };
                let ticket = Tls13Ticket::parse_message(&message)?;
                if let Some(limit) = ticket.early_data {
                    if limit != u32::MAX {
                        return Err(QuicControlError::EarlyDataLimit(limit));
                    }
                }
                if let Some(context) = &self.tickets {
                    context.store_ticket(ticket)?;
                }
            }
        }
        Ok(())
    }
}
