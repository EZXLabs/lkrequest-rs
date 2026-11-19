use std::collections::VecDeque;

use crate::error::{Result, TlsError};
use crate::extensions::quic_transport_params::QuicTransportParams;
use crate::handshake::driver::{
    PostHandshakeState, QuicHandshakeDriver, QuicHandshakeOutput, QuicTrafficSecrets,
};
use crate::session_store::SessionTicketData;

use super::{QuicControlError, QuicPostHandshake};

const OUTPUT_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicLevel {
    Initial,
    Handshake,
    OneRtt,
}

struct Flight {
    level: QuicLevel,
    bytes: Vec<u8>,
    next_keys: Option<(QuicLevel, QuicTrafficSecrets)>,
}

enum Phase {
    Handshaking(Box<QuicHandshakeDriver>),
    Established(Box<QuicPostHandshake>),
    Failed { authenticated: bool },
}

/// Authenticated metadata and packet-key state handed to the QUIC transport.
/// TLS framing and ticket processing remain owned by the connection.
pub struct QuicConnectionEstablished {
    pub negotiated_alpn: Option<String>,
    pub negotiated_cipher_suite: Option<u16>,
    pub peer_transport_params: Option<QuicTransportParams>,
    pub post_handshake: Option<PostHandshakeState>,
    pub early_data_accepted: bool,
    pub session_resumed: bool,
}

/// Continuous TLS ownership over QUIC CRYPTO, without a TLS record layer.
pub struct QuicClientConnection {
    phase: Phase,
    flights: VecDeque<Flight>,
    queued_bytes: usize,
    write_level: QuicLevel,
    next_level: QuicLevel,
    retried: bool,
}

impl QuicClientConnection {
    pub fn new(mut driver: QuicHandshakeDriver) -> Result<Self> {
        let hello = driver.start()?;
        let mut connection = Self {
            phase: Phase::Handshaking(Box::new(driver)),
            flights: VecDeque::new(),
            queued_bytes: 0,
            write_level: QuicLevel::Initial,
            next_level: QuicLevel::Initial,
            retried: false,
        };
        connection.queue(hello, None)?;
        Ok(connection)
    }

    /// Compatibility entry point for transports that already completed TLS.
    pub fn from_post_handshake(control: QuicPostHandshake) -> Self {
        Self {
            phase: Phase::Established(Box::new(control)),
            flights: VecDeque::new(),
            queued_bytes: 0,
            write_level: QuicLevel::OneRtt,
            next_level: QuicLevel::OneRtt,
            retried: false,
        }
    }

    pub fn early_data_offer(&self) -> Option<(&SessionTicketData, &[u8])> {
        match &self.phase {
            Phase::Handshaking(driver) => driver.early_data_offer(),
            _ => None,
        }
    }

    pub fn resumption_ticket(&self) -> Option<&SessionTicketData> {
        match &self.phase {
            Phase::Handshaking(driver) => driver.resumption_ticket(),
            _ => None,
        }
    }

    pub fn is_handshaking(&self) -> bool {
        !matches!(
            self.phase,
            Phase::Established(_)
                | Phase::Failed {
                    authenticated: true
                }
        )
    }

    pub fn has_retried(&self) -> bool {
        self.retried
    }

    pub fn has_pending_message(&self) -> bool {
        match &self.phase {
            Phase::Established(control) => control.has_pending_message(),
            _ => false,
        }
    }

    pub fn read(
        &mut self,
        bytes: &[u8],
    ) -> std::result::Result<Option<QuicConnectionEstablished>, QuicControlError> {
        let result = self.read_inner(bytes);
        if result.is_err() {
            self.phase = Phase::Failed {
                authenticated: !self.is_handshaking(),
            };
            self.flights.clear();
            self.queued_bytes = 0;
        }
        result
    }

    fn read_inner(
        &mut self,
        bytes: &[u8],
    ) -> std::result::Result<Option<QuicConnectionEstablished>, QuicControlError> {
        // Quinn can deliver multiple CRYPTO frames before requesting keys.
        // Bytes at the previous level cannot cross an undelivered transition.
        if self.write_level != self.next_level && !bytes.is_empty() {
            return Err(TlsError::local_alert(
                crate::error::AlertDescription::UnexpectedMessage,
                "QUIC CRYPTO input before the pending keys were installed",
            )
            .into());
        }
        match &mut self.phase {
            Phase::Failed { .. } => return Err(QuicControlError::Failed),
            Phase::Established(control) => {
                control.read(bytes)?;
                return Ok(None);
            }
            Phase::Handshaking(driver) => driver.feed(bytes),
        }
        loop {
            let Phase::Handshaking(driver) = &mut self.phase else {
                unreachable!("handshake phase is consumed only by completion");
            };
            match driver.progress()? {
                QuicHandshakeOutput::NeedData => return Ok(None),
                QuicHandshakeOutput::SendData(bytes) => {
                    self.retried = true;
                    self.queue(bytes, None)?;
                }
                QuicHandshakeOutput::HandshakeSecretsReady { to_send, secrets } => {
                    self.queue(to_send, Some((QuicLevel::Handshake, secrets)))?;
                    return Ok(None);
                }
                QuicHandshakeOutput::Done { to_send, result } => {
                    self.queue(to_send, Some((QuicLevel::OneRtt, result.app_secrets)))?;
                    self.phase = Phase::Established(Box::new(QuicPostHandshake::new(
                        result.session_ticket_ctx,
                    )));
                    return Ok(Some(QuicConnectionEstablished {
                        negotiated_alpn: result.negotiated_alpn,
                        negotiated_cipher_suite: result.negotiated_cipher_suite,
                        peer_transport_params: result.peer_transport_params,
                        post_handshake: result.post_handshake,
                        early_data_accepted: result.early_data_accepted,
                        session_resumed: result.session_resumed,
                    }));
                }
            }
        }
    }

    fn queue(
        &mut self,
        bytes: Vec<u8>,
        next_keys: Option<(QuicLevel, QuicTrafficSecrets)>,
    ) -> Result<()> {
        if bytes.len() > OUTPUT_LIMIT.saturating_sub(self.queued_bytes) {
            return Err(TlsError::HandshakeFailure(
                "QUIC TLS output budget exceeded".into(),
            ));
        }
        let level = self.next_level;
        if let Some((next, _)) = &next_keys {
            if !matches!(
                (level, next),
                (QuicLevel::Initial, QuicLevel::Handshake)
                    | (QuicLevel::Handshake, QuicLevel::OneRtt)
            ) {
                return Err(TlsError::HandshakeFailure(
                    "invalid QUIC TLS key transition".into(),
                ));
            }
            self.next_level = *next;
        }
        self.queued_bytes += bytes.len();
        self.flights.push_back(Flight {
            level,
            bytes,
            next_keys,
        });
        Ok(())
    }

    /// Commit CRYPTO bytes at the current level, stopping at the first key
    /// transition. The caller installs returned keys after consuming these bytes.
    pub fn write_handshake(
        &mut self,
        output: &mut Vec<u8>,
    ) -> Option<(QuicLevel, QuicTrafficSecrets)> {
        while let Some(flight) = self.flights.pop_front() {
            debug_assert_eq!(flight.level, self.write_level);
            output.extend_from_slice(&flight.bytes);
            self.queued_bytes -= flight.bytes.len();
            if let Some((level, secrets)) = flight.next_keys {
                self.write_level = level;
                return Some((level, secrets));
            }
        }
        None
    }
}
