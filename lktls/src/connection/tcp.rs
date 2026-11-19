use crate::behavior::ClientBehavior;
use crate::error::{AlertDescription, AlertLevel, Result, TlsAlert, TlsError};
use crate::handshake::content_type;
use crate::handshake::driver::{HandshakeResult, PostHandshakeState, SessionTicketContext};
use crate::handshake::framing::HandshakeDeframer;
use crate::profile::types::TlsClientHelloStyle;
use crate::record::buffer::RecordBuffer;
use crate::record::reader::RecordReader;
use crate::record::writer::{RecordWriter, WriteStop};

const MAX_POST_HANDSHAKE_MSG_LEN: usize = 64 * 1024;
const RECORD_WORK_BUDGET: usize = 64;
const OUTPUT_LIMIT: usize = 256 * 1024;
const CONTROL_RESERVE: usize = 1024;
const INPUT_LIMIT: usize = 64 * 1024;

#[cfg(test)]
mod tests;

/// The next action needed by a TCP I/O adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadProgress {
    Plaintext,
    NeedInput,
    Flush,
    PeerClosed,
    /// A bounded amount of control traffic was processed; let other tasks run.
    Yield,
}

/// Established TLS-over-TCP state, without sockets or an async runtime.
///
/// Owns record protection, post-handshake control and committed ciphertext.
/// The adapter consumes output only after the transport accepts those bytes.
pub struct TcpConnection {
    reader: RecordReader,
    writer: RecordWriter,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: RecordBuffer,
    write_error: Option<TlsError>,
    closed: bool,
    failed: bool,
    behavior: ClientBehavior,
    key_update_flush_pending: bool,
    consecutive_key_updates: u8,
    pending_key_update_bytes: usize,
    pending_key_update_record_len: usize,
    key_update_without_application_write: bool,
    negotiated_alpn: Option<String>,
    negotiated_cipher_suite: Option<u16>,
    negotiated_version: Option<u16>,
    peer_certificates: Vec<Vec<u8>>,
    post_handshake: Option<PostHandshakeState>,
    session_ticket_ctx: Option<SessionTicketContext>,
    post_handshake_buf: HandshakeDeframer,
    received_close_notify: bool,
}

impl TcpConnection {
    /// Transfer the legacy handshake result into one connection owner.
    pub fn from_handshake(result: HandshakeResult, style: TlsClientHelloStyle) -> Self {
        Self::from_handshake_with_output(result, style, RecordBuffer::new(OUTPUT_LIMIT))
    }

    pub(crate) fn from_handshake_with_output(
        result: HandshakeResult,
        style: TlsClientHelloStyle,
        output: RecordBuffer,
    ) -> Self {
        Self {
            reader: result.reader,
            writer: result.writer,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: output,
            write_error: None,
            closed: false,
            failed: false,
            behavior: ClientBehavior(style),
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
            post_handshake_buf: HandshakeDeframer::new(MAX_POST_HANDSHAKE_MSG_LEN),
            received_close_notify: false,
        }
    }

    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.negotiated_cipher_suite
    }
    pub fn negotiated_version(&self) -> Option<u16> {
        self.negotiated_version
    }
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }
    pub fn received_close_notify(&self) -> bool {
        self.received_close_notify
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if !self.failed && !self.received_close_notify {
            self.reader.feed(bytes);
        }
    }

    pub fn input_capacity(&self) -> usize {
        INPUT_LIMIT.saturating_sub(self.reader.buffered_len())
    }

    pub fn feed_bounded(&mut self, bytes: &[u8]) -> usize {
        if self.failed || self.received_close_notify {
            return 0;
        }
        self.reader.feed_bounded(bytes, INPUT_LIMIT)
    }

    pub fn plaintext(&self) -> &[u8] {
        &self.read_buf[self.read_pos..]
    }

    pub fn consume_plaintext(&mut self, count: usize) {
        assert!(
            count <= self.plaintext().len(),
            "consumed unavailable plaintext"
        );
        self.read_pos += count;
    }

    /// Stable committed output until the next mutable connection operation.
    pub fn output(&self) -> &[u8] {
        self.write_buf.as_slice()
    }

    pub fn consume_output(&mut self, count: usize) {
        assert!(
            count <= self.write_buf.len(),
            "consumed unavailable ciphertext"
        );
        self.write_buf.consume(count);
        self.pending_key_update_bytes = self.pending_key_update_bytes.saturating_sub(count);
    }

    /// Output eligible for an idle browser flush, preserving a deferred response.
    pub fn idle_output(&self) -> &[u8] {
        let retained = if self.behavior.defer_idle_key_update() && !self.failed {
            self.unsent_trailing_key_update_len()
        } else {
            0
        };
        &self.write_buf.as_slice()[..self.write_buf.len() - retained]
    }

    pub fn flush_required(&self) -> bool {
        self.key_update_flush_pending
    }

    /// Acknowledge a completed transport flush requested by the protocol.
    pub fn acknowledge_flush(&mut self) {
        self.key_update_flush_pending = false;
    }

    pub fn flush_buffered_records(&mut self) {
        let records = self.writer.flush();
        if self.write_buf.append(&records) != records.len() {
            self.fail();
            self.discard_output();
            self.write_error = Some(TlsError::UnexpectedMessage(
                "coalesced output exceeded its connection budget".into(),
            ));
        }
    }

    /// Mark a terminal transport failure. Committed output may still be drained.
    pub fn fail(&mut self) {
        self.closed = true;
        self.failed = true;
    }

    /// Discard output only when the transport cannot deliver it.
    pub fn discard_output(&mut self) {
        self.write_buf.clear();
        self.pending_key_update_bytes = 0;
        self.key_update_flush_pending = false;
    }

    pub fn write_application(&mut self, bytes: &[u8]) -> Result<usize> {
        if let Some(error) = self.write_error.take() {
            return Err(error);
        }
        if self.closed {
            return Err(TlsError::UnexpectedMessage(
                "TLS connection is closed".into(),
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.writer.remaining_records() <= 1 {
            if self.writer.remaining_records() == 0 {
                self.fail();
                self.discard_output();
                return Err(TlsError::CryptoError(
                    "write key usage limit exhausted".into(),
                ));
            }
            if self.write_buf.remaining_capacity() < CONTROL_RESERVE {
                return Ok(0);
            }
            if self.post_handshake.is_some() {
                if let Err(error) = self.queue_key_update() {
                    self.fail();
                    self.discard_output();
                    return Err(error);
                }
            } else {
                self.start_close();
                return Err(TlsError::CryptoError(
                    "TLS 1.2 write key usage limit reached".into(),
                ));
            }
        }
        // Reserve the final old-key record for KeyUpdate or close_notify. A
        // short accepted prefix is retried after the adapter drains output.
        let record_budget =
            usize::try_from(self.writer.remaining_records() - 1).unwrap_or(usize::MAX);
        let plaintext_budget = record_budget.saturating_mul(
            self.writer
                .max_plaintext_chunk(content_type::APPLICATION_DATA),
        );
        let bytes = &bytes[..bytes.len().min(plaintext_budget)];
        let (output, limit) = self.write_buf.application_output_storage();
        let progress = self.writer.write_into(
            content_type::APPLICATION_DATA,
            bytes,
            output,
            limit.saturating_sub(CONTROL_RESERVE),
        );
        if progress.accepted_plaintext != 0 {
            self.key_update_without_application_write = false;
        }
        if let WriteStop::Terminal(error) = progress.stop {
            self.fail();
            self.discard_output();
            if progress.accepted_plaintext == 0 {
                return Err(error);
            }
            self.write_error = Some(error);
        } else if progress.accepted_plaintext != 0
            && self.post_handshake.is_none()
            && self.writer.remaining_records() == 1
        {
            self.start_close();
        }
        Ok(progress.accepted_plaintext)
    }

    fn queue_key_update(&mut self) -> Result<()> {
        let (message, next_key) = self
            .post_handshake
            .as_mut()
            .ok_or_else(|| TlsError::UnexpectedMessage("KeyUpdate requires TLS 1.3".into()))?
            .build_key_update_response()?;
        // Commit once under the old epoch; partial transport writes only move
        // the output cursor and cannot derive or seal the update again.
        let record_len = self.write_control(content_type::HANDSHAKE, &message)?;
        self.pending_key_update_bytes = self.write_buf.len();
        self.pending_key_update_record_len = record_len;
        self.key_update_without_application_write = true;
        self.writer.set_keys(next_key);
        self.key_update_flush_pending = self.behavior.flush_key_update();
        Ok(())
    }

    pub fn take_write_error(&mut self) -> Option<TlsError> {
        self.write_error.take()
    }

    fn write_control(&mut self, kind: u8, bytes: &[u8]) -> Result<usize> {
        let (output, limit) = self.write_buf.output_storage();
        let progress = self.writer.write_into(kind, bytes, output, limit);
        match progress.stop {
            WriteStop::Complete => Ok(progress.committed_ciphertext),
            WriteStop::Terminal(error) => {
                self.discard_output();
                self.fail();
                Err(error)
            }
            WriteStop::NeedOutputCapacity => Err(TlsError::UnexpectedMessage(
                "control record exceeds reserved output capacity".into(),
            )),
        }
    }

    pub fn start_close(&mut self) {
        self.close(false);
    }
    pub fn start_browser_close(&mut self) {
        self.close(true);
    }

    fn close(&mut self, browser: bool) {
        if self.closed {
            return;
        }
        self.closed = true;
        if !browser || self.behavior.browser_close_notify() {
            if let Err(error) = self.write_control(content_type::ALERT, &[1, 0]) {
                self.write_error = Some(error);
            }
        } else {
            let discard = self.unsent_trailing_key_update_len();
            if discard != 0 {
                self.write_buf
                    .truncate_pending(self.write_buf.len() - discard);
                self.pending_key_update_bytes = 0;
            }
        }
    }

    pub fn process_read(&mut self) -> Result<ReadProgress> {
        if self.failed {
            return Err(TlsError::UnexpectedMessage(
                "TLS connection has failed".into(),
            ));
        }
        if self.flush_required() {
            return Ok(ReadProgress::Flush);
        }
        if !self.plaintext().is_empty() {
            return Ok(ReadProgress::Plaintext);
        }
        if self.received_close_notify {
            return Ok(ReadProgress::PeerClosed);
        }
        let result = self.process_records();
        if let Err(error) = &result {
            self.fail_with_error(error);
        }
        result
    }

    fn process_records(&mut self) -> Result<ReadProgress> {
        for _ in 0..RECORD_WORK_BUDGET {
            if self.write_buf.remaining_capacity() < CONTROL_RESERVE {
                self.key_update_flush_pending = true;
                return Ok(ReadProgress::Flush);
            }
            self.read_pos = 0;
            let Some(kind) = self.reader.next_record_into(&mut self.read_buf)? else {
                return Ok(ReadProgress::NeedInput);
            };
            if self.is_tls13()
                && kind != content_type::HANDSHAKE
                && !self.post_handshake_buf.is_empty()
            {
                self.read_buf.clear();
                return Err(TlsError::local_alert(
                    AlertDescription::UnexpectedMessage,
                    "TLS 1.3 handshake messages cannot be interleaved with other record types",
                ));
            }
            match kind {
                content_type::APPLICATION_DATA => {
                    if !self.read_buf.is_empty() {
                        self.consecutive_key_updates = 0;
                        return Ok(ReadProgress::Plaintext);
                    }
                }
                content_type::ALERT => {
                    let alert = TlsAlert::from_bytes(
                        self.read_buf.first().copied().unwrap_or(0),
                        self.read_buf.get(1).copied().unwrap_or(0),
                    );
                    self.read_buf.clear();
                    if alert.is_close_notify() {
                        self.received_close_notify = true;
                        return Ok(ReadProgress::PeerClosed);
                    }
                    if alert.level != AlertLevel::Warning {
                        return Err(TlsError::Alert(alert));
                    }
                }
                content_type::HANDSHAKE => {
                    let mut payload = std::mem::take(&mut self.read_buf);
                    let result = self.handle_post_handshake_record(&payload);
                    payload.clear();
                    self.read_buf = payload;
                    result?;
                    if self.flush_required() {
                        return Ok(ReadProgress::Flush);
                    }
                }
                _ => {}
            }
            self.read_buf.clear();
        }
        Ok(ReadProgress::Yield)
    }

    fn handle_post_handshake_record(&mut self, payload: &[u8]) -> Result<()> {
        let result = self.process_post_handshake_record(payload);
        if let Err(error) = &result {
            self.fail_with_error(error);
        }
        result
    }

    fn process_post_handshake_record(&mut self, payload: &[u8]) -> Result<()> {
        self.post_handshake_buf
            .push(payload)
            .map_err(|error| TlsError::HandshakeFailure(error.to_string()))?;
        loop {
            if self.is_tls13() {
                if let Some(kind) = self.post_handshake_buf.message_type() {
                    if !matches!(kind, 4 | 24) {
                        return Err(TlsError::local_alert(
                            AlertDescription::UnexpectedMessage,
                            format!("unexpected TLS 1.3 post-handshake message {kind:#04x}"),
                        ));
                    }
                }
            }
            let Some(message) = self
                .post_handshake_buf
                .take_message()
                .map_err(|error| TlsError::HandshakeFailure(error.to_string()))?
            else {
                break;
            };
            self.handle_post_handshake_message(&message, self.post_handshake_buf.is_empty())?;
        }
        Ok(())
    }

    fn is_tls13(&self) -> bool {
        self.negotiated_version == Some(0x0304) || self.post_handshake.is_some()
    }

    fn handle_post_handshake_message(&mut self, payload: &[u8], at_record_end: bool) -> Result<()> {
        match payload[0] {
            24 if self.post_handshake.is_some() => {
                if let Some(limit) = self.behavior.key_update_limit() {
                    if self.consecutive_key_updates == limit {
                        return Err(TlsError::local_alert(
                            AlertDescription::UnexpectedMessage,
                            "too many consecutive KeyUpdate messages",
                        ));
                    }
                    self.consecutive_key_updates += 1;
                }
                if payload.len() != 5 {
                    return Err(TlsError::local_alert(
                        AlertDescription::DecodeError,
                        "KeyUpdate must contain exactly one request byte",
                    ));
                }
                if payload[4] > 1 {
                    return Err(TlsError::local_alert(
                        self.behavior.invalid_key_update(),
                        "invalid KeyUpdate request value",
                    ));
                }
                if !at_record_end {
                    return Err(TlsError::local_alert(
                        AlertDescription::UnexpectedMessage,
                        "KeyUpdate must end at a record boundary",
                    ));
                }
                let ph = self.post_handshake.as_mut().unwrap();
                self.reader.set_keys(ph.process_key_update()?);
                if payload[4] == 1
                    && !self.closed
                    && self.behavior.respond_to_key_update(
                        self.pending_key_update_bytes != 0,
                        self.key_update_without_application_write,
                    )
                {
                    self.queue_key_update()?;
                }
            }
            4 if self.is_tls13() => {
                let ticket = crate::session_store::ticket::Tls13Ticket::parse_message(payload)?;
                if let Some(context) = &self.session_ticket_ctx {
                    context.store_ticket(ticket)?;
                }
            }
            0 if self.negotiated_version.is_some_and(|v| v < 0x0304) => {
                return Err(TlsError::local_alert(AlertDescription::NoRenegotiation,
                    "server requested TLS 1.2 renegotiation (HelloRequest); refused with no_renegotiation"));
            }
            _ if self.is_tls13() => {
                return Err(TlsError::local_alert(
                    AlertDescription::UnexpectedMessage,
                    "TLS 1.3 post-handshake message is unavailable in the current state",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn queue_alert(&mut self, alert: TlsAlert) {
        if self.closed {
            return;
        }
        let _ = self.write_control(
            content_type::ALERT,
            &[alert.level.as_byte(), alert.description.as_byte()],
        );
    }

    fn fail_with_error(&mut self, error: &TlsError) {
        self.reader.invalidate_tls12_session();
        self.writer.invalidate_tls12_session();
        if self.writer.is_poisoned() {
            self.discard_output();
            self.fail();
            return;
        }
        if !self.failed {
            if let TlsError::LocalAlert { alert, .. } = error {
                self.queue_alert(*alert);
            }
            self.fail();
        }
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
}
