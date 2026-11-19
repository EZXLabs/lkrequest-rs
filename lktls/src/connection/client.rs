use std::sync::Arc;

use crate::config::{CompiledClientConfig, ConnectionInputs};
use crate::error::{Result, TlsError};
use crate::handshake::driver::{HandshakeDriver, HandshakeOutput, HandshakeResult};
use crate::profile::types::TlsClientHelloStyle;
use crate::record::buffer::RecordBuffer;

use super::{ReadProgress, TcpConnection};

const OUTPUT_LIMIT: usize = 256 * 1024;
const INPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeProgress {
    NeedInput,
    NeedOutput,
    Complete,
}

enum Phase {
    Handshaking(Box<HandshakeDriver>),
    Established(Box<TcpConnection>),
    Failed,
}

/// One TCP client owner from ClientHello through authenticated application data.
///
/// Output is committed once, retained across short writes, and consumed only by
/// the number of bytes accepted by the transport. Handshake completion does not
/// transfer record keys or mutable protocol state to the I/O adapter.
pub struct ClientConnection {
    phase: Phase,
    output: RecordBuffer,
    style: TlsClientHelloStyle,
}

impl ClientConnection {
    pub fn from_compiled(
        config: Arc<CompiledClientConfig>,
        inputs: ConnectionInputs,
    ) -> Result<Self> {
        let style = config.profile().tls_client_hello_style;
        let mut driver = HandshakeDriver::from_compiled(config, inputs)?;
        let hello = driver.start()?;
        let mut output = RecordBuffer::new(OUTPUT_LIMIT);
        if output.append(&hello) != hello.len() {
            return Err(output_overflow());
        }
        Ok(Self {
            phase: Phase::Handshaking(Box::new(driver)),
            output,
            style,
        })
    }

    /// Compatibility entry point for callers already using HandshakeDriver.
    pub fn from_handshake(result: HandshakeResult, style: TlsClientHelloStyle) -> Self {
        Self {
            phase: Phase::Established(Box::new(TcpConnection::from_handshake(result, style))),
            output: RecordBuffer::new(OUTPUT_LIMIT),
            style,
        }
    }

    pub fn progress_handshake(&mut self) -> Result<HandshakeProgress> {
        if matches!(self.phase, Phase::Failed) {
            return Err(not_ready());
        }
        if !self.output().is_empty() {
            return Ok(HandshakeProgress::NeedOutput);
        }
        let Phase::Handshaking(driver) = &mut self.phase else {
            return Ok(HandshakeProgress::Complete);
        };
        let action = match driver.progress() {
            Ok(action) => action,
            Err(error) => {
                if let Some(alert) = driver.take_pending_alert() {
                    if self.output.append(&alert) != alert.len() {
                        self.output.clear();
                    }
                }
                self.phase = Phase::Failed;
                return Err(error);
            }
        };
        match action {
            HandshakeOutput::NeedData => Ok(HandshakeProgress::NeedInput),
            HandshakeOutput::SendData(bytes) => {
                if self.output.append(&bytes) != bytes.len() {
                    self.phase = Phase::Failed;
                    self.output.clear();
                    return Err(output_overflow());
                }
                Ok(HandshakeProgress::NeedOutput)
            }
            HandshakeOutput::Done { to_send, result } => {
                if self.output.append(&to_send) != to_send.len() {
                    self.phase = Phase::Failed;
                    self.output.clear();
                    return Err(output_overflow());
                }
                let output = std::mem::replace(&mut self.output, RecordBuffer::new(OUTPUT_LIMIT));
                self.phase = Phase::Established(Box::new(
                    TcpConnection::from_handshake_with_output(*result, self.style, output),
                ));
                Ok(if self.output().is_empty() {
                    HandshakeProgress::Complete
                } else {
                    HandshakeProgress::NeedOutput
                })
            }
        }
    }

    fn established(&self) -> Option<&TcpConnection> {
        match &self.phase {
            Phase::Established(connection) => Some(connection),
            _ => None,
        }
    }
    fn established_mut(&mut self) -> Result<&mut TcpConnection> {
        match &mut self.phase {
            Phase::Established(connection) => Ok(connection),
            _ => Err(not_ready()),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        match &mut self.phase {
            Phase::Handshaking(driver) => driver.feed(bytes),
            Phase::Established(connection) => connection.feed(bytes),
            Phase::Failed => {}
        }
    }
    pub fn feed_bounded(&mut self, bytes: &[u8]) -> usize {
        match &mut self.phase {
            Phase::Handshaking(driver) => driver.feed_bounded(bytes, INPUT_LIMIT),
            Phase::Established(connection) => connection.feed_bounded(bytes),
            Phase::Failed => 0,
        }
    }
    pub fn input_capacity(&self) -> usize {
        match &self.phase {
            Phase::Handshaking(driver) => INPUT_LIMIT.saturating_sub(driver.buffered_input()),
            Phase::Established(connection) => connection.input_capacity(),
            Phase::Failed => 0,
        }
    }
    pub fn output(&self) -> &[u8] {
        self.established()
            .map_or_else(|| self.output.as_slice(), TcpConnection::output)
    }
    pub fn consume_output(&mut self, count: usize) {
        match &mut self.phase {
            Phase::Established(connection) => connection.consume_output(count),
            _ => self.output.consume(count),
        }
    }
    pub fn idle_output(&self) -> &[u8] {
        self.established()
            .map_or_else(|| self.output.as_slice(), TcpConnection::idle_output)
    }
    pub fn discard_output(&mut self) {
        self.output.clear();
        if let Ok(connection) = self.established_mut() {
            connection.discard_output();
        }
    }
    pub fn plaintext(&self) -> &[u8] {
        self.established().map_or(&[], TcpConnection::plaintext)
    }
    pub fn consume_plaintext(&mut self, count: usize) {
        self.established_mut()
            .expect("plaintext requires an established connection")
            .consume_plaintext(count);
    }
    pub fn process_read(&mut self) -> Result<ReadProgress> {
        self.established_mut()?.process_read()
    }
    pub fn write_application(&mut self, bytes: &[u8]) -> Result<usize> {
        self.established_mut()?.write_application(bytes)
    }
    pub fn take_write_error(&mut self) -> Option<TlsError> {
        self.established_mut().ok()?.take_write_error()
    }
    pub fn flush_required(&self) -> bool {
        self.established()
            .is_some_and(TcpConnection::flush_required)
    }
    pub fn acknowledge_flush(&mut self) {
        if let Ok(connection) = self.established_mut() {
            connection.acknowledge_flush();
        }
    }
    pub fn flush_buffered_records(&mut self) {
        if let Ok(connection) = self.established_mut() {
            connection.flush_buffered_records();
        }
    }
    pub fn start_close(&mut self) {
        if let Ok(connection) = self.established_mut() {
            connection.start_close();
        }
    }
    pub fn start_browser_close(&mut self) {
        if let Ok(connection) = self.established_mut() {
            connection.start_browser_close();
        }
    }
    pub fn fail(&mut self) {
        match &mut self.phase {
            Phase::Established(connection) => connection.fail(),
            _ => self.phase = Phase::Failed,
        }
    }
    pub fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Failed)
            || self.established().is_some_and(TcpConnection::is_closed)
    }
    pub fn received_close_notify(&self) -> bool {
        self.established()
            .is_some_and(TcpConnection::received_close_notify)
    }
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.established()?.negotiated_alpn()
    }
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.established()?.negotiated_cipher_suite()
    }
    pub fn negotiated_version(&self) -> Option<u16> {
        self.established()?.negotiated_version()
    }
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.established()
            .map_or(&[], TcpConnection::peer_certificates)
    }
}

fn not_ready() -> TlsError {
    TlsError::UnexpectedMessage("TLS client connection is not ready or has failed".into())
}
fn output_overflow() -> TlsError {
    TlsError::InvalidProfile("TLS client flight exceeds the output budget".into())
}
