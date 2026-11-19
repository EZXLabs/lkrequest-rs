//! Shared bounded handshake framing. Transport epochs and message legality
//! remain with the protocol state machines and their TCP/QUIC endpoints.

use crate::error::{AlertDescription, TlsError};

pub const MAX_HANDSHAKE_BODY: usize = 0x00ff_ffff;
pub const INPUT_FRAGMENT: usize = 16 * 1024;

#[cfg(test)]
thread_local! {
    static PARSED_HEADERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("handshake message length {length} exceeds the {limit} byte limit")]
    MessageTooLarge { length: usize, limit: usize },
    #[error("pending handshake input exceeds the {0} byte limit")]
    BufferLimit(usize),
    #[error("truncated handshake message")]
    Truncated,
    #[error("handshake buffer allocation failed")]
    Allocation,
}

impl From<FramingError> for TlsError {
    fn from(error: FramingError) -> Self {
        Self::local_alert(AlertDescription::DecodeError, error.to_string())
    }
}

/// Length of the first complete message, including its four-byte header.
/// Checks a declared length as soon as the header is available.
pub fn message_length(input: &[u8], max_body: usize) -> Result<Option<usize>, FramingError> {
    Ok(declared_length(input, max_body)?.filter(|&length| length <= input.len()))
}

fn declared_length(input: &[u8], max_body: usize) -> Result<Option<usize>, FramingError> {
    let Some(header) = input.get(..4) else {
        return Ok(None);
    };
    #[cfg(test)]
    PARSED_HEADERS.with(|count| count.set(count.get() + 1));
    let length = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    if length > max_body {
        return Err(FramingError::MessageTooLarge {
            length,
            limit: max_body,
        });
    }
    Ok(Some(4 + length))
}

/// A bounded cursor buffer. Consuming messages advances a cursor instead of
/// moving every remaining byte. Compaction happens only after half is consumed.
pub struct HandshakeDeframer {
    buffer: Vec<u8>,
    consumed: usize,
    max_body: usize,
    // Zero means the next message header is still incomplete or unparsed.
    pending_length: usize,
    #[cfg(test)]
    moved_bytes: usize,
}

impl Default for HandshakeDeframer {
    fn default() -> Self {
        Self::new(MAX_HANDSHAKE_BODY)
    }
}

impl HandshakeDeframer {
    pub fn new(max_body: usize) -> Self {
        Self {
            buffer: Vec::new(),
            consumed: 0,
            max_body: max_body.min(MAX_HANDSHAKE_BODY),
            pending_length: 0,
            #[cfg(test)]
            moved_bytes: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.consumed == self.buffer.len()
    }
    pub fn len(&self) -> usize {
        self.buffer.len() - self.consumed
    }

    /// Available only after a complete header; does not interpret the type.
    pub fn message_type(&self) -> Option<u8> {
        (self.len() >= 4).then(|| self.buffer[self.consumed])
    }

    /// Append a transport fragment. Callers with arbitrarily large deliveries
    /// feed INPUT_FRAGMENT-sized chunks and drain complete messages between them.
    pub fn push(&mut self, input: &[u8]) -> Result<(), FramingError> {
        let limit = self.max_body + 4 + INPUT_FRAGMENT;
        if input.len() > limit - self.len() {
            return Err(FramingError::BufferLimit(limit));
        }
        if self.consumed != 0 && self.consumed >= self.len() {
            let pending = self.len();
            self.buffer.copy_within(self.consumed.., 0);
            self.buffer.truncate(pending);
            self.consumed = 0;
            #[cfg(test)]
            {
                self.moved_bytes += pending;
            }
        }
        let required = self.buffer.len() + input.len();
        if required > self.buffer.capacity() {
            let capacity = required
                .max(self.buffer.capacity().saturating_mul(2))
                .min(2 * limit);
            self.buffer
                .try_reserve_exact(capacity - self.buffer.len())
                .map_err(|_| FramingError::Allocation)?;
        }
        self.buffer.extend_from_slice(input);
        Ok(())
    }

    pub fn take_message(&mut self) -> Result<Option<Vec<u8>>, FramingError> {
        match self.complete_length(0)? {
            Some(length) => {
                self.pending_length = 0;
                Ok(Some(self.take(length)))
            }
            None => Ok(None),
        }
    }

    pub fn take_complete(&mut self) -> Result<Option<Vec<u8>>, FramingError> {
        let mut count = 0;
        while let Some(length) = self.complete_length(count)? {
            count += length;
            self.pending_length = 0;
        }
        Ok((count != 0).then(|| self.take(count)))
    }

    fn complete_length(&mut self, offset: usize) -> Result<Option<usize>, FramingError> {
        let pending = &self.buffer[self.consumed + offset..];
        if self.pending_length == 0 {
            let Some(length) = declared_length(pending, self.max_body)? else {
                return Ok(None);
            };
            self.pending_length = length;
        }
        Ok((self.pending_length <= pending.len()).then_some(self.pending_length))
    }

    fn take(&mut self, count: usize) -> Vec<u8> {
        let output = self.buffer[self.consumed..self.consumed + count].to_vec();
        self.consumed += count;
        if self.is_empty() {
            self.consumed = 0;
            if self.buffer.capacity() > INPUT_FRAGMENT * 4 {
                self.buffer = Vec::new();
            } else {
                self.buffer.clear();
            }
        }
        output
    }
}

/// Iterate a complete batch without copying message payloads. An incomplete
/// trailer is an error; streaming callers must use HandshakeDeframer first.
pub(crate) struct Messages<'a> {
    remaining: &'a [u8],
}

impl<'a> Messages<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<&'a [u8], FramingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let result = message_length(self.remaining, MAX_HANDSHAKE_BODY);
        match result {
            Ok(Some(length)) => {
                let (message, rest) = self.remaining.split_at(length);
                self.remaining = rest;
                Some(Ok(message))
            }
            error => {
                self.remaining = &[];
                Some(Err(error.err().unwrap_or(FramingError::Truncated)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_header_is_parsed_once_until_its_body_completes() {
        let mut message = vec![11, 0, 0, 32];
        message.extend_from_slice(&[0x42; 32]);
        for batch in [false, true] {
            PARSED_HEADERS.with(|count| count.set(0));
            let mut deframer = HandshakeDeframer::new(32);
            for (index, byte) in message.iter().enumerate() {
                deframer.push(std::slice::from_ref(byte)).unwrap();
                let output = if batch {
                    deframer.take_complete().unwrap()
                } else {
                    deframer.take_message().unwrap()
                };
                if index + 1 == message.len() {
                    assert_eq!(output.as_deref(), Some(message.as_slice()));
                } else {
                    assert!(output.is_none());
                }
            }
            assert_eq!(PARSED_HEADERS.with(|count| count.get()), 1);
            assert!(deframer.is_empty());
        }
    }

    #[test]
    fn parsed_header_survives_compaction_and_alternating_drains() {
        PARSED_HEADERS.with(|count| count.set(0));
        let first = [1, 0, 0, 20].into_iter().chain([7; 20]).collect::<Vec<_>>();
        let second = [11, 0, 0, 16]
            .into_iter()
            .chain([9; 16])
            .collect::<Vec<_>>();
        let mut deframer = HandshakeDeframer::new(32);
        deframer.push(&first).unwrap();
        deframer.push(&second[..8]).unwrap();
        assert_eq!(deframer.take_complete().unwrap().unwrap(), first);
        for (index, byte) in second[8..].iter().enumerate() {
            deframer.push(std::slice::from_ref(byte)).unwrap();
            let output = if index % 2 == 0 {
                deframer.take_message().unwrap()
            } else {
                deframer.take_complete().unwrap()
            };
            if index + 9 == second.len() {
                assert_eq!(output.as_deref(), Some(second.as_slice()));
            } else {
                assert!(output.is_none());
            }
        }
        assert_eq!(deframer.moved_bytes, 8);
        assert_eq!(PARSED_HEADERS.with(|count| count.get()), 2);
        assert!(deframer.is_empty());
    }

    #[test]
    fn parsed_header_error_does_not_skip_a_complete_prefix() {
        let mut deframer = HandshakeDeframer::new(4);
        deframer.push(&[1, 0, 0, 0, 11, 0, 0, 5]).unwrap();
        assert!(matches!(
            deframer.take_complete(),
            Err(FramingError::MessageTooLarge { .. })
        ));
        assert_eq!(deframer.take_message().unwrap().unwrap(), [1, 0, 0, 0]);
        assert!(matches!(
            deframer.take_message(),
            Err(FramingError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn every_split_preserves_complete_messages_and_partial_trailers() {
        let input = [1, 0, 0, 2, 7, 8, 2, 0, 0, 0, 3, 0];
        for split in 0..=input.len() {
            let mut deframer = HandshakeDeframer::default();
            deframer.push(&input[..split]).unwrap();
            let mut output = deframer.take_complete().unwrap().unwrap_or_default();
            deframer.push(&input[split..]).unwrap();
            output.extend(deframer.take_complete().unwrap().unwrap_or_default());
            assert_eq!(output, input[..10]);
            assert_eq!(deframer.len(), 2);
        }
    }

    #[test]
    fn announced_and_accumulated_lengths_are_bounded_before_allocation() {
        let mut deframer = HandshakeDeframer::new(8);
        deframer.push(&[4, 0, 0, 9]).unwrap();
        assert!(matches!(
            deframer.take_message(),
            Err(FramingError::MessageTooLarge { .. })
        ));
        let capacity = deframer.buffer.capacity();
        assert!(matches!(
            deframer.push(&vec![0; INPUT_FRAGMENT + 16]),
            Err(FramingError::BufferLimit(_))
        ));
        assert_eq!(deframer.buffer.capacity(), capacity);
        assert_eq!(deframer.len(), 4);
    }

    #[test]
    fn tiny_fragments_and_coalesced_messages_have_linear_compaction() {
        let mut deframer = HandshakeDeframer::new(64);
        let message = [4, 0, 0, 2, 1, 2];
        for _ in 0..10_000 {
            deframer.push(&message).unwrap();
            deframer.push(&message[..3]).unwrap();
            assert_eq!(deframer.take_message().unwrap().unwrap(), message);
            deframer.push(&message[3..]).unwrap();
            assert_eq!(deframer.take_message().unwrap().unwrap(), message);
        }
        assert!(deframer.moved_bytes <= 10_000 * message.len());
        assert!(deframer.is_empty());
        assert!(deframer.buffer.capacity() <= 2 * (64 + 4 + INPUT_FRAGMENT));
    }

    #[test]
    fn large_scratch_storage_is_released_after_the_message() {
        let mut input = vec![0; 128 * 1024 + 4];
        input[..4].copy_from_slice(&[11, 2, 0, 0]);
        let mut deframer = HandshakeDeframer::default();
        for fragment in input.chunks(1_000) {
            deframer.push(fragment).unwrap();
        }
        assert_eq!(deframer.take_message().unwrap().unwrap(), input);
        assert_eq!(deframer.buffer.capacity(), 0);
    }
}
