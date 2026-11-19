//! Bounds-checked ClientHello layout for actual-offer validation and inspection.

use crate::error::{Result, TlsError};
use serde::{Deserialize, Serialize};
use std::ops::Range;

fn invalid(message: &str) -> TlsError {
    TlsError::InvalidProfile(format!("ClientHello: {message}"))
}

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or_else(|| invalid("length overflow"))?;
        let value = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| invalid("truncated field"))?;
        self.pos = end;
        Ok(value)
    }
    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn word(&mut self) -> Result<u16> {
        let value = self.take(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }
    pub(crate) fn vector8(&mut self) -> Result<&'a [u8]> {
        let len = self.byte()? as usize;
        self.take(len)
    }
    pub(crate) fn vector16(&mut self) -> Result<&'a [u8]> {
        let len = self.word()? as usize;
        self.take(len)
    }
    pub(crate) fn finished(&self) -> Result<()> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(invalid("trailing field bytes"))
        }
    }
}

/// Original plaintext record boundaries, not TCP segmentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHelloRecord {
    pub version: u16,
    pub length: u16,
}

#[derive(Debug, Clone)]
pub struct WireExtension {
    pub extension_type: u16,
    /// Range in the reassembled handshake, excluding the extension header.
    pub payload: Range<usize>,
}

#[derive(Debug, Clone)]
pub struct WireKeyShare {
    pub group: u16,
    pub key_exchange: Range<usize>,
}

/// A complete, reassembled ClientHello with original offsets.
#[derive(Debug, Clone)]
pub struct ClientHelloWire {
    pub handshake: Vec<u8>,
    pub records: Option<Vec<ClientHelloRecord>>,
    pub protocol_version: u16,
    pub session_id: Range<usize>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<WireExtension>,
}

impl ClientHelloWire {
    /// Accept exactly one handshake, either bare or fragmented across full records.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (handshake, records) = if data.first() == Some(&22) {
            let mut cursor = Cursor::new(data);
            let mut handshake = Vec::new();
            let mut records = Vec::new();
            while cursor.pos < data.len() {
                if cursor.byte()? != 22 {
                    return Err(invalid("expected handshake record"));
                }
                let version = cursor.word()?;
                let length = cursor.word()?;
                if length as usize > 16384 {
                    return Err(invalid("plaintext record exceeds 16384 bytes"));
                }
                handshake.extend_from_slice(cursor.take(length as usize)?);
                records.push(ClientHelloRecord { version, length });
            }
            (handshake, Some(records))
        } else {
            (data.to_vec(), None)
        };
        Self::from_parts(handshake, records)
    }

    pub(crate) fn from_handshake(handshake: Vec<u8>) -> Result<Self> {
        Self::from_parts(handshake, None)
    }

    fn from_parts(handshake: Vec<u8>, records: Option<Vec<ClientHelloRecord>>) -> Result<Self> {
        let mut cursor = Cursor::new(&handshake);
        if cursor.byte()? != 1 {
            return Err(invalid("expected ClientHello handshake type"));
        }
        let len = cursor.take(3)?;
        let body_len = ((len[0] as usize) << 16) | ((len[1] as usize) << 8) | len[2] as usize;
        if body_len != handshake.len() - 4 {
            return Err(invalid("handshake length mismatch"));
        }
        let protocol_version = cursor.word()?;
        cursor.take(32)?;
        let sid_length = cursor.byte()? as usize;
        if sid_length > 32 {
            return Err(invalid("session ID exceeds 32 bytes"));
        }
        let session_id = cursor.pos..cursor.pos + sid_length;
        cursor.take(sid_length)?;
        let suites = cursor.vector16()?;
        if suites.is_empty() || suites.len() % 2 != 0 {
            return Err(invalid("invalid cipher suite vector length"));
        }
        let cipher_suites = suites
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
            .collect();
        let compression_methods = cursor.vector8()?.to_vec();
        if compression_methods.is_empty() {
            return Err(invalid("empty compression methods"));
        }
        let mut extensions = Vec::new();
        if cursor.pos < handshake.len() {
            let total = cursor.word()? as usize;
            if total != handshake.len() - cursor.pos {
                return Err(invalid("extensions length mismatch"));
            }
            while cursor.pos < handshake.len() {
                let extension_type = cursor.word()?;
                let length = cursor.word()? as usize;
                let start = cursor.pos;
                cursor.take(length)?;
                extensions.push(WireExtension {
                    extension_type,
                    payload: start..cursor.pos,
                });
            }
        }
        Ok(Self {
            handshake,
            records,
            protocol_version,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Parse and bound every key-share entry; cryptographic support is checked separately.
    pub fn key_shares(&self) -> Result<Vec<WireKeyShare>> {
        let mut shares = Vec::new();
        for extension in self
            .extensions
            .iter()
            .filter(|ext| ext.extension_type == 51)
        {
            let payload = &self.handshake[extension.payload.clone()];
            let mut cursor = Cursor::new(payload);
            let length = cursor.word()? as usize;
            if length != payload.len() - cursor.pos {
                return Err(invalid("key_share vector length mismatch"));
            }
            while cursor.pos < payload.len() {
                let group = cursor.word()?;
                let length = cursor.word()? as usize;
                let start = extension.payload.start + cursor.pos;
                cursor.take(length)?;
                shares.push(WireKeyShare {
                    group,
                    key_exchange: start..start + length,
                });
            }
        }
        Ok(shares)
    }

    /// Restore the captured record layout, failing if the message length changed.
    pub fn frame(&self, message: &[u8]) -> Result<Vec<u8>> {
        let records = self
            .records
            .as_ref()
            .ok_or_else(|| invalid("record boundaries unavailable"))?;
        let mut cursor = Cursor::new(message);
        let mut output = Vec::new();
        for record in records {
            output.push(22);
            output.extend_from_slice(&record.version.to_be_bytes());
            output.extend_from_slice(&record.length.to_be_bytes());
            output.extend_from_slice(cursor.take(record.length as usize)?);
        }
        cursor.finished()?;
        Ok(output)
    }
}

/// RFC 8701 values have identical bytes as well as the 0x?a?a pattern.
pub fn is_grease(value: u16) -> bool {
    value as u8 == (value >> 8) as u8 && value & 0x0f0f == 0x0a0a
}
