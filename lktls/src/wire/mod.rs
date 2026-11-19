//! Bounded protocol codecs, with no transport or handshake-state ownership.

pub(crate) mod tls12;

use crate::error::{AlertDescription, Result, TlsError};
use bytes::Buf;

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self(input)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        self.0
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        self.0
            .try_get_u8()
            .map_err(|_| decode_error("truncated u8"))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        self.0
            .try_get_u16()
            .map_err(|_| decode_error("truncated u16"))
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.0.remaining() {
            return Err(decode_error("truncated protocol vector"));
        }
        let (value, remaining) = self.0.split_at(length);
        self.0 = remaining;
        Ok(value)
    }

    pub(crate) fn vector8(&mut self) -> Result<&'a [u8]> {
        let length = self.u8()? as usize;
        self.take(length)
    }

    pub(crate) fn vector16(&mut self) -> Result<&'a [u8]> {
        let length = self.u16()? as usize;
        self.take(length)
    }

    pub(crate) fn vector24(&mut self) -> Result<&'a [u8]> {
        let length = self
            .0
            .try_get_uint(3)
            .map_err(|_| decode_error("truncated u24"))?;
        self.take(length as usize)
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(decode_error("trailing protocol bytes"))
        }
    }
}

pub(crate) fn decode_error(message: &str) -> TlsError {
    TlsError::local_alert(AlertDescription::DecodeError, message)
}
