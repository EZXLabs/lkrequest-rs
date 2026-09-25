//! Stateful HPACK decoder (RFC 7541).
//!
//! Representation parsing and integer limits are cross-checked against the
//! `h2` implementation; interoperability is enforced by RFC state-sequence
//! tests and end-to-end tests against an `h2` peer.

use super::huffman;
use super::table::DynamicTable;

type HeaderField = (Vec<u8>, Vec<u8>);
type HeaderBlock = Vec<HeaderField>;
type DecodedLiteral = (HeaderField, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    TruncatedInteger,
    IntegerOverflow,
    TruncatedString,
    InvalidHuffman(huffman::DecodeError),
    InvalidIndex,
    InvalidTableSize,
    TableSizeUpdateAfterHeader,
}

pub(crate) struct Decoder {
    dynamic: DynamicTable,
    max_allowed_table_size: usize,
}

impl Decoder {
    pub(crate) fn new(max_table_size: usize) -> Self {
        Self {
            dynamic: DynamicTable::new(max_table_size),
            max_allowed_table_size: max_table_size,
        }
    }

    pub(crate) fn set_max_table_size(&mut self, size: usize) {
        self.max_allowed_table_size = size;
        self.dynamic.set_max_size(size);
    }

    pub(crate) fn decode(&mut self, block: &[u8]) -> Result<HeaderBlock, DecodeError> {
        let mut headers = Vec::new();
        let mut cursor = 0usize;
        let mut saw_header = false;

        while cursor < block.len() {
            let first = block[cursor];
            let remaining = &block[cursor..];
            if first & 0x80 != 0 {
                let (index, consumed) = decode_integer(remaining, 7)?;
                headers.push(self.lookup_owned(index)?);
                cursor += consumed;
                saw_header = true;
            } else if first & 0x40 != 0 {
                let ((name, value), consumed) = self.decode_literal(remaining, 6)?;
                self.dynamic.insert(name.clone(), value.clone());
                headers.push((name, value));
                cursor += consumed;
                saw_header = true;
            } else if first & 0x20 != 0 {
                if saw_header {
                    return Err(DecodeError::TableSizeUpdateAfterHeader);
                }
                let (size, consumed) = decode_integer(remaining, 5)?;
                if size > self.max_allowed_table_size {
                    return Err(DecodeError::InvalidTableSize);
                }
                self.dynamic.set_max_size(size);
                cursor += consumed;
            } else {
                let ((name, value), consumed) = self.decode_literal(remaining, 4)?;
                headers.push((name, value));
                cursor += consumed;
                saw_header = true;
            }
        }
        Ok(headers)
    }

    fn lookup_owned(&self, index: usize) -> Result<HeaderField, DecodeError> {
        self.dynamic
            .lookup(index)
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .ok_or(DecodeError::InvalidIndex)
    }

    fn decode_literal(&self, input: &[u8], prefix_bits: u8) -> Result<DecodedLiteral, DecodeError> {
        let (name_index, mut consumed) = decode_integer(input, prefix_bits)?;
        let name = if name_index == 0 {
            let (name, used) = decode_string(&input[consumed..])?;
            consumed += used;
            name
        } else {
            self.dynamic
                .lookup(name_index)
                .map(|(name, _)| name.to_vec())
                .ok_or(DecodeError::InvalidIndex)?
        };
        let (value, used) = decode_string(&input[consumed..])?;
        consumed += used;
        Ok(((name, value), consumed))
    }
}

fn decode_integer(input: &[u8], prefix_bits: u8) -> Result<(usize, usize), DecodeError> {
    let Some(&first) = input.first() else {
        return Err(DecodeError::TruncatedInteger);
    };
    let mask = (1usize << prefix_bits) - 1;
    let mut value = (first as usize) & mask;
    if value < mask {
        return Ok((value, 1));
    }

    let mut shift = 0u32;
    let mut bytes = 1usize;
    for (offset, &byte) in input[1..].iter().enumerate() {
        bytes += 1;
        let chunk = ((byte & 0x7f) as usize)
            .checked_shl(shift)
            .ok_or(DecodeError::IntegerOverflow)?;
        value = value
            .checked_add(chunk)
            .ok_or(DecodeError::IntegerOverflow)?;
        if byte & 0x80 == 0 {
            return Ok((value, offset + 2));
        }
        if bytes == 5 {
            return Err(DecodeError::IntegerOverflow);
        }
        shift += 7;
    }
    Err(DecodeError::TruncatedInteger)
}

fn decode_string(input: &[u8]) -> Result<(Vec<u8>, usize), DecodeError> {
    let huffman_encoded = input
        .first()
        .map(|byte| byte & 0x80 != 0)
        .ok_or(DecodeError::TruncatedString)?;
    let (length, prefix_len) = decode_integer(input, 7)?;
    let end = prefix_len
        .checked_add(length)
        .ok_or(DecodeError::IntegerOverflow)?;
    let encoded = input
        .get(prefix_len..end)
        .ok_or(DecodeError::TruncatedString)?;
    if !huffman_encoded {
        return Ok((encoded.to_vec(), end));
    }

    let mut decoded = Vec::with_capacity(length.saturating_mul(2));
    huffman::decode(encoded, &mut decoded).map_err(DecodeError::InvalidHuffman)?;
    Ok((decoded, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rfc_huffman_request_sequence() {
        let mut decoder = Decoder::new(4096);
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        assert_eq!(
            decoder.decode(&first).unwrap(),
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]
        );

        let second = [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf,
        ];
        let decoded = decoder.decode(&second).unwrap();
        assert_eq!(
            decoded[3],
            (b":authority".to_vec(), b"www.example.com".to_vec())
        );
        assert_eq!(
            decoded[4],
            (b"cache-control".to_vec(), b"no-cache".to_vec())
        );

        let third = [
            0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
            0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
        ];
        assert_eq!(
            decoder.decode(&third).unwrap(),
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":path".to_vec(), b"/index.html".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
                (b"custom-key".to_vec(), b"custom-value".to_vec()),
            ]
        );
    }

    #[test]
    fn decodes_rfc_huffman_response_sequence() {
        let mut decoder = Decoder::new(256);
        let first = [
            0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0,
            0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81,
            0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad, 0x17, 0x18,
            0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
        ];
        assert_eq!(
            decoder.decode(&first).unwrap(),
            vec![
                (b":status".to_vec(), b"302".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]
        );

        let second = [0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf];
        assert_eq!(
            decoder.decode(&second).unwrap(),
            vec![
                (b":status".to_vec(), b"307".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]
        );

        let third = [
            0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20,
            0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d, 0x1b, 0xff, 0xc0, 0x5a,
            0x83, 0x9b, 0xd9, 0xab, 0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7,
            0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b, 0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36,
            0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f, 0x95, 0x87, 0x31, 0x60, 0x65, 0xc0,
            0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07,
        ];
        assert_eq!(
            decoder.decode(&third).unwrap(),
            vec![
                (b":status".to_vec(), b"200".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:22 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"content-encoding".to_vec(), b"gzip".to_vec()),
                (
                    b"set-cookie".to_vec(),
                    b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".to_vec(),
                ),
            ]
        );
    }

    #[test]
    fn rejects_invalid_indices_and_size_updates() {
        let mut decoder = Decoder::new(128);
        assert_eq!(decoder.decode(&[0x80]), Err(DecodeError::InvalidIndex));
        assert_eq!(
            decoder.decode(&[0x3f, 0x62, 0x82]),
            Err(DecodeError::InvalidTableSize)
        );
        assert_eq!(
            decoder.decode(&[0x82, 0x20]),
            Err(DecodeError::TableSizeUpdateAfterHeader)
        );
    }

    #[test]
    fn accepts_size_update_only_blocks_and_rejects_long_integers() {
        let mut decoder = Decoder::new(4096);
        assert_eq!(decoder.decode(&[0x20]).unwrap(), Vec::<HeaderField>::new());
        assert_eq!(
            decoder.decode(&[0xff, 0x80, 0x80, 0x80, 0x80]),
            Err(DecodeError::IntegerOverflow)
        );
        assert_eq!(
            decoder.decode(&[0xff, 0x80, 0x80, 0x80]),
            Err(DecodeError::TruncatedInteger)
        );
    }
}
