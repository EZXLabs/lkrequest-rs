//! HPACK Huffman encoding (RFC 7541, Appendix B).
//!
//! Encode table extracted from the `h2` crate (Apache-2.0 / MIT).

use std::sync::OnceLock;

/// (num_bits, code) for each byte value 0..=255, plus EOS at index 256.
pub(crate) static ENCODE_TABLE: [(u8, u32); 257] = [
    (13, 0x1ff8),
    (23, 0x007f_ffd8),
    (28, 0x0fff_ffe2),
    (28, 0x0fff_ffe3),
    (28, 0x0fff_ffe4),
    (28, 0x0fff_ffe5),
    (28, 0x0fff_ffe6),
    (28, 0x0fff_ffe7),
    (28, 0x0fff_ffe8),
    (24, 0x00ff_ffea),
    (30, 0x3fff_fffc),
    (28, 0x0fff_ffe9),
    (28, 0x0fff_ffea),
    (30, 0x3fff_fffd),
    (28, 0x0fff_ffeb),
    (28, 0x0fff_ffec),
    (28, 0x0fff_ffed),
    (28, 0x0fff_ffee),
    (28, 0x0fff_ffef),
    (28, 0x0fff_fff0),
    (28, 0x0fff_fff1),
    (28, 0x0fff_fff2),
    (30, 0x3fff_fffe),
    (28, 0x0fff_fff3),
    (28, 0x0fff_fff4),
    (28, 0x0fff_fff5),
    (28, 0x0fff_fff6),
    (28, 0x0fff_fff7),
    (28, 0x0fff_fff8),
    (28, 0x0fff_fff9),
    (28, 0x0fff_fffa),
    (28, 0x0fff_fffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0x0fff_fffc),
    (20, 0xfffe6),
    (22, 0x003f_ffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x003f_ffd3),
    (22, 0x003f_ffd4),
    (22, 0x003f_ffd5),
    (23, 0x007f_ffd9),
    (22, 0x003f_ffd6),
    (23, 0x007f_ffda),
    (23, 0x007f_ffdb),
    (23, 0x007f_ffdc),
    (23, 0x007f_ffdd),
    (23, 0x007f_ffde),
    (24, 0x00ff_ffeb),
    (23, 0x007f_ffdf),
    (24, 0x00ff_ffec),
    (24, 0x00ff_ffed),
    (22, 0x003f_ffd7),
    (23, 0x007f_ffe0),
    (24, 0x00ff_ffee),
    (23, 0x007f_ffe1),
    (23, 0x007f_ffe2),
    (23, 0x007f_ffe3),
    (23, 0x007f_ffe4),
    (21, 0x001f_ffdc),
    (22, 0x003f_ffd8),
    (23, 0x007f_ffe5),
    (22, 0x003f_ffd9),
    (23, 0x007f_ffe6),
    (23, 0x007f_ffe7),
    (24, 0x00ff_ffef),
    (22, 0x003f_ffda),
    (21, 0x001f_ffdd),
    (20, 0xfffe9),
    (22, 0x003f_ffdb),
    (22, 0x003f_ffdc),
    (23, 0x007f_ffe8),
    (23, 0x007f_ffe9),
    (21, 0x001f_ffde),
    (23, 0x007f_ffea),
    (22, 0x003f_ffdd),
    (22, 0x003f_ffde),
    (24, 0x00ff_fff0),
    (21, 0x001f_ffdf),
    (22, 0x003f_ffdf),
    (23, 0x007f_ffeb),
    (23, 0x007f_ffec),
    (21, 0x001f_ffe0),
    (21, 0x001f_ffe1),
    (22, 0x003f_ffe0),
    (21, 0x001f_ffe2),
    (23, 0x007f_ffed),
    (22, 0x003f_ffe1),
    (23, 0x007f_ffee),
    (23, 0x007f_ffef),
    (20, 0xfffea),
    (22, 0x003f_ffe2),
    (22, 0x003f_ffe3),
    (22, 0x003f_ffe4),
    (23, 0x007f_fff0),
    (22, 0x003f_ffe5),
    (22, 0x003f_ffe6),
    (23, 0x007f_fff1),
    (26, 0x03ff_ffe0),
    (26, 0x03ff_ffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x003f_ffe7),
    (23, 0x007f_fff2),
    (22, 0x003f_ffe8),
    (25, 0x01ff_ffec),
    (26, 0x03ff_ffe2),
    (26, 0x03ff_ffe3),
    (26, 0x03ff_ffe4),
    (27, 0x07ff_ffde),
    (27, 0x07ff_ffdf),
    (26, 0x03ff_ffe5),
    (24, 0x00ff_fff1),
    (25, 0x01ff_ffed),
    (19, 0x7fff2),
    (21, 0x001f_ffe3),
    (26, 0x03ff_ffe6),
    (27, 0x07ff_ffe0),
    (27, 0x07ff_ffe1),
    (26, 0x03ff_ffe7),
    (27, 0x07ff_ffe2),
    (24, 0x00ff_fff2),
    (21, 0x001f_ffe4),
    (21, 0x001f_ffe5),
    (26, 0x03ff_ffe8),
    (26, 0x03ff_ffe9),
    (28, 0x0fff_fffd),
    (27, 0x07ff_ffe3),
    (27, 0x07ff_ffe4),
    (27, 0x07ff_ffe5),
    (20, 0xfffec),
    (24, 0x00ff_fff3),
    (20, 0xfffed),
    (21, 0x001f_ffe6),
    (22, 0x003f_ffe9),
    (21, 0x001f_ffe7),
    (21, 0x001f_ffe8),
    (23, 0x007f_fff3),
    (22, 0x003f_ffea),
    (22, 0x003f_ffeb),
    (25, 0x01ff_ffee),
    (25, 0x01ff_ffef),
    (24, 0x00ff_fff4),
    (24, 0x00ff_fff5),
    (26, 0x03ff_ffea),
    (23, 0x007f_fff4),
    (26, 0x03ff_ffeb),
    (27, 0x07ff_ffe6),
    (26, 0x03ff_ffec),
    (26, 0x03ff_ffed),
    (27, 0x07ff_ffe7),
    (27, 0x07ff_ffe8),
    (27, 0x07ff_ffe9),
    (27, 0x07ff_ffea),
    (27, 0x07ff_ffeb),
    (28, 0x0fff_fffe),
    (27, 0x07ff_ffec),
    (27, 0x07ff_ffed),
    (27, 0x07ff_ffee),
    (27, 0x07ff_ffef),
    (27, 0x07ff_fff0),
    (26, 0x03ff_ffee),
    (30, 0x3fff_ffff), // EOS
];

/// Compute the encoded length in bytes of `src` under HPACK Huffman.
pub(crate) fn encoded_len(src: &[u8]) -> usize {
    let bits: usize = src
        .iter()
        .map(|&b| ENCODE_TABLE[b as usize].0 as usize)
        .sum();
    bits.div_ceil(8)
}

/// Huffman-encode `src` and append the result to `dst`.
pub(crate) fn encode(src: &[u8], dst: &mut Vec<u8>) {
    let mut bits: u64 = 0;
    let mut bits_left: usize = 40;

    for &b in src {
        let (nbits, code) = ENCODE_TABLE[b as usize];
        let nbits = nbits as usize;

        bits |= (code as u64) << (bits_left - nbits);
        bits_left -= nbits;

        while bits_left <= 32 {
            dst.push((bits >> 32) as u8);
            bits <<= 8;
            bits_left += 8;
        }
    }

    if bits_left != 40 {
        bits |= (1u64 << bits_left) - 1;
        dst.push((bits >> 32) as u8);
    }
}

#[derive(Clone, Copy)]
struct DecodeNode {
    children: [u16; 2],
    symbol: i16,
}

impl DecodeNode {
    const NONE: u16 = u16::MAX;

    const fn new() -> Self {
        Self {
            children: [Self::NONE; 2],
            symbol: -1,
        }
    }
}

fn decode_nodes() -> &'static [DecodeNode] {
    static NODES: OnceLock<Vec<DecodeNode>> = OnceLock::new();
    NODES.get_or_init(|| {
        let mut nodes = vec![DecodeNode::new()];
        for (symbol, &(bit_count, code)) in ENCODE_TABLE.iter().enumerate() {
            let mut node_index = 0usize;
            for shift in (0..bit_count).rev() {
                let bit = ((code >> shift) & 1) as usize;
                let child = nodes[node_index].children[bit];
                node_index = if child == DecodeNode::NONE {
                    let next = u16::try_from(nodes.len()).expect("HPACK Huffman trie too large");
                    nodes.push(DecodeNode::new());
                    nodes[node_index].children[bit] = next;
                    next as usize
                } else {
                    child as usize
                };
            }
            debug_assert_eq!(nodes[node_index].symbol, -1);
            nodes[node_index].symbol = symbol as i16;
        }
        nodes
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    InvalidCode,
    UnexpectedEos,
    InvalidPadding,
}

/// Decode an RFC 7541 Huffman string.
///
/// The immutable decoding trie is constructed once per process and reused by
/// every connection. The hot path performs only compact array lookups; it does
/// not allocate lookup tables or hash individual bits.
pub(crate) fn decode(src: &[u8], dst: &mut Vec<u8>) -> Result<(), DecodeError> {
    let nodes = decode_nodes();
    let mut node_index = 0usize;
    let mut trailing_bits = 0u8;
    let mut trailing_len = 0u8;

    for &byte in src {
        for shift in (0..8).rev() {
            let bit = ((byte >> shift) & 1) as usize;
            trailing_bits = (trailing_bits << 1) | bit as u8;
            trailing_len += 1;

            let child = nodes[node_index].children[bit];
            if child == DecodeNode::NONE {
                return Err(DecodeError::InvalidCode);
            }
            node_index = child as usize;

            let symbol = nodes[node_index].symbol;
            if symbol >= 0 {
                if symbol == 256 {
                    return Err(DecodeError::UnexpectedEos);
                }
                dst.push(symbol as u8);
                node_index = 0;
                trailing_bits = 0;
                trailing_len = 0;
            }
        }
    }

    if node_index == 0 {
        return Ok(());
    }
    if trailing_len > 7 || trailing_bits != ((1u16 << trailing_len) - 1) as u8 {
        return Err(DecodeError::InvalidPadding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_hello() {
        // HPACK Huffman (RFC 7541 Appendix B) of "hello":
        //   h=100111 e=00101 l=101000 l=101000 o=00111, then 1-padded to a byte
        //   boundary → 4 bytes: 0x9C 0xB4 0x50 0x7F.
        let mut dst = Vec::new();
        encode(b"hello", &mut dst);
        assert_eq!(dst, vec![0x9C, 0xB4, 0x50, 0x7F]);
    }

    #[test]
    fn test_encoded_len() {
        let src = b"www.example.com";
        let len = encoded_len(src);
        let mut dst = Vec::new();
        encode(src, &mut dst);
        assert_eq!(len, dst.len());
    }

    #[test]
    fn test_encode_known_value() {
        // RFC 7541 Appendix C.4.1: "www.example.com" → 12 bytes
        let mut dst = Vec::new();
        encode(b"www.example.com", &mut dst);
        assert_eq!(dst.len(), 12);
    }

    #[test]
    fn test_decode_roundtrip() {
        let inputs: &[&[u8]] = &[
            b"hello",
            b"www.example.com",
            b"Mon, 21 Oct 2013 20:13:21 GMT",
            b"custom-value",
        ];
        for input in inputs {
            let mut encoded = Vec::new();
            encode(input, &mut encoded);
            let mut decoded = Vec::new();
            decode(&encoded, &mut decoded).unwrap();
            assert_eq!(&decoded, input);
        }
    }

    #[test]
    fn test_decode_roundtrip_all_octets() {
        let input: Vec<u8> = (0..=u8::MAX).collect();
        let mut encoded = Vec::new();
        encode(&input, &mut encoded);
        let mut decoded = Vec::new();
        decode(&encoded, &mut decoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_decode_independent_known_vectors() {
        let cases: &[(&[u8], &[u8])] = &[
            (&[0b0011_1111], b"o"),
            (&[0x07], b"0"),
            (&[0x87], b"A"),
            (&[0xff, 0xaf], b"#"),
            (&[0xff, 0xcf], b"$"),
            (&[0xff, 0xff, 0xff, 0xf3], b"\n"),
            (&[0xfe, 0x01], b"!0"),
            (&[0x53, 0xf8], b" !"),
        ];
        for &(encoded, expected) in cases {
            let mut decoded = Vec::new();
            decode(encoded, &mut decoded).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn test_decode_rejects_eos_and_bad_padding() {
        let mut decoded = Vec::new();
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff], &mut decoded),
            Err(DecodeError::UnexpectedEos)
        );
        decoded.clear();
        assert_eq!(
            decode(&[0x00], &mut decoded),
            Err(DecodeError::InvalidPadding)
        );
    }
}
