//! Parse a reassembled, decrypted H3 control-stream prefix independently of
//! the sending backend. Input includes stream type 0 and ends at a frame boundary.
//! Unknown frames, duplicate settings and raw priority text remain observable;
//! this is a fingerprint parser, not a full HTTP/3 protocol validator.

use crate::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ControlFrame<'a> {
    pub frame_type: u64,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3PriorityUpdate<'a> {
    /// Request (0xf0700) and push (0xf0701) updates are distinct.
    pub frame_type: u64,
    pub element_id: u64,
    pub field_value: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ControlStream<'a> {
    pub frames: Vec<H3ControlFrame<'a>>,
    /// Entries retain observed order, including unknown and duplicate IDs.
    pub settings: Vec<(u64, u64)>,
    pub priority_updates: Vec<H3PriorityUpdate<'a>>,
}

/// Parse complete observed frames; never infer absent frames from a profile.
///
/// The first frame must be SETTINGS. An incomplete final frame is an error,
/// rather than a silently accepted fingerprint. A frame-aligned prefix remains
/// a prefix: successful parsing does not imply a closed or complete stream.
pub fn parse_h3_control_stream(mut input: &[u8]) -> Result<H3ControlStream<'_>, ParseError> {
    if read_varint(&mut input)? != 0 {
        return Err(ParseError::UnexpectedValue(
            "not an H3 control stream".into(),
        ));
    }
    let mut result = H3ControlStream {
        frames: Vec::new(),
        settings: Vec::new(),
        priority_updates: Vec::new(),
    };
    while !input.is_empty() {
        let frame_type = read_varint(&mut input)?;
        let length = read_varint(&mut input)?;
        if length > input.len() as u64 {
            return Err(ParseError::DataTooShort("H3 frame payload".into()));
        }
        let (payload, remaining) = input.split_at(length as usize);
        input = remaining;
        if result.frames.is_empty() && frame_type != 4 {
            return Err(ParseError::UnexpectedValue(
                "H3 SETTINGS must be first".into(),
            ));
        }
        match frame_type {
            4 => {
                let mut fields = payload;
                while !fields.is_empty() {
                    let id = read_varint(&mut fields)?;
                    let value = read_varint(&mut fields)?;
                    result.settings.push((id, value));
                }
            }
            0xf0700 | 0xf0701 => {
                let mut fields = payload;
                let element_id = read_varint(&mut fields)?;
                result.priority_updates.push(H3PriorityUpdate {
                    frame_type,
                    element_id,
                    field_value: fields,
                });
            }
            _ => {}
        }
        result.frames.push(H3ControlFrame {
            frame_type,
            payload,
        });
    }
    if result.frames.is_empty() {
        return Err(ParseError::DataTooShort("H3 SETTINGS frame".into()));
    }
    Ok(result)
}

fn read_varint(input: &mut &[u8]) -> Result<u64, ParseError> {
    let first = *input
        .first()
        .ok_or_else(|| ParseError::DataTooShort("QUIC varint".into()))?;
    let length = 1usize << (first >> 6);
    let bytes = input
        .get(..length)
        .ok_or_else(|| ParseError::DataTooShort("QUIC varint".into()))?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[length..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_order_unknown_frames_and_distinct_priority_targets() {
        let bytes = hex::decode("00040507010140402102aabb800f07000404753d36800f070106407b693d3f30")
            .unwrap();
        let parsed = parse_h3_control_stream(&bytes).unwrap();
        assert_eq!(parsed.settings, [(7, 1), (1, 64)]);
        assert_eq!(
            parsed
                .frames
                .iter()
                .map(|f| f.frame_type)
                .collect::<Vec<_>>(),
            [4, 33, 0xf0700, 0xf0701]
        );
        assert_eq!(parsed.frames[1].payload, [0xaa, 0xbb]);
        assert_eq!(parsed.priority_updates[0].element_id, 4);
        assert_eq!(parsed.priority_updates[0].field_value, b"u=6");
        assert_eq!(parsed.priority_updates[1].element_id, 123);
        assert_eq!(parsed.priority_updates[1].field_value, b"i=?0");
        assert_eq!(parsed.priority_updates[1].frame_type, 0xf0701);
    }

    #[test]
    fn incomplete_varints_and_frames_never_become_partial_success() {
        for bytes in [
            &[][..],
            &[0],
            &[0, 4],
            &[0, 4, 1],
            &[0, 4, 1, 1],
            &[0, 4, 0, 0x40],
            &[0, 4, 0, 0x80, 0, 0],
            &[0, 4, 0, 0xc0, 0, 0, 0, 0, 0, 0],
            &[0, 4, 0, 33, 0x40],
            &[0, 4, 0, 33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0, 4, 0, 0x80, 0x0f, 7, 0, 0],
        ] {
            assert!(parse_h3_control_stream(bytes).is_err(), "{bytes:x?}");
        }
        assert!(parse_h3_control_stream(&[2, 4, 0]).is_err());
        assert!(parse_h3_control_stream(&[0, 33, 0]).is_err());
        assert_eq!(parse_h3_control_stream(&[0, 4, 0]).unwrap().settings, []);
    }

    #[test]
    fn accepts_nonminimal_varints_and_retains_all_62_bits() {
        let bytes =
            hex::decode("400080000004c000000000000010ffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(
            parse_h3_control_stream(&bytes).unwrap().settings,
            [(0x3fff_ffff_ffff_ffff, 0x3fff_ffff_ffff_ffff)]
        );
    }

    #[test]
    fn duplicate_settings_are_evidence_not_silently_deduplicated() {
        let parsed = parse_h3_control_stream(&[0, 4, 4, 1, 2, 1, 3]).unwrap();
        assert_eq!(parsed.settings, [(1, 2), (1, 3)]);
    }
}
