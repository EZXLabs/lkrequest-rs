//! EC Point Formats extension — type 0x000b.
//!
//! Indicates the set of point formats that the client can parse for
//! elliptic curve points (typically just `uncompressed` = 0x00).

use super::Extension;

pub(super) fn parse_tls12_server(
    data: &[u8],
) -> crate::error::Result<super::tls12::ServerValue<'_>> {
    let Some((&length, formats)) = data.split_first() else {
        return Err(super::tls12::decode_error("missing point formats vector"));
    };
    if length == 0 || length as usize != formats.len() {
        return Err(super::tls12::decode_error("invalid point formats vector"));
    }
    if !formats.contains(&0) {
        return Err(crate::error::TlsError::local_alert(
            crate::error::AlertDescription::IllegalParameter,
            "server point formats omit uncompressed points",
        ));
    }
    Ok(super::tls12::ServerValue::PointFormats)
}

/// EC Point Formats extension.
pub struct EcPointFormats {
    /// List of supported point format codes (e.g. `[0x00]` for uncompressed).
    pub formats: Vec<u8>,
}

impl Extension for EcPointFormats {
    fn extension_type(&self) -> u16 {
        0x000b
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) {
        buf.push(self.formats.len() as u8);
        buf.extend_from_slice(&self.formats);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_uncompressed_only() {
        let ext = EcPointFormats {
            formats: vec![0x00],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        // type(2) + length(2) + payload(1 len byte + 1 format byte)
        assert_eq!(buf, [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_multiple_formats() {
        let ext = EcPointFormats {
            formats: vec![0x00, 0x01, 0x02],
        };
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        assert_eq!(buf, [0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02]);
    }
}
