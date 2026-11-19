const TARGET: &str = "lkh2::request";
const FIELD_NAMES: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
];

pub(crate) fn warn_if_noncompliant<N: AsRef<str>, V: AsRef<str>>(
    stream_id: u32,
    headers: &[(N, V)],
) {
    if !tracing::enabled!(target: TARGET, tracing::Level::WARN) {
        return;
    }

    let mut flagged = [false; FIELD_NAMES.len()];
    for (name, value) in headers {
        let Some(index) = FIELD_NAMES
            .iter()
            .position(|field| name.as_ref().eq_ignore_ascii_case(field))
        else {
            continue;
        };
        let valid_te = FIELD_NAMES[index] == "te"
            && value.as_ref().split(',').all(|token| {
                token
                    .trim_matches([' ', '\t'])
                    .eq_ignore_ascii_case("trailers")
            });
        flagged[index] |= !valid_te;
    }

    if flagged.iter().any(|flag| *flag) {
        // Report only fixed field names, never values, Connection tokens or URLs.
        let fields: Vec<_> = FIELD_NAMES
            .iter()
            .zip(flagged)
            .filter_map(|(name, flag)| flag.then_some(*name))
            .collect();
        tracing::warn!(
            target: TARGET,
            diagnostic = "h2.request_headers_noncompliant",
            protocol = "h2",
            stream_id,
            headers = ?fields,
            "HTTP/2 request headers violate RFC 9113 section 8.2.2; peer may reset the stream with PROTOCOL_ERROR; headers are sent unchanged"
        );
    }
}
