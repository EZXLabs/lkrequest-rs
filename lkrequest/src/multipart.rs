//! Multipart/form-data request body builder.
//!
//! Supports file uploads and complex form submissions via the
//! `multipart/form-data` content type (RFC 2046 / RFC 7578).
//!
//! # Example
//!
//! ```rust,no_run
//! # use lkrequest::Client;
//! # use lktls::profile::presets;
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! # let client = Client::builder().fingerprint(presets::chrome_131()).build();
//! # let session = client.session().build();
//! # let image_bytes = vec![0u8; 100];
//! use lkrequest::multipart::{Multipart, Part};
//!
//! let form = Multipart::new()
//!     .text("username", "alice")
//!     .text("bio", "Rustacean")
//!     .file("avatar", "avatar.png", "image/png", image_bytes);
//!
//! let resp = session.post("https://example.com/upload")
//!     .multipart(form)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use bytes::Bytes;

use crate::error::Error;

/// Escape a value that goes inside a quoted `Content-Disposition` parameter,
/// the way Chrome does.
///
/// Captured from Chrome 151 (see `tests/b_layer_chrome_multipart.rs`, which
/// drives real Chrome at a local server and prints the raw body):
///
/// ```text
/// Content-Disposition: form-data; name="qu%22ote"
/// Content-Disposition: form-data; name="back\slash"
/// Content-Disposition: form-data; name="semi;colon"
/// Content-Disposition: form-data; name="unicode-中文"
/// ```
///
/// So exactly three characters are percent-encoded — `"`, CR and LF — and
/// everything else, backslash and `;` and non-ASCII included, goes out
/// verbatim as UTF-8. Notably `%` itself is *not* escaped, so the encoding is
/// not reversible; that is Chrome's behaviour and this crate exists to
/// reproduce it.
///
/// This also closes the injection hole that made these values dangerous: a CR
/// or LF would otherwise terminate the header line (RFC 5322 §2.2) and let a
/// caller-supplied name append part headers, start an extra part, or forge the
/// boundary. Escaping is strictly better than the rejection this replaces —
/// same safety, and it matches the wire.
fn escape_header_param(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("%22"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a form field *name*.
///
/// Chrome normalises newlines in a name to CRLF before escaping, so a lone CR
/// and a lone LF both come out as `%0D%0A`. From the same capture: the inputs
/// `cr\rhere`, `lf\nhere` and `crlf\r\nhere` all produced
///
/// ```text
/// name="cr%0D%0Ahere"   name="lf%0D%0Ahere"   name="crlf%0D%0Ahere"
/// ```
///
/// Filenames do *not* get this step — see [`escape_filename`].
fn escape_field_name(name: &str) -> String {
    escape_header_param(&normalize_newlines(name))
}

/// Escape a part *filename*.
///
/// Unlike a field name this is not newline-normalised: the captured filename
/// `f"o\o\n中.txt` came back as `f%22o\o%0A中.txt` — a lone LF stayed a lone
/// `%0A`.
fn escape_filename(filename: &str) -> String {
    escape_header_param(filename)
}

/// Replace every lone CR and lone LF with CRLF, leaving existing CRLFs alone.
fn normalize_newlines(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\r\n");
            }
            '\n' => out.push_str("\r\n"),
            other => out.push(other),
        }
    }
    out
}

/// Reject a MIME type that cannot be put on the wire.
///
/// `Content-Type` is not a quoted parameter, so the percent-encoding above does
/// not apply to it and a CR or LF there is a live header-injection vector.
///
/// Chrome's own answer is to discard the type entirely: a `File` constructed
/// with `type: "text/plain\r\nX-Injected: yes"` was sent as
/// `Content-Type: application/octet-stream`. We report an error instead of
/// silently substituting — nothing divergent reaches the wire either way, and
/// for a library API a rejected call is easier to debug than a quietly changed
/// one.
fn reject_control_chars(field: &str, value: &str) -> Result<(), Error> {
    if value.contains(['\r', '\n']) {
        return Err(Error::Http(format!(
            "multipart {field} must not contain CR or LF (would inject part headers): {value:?}"
        )));
    }
    Ok(())
}

/// A multipart/form-data body builder.
///
/// Accumulates [`Part`]s and encodes them into a multipart body when sent.
pub struct Multipart {
    boundary: String,
    parts: Vec<Part>,
}

/// A single part in a multipart form.
pub struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Bytes,
}

impl Part {
    /// Create a new part with the given form field name and body bytes.
    ///
    /// Accepts any type that implements `Into<Bytes>`, including `Vec<u8>`,
    /// `&'static [u8]`, `Bytes`, etc.
    pub fn new(name: &str, body: impl Into<Bytes>) -> Self {
        Self {
            name: name.to_string(),
            filename: None,
            content_type: None,
            body: body.into(),
        }
    }

    /// Set the filename for this part (shown in `Content-Disposition`).
    pub fn filename(mut self, filename: &str) -> Self {
        self.filename = Some(filename.to_string());
        self
    }

    /// Set the MIME content type for this part.
    pub fn content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Check that this part's header values can be encoded safely.
    ///
    /// Only the content type can fail: names and filenames are escaped the way
    /// Chrome escapes them (see [`escape_field_name`] / [`escape_filename`]),
    /// while a MIME type has no quoted form to escape into — see
    /// [`reject_control_chars`].
    fn validate(&self) -> Result<(), Error> {
        if let Some(content_type) = &self.content_type {
            reject_control_chars("content type", content_type)?;
        }
        Ok(())
    }
}

impl Default for Multipart {
    fn default() -> Self {
        Self::new()
    }
}

impl Multipart {
    /// Create a new empty multipart form with a random boundary.
    pub fn new() -> Self {
        Self {
            boundary: generate_boundary(),
            parts: Vec::new(),
        }
    }

    /// Add a plain text field.
    pub fn text(mut self, name: &str, value: &str) -> Self {
        self.parts.push(Part {
            name: name.to_string(),
            filename: None,
            content_type: None,
            body: Bytes::copy_from_slice(value.as_bytes()),
        });
        self
    }

    /// Add a file upload field.
    ///
    /// # Arguments
    ///
    /// * `name` - The form field name.
    /// * `filename` - The filename to report to the server.
    /// * `content_type` - The MIME type (e.g. `"image/png"`).
    /// * `data` - The file contents (accepts `Vec<u8>`, `Bytes`, etc.).
    pub fn file(
        mut self,
        name: &str,
        filename: &str,
        content_type: &str,
        data: impl Into<Bytes>,
    ) -> Self {
        self.parts.push(Part {
            name: name.to_string(),
            filename: Some(filename.to_string()),
            content_type: Some(content_type.to_string()),
            body: data.into(),
        });
        self
    }

    /// Add a custom [`Part`].
    pub fn part(mut self, part: Part) -> Self {
        self.parts.push(part);
        self
    }

    /// Returns the `Content-Type` header value including the boundary.
    ///
    /// Example: `multipart/form-data; boundary=----WebKitFormBoundary0FZWHTjjFlLPvBTm`
    pub(crate) fn content_type_header(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Encode all parts into the multipart body bytes (RFC 2046).
    ///
    /// ```text
    /// --boundary\r\n
    /// Content-Disposition: form-data; name="field"\r\n
    /// \r\n
    /// value\r\n
    /// --boundary\r\n
    /// Content-Disposition: form-data; name="file"; filename="a.txt"\r\n
    /// Content-Type: text/plain\r\n
    /// \r\n
    /// <file data>\r\n
    /// --boundary--\r\n
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if any part's content type contains a CR or an
    /// LF, which would let the caller inject extra part headers.  Nothing is
    /// encoded in that case.  Field names and filenames cannot fail: they are
    /// percent-escaped exactly as Chrome escapes them.
    pub(crate) fn encode(self) -> Result<Vec<u8>, Error> {
        // Validate every part up front so a rejection does not depend on how
        // much of the body happened to be built first.
        for part in &self.parts {
            part.validate()?;
        }

        let mut buf = Vec::new();

        for part in &self.parts {
            // Boundary delimiter
            buf.extend_from_slice(b"--");
            buf.extend_from_slice(self.boundary.as_bytes());
            buf.extend_from_slice(b"\r\n");

            // Content-Disposition header
            buf.extend_from_slice(b"Content-Disposition: form-data; name=\"");
            buf.extend_from_slice(escape_field_name(&part.name).as_bytes());
            buf.push(b'"');

            if let Some(ref filename) = part.filename {
                buf.extend_from_slice(b"; filename=\"");
                buf.extend_from_slice(escape_filename(filename).as_bytes());
                buf.push(b'"');
            }
            buf.extend_from_slice(b"\r\n");

            // Content-Type header (if present)
            if let Some(ref ct) = part.content_type {
                buf.extend_from_slice(b"Content-Type: ");
                buf.extend_from_slice(ct.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }

            // Empty line separating headers from body
            buf.extend_from_slice(b"\r\n");

            // Part body
            buf.extend_from_slice(&part.body);
            buf.extend_from_slice(b"\r\n");
        }

        // Closing boundary
        buf.extend_from_slice(b"--");
        buf.extend_from_slice(self.boundary.as_bytes());
        buf.extend_from_slice(b"--\r\n");

        Ok(buf)
    }
}

/// Characters WebKit draws the random part of a boundary from.
const BOUNDARY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Length of the random part, measured from real Chrome.
const BOUNDARY_RANDOM_LEN: usize = 16;

/// Generate a boundary in the format Chrome (and every other WebKit/Blink
/// browser) uses.
///
/// This used to emit `----lkrequest{hex}`, which announced the library by name
/// in the `Content-Type` header of every single upload — the most direct
/// fingerprint tell in the crate, and fatal for something whose purpose is to
/// be indistinguishable from a browser. No amount of TLS or H2 fidelity
/// survives a body that says `lkrequest`.
///
/// Chrome 151, six samples captured by `tests/b_layer_chrome_multipart.rs`:
///
/// ```text
/// ----WebKitFormBoundarySduTHHBQCpnKt9fu
/// ----WebKitFormBoundary0FZWHTjjFlLPvBTm
/// ----WebKitFormBoundaryBqlloZkcPhMVRkhd
/// ```
///
/// Four dashes, the literal `WebKitFormBoundary`, then exactly 16 alphanumeric
/// characters — 38 characters in total, every sample.
///
/// The random part is drawn by rejection sampling so every character of the
/// 62-character alphabet is equally likely; taking `byte % 62` would bias the
/// first 8 letters, and a boundary whose character distribution differs from
/// Chrome's is a tell of exactly the kind this replaces.
fn generate_boundary() -> String {
    let rng = SystemRandom::new();
    let mut random = String::with_capacity(BOUNDARY_RANDOM_LEN);

    // 256 is not a multiple of 62, so bytes at or above the largest multiple
    // are discarded rather than folded in.
    let limit = (256 / BOUNDARY_ALPHABET.len() * BOUNDARY_ALPHABET.len()) as u16;
    let mut pool = [0u8; 64];
    while random.len() < BOUNDARY_RANDOM_LEN {
        rng.fill(&mut pool).expect("RNG failure");
        for &byte in &pool {
            if (byte as u16) < limit {
                random.push(BOUNDARY_ALPHABET[byte as usize % BOUNDARY_ALPHABET.len()] as char);
                if random.len() == BOUNDARY_RANDOM_LEN {
                    break;
                }
            }
        }
    }

    format!("----WebKitFormBoundary{random}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipart_text_only() {
        let form = Multipart::new()
            .text("field1", "value1")
            .text("field2", "value2");

        let ct = form.content_type_header();
        assert!(ct.starts_with("multipart/form-data; boundary="));

        let body = form.encode().expect("valid form encodes");
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("name=\"field1\""));
        assert!(body_str.contains("value1"));
        assert!(body_str.contains("name=\"field2\""));
        assert!(body_str.contains("value2"));
        assert!(body_str.ends_with("--\r\n"));
    }

    #[test]
    fn test_multipart_with_file() {
        let form = Multipart::new().text("name", "test").file(
            "upload",
            "test.txt",
            "text/plain",
            b"hello world".to_vec(),
        );

        let body = form.encode().expect("valid form encodes");
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("filename=\"test.txt\""));
        assert!(body_str.contains("Content-Type: text/plain"));
        assert!(body_str.contains("hello world"));
    }

    #[test]
    fn test_multipart_custom_part() {
        let part = Part::new("data", b"binary data".to_vec())
            .filename("data.bin")
            .content_type("application/octet-stream");

        let form = Multipart::new().part(part);
        let body = form.encode().expect("valid form encodes");
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("name=\"data\""));
        assert!(body_str.contains("filename=\"data.bin\""));
        assert!(body_str.contains("Content-Type: application/octet-stream"));
        assert!(body_str.contains("binary data"));
    }

    /// The boundary must look like Chrome's, not like ours. Shape captured
    /// from Chrome 151 by `tests/b_layer_chrome_multipart.rs`: four dashes,
    /// `WebKitFormBoundary`, then 16 alphanumerics -- 38 characters total.
    #[test]
    fn boundary_matches_the_captured_chrome_format() {
        let b1 = generate_boundary();
        let b2 = generate_boundary();

        assert_ne!(b1, b2, "each form gets its own boundary");
        for b in [&b1, &b2] {
            assert_eq!(b.len(), 38, "captured length was 38: {b}");
            let random = b
                .strip_prefix("----WebKitFormBoundary")
                .unwrap_or_else(|| panic!("wrong prefix: {b}"));
            assert_eq!(random.len(), 16, "captured random part was 16 chars: {b}");
            assert!(
                random.chars().all(|c| c.is_ascii_alphanumeric()),
                "the random part is alphanumeric in every captured sample: {b}"
            );
        }
    }

    /// Regression guard for the tell this replaced: the crate name must not
    /// appear anywhere in an encoded body.
    #[test]
    fn nothing_on_the_wire_says_lkrequest() {
        let body = Multipart::new()
            .text("f", "v")
            .encode()
            .expect("valid form encodes");
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            !body_str.to_ascii_lowercase().contains("lkrequest"),
            "the body must not name the library: {body_str}"
        );
    }

    // ====================================================================
    // Part-header injection (CR/LF)
    // ====================================================================

    /// A CRLF in the field name would close `Content-Disposition` and let the
    /// caller append headers of their own. Chrome percent-encodes it instead
    /// of refusing the form, so we do too.
    #[test]
    fn crlf_in_field_name_is_percent_encoded() {
        let body = Multipart::new()
            .text("a\r\nX-Injected: yes", "v")
            .encode()
            .expect("Chrome encodes rather than rejects");
        let body_str = String::from_utf8_lossy(&body);

        assert!(
            body_str.contains("name=\"a%0D%0AX-Injected: yes\""),
            "expected the captured encoding: {body_str}"
        );
        assert_eq!(
            body_str
                .split("\r\n")
                .filter(|line| line.starts_with("Content-Disposition:"))
                .count(),
            1,
            "the injected header must not become a real one: {body_str}"
        );
    }

    /// Same for the filename, which is the value an attacker most often
    /// controls (an uploaded file's own name).
    #[test]
    fn crlf_in_filename_is_percent_encoded() {
        let body = Multipart::new()
            .file(
                "upload",
                "a.txt\r\nContent-Type: text/html",
                "text/plain",
                b"x".to_vec(),
            )
            .encode()
            .expect("Chrome encodes rather than rejects");
        let body_str = String::from_utf8_lossy(&body);

        assert!(
            body_str.contains("filename=\"a.txt%0D%0AContent-Type: text/html\""),
            "expected the captured encoding: {body_str}"
        );
        assert_eq!(
            body_str
                .split("\r\n")
                .filter(|line| line.starts_with("Content-Type:"))
                .count(),
            1,
            "the injected text stays inside the quoted filename, on one line: {body_str}"
        );
    }

    /// And for the content type.
    #[test]
    fn crlf_in_content_type_is_rejected() {
        let err = Multipart::new()
            .part(Part::new("p", b"x".to_vec()).content_type("text/plain\r\nX-Injected: yes"))
            .encode()
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("content type"),
            "error should name the offending field: {msg}"
        );
    }

    /// Names and filenames diverge here, and the capture is the only reason we
    /// know: Chrome normalises a lone CR or LF in a *name* to CRLF before
    /// escaping (both came back as `%0D%0A`), but leaves a lone LF in a
    /// *filename* alone (`%0A`).
    #[test]
    fn lone_cr_or_lf_normalises_in_a_name_but_not_in_a_filename() {
        for input in ["a\rb", "a\nb"] {
            let body = Multipart::new().text(input, "v").encode().expect("encodes");
            let body_str = String::from_utf8_lossy(&body);
            assert!(
                body_str.contains("name=\"a%0D%0Ab\""),
                "a lone newline in a name normalises to CRLF: {body_str}"
            );
        }

        let body = Multipart::new()
            .file("f", "a\nb.txt", "text/plain", b"x".to_vec())
            .encode()
            .expect("encodes");
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("filename=\"a%0Ab.txt\""),
            "a filename is not newline-normalised: {body_str}"
        );
    }

    /// A forged boundary is what makes this more than header injection: the
    /// escaping has to stop the body being restructured entirely.
    #[test]
    fn boundary_cannot_be_forged_through_a_part_header() {
        let form = Multipart::new();
        let boundary = form.boundary.clone();
        let injected = format!("f\r\n\r\nowned\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"admin\"\r\n\r\n1");

        let body = form.text(&injected, "v").encode().expect("encodes");
        let body_str = String::from_utf8_lossy(&body);

        let delimiter = format!("--{boundary}");
        let closing = format!("--{boundary}--");
        assert_eq!(
            body_str
                .split("\r\n")
                .filter(|line| *line == delimiter || *line == closing)
                .count(),
            2,
            "a delimiter only counts when it stands alone on a line -- the \
             injected copy is trapped inside the quoted name: {body_str}"
        );
        assert!(
            !body_str.contains("name=\"admin\""),
            "the forged part must not materialise: {body_str}"
        );
        assert_eq!(
            body_str
                .split("\r\n")
                .filter(|line| line.starts_with("Content-Disposition:"))
                .count(),
            1,
            "the forged header must stay inside the quoted name: {body_str}"
        );
    }

    /// Counter-case: values that merely *look* awkward must keep working, so
    /// the fix cannot pass by rejecting everything.
    #[test]
    fn ordinary_names_and_filenames_still_encode() {
        let body = Multipart::new()
            .text("normal_field", "value")
            .file(
                "upload",
                "my report (final) — café.txt",
                "text/plain; charset=utf-8",
                b"data".to_vec(),
            )
            .encode()
            .expect("ordinary names and filenames must still encode");
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("filename=\"my report (final) — café.txt\""),
            "spaces and unicode must survive verbatim: {body_str}"
        );
        assert!(
            body_str.contains("Content-Type: text/plain; charset=utf-8"),
            "a parameterised content type must survive: {body_str}"
        );
    }

    /// The other half of the captured escaping: `"` becomes `%22`, while `\\`
    /// and `;` and non-ASCII go out verbatim. Chrome does not escape `%`
    /// either, so the encoding is deliberately not reversible.
    #[test]
    fn quotes_are_percent_encoded_but_backslashes_are_not() {
        let body = Multipart::new()
            .file(
                "f",
                "a\"b\\c;d-\u{4e2d}\u{6587}.txt",
                "text/plain",
                b"x".to_vec(),
            )
            .encode()
            .expect("quotes are escaped, not rejected");
        let body_str = String::from_utf8_lossy(&body);

        assert!(
            body_str.contains("filename=\"a%22b\\c;d-\u{4e2d}\u{6587}.txt\""),
            "expected the captured encoding: {body_str}"
        );
    }

    /// `%` is passed through, which is what makes the encoding lossy. Pinned
    /// because it looks like a bug and is not one.
    #[test]
    fn percent_is_not_escaped() {
        let body = Multipart::new()
            .text("a%22b", "v")
            .encode()
            .expect("encodes");
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("name=\"a%22b\""),
            "a literal %22 is indistinguishable from an escaped quote, as in Chrome: {body_str}"
        );
    }
    /// The evidence test: feed the encoder exactly the inputs that were sent
    /// through real Chrome 151 in `tests/b_layer_chrome_multipart.rs`, and
    /// require exactly the `Content-Disposition` lines Chrome put on the wire.
    ///
    /// Anything that changes the escaping has to change this table, which
    /// means going back to a browser rather than guessing.
    #[test]
    fn field_names_match_the_chrome_151_capture() {
        // (input name, line Chrome emitted)
        let cases: &[(&str, &str)] = &[
            ("plain", "Content-Disposition: form-data; name=\"plain\""),
            (
                "qu\"ote",
                "Content-Disposition: form-data; name=\"qu%22ote\"",
            ),
            (
                "back\\slash",
                "Content-Disposition: form-data; name=\"back\\slash\"",
            ),
            (
                "cr\rhere",
                "Content-Disposition: form-data; name=\"cr%0D%0Ahere\"",
            ),
            (
                "lf\nhere",
                "Content-Disposition: form-data; name=\"lf%0D%0Ahere\"",
            ),
            (
                "crlf\r\nhere",
                "Content-Disposition: form-data; name=\"crlf%0D%0Ahere\"",
            ),
            (
                "semi;colon",
                "Content-Disposition: form-data; name=\"semi;colon\"",
            ),
            (
                "unicode-\u{4e2d}\u{6587}",
                "Content-Disposition: form-data; name=\"unicode-\u{4e2d}\u{6587}\"",
            ),
        ];

        for (input, expected) in cases {
            let body = Multipart::new().text(input, "v").encode().expect("encodes");
            let body_str = String::from_utf8_lossy(&body);
            assert!(
                body_str.split("\r\n").any(|line| line == *expected),
                "input {input:?}\n  expected: {expected}\n  got:\n{body_str}"
            );
        }
    }

    /// Same, for the filename Chrome emitted: `f"o\o\n中.txt` came back with
    /// the quote escaped, the backslash kept, and the lone LF *not*
    /// normalised.
    #[test]
    fn filename_matches_the_chrome_151_capture() {
        let body = Multipart::new()
            .file(
                "upload",
                "f\"o\\o\n\u{4e2d}.txt",
                "text/plain",
                b"file body".to_vec(),
            )
            .encode()
            .expect("encodes");
        let body_str = String::from_utf8_lossy(&body);

        let expected = "Content-Disposition: form-data; name=\"upload\"; \
                        filename=\"f%22o\\o%0A\u{4e2d}.txt\"";
        assert!(
            body_str.split("\r\n").any(|line| line == expected),
            "expected:\n  {expected}\ngot:\n{body_str}"
        );
    }
}
