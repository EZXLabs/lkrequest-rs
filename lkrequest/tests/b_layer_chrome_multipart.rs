//! Tier 1 — capture real Chrome's `multipart/form-data` wire format.
//!
//! `#[ignore]`d: needs a real Chrome on the machine. Run with
//!
//! ```text
//! cargo test -p lkrequest --test b_layer_chrome_multipart -- --ignored --nocapture
//! ```
//!
//! Chrome posts to a **plaintext** local server, so the body is readable
//! straight off the socket — no key log and no pcap decryption. Two questions
//! this answers:
//!
//! * **The boundary format** (F-01). Ours says `----lkrequest{hex}`, which
//!   announces the library in every upload — a fatal tell for a library whose
//!   whole purpose is to be indistinguishable from a browser.
//! * **How a field name containing `"`, `\`, CR, LF and non-ASCII is encoded**
//!   (B-05b). RFC 7578 §5.1 and what browsers actually do are not the same
//!   thing, and the browser is what we have to match.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use headless_chrome::{Browser, LaunchOptions};

/// How many separate submissions to collect, so the boundary's random part can
/// be checked for length and alphabet rather than guessed from one sample.
const SAMPLES: usize = 6;

/// Serve the form to GETs and capture POST bodies, sending each one back.
fn serve(listener: TcpListener, tx: mpsc::Sender<String>) {
    while let Ok((stream, _)) = listener.accept() {
        match handle(stream) {
            Ok(Some(request)) => {
                if tx.send(request).is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }
}

/// Handle one connection. Returns `Some(raw_request)` for a POST, `None` for
/// the form GET and anything else.
fn handle(mut stream: TcpStream) -> std::io::Result<Option<String>> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut headers = String::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
        {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push_str(&line);
    }

    if request_line.starts_with("POST") {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
        return Ok(Some(format!(
            "{headers}\r\n{}",
            String::from_utf8_lossy(&body)
        )));
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{PAGE}",
        PAGE.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    Ok(None)
}

/// The form is built entirely in JS so the exact bytes of each name reach
/// Chrome — an HTML attribute cannot carry a raw CR or LF.
///
/// `\u{22}` = `"`, `\u{5C}` = `\`, `\u{0D}`/`\u{0A}` = CR/LF, plus a non-ASCII
/// run and a `;` (which would terminate a parameter if it were not quoted).
const PAGE: &str = r#"<!doctype html><meta charset="utf-8">
<form id="f" method="post" enctype="multipart/form-data" action="/upload"></form>
<script>
  // JS escapes, not literal control characters: an HTML attribute cannot carry
  // a raw CR or LF, and neither can a Rust string.
  const DQ = String.fromCharCode(34),   // double quote
        BS = String.fromCharCode(92),   // backslash
        CR = String.fromCharCode(13),
        LF = String.fromCharCode(10);
  const f = document.getElementById("f");
  const text = (name, value) => {
    const i = document.createElement("input");
    i.type = "text";
    i.setAttribute("name", name);
    i.value = value;
    f.appendChild(i);
  };

  text("plain", "simple");
  text("qu" + DQ + "ote", "dquote");
  text("back" + BS + "slash", "backslash");
  text("cr" + CR + "here", "cr");
  text("lf" + LF + "here", "lf");
  text("crlf" + CR + LF + "here", "crlf");
  text("semi;colon", "semi");
  text("unicode-中文", "unicode");

  const dt = new DataTransfer();
  dt.items.add(new File(["file body"],
                        "f" + DQ + "o" + BS + "o" + LF + "中.txt",
                        {type: "text/plain"}));
  const file = document.createElement("input");
  file.type = "file";
  file.name = "upload";
  f.appendChild(file);
  file.files = dt.files;

  // Content-Type is NOT a quoted string in the part header, so percent-encoding
  // does not apply there. What does Chrome do with a hostile MIME type?
  const dt2 = new DataTransfer();
  dt2.items.add(new File(["evil body"], "evil.txt",
                         {type: "text/plain" + CR + LF + "X-Injected: yes"}));
  const file2 = document.createElement("input");
  file2.type = "file";
  file2.name = "hostile_mime";
  f.appendChild(file2);
  file2.files = dt2.files;

  f.submit();
</script>"#;

/// Pull `boundary=...` out of the captured Content-Type header.
fn boundary_of(request: &str) -> Option<String> {
    let line = request
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))?;
    Some(line.split("boundary=").nth(1)?.trim().to_string())
}

#[test]
#[ignore = "Tier 1: requires a real Chrome installation"]
fn capture_chrome_multipart_wire_format() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || serve(listener, tx));

    let options = LaunchOptions::default_builder()
        .headless(false)
        .args(vec![std::ffi::OsStr::new("--headless=new")])
        .build()
        .expect("launch options");
    let browser = Browser::new(options).expect("launch Chrome");

    let mut boundaries = Vec::new();
    let mut first_body = None;

    for i in 0..SAMPLES {
        let tab = browser.new_tab().expect("tab");
        tab.set_default_timeout(Duration::from_secs(30));
        tab.navigate_to(&format!("http://127.0.0.1:{port}/?i={i}"))
            .expect("navigate");

        let request = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("Chrome never posted");
        boundaries.push(boundary_of(&request).expect("no boundary in Content-Type"));
        if first_body.is_none() {
            first_body = Some(request);
        }
        let _ = tab.close(true);
    }

    println!("================ RAW CHROME BODY ================");
    println!("{}", first_body.expect("captured at least one"));
    println!("================ BOUNDARY SAMPLES ================");
    for b in &boundaries {
        println!("{b}   (len={})", b.len());
    }

    let prefix = "----WebKitFormBoundary";
    let alphabet: std::collections::BTreeSet<char> = boundaries
        .iter()
        .filter_map(|b| b.strip_prefix(prefix))
        .flat_map(|suffix| suffix.chars())
        .collect();
    println!("================ RANDOM PART ================");
    println!("suffix lengths: {:?}", {
        let mut lens: Vec<_> = boundaries
            .iter()
            .filter_map(|b| b.strip_prefix(prefix))
            .map(str::len)
            .collect();
        lens.sort_unstable();
        lens.dedup();
        lens
    });
    println!("alphabet seen: {}", alphabet.iter().collect::<String>());

    assert!(
        boundaries.iter().all(|b| b.starts_with(prefix)),
        "unexpected boundary shape: {boundaries:?}"
    );
}
