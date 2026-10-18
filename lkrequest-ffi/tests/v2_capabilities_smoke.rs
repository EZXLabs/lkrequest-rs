#[path = "support/server_regressions.rs"]
mod server_regressions;

use std::ffi::{c_char, c_void, CStr, CString};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ptr;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use lkrequest_ffi::{
    lk_client_builder_build, lk_client_builder_free, lk_client_builder_new,
    lk_client_builder_set_dns, lk_client_builder_set_dns_custom,
    lk_client_builder_set_use_native_certs, lk_client_free, lk_client_new, lk_client_new_default,
    lk_client_t, lk_dns_config_t, lk_error_code, lk_error_free, lk_error_message, lk_error_t,
    lk_log_init_callback, lk_multipart_add_file, lk_multipart_add_text, lk_multipart_new,
    lk_op_free, lk_op_state_t, lk_op_take_proxy_guard, lk_op_take_session_pool_guard,
    lk_op_take_socks5_udp_probe_report, lk_op_wait, lk_preset_get_detail_json, lk_preset_list_json,
    lk_proxy_auth_header_t, lk_proxy_config_free, lk_proxy_config_identity, lk_proxy_config_parse,
    lk_proxy_config_set_auth_header, lk_proxy_config_set_http_auth, lk_proxy_config_set_user_pass,
    lk_proxy_config_t, lk_proxy_config_url, lk_proxy_guard_free, lk_proxy_guard_mark_bad,
    lk_proxy_guard_t, lk_proxy_guard_url, lk_proxy_pool_acquire, lk_proxy_pool_acquire_async,
    lk_proxy_pool_builder_add_proxy, lk_proxy_pool_builder_add_proxy_config,
    lk_proxy_pool_builder_build, lk_proxy_pool_builder_free, lk_proxy_pool_builder_new,
    lk_proxy_pool_builder_set_provider, lk_proxy_pool_builder_set_proxy_buffer,
    lk_proxy_pool_builder_set_rotation, lk_proxy_pool_free, lk_proxy_pool_mark_bad,
    lk_proxy_pool_t, lk_proxy_provider_t, lk_request_free, lk_request_new, lk_request_send,
    lk_request_send_streaming, lk_request_set_cookie_override, lk_request_set_multipart,
    lk_request_t, lk_response_cookie_count, lk_response_cookie_name_at,
    lk_response_cookie_value_at, lk_response_error_for_status, lk_response_free,
    lk_response_redirect_count, lk_response_redirect_status_at, lk_response_redirect_url_at,
    lk_response_t, lk_response_text, lk_response_was_redirected, lk_rotation_strategy_t,
    lk_session_builder_set_proxy_config, lk_session_clear_cookies,
    lk_session_connection_pool_clear, lk_session_connection_pool_stats, lk_session_free,
    lk_session_get_cookie, lk_session_get_cookies_json, lk_session_new, lk_session_pool_acquire,
    lk_session_pool_acquire_async, lk_session_pool_builder_build, lk_session_pool_builder_free,
    lk_session_pool_builder_new, lk_session_pool_builder_set_idle_timeout,
    lk_session_pool_builder_set_max_sessions, lk_session_pool_builder_set_proxy_buffer,
    lk_session_pool_builder_set_rotation, lk_session_pool_free, lk_session_pool_guard_free,
    lk_session_pool_guard_request_new, lk_session_pool_guard_t, lk_session_pool_mark_bad,
    lk_session_pool_stats, lk_session_pool_t, lk_session_preconnect, lk_session_preconnect_async,
    lk_session_set_cookie, lk_session_t, lk_socks5_udp_probe, lk_socks5_udp_probe_async,
    lk_socks5_udp_probe_config_t, lk_socks5_udp_probe_mode_t, lk_socks5_udp_probe_report_error,
    lk_socks5_udp_probe_report_free, lk_socks5_udp_probe_report_json,
    lk_socks5_udp_probe_report_phase, lk_socks5_udp_probe_report_proxy,
    lk_socks5_udp_probe_report_support, lk_socks5_udp_probe_report_t,
    lk_socks5_udp_probe_support_t, lk_status_t, lk_stream_close, lk_stream_read,
    lk_streaming_response_free, lk_streaming_response_get_diagnostics_json,
    lk_streaming_response_get_header_by_name, lk_streaming_response_t,
};

struct TestServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("server addr");
        listener.set_nonblocking(true).expect("set nonblocking");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        // Accepted Windows sockets may inherit nonblocking mode.
                        stream.set_nonblocking(false).expect("blocking stream");
                        handle_connection(stream);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            if let Err(failure) = thread.join() {
                // Report server assertions, but never panic twice during cleanup.
                if !thread::panicking() {
                    std::panic::resume_unwind(failure);
                }
            }
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let request = read_http_request(&mut stream).expect("request");
    let route = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());

    if let Some(rest) = route.strip_prefix("/redirect/") {
        let n: usize = rest.parse().expect("redirect count");
        let location = if n == 0 {
            "/final".to_string()
        } else {
            format!("/redirect/{}", n - 1)
        };
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .expect("redirect write");
        return;
    }

    match route {
        "/final" => write_response(&mut stream, 200, b"redirected", &[]),
        "/set-cookie" => write_response(
            &mut stream,
            200,
            b"cookies",
            &[
                ("Set-Cookie", "alpha=one; Path=/"),
                ("Set-Cookie", "beta=two; Path=/"),
            ],
        ),
        "/set-cookie-attrs" => write_response(
            &mut stream,
            200,
            b"cookies",
            &[
                (
                    "Set-Cookie",
                    "ttl=live; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
                ),
                ("Set-Cookie", "session=present; Path=/; SameSite=Strict"),
                ("Set-Cookie", "expired=gone; Path=/; Max-Age=0"),
            ],
        ),
        "/status/404" => write_response(&mut stream, 404, b"missing", &[]),
        "/echo-cookie" => {
            let cookie = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_bytes().to_vec())
                .unwrap_or_default();
            write_response(&mut stream, 200, &cookie, &[]);
        }
        "/multipart" => {
            let content_type = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            let mut body = content_type.as_bytes().to_vec();
            body.push(b'\n');
            body.extend_from_slice(&request.body);
            write_response(&mut stream, 200, &body, &[]);
        }
        "/stream" => {
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Transfer-Encoding: chunked\r\n",
                "X-Stream: yes\r\n",
                "Connection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .expect("stream headers");
            stream.write_all(b"5\r\nhello\r\n").expect("stream chunk");
            stream.write_all(b"0\r\n\r\n").expect("stream eof");
        }
        _ => write_response(
            &mut stream,
            200,
            format!("{} {}", request.method, request.path).as_bytes(),
            &[],
        ),
    }
}

fn write_response(stream: &mut TcpStream, status: u16, body: &[u8], headers: &[(&str, &str)]) {
    let reason = if status == 404 { "Not Found" } else { "OK" };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .and_then(|_| stream.write_all(body))
        .expect("write response");
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    let header_end;
    loop {
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed before request",
            ));
        }
        data.extend_from_slice(&buffer[..n]);
        if let Some(idx) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = idx;
            break;
        }
    }

    let header_text = str::from_utf8(&data[..header_end]).expect("header utf8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().expect("method").to_string();
    let path = parts.next().expect("path").to_string();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').expect("header");
        let name = name.trim().to_string();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().expect("content-length");
        }
        headers.push((name, value));
    }

    let mut body = data[(header_end + 4)..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..n]);
    }
    body.truncate(content_length);

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn cstring(value: &str) -> CString {
    CString::new(value).expect("cstring")
}

unsafe fn view_string(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        String::new()
    } else {
        let bytes = slice::from_raw_parts(ptr.cast::<u8>(), len);
        str::from_utf8(bytes).expect("utf8").to_string()
    }
}

unsafe fn view_c_string(ptr: *const c_char) -> String {
    CStr::from_ptr(ptr).to_str().expect("utf8").to_string()
}

unsafe fn error_message(err: *const lk_error_t) -> String {
    let mut ptr = ptr::null();
    let mut len = 0usize;
    assert_eq!(
        lk_error_message(err, &mut ptr, &mut len),
        lk_status_t::LK_OK
    );
    view_string(ptr, len)
}

unsafe fn new_client_and_session() -> (*mut lk_client_t, *mut lk_session_t) {
    let mut client = ptr::null_mut();
    let mut err = ptr::null_mut::<lk_error_t>();
    assert_eq!(
        lk_client_new_default(&mut client, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());

    let mut session = ptr::null_mut();
    assert_eq!(
        lk_session_new(client, &mut session, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    (client, session)
}

struct ProviderContext {
    urls: Vec<CString>,
    next: AtomicUsize,
}

static PROVIDER_DESTROY_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn provider_next_proxy(
    context: *mut c_void,
    out_url_ptr: *mut *const c_char,
    out_url_len: *mut usize,
) -> lk_status_t {
    let ctx = &*(context.cast::<ProviderContext>());
    let index = ctx.next.fetch_add(1, Ordering::Relaxed) % ctx.urls.len();
    let url = &ctx.urls[index];
    *out_url_ptr = url.as_ptr();
    *out_url_len = url.as_bytes().len();
    lk_status_t::LK_OK
}

unsafe extern "C" fn provider_len(context: *mut c_void) -> usize {
    (&*(context.cast::<ProviderContext>())).urls.len()
}

unsafe extern "C" fn provider_destroy(context: *mut c_void) {
    PROVIDER_DESTROY_COUNT.fetch_add(1, Ordering::Relaxed);
    drop(Box::from_raw(context.cast::<ProviderContext>()));
}

fn static_provider() -> lk_proxy_provider_t {
    let ctx = Box::new(ProviderContext {
        urls: vec![
            cstring("http://user:pass@proxy-a.local:8080"),
            cstring("socks5h://proxy-b.local:1080"),
        ],
        next: AtomicUsize::new(0),
    });
    lk_proxy_provider_t {
        context: Box::into_raw(ctx).cast::<c_void>(),
        next_proxy: Some(provider_next_proxy),
        len: Some(provider_len),
        is_dynamic: None,
        destroy: Some(provider_destroy),
    }
}

static LOG_EVENTS: OnceLock<Mutex<Vec<(i32, String, String)>>> = OnceLock::new();
static V2_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

unsafe extern "C" fn log_callback(
    _context: *mut c_void,
    level: i32,
    target: *const c_char,
    message: *const c_char,
) {
    let store = LOG_EVENTS.get_or_init(|| Mutex::new(Vec::new()));
    store
        .lock()
        .unwrap()
        .push((level, view_c_string(target), view_c_string(message)));
}

unsafe fn cookie_attrs_json(session: *const lk_session_t, url: Option<&str>) -> serde_json::Value {
    let mut json_ptr = ptr::null();
    let mut json_len = 0;
    let mut err = ptr::null_mut();
    let status = match url {
        Some(url) => lkrequest_ffi::lk_session_get_cookies_with_attrs_json(
            session,
            url.as_ptr().cast(),
            url.len(),
            &mut json_ptr,
            &mut json_len,
            &mut err,
        ),
        None => lkrequest_ffi::lk_session_get_all_cookies_json(
            session,
            &mut json_ptr,
            &mut json_len,
            &mut err,
        ),
    };
    assert_eq!(status, lk_status_t::LK_OK);
    assert!(err.is_null());
    assert!(!json_ptr.is_null());
    assert_eq!(CStr::from_ptr(json_ptr).to_bytes().len(), json_len);
    serde_json::from_slice(slice::from_raw_parts(json_ptr.cast::<u8>(), json_len))
        .expect("cookie attributes JSON")
}

#[test]
fn cookie_attribute_readers_preserve_scope_order_and_legacy_schema() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        let (client, session) = new_client_and_session();
        assert_eq!(cookie_attrs_json(session, None), serde_json::json!([]));
        for (url, value, path, domain, secure) in [
            ("https://a.example.test/", "root", "/", None, false),
            (
                "https://a.example.test/api",
                "api",
                "/api",
                Some("example.test"),
                true,
            ),
            ("https://b.other.test/", "other", "/", None, false),
        ] {
            let mut err = ptr::null_mut();
            let (domain_ptr, domain_len) = domain
                .map(|domain| (domain.as_ptr().cast(), domain.len()))
                .unwrap_or((ptr::null(), 0));
            assert_eq!(
                lkrequest_ffi::lk_session_set_cookie_with_attrs(
                    session,
                    url.as_ptr().cast(),
                    url.len(),
                    cstring("dup").as_ptr(),
                    3,
                    value.as_ptr().cast(),
                    value.len(),
                    path.as_ptr().cast(),
                    path.len(),
                    domain_ptr,
                    domain_len,
                    secure,
                    true,
                    &mut err,
                ),
                lk_status_t::LK_OK
            );
            assert!(err.is_null());
        }

        let all = cookie_attrs_json(session, None);
        assert_eq!(all.as_array().unwrap().len(), 3);
        assert_eq!(
            all[0],
            serde_json::json!({
                "name": "dup", "value": "root", "domain": "a.example.test",
                "host_only": true, "path": "/", "secure": false, "http_only": true,
                "same_site": null, "expires_unix": null,
            })
        );
        assert_eq!(all[1]["value"], "api");
        assert_eq!(all[1]["path"], "/api");
        assert_eq!(all[1]["domain"], "example.test");
        assert_eq!(all[1]["host_only"], false);
        assert_eq!(all[1]["secure"], true);
        assert_eq!(all[2]["value"], "other");

        let url = "https://a.example.test/api/users";
        let mut legacy_ptr = ptr::null();
        assert_eq!(
            lk_session_get_cookies_json(session, url.as_ptr().cast(), url.len(), &mut legacy_ptr),
            lk_status_t::LK_OK
        );
        let legacy_copy = view_c_string(legacy_ptr);
        let filtered = cookie_attrs_json(session, Some(url));
        assert_eq!(filtered, serde_json::json!([all[1], all[0]]));
        assert_eq!(view_c_string(legacy_ptr), legacy_copy);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&legacy_copy).unwrap(),
            serde_json::json!([
                {"name": "dup", "value": "api"}, {"name": "dup", "value": "root"},
            ])
        );
        assert_eq!(
            cookie_attrs_json(session, Some("http://a.example.test/api/users")),
            serde_json::json!([all[0]])
        );
        assert_eq!(
            cookie_attrs_json(session, Some("https://sub.a.example.test/api")),
            serde_json::json!([all[1]])
        );
        assert_eq!(
            cookie_attrs_json(session, Some("https://a.example.test/apix")),
            serde_json::json!([all[0]])
        );
        assert_eq!(
            cookie_attrs_json(session, Some("https://unrelated.test/")),
            serde_json::json!([])
        );
        assert_eq!(
            cookie_attrs_json(session, Some("not-a-url")),
            serde_json::json!([])
        );

        assert_eq!(
            lk_session_set_cookie(
                session,
                url.as_ptr().cast(),
                url.len(),
                cstring("new").as_ptr(),
                3,
                cstring("value").as_ptr(),
                5
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            cookie_attrs_json(session, None).as_array().unwrap().len(),
            4
        );
        assert_eq!(lk_session_clear_cookies(session), lk_status_t::LK_OK);
        assert_eq!(cookie_attrs_json(session, None), serde_json::json!([]));
        assert_eq!(cookie_attrs_json(session, Some(url)), serde_json::json!([]));
        lk_session_free(session);
        lk_client_free(client);
    }
}

#[test]
fn cookie_attribute_readers_include_response_expiry_and_same_site() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let server = TestServer::start();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    unsafe {
        let (client, session) = new_client_and_session();
        let url = server.url("/set-cookie-attrs");
        let mut request = ptr::null_mut();
        let mut response = ptr::null_mut();
        let mut err = ptr::null_mut();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url.as_ptr().cast(),
                url.len(),
                &mut request,
                &mut err
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_send(request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_response_free(response);
        lk_request_free(request);

        let all = cookie_attrs_json(session, None);
        let filtered = cookie_attrs_json(session, Some(&url));
        assert_eq!(filtered, all);
        assert_eq!(all.as_array().unwrap().len(), 2);
        let ttl = all
            .as_array()
            .unwrap()
            .iter()
            .find(|cookie| cookie["name"] == "ttl")
            .unwrap();
        assert_eq!(ttl["same_site"], "Lax");
        assert_eq!(ttl["http_only"], true);
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((before + 3600..=after + 3600).contains(&ttl["expires_unix"].as_i64().unwrap()));
        let transient = all
            .as_array()
            .unwrap()
            .iter()
            .find(|cookie| cookie["name"] == "session")
            .unwrap();
        assert_eq!(transient["same_site"], "Strict");
        assert!(transient["expires_unix"].is_null());
        lk_session_free(session);
        lk_client_free(client);
    }
}

fn response_and_session_extensions_work() -> usize {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();

        let url = server.url("/set-cookie");
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring(&url).as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request);

        let mut text_ptr = ptr::null();
        let mut text_len = 0usize;
        assert_eq!(
            lk_response_text(response, &mut text_ptr, &mut text_len, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "cookies");
        assert_eq!(lk_response_cookie_count(response), 2);
        assert_eq!(
            lk_response_cookie_name_at(response, 0, &mut text_ptr, &mut text_len),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "alpha");
        assert_eq!(
            lk_response_cookie_value_at(response, 1, &mut text_ptr, &mut text_len),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "two");
        lk_response_free(response);

        let redirect_url = server.url("/redirect/2");
        let mut redirect_request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring(&redirect_url).as_ptr(),
                redirect_url.len(),
                &mut redirect_request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_send(redirect_request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(redirect_request);
        assert!(lk_response_was_redirected(response));
        assert_eq!(lk_response_redirect_count(response), 3);
        assert_eq!(
            lk_response_redirect_url_at(response, 0, &mut text_ptr, &mut text_len),
            lk_status_t::LK_OK
        );
        assert!(view_string(text_ptr, text_len).contains("/redirect/2"));
        assert_eq!(lk_response_redirect_status_at(response, 2), 302);
        lk_response_free(response);

        let not_found_url = server.url("/status/404");
        let mut missing_request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring(&not_found_url).as_ptr(),
                not_found_url.len(),
                &mut missing_request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_send(missing_request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_response_error_for_status(response, &mut err),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_STATUS
        );
        lk_error_free(err);
        lk_request_free(missing_request);
        lk_response_free(response);

        let base_url = server.url("/");
        assert_eq!(
            lk_session_set_cookie(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                cstring("jar").as_ptr(),
                3,
                cstring("cookie").as_ptr(),
                6,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_set_cookie(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                cstring("jar2").as_ptr(),
                4,
                cstring("bridge").as_ptr(),
                6,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_get_cookie(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                cstring("jar").as_ptr(),
                3,
                &mut text_ptr,
                &mut text_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "cookie");
        let first_cookie_ptr = text_ptr;
        let first_cookie_len = text_len;
        assert_eq!(
            lk_session_get_cookie(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                cstring("jar2").as_ptr(),
                4,
                &mut text_ptr,
                &mut text_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "bridge");
        assert_eq!(view_string(first_cookie_ptr, first_cookie_len), "cookie");

        let mut json_ptr = ptr::null();
        assert_eq!(
            lk_session_get_cookies_json(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                &mut json_ptr,
            ),
            lk_status_t::LK_OK
        );
        let cookies_json: serde_json::Value =
            serde_json::from_str(&view_c_string(json_ptr)).expect("cookie json");
        assert!(cookies_json
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["name"] == "jar" && entry["value"] == "cookie" }));
        assert!(cookies_json
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["name"] == "jar2" && entry["value"] == "bridge" }));

        let echo_cookie_url = server.url("/echo-cookie");
        let mut cookie_request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring(&echo_cookie_url).as_ptr(),
                echo_cookie_url.len(),
                &mut cookie_request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_cookie_override(
                cookie_request,
                cstring("jar").as_ptr(),
                3,
                cstring("override").as_ptr(),
                8,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_send(cookie_request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(cookie_request);
        assert_eq!(
            lk_response_text(response, &mut text_ptr, &mut text_len, &mut err),
            lk_status_t::LK_OK
        );
        let cookie_header = view_string(text_ptr, text_len);
        assert!(cookie_header.contains("jar=override"));
        assert!(!cookie_header.contains("jar=cookie"));
        lk_response_free(response);

        let multipart = lk_multipart_new();
        assert_eq!(
            lk_multipart_add_text(
                multipart,
                cstring("field").as_ptr(),
                5,
                cstring("value").as_ptr(),
                5,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_multipart_add_file(
                multipart,
                cstring("upload").as_ptr(),
                6,
                cstring("a.txt").as_ptr(),
                5,
                cstring("text/plain").as_ptr(),
                10,
                b"hello".as_ptr(),
                5,
            ),
            lk_status_t::LK_OK
        );

        let multipart_url = server.url("/multipart");
        let mut multipart_request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("POST").as_ptr(),
                4,
                cstring(&multipart_url).as_ptr(),
                multipart_url.len(),
                &mut multipart_request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_multipart(multipart_request, multipart),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_send(multipart_request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(multipart_request);
        assert_eq!(
            lk_response_text(response, &mut text_ptr, &mut text_len, &mut err),
            lk_status_t::LK_OK
        );
        let multipart_body = view_string(text_ptr, text_len);
        assert!(multipart_body.contains("multipart/form-data; boundary="));
        assert!(multipart_body.contains("name=\"field\""));
        assert!(multipart_body.contains("filename=\"a.txt\""));
        lk_response_free(response);

        let mut out_h2 = 0usize;
        let mut out_h1 = 0usize;
        let mut out_total = 0usize;
        let mut out_max = 0usize;
        let mut out_at_capacity = false;
        assert_eq!(
            lk_session_preconnect(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_connection_pool_stats(
                session,
                &mut out_h2,
                &mut out_h1,
                &mut out_total,
                &mut out_max,
                &mut out_at_capacity,
            ),
            lk_status_t::LK_OK
        );
        assert!(out_total >= 1);
        assert_eq!(
            lk_session_connection_pool_clear(session),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_connection_pool_stats(
                session,
                &mut out_h2,
                &mut out_h1,
                &mut out_total,
                &mut out_max,
                &mut out_at_capacity,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(out_total, 0);

        let mut preconnect_op = ptr::null_mut();
        assert_eq!(
            lk_session_preconnect_async(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                &mut preconnect_op,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_op_wait(preconnect_op, 0),
            lk_op_state_t::LK_OP_COMPLETED_OK
        );
        lk_op_free(preconnect_op);

        assert_eq!(lk_session_clear_cookies(session), lk_status_t::LK_OK);
        assert_eq!(
            lk_session_get_cookie(
                session,
                cstring(&base_url).as_ptr(),
                base_url.len(),
                cstring("jar").as_ptr(),
                3,
                &mut text_ptr,
                &mut text_len,
                &mut err,
            ),
            lk_status_t::LK_ERR
        );
        assert!(error_message(err).contains("cookie not found"));
        lk_error_free(err);

        lk_session_free(session);
        lk_client_free(client);
    }

    6
}

fn proxy_and_session_pool_extensions_work() -> usize {
    let server = TestServer::start();

    unsafe {
        PROVIDER_DESTROY_COUNT.store(0, Ordering::Relaxed);

        let proxy_builder = lk_proxy_pool_builder_new();
        assert_eq!(
            lk_proxy_pool_builder_add_proxy(
                proxy_builder,
                cstring("http://127.0.0.1:8080").as_ptr(),
                "http://127.0.0.1:8080".len(),
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_proxy_pool_builder_set_rotation(
                proxy_builder,
                lk_rotation_strategy_t::LK_ROTATION_RANDOM,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_proxy_pool_builder_set_proxy_buffer(proxy_builder, 2),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_proxy_pool_builder_set_provider(proxy_builder, static_provider()),
            lk_status_t::LK_OK
        );

        let mut proxy_pool = ptr::null_mut::<lk_proxy_pool_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_proxy_pool_builder_build(proxy_builder, &mut proxy_pool, &mut err),
            lk_status_t::LK_OK
        );
        lk_proxy_pool_builder_free(proxy_builder);

        let mut proxy_guard = ptr::null_mut::<lk_proxy_guard_t>();
        assert_eq!(
            lk_proxy_pool_acquire(proxy_pool, &mut proxy_guard, &mut err),
            lk_status_t::LK_OK
        );
        let mut ptr_out = ptr::null();
        let mut len_out = 0usize;
        assert_eq!(
            lk_proxy_guard_url(proxy_guard, &mut ptr_out, &mut len_out),
            lk_status_t::LK_OK
        );
        let first_url = view_string(ptr_out, len_out);
        assert!(
            first_url == "http://user:pass@proxy-a.local:8080"
                || first_url == "socks5h://proxy-b.local:1080"
        );
        assert_eq!(lk_proxy_guard_mark_bad(proxy_guard), lk_status_t::LK_OK);
        assert_eq!(
            lk_proxy_pool_mark_bad(
                proxy_pool,
                cstring("user@proxy-a.local:8080").as_ptr(),
                "user@proxy-a.local:8080".len(),
            ),
            lk_status_t::LK_OK
        );
        lk_proxy_guard_free(proxy_guard);

        let mut proxy_op = ptr::null_mut();
        assert_eq!(
            lk_proxy_pool_acquire_async(proxy_pool, &mut proxy_op, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(lk_op_wait(proxy_op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);
        assert_eq!(
            lk_op_take_proxy_guard(proxy_op, &mut proxy_guard, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_proxy_guard_url(proxy_guard, &mut ptr_out, &mut len_out),
            lk_status_t::LK_OK
        );
        let second_url = view_string(ptr_out, len_out);
        assert!(
            second_url == "http://user:pass@proxy-a.local:8080"
                || second_url == "socks5h://proxy-b.local:1080"
        );
        lk_proxy_guard_free(proxy_guard);
        lk_op_free(proxy_op);
        lk_proxy_pool_free(proxy_pool);

        let provider_builder = lk_proxy_pool_builder_new();
        assert_eq!(
            lk_proxy_pool_builder_set_provider(provider_builder, static_provider()),
            lk_status_t::LK_OK
        );
        lk_proxy_pool_builder_free(provider_builder);
        assert_eq!(PROVIDER_DESTROY_COUNT.load(Ordering::Relaxed), 1);

        let builder = lk_client_builder_new();
        assert_eq!(
            lk_client_builder_set_dns(builder, lk_dns_config_t::LK_DNS_CLOUDFLARE),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_client_builder_set_dns_custom(
                builder,
                cstring("1.1.1.1:53").as_ptr(),
                "1.1.1.1:53".len(),
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_client_builder_set_use_native_certs(builder, false),
            lk_status_t::LK_OK
        );
        let mut client = ptr::null_mut::<lk_client_t>();
        assert_eq!(
            lk_client_builder_build(builder, &mut client, &mut err),
            lk_status_t::LK_OK
        );
        lk_client_builder_free(builder);

        let session_pool_builder = lk_session_pool_builder_new(client);
        assert_eq!(
            lk_session_pool_builder_set_max_sessions(session_pool_builder, 2),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_pool_builder_set_idle_timeout(session_pool_builder, 100),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_pool_builder_set_rotation(
                session_pool_builder,
                lk_rotation_strategy_t::LK_ROTATION_ROUND_ROBIN,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_pool_builder_set_proxy_buffer(session_pool_builder, 1),
            lk_status_t::LK_OK
        );
        let mut session_pool = ptr::null_mut::<lk_session_pool_t>();
        assert_eq!(
            lk_session_pool_builder_build(session_pool_builder, &mut session_pool, &mut err),
            lk_status_t::LK_OK
        );
        lk_session_pool_builder_free(session_pool_builder);

        let mut session_guard = ptr::null_mut::<lk_session_pool_guard_t>();
        assert_eq!(
            lk_session_pool_acquire(session_pool, &mut session_guard, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_pool_mark_bad(session_pool, session_guard),
            lk_status_t::LK_OK
        );

        let mut request = ptr::null_mut::<lk_request_t>();
        let request_url = server.url("/final");
        assert_eq!(
            lk_session_pool_guard_request_new(
                session_guard,
                cstring("GET").as_ptr(),
                3,
                cstring(&request_url).as_ptr(),
                request_url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        lk_session_pool_guard_free(session_guard);

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request);
        let mut text_ptr = ptr::null();
        let mut text_len = 0usize;
        assert_eq!(
            lk_response_text(response, &mut text_ptr, &mut text_len, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "redirected");
        lk_response_free(response);

        thread::sleep(Duration::from_millis(50));
        let mut idle = 0usize;
        let mut max = 0usize;
        assert_eq!(
            lk_session_pool_stats(session_pool, &mut idle, &mut max),
            lk_status_t::LK_OK
        );
        assert_eq!(
            idle, 0,
            "a marked-bad session must not return to the idle pool"
        );
        assert_eq!(max, 2);

        let mut pool_op = ptr::null_mut();
        assert_eq!(
            lk_session_pool_acquire_async(session_pool, &mut pool_op, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(lk_op_wait(pool_op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);
        assert_eq!(
            lk_op_take_session_pool_guard(pool_op, &mut session_guard, &mut err),
            lk_status_t::LK_OK
        );
        lk_op_free(pool_op);
        lk_session_pool_guard_free(session_guard);
        assert_eq!(
            lk_session_pool_stats(session_pool, &mut idle, &mut max),
            lk_status_t::LK_OK
        );
        assert_eq!(idle, 1, "a healthy replacement remains reusable");
        lk_session_pool_free(session_pool);
        lk_client_free(client);
    }

    4
}

fn streaming_and_logging_callback_extensions_work() -> usize {
    let server = TestServer::start();

    unsafe {
        LOG_EVENTS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .clear();
        assert_eq!(
            lk_log_init_callback(Some(log_callback), ptr::null_mut(), 0),
            lk_status_t::LK_OK
        );
        tracing::info!(target: "ffi.test", "callback works");

        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();
        let url = server.url("/stream");
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring(&url).as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );

        let mut stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(request, &mut stream, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request);

        let mut header_ptr = ptr::null();
        let mut header_len = 0usize;
        assert_eq!(
            lk_streaming_response_get_header_by_name(
                stream,
                cstring("x-stream").as_ptr(),
                "x-stream".len(),
                &mut header_ptr,
                &mut header_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            str::from_utf8(slice::from_raw_parts(header_ptr, header_len)).unwrap(),
            "yes"
        );

        let mut diag_ptr = ptr::null();
        assert_eq!(
            lk_streaming_response_get_diagnostics_json(stream, &mut diag_ptr),
            lk_status_t::LK_OK
        );
        let diagnostics: serde_json::Value =
            serde_json::from_str(&view_c_string(diag_ptr)).expect("diagnostics json");
        assert_eq!(diagnostics["schema_version"], 1);

        let mut chunk = lkrequest_ffi::lk_chunk_view_t::default();
        assert_eq!(
            lk_stream_read(stream, &mut chunk, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(
            str::from_utf8(slice::from_raw_parts(chunk.data, chunk.len)).unwrap(),
            "hello"
        );
        assert_eq!(lk_stream_close(stream), lk_status_t::LK_OK);
        lk_streaming_response_free(stream);

        let events = LOG_EVENTS.get().unwrap().lock().unwrap().clone();
        assert!(events.iter().any(|(_, target, message)| {
            target == "ffi.test" && message.contains("callback works")
        }));

        lk_session_free(session);
        lk_client_free(client);
    }

    4
}

fn socks5_udp_probe_ffi_extensions_work() -> usize {
    unsafe {
        let proxy = cstring("http://127.0.0.1:8080");
        let dns_server = cstring("1.1.1.1:53");
        let dns_query = cstring("example.com");
        let config = lk_socks5_udp_probe_config_t {
            mode: lk_socks5_udp_probe_mode_t::LK_SOCKS5_UDP_PROBE_ASSOCIATE_ONLY,
            timeout_ms: 100,
            dns_server_addr_ptr: dns_server.as_ptr(),
            dns_server_addr_len: "1.1.1.1:53".len(),
            dns_server_host_ptr: ptr::null(),
            dns_server_host_len: 0,
            dns_query_ptr: dns_query.as_ptr(),
            dns_query_len: "example.com".len(),
        };

        let mut err = ptr::null_mut::<lk_error_t>();
        let mut report = ptr::null_mut::<lk_socks5_udp_probe_report_t>();
        assert_eq!(
            lk_socks5_udp_probe(
                ptr::null(),
                proxy.as_ptr(),
                "http://127.0.0.1:8080".len(),
                &config,
                &mut report,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_socks5_udp_probe_report_support(report),
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_NOT_SOCKS5
        );
        let _phase = lk_socks5_udp_probe_report_phase(report);

        let mut out_ptr = ptr::null();
        let mut out_len = 0usize;
        assert_eq!(
            lk_socks5_udp_probe_report_proxy(report, &mut out_ptr, &mut out_len),
            lk_status_t::LK_OK
        );
        assert_eq!(
            str::from_utf8(slice::from_raw_parts(out_ptr.cast::<u8>(), out_len)).unwrap(),
            r#"[["http","127.0.0.1",8080,null]]"#
        );

        assert_eq!(
            lk_socks5_udp_probe_report_error(report, &mut out_ptr, &mut out_len),
            lk_status_t::LK_OK
        );
        assert!(
            str::from_utf8(slice::from_raw_parts(out_ptr.cast::<u8>(), out_len))
                .unwrap()
                .contains("not SOCKS5")
        );

        assert_eq!(
            lk_socks5_udp_probe_report_json(report, &mut out_ptr, &mut out_len),
            lk_status_t::LK_OK
        );
        let json: serde_json::Value =
            serde_json::from_slice(slice::from_raw_parts(out_ptr.cast::<u8>(), out_len))
                .expect("probe report json");
        assert_eq!(json["support"], "NotSocks5");
        lk_socks5_udp_probe_report_free(report);

        let mut op = ptr::null_mut();
        assert_eq!(
            lk_socks5_udp_probe_async(
                ptr::null(),
                proxy.as_ptr(),
                "http://127.0.0.1:8080".len(),
                &config,
                &mut op,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(lk_op_wait(op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);
        assert_eq!(
            lk_op_take_socks5_udp_probe_report(op, &mut report, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_socks5_udp_probe_report_support(report),
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_NOT_SOCKS5
        );
        lk_socks5_udp_probe_report_free(report);
        lk_op_free(op);
    }

    2
}

fn browser_preset_ffi_extensions_work(
    preset_name: &str,
    tls_profile_name: &str,
    expect_trust_anchor_ids: bool,
    expected_h2_window_update: u64,
) -> usize {
    unsafe {
        let mut list_ptr = ptr::null();
        assert_eq!(lk_preset_list_json(&mut list_ptr), lk_status_t::LK_OK);
        let preset_list: serde_json::Value =
            serde_json::from_str(&view_c_string(list_ptr)).expect("preset list json");
        assert!(preset_list
            .as_array()
            .expect("preset list")
            .iter()
            .any(|value| value == preset_name));

        let name = cstring(preset_name);
        let mut detail_ptr = ptr::null();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_preset_get_detail_json(name.as_ptr(), preset_name.len(), &mut detail_ptr, &mut err,),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        let detail: serde_json::Value =
            serde_json::from_str(&view_c_string(detail_ptr)).expect("preset detail json");
        assert_eq!(detail["name"], preset_name);
        assert_eq!(detail["tls_profile"]["name"], tls_profile_name);
        let has_trust_anchor_ids = detail["tls_profile"]["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|extension| extension["extension_type"] == 0xca34);
        assert_eq!(has_trust_anchor_ids, expect_trust_anchor_ids);
        assert_eq!(
            detail["h2_profile"]["window_update"],
            expected_h2_window_update
        );
        assert_eq!(
            detail["h2_profile"]["initial_stream_id"],
            if preset_name == "firefox_156" { 3 } else { 1 },
            "FFI preset details preserve the browser's initial H2 stream ID"
        );
        assert_eq!(
            detail["h2_profile"]["settings"].as_array().unwrap().len(),
            4
        );

        let mut client = ptr::null_mut::<lk_client_t>();
        assert_eq!(
            lk_client_new(name.as_ptr(), &mut client, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        assert!(!client.is_null());
        lk_client_free(client);
    }

    3
}

#[test]
fn response_and_session_extensions_cover_cookies_redirects_multipart_and_preconnect() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(response_and_session_extensions_work(), 6);
}

#[test]
fn proxy_and_session_pool_ffi_apis_cover_builders_guards_and_async_ops() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(proxy_and_session_pool_extensions_work(), 4);
}

#[test]
fn streaming_logging_callback_and_dns_builder_extensions_work() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(streaming_and_logging_callback_extensions_work(), 4);
}

#[test]
fn socks5_udp_probe_ffi_apis_return_structured_reports() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(socks5_udp_probe_ffi_extensions_work(), 2);
}

#[test]
fn chrome_153_preset_is_exposed_through_ffi() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(
        browser_preset_ffi_extensions_work("chrome_153", "Chrome 153", true, 15_663_105),
        3
    );
}

#[test]
fn chrome_154_preset_is_exposed_through_ffi() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(
        browser_preset_ffi_extensions_work("chrome_154", "Chrome 154", true, 15_663_105),
        3
    );
}

#[test]
fn firefox_156_preset_is_exposed_through_ffi() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(
        browser_preset_ffi_extensions_work("firefox_156", "Firefox 156", false, 12_517_377),
        3
    );
}

#[test]
fn chrome_155_preset_is_exposed_through_ffi() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(
        browser_preset_ffi_extensions_work("chrome_155", "Chrome 155", true, 15_663_105),
        3
    );
}

#[test]
fn default_clients_use_chrome_155_and_explicit_144_remains_available() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        let mut clients = Vec::new();
        let mut client = ptr::null_mut();
        let mut err = ptr::null_mut();
        assert_eq!(
            lk_client_new_default(&mut client, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        clients.push((client, lkrequest::preset::chrome_155()));

        let builder = lk_client_builder_new();
        assert!(!builder.is_null());
        assert_eq!(
            lk_client_builder_build(builder, &mut client, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_client_builder_free(builder);
        clients.push((client, lkrequest::preset::chrome_155()));

        for (name, expected) in [
            ("default", lkrequest::preset::chrome_155()),
            ("chrome_144", lkrequest::preset::chrome_144()),
        ] {
            let name = cstring(name);
            assert_eq!(
                lk_client_new(name.as_ptr(), &mut client, &mut err),
                lk_status_t::LK_OK
            );
            assert!(err.is_null());
            clients.push((client, expected));
        }

        for (client, expected) in clients {
            let mut json_ptr = ptr::null();
            let mut json_len = 0;
            assert_eq!(
                lkrequest_ffi::lk_client_fingerprint_info_json(
                    client,
                    &mut json_ptr,
                    &mut json_len,
                    &mut err,
                ),
                lk_status_t::LK_OK
            );
            assert!(err.is_null());
            let actual: serde_json::Value =
                serde_json::from_slice(slice::from_raw_parts(json_ptr.cast::<u8>(), json_len))
                    .expect("client fingerprint JSON");
            assert_eq!(
                actual["tls"],
                serde_json::to_value(expected.tls_profile).unwrap()
            );
            assert_eq!(
                actual["h2"],
                serde_json::to_value(expected.h2_profile).unwrap()
            );
            assert_eq!(
                actual["quic"],
                serde_json::to_value(expected.quic_profile).unwrap()
            );
            lk_client_free(client);
        }
    }
}

#[test]
fn chrome_152_preset_is_exposed_through_ffi() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(
        browser_preset_ffi_extensions_work("chrome_152", "Chrome 152", true, 15_663_105),
        3
    );
}

#[test]
fn chrome_151_preset_remains_exposed_through_ffi() {
    let _guard = V2_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    assert_eq!(
        browser_preset_ffi_extensions_work("chrome_151", "Chrome 151", false, 15_663_105),
        3
    );
}

#[test]
fn metrics_snapshot_ffi_is_callable_and_rejects_null() {
    // Always present in the ABI; without the `telemetry` build feature it
    // reports zero counters but must still succeed.
    let mut snapshot = lkrequest_ffi::lk_metrics_snapshot_t::default();
    let status = lkrequest_ffi::lk_metrics_snapshot(&mut snapshot);
    assert_eq!(status as i32, lkrequest_ffi::lk_status_t::LK_OK as i32);

    // A null out-pointer is rejected rather than dereferenced.
    let null_status = lkrequest_ffi::lk_metrics_snapshot(ptr::null_mut());
    assert_ne!(null_status as i32, lkrequest_ffi::lk_status_t::LK_OK as i32);
}

// -- Proxy configuration handles (MASQUE + non-Basic credentials) ------------

unsafe fn parse_proxy_config(url: &str) -> *mut lk_proxy_config_t {
    let owned = cstring(url);
    let mut config = ptr::null_mut::<lk_proxy_config_t>();
    assert_eq!(
        lk_proxy_config_parse(owned.as_ptr(), url.len(), &mut config),
        lk_status_t::LK_OK,
        "parsing {url}"
    );
    assert!(!config.is_null());
    config
}

unsafe fn proxy_config_url(config: *const lk_proxy_config_t) -> String {
    let mut ptr_out = ptr::null();
    let mut len_out = 0usize;
    assert_eq!(
        lk_proxy_config_url(config, &mut ptr_out, &mut len_out),
        lk_status_t::LK_OK
    );
    view_string(ptr_out, len_out)
}

unsafe fn proxy_config_identity(config: *const lk_proxy_config_t) -> String {
    let mut ptr_out = ptr::null();
    let mut len_out = 0usize;
    assert_eq!(
        lk_proxy_config_identity(config, &mut ptr_out, &mut len_out),
        lk_status_t::LK_OK
    );
    view_string(ptr_out, len_out)
}

unsafe fn set_http_auth(
    config: *mut lk_proxy_config_t,
    scheme: &str,
    credentials: &str,
) -> lk_status_t {
    let scheme_c = cstring(scheme);
    let credentials_c = cstring(credentials);
    lk_proxy_config_set_http_auth(
        config,
        scheme_c.as_ptr(),
        scheme.len(),
        credentials_c.as_ptr(),
        credentials.len(),
    )
}

/// The scheme this exercise is built on.
///
/// MASQUE is why header credentials exist on this handle at all, so it is the
/// scheme to test them with wherever it exists. `ProxyScheme::Masque` is gated
/// behind the `masque` feature, though, and without it `masque://` no longer
/// parses — the handle surface itself is scheme independent, so the same
/// exercise then runs over an HTTP CONNECT proxy instead of being skipped.
#[cfg(feature = "masque")]
const HANDLE_SCHEME: &str = "masque";
#[cfg(feature = "masque")]
const HANDLE_DEFAULT_PORT: u16 = 443;
#[cfg(not(feature = "masque"))]
const HANDLE_SCHEME: &str = "http";
#[cfg(not(feature = "masque"))]
const HANDLE_DEFAULT_PORT: u16 = 80;

/// Without the `masque` feature the scheme is refused where it is configured,
/// so a caller learns the build cannot do MASQUE before any request depends on
/// it.
#[test]
#[cfg(not(feature = "masque"))]
fn proxy_config_parse_rejects_masque_without_the_feature() {
    let url = "masque://proxy.example.com:443";
    let owned = cstring(url);
    let mut config = ptr::null_mut::<lk_proxy_config_t>();
    assert_ne!(
        lk_proxy_config_parse(owned.as_ptr(), url.len(), &mut config),
        lk_status_t::LK_OK
    );
    assert!(config.is_null());
}

/// The MASQUE outer-connection surface without the `masque` feature.
///
/// The `lk_masque_config_*` symbols exist in every build, so the generated
/// header and the ABI do not change shape with a Cargo feature — a C caller
/// links the same library either way. What changes is the answer: no handle can
/// be created, so a caller learns the build cannot do MASQUE at the first call
/// rather than after wiring up a configuration that would be silently ignored.
///
/// The surface's real behaviour lives in `masque_config_ffi.rs`, which needs
/// the feature.
#[test]
#[cfg(not(feature = "masque"))]
fn masque_config_entry_points_report_the_missing_feature() {
    let mut config = ptr::null_mut::<lkrequest_ffi::lk_masque_config_t>();
    assert_eq!(
        lkrequest_ffi::lk_masque_config_new(&mut config),
        lk_status_t::LK_ERR
    );
    assert!(config.is_null(), "no handle may be produced");

    // The consumers refuse too, so `masque` cannot be half-configured.
    let builder = lk_client_builder_new();
    assert_ne!(
        lkrequest_ffi::lk_client_builder_set_masque_config(builder, ptr::null()),
        lk_status_t::LK_OK
    );
    lk_client_builder_free(builder);

    let pool_builder = lk_proxy_pool_builder_new();
    assert_ne!(
        lkrequest_ffi::lk_proxy_pool_builder_set_masque_tunnel_probe(pool_builder, ptr::null()),
        lk_status_t::LK_OK
    );
    lkrequest_ffi::lk_proxy_pool_builder_free(pool_builder);

    // And freeing the null handle the failed create left behind is a no-op.
    lkrequest_ffi::lk_masque_config_free(config);
}

/// With the feature on, the same handle is creatable — the counterpart of the
/// test above, so the two together say the gate is the feature and nothing
/// else. Everything the handle *does* is covered in `masque_config_ffi.rs`.
#[test]
#[cfg(feature = "masque")]
fn masque_config_handles_are_available_with_the_feature() {
    let mut config = ptr::null_mut::<lkrequest_ffi::lk_masque_config_t>();
    assert_eq!(
        lkrequest_ffi::lk_masque_config_new(&mut config),
        lk_status_t::LK_OK
    );
    assert!(!config.is_null());
    lkrequest_ffi::lk_masque_config_free(config);
}

#[test]
fn proxy_config_handles_round_trip_masque_urls_and_header_credentials() {
    unsafe {
        // The URL parses, fills in the default port, and echoes back.
        let masque = parse_proxy_config(&format!("{HANDLE_SCHEME}://proxy.example.com"));
        assert_eq!(
            proxy_config_url(masque),
            format!("{HANDLE_SCHEME}://proxy.example.com:{HANDLE_DEFAULT_PORT}")
        );
        lk_proxy_config_free(masque);

        let masque = parse_proxy_config(&format!(
            "{HANDLE_SCHEME}://user:pass@proxy.example.com:10001"
        ));
        assert_eq!(
            proxy_config_url(masque),
            format!("{HANDLE_SCHEME}://user:pass@proxy.example.com:10001")
        );

        // Username/password can also be set through the handle.
        let user = cstring("other");
        let password = cstring("secret");
        assert_eq!(
            lk_proxy_config_set_user_pass(
                masque,
                user.as_ptr(),
                "other".len(),
                password.as_ptr(),
                "secret".len(),
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            proxy_config_url(masque),
            format!("{HANDLE_SCHEME}://other:secret@proxy.example.com:10001")
        );

        // A header credential has no URL form, so the echoed URL is anonymous,
        // but the identity still distinguishes it.
        let anonymous_identity = {
            let plain = parse_proxy_config(&format!("{HANDLE_SCHEME}://proxy.example.com:10001"));
            let identity = proxy_config_identity(plain);
            lk_proxy_config_free(plain);
            identity
        };
        assert_eq!(
            set_http_auth(masque, "Preshared", "psk-a"),
            lk_status_t::LK_OK
        );
        assert_eq!(
            proxy_config_url(masque),
            format!("{HANDLE_SCHEME}://proxy.example.com:10001")
        );
        let psk_a_identity = proxy_config_identity(masque);
        assert_ne!(psk_a_identity, anonymous_identity);
        assert!(!psk_a_identity.contains("psk-a"), "{psk_a_identity}");

        // Same address, different credentials → different cooldown key.
        assert_eq!(
            set_http_auth(masque, "Preshared", "psk-b"),
            lk_status_t::LK_OK
        );
        assert_ne!(proxy_config_identity(masque), psk_a_identity);

        // The authorization header is selectable.
        assert_eq!(
            lk_proxy_config_set_auth_header(
                masque,
                lk_proxy_auth_header_t::LK_PROXY_AUTH_HEADER_AUTHORIZATION,
            ),
            lk_status_t::LK_OK
        );

        // A header credential on SOCKS5 is refused, not silently ignored.
        let socks = parse_proxy_config("socks5://proxy.example.com:1080");
        assert_ne!(set_http_auth(socks, "Preshared", "psk"), lk_status_t::LK_OK);
        lk_proxy_config_free(socks);

        // The handle can be handed to a Session builder and a ProxyPool builder.
        let (client, session) = new_client_and_session();
        let session_builder = lkrequest_ffi::lk_session_builder_new(client);
        assert!(!session_builder.is_null());
        assert_eq!(
            lk_session_builder_set_proxy_config(session_builder, masque),
            lk_status_t::LK_OK
        );
        let mut built = ptr::null_mut();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lkrequest_ffi::lk_session_builder_build(session_builder, &mut built, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lkrequest_ffi::lk_session_builder_free(session_builder);
        lk_session_free(built);
        lk_session_free(session);
        lk_client_free(client);

        let pool_builder = lk_proxy_pool_builder_new();
        assert_eq!(
            lk_proxy_pool_builder_add_proxy_config(pool_builder, masque),
            lk_status_t::LK_OK
        );
        lkrequest_ffi::lk_proxy_pool_builder_free(pool_builder);

        // Null handles are rejected rather than dereferenced.
        assert_ne!(
            lk_proxy_config_url(ptr::null(), ptr::null_mut(), ptr::null_mut()),
            lk_status_t::LK_OK
        );
        assert_ne!(
            set_http_auth(ptr::null_mut(), "Preshared", "psk"),
            lk_status_t::LK_OK
        );
        let bogus = cstring("ftp://proxy.example.com:21");
        let mut out = ptr::null_mut::<lk_proxy_config_t>();
        assert_ne!(
            lk_proxy_config_parse(bogus.as_ptr(), "ftp://proxy.example.com:21".len(), &mut out),
            lk_status_t::LK_OK
        );
        assert!(out.is_null());

        lk_proxy_config_free(masque);
    }
}
