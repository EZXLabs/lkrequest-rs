//! Attempt configuration and observation through the public C API only.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lkrequest_ffi::*;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(5);
const SENTINEL: u8 = 0xa5;

struct Handle<T> {
    ptr: *mut T,
    free: extern "C" fn(*mut T),
}

impl<T> Handle<T> {
    fn new(ptr: *mut T, free: extern "C" fn(*mut T)) -> Self {
        assert!(!ptr.is_null());
        Self { ptr, free }
    }
}

impl<T> Drop for Handle<T> {
    fn drop(&mut self) {
        (self.free)(self.ptr);
    }
}

fn error_text(error: *const lk_error_t) -> String {
    if error.is_null() {
        return "no error handle".into();
    }
    let mut data = ptr::null();
    let mut len = 0;
    assert_eq!(
        lk_error_message(error, &mut data, &mut len),
        lk_status_t::LK_OK
    );
    String::from_utf8_lossy(unsafe { slice::from_raw_parts(data.cast::<u8>(), len) }).into_owned()
}

fn ok(call: impl FnOnce(*mut *mut lk_error_t) -> lk_status_t) {
    let mut error = ptr::null_mut();
    let status = call(&mut error);
    let message = error_text(error);
    lk_error_free(error);
    assert_eq!(status, lk_status_t::LK_OK, "{message}");
    assert!(
        error.is_null(),
        "successful call returned an error: {message}"
    );
}

fn failure(call: impl FnOnce(*mut *mut lk_error_t) -> lk_status_t) -> Handle<lk_error_t> {
    let mut error = ptr::null_mut();
    assert_eq!(call(&mut error), lk_status_t::LK_ERR);
    Handle::new(error, lk_error_free)
}

fn builder() -> Handle<lk_client_builder_t> {
    let builder = Handle::new(lk_client_builder_new(), lk_client_builder_free);
    assert_eq!(
        lk_client_builder_set_timeout_total(builder.ptr, 5_000),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_retry_on_connection_close(builder.ptr, false),
        lk_status_t::LK_OK
    );
    builder
}

fn build_client(builder: &Handle<lk_client_builder_t>) -> Handle<lk_client_t> {
    let mut client = ptr::null_mut();
    ok(|error| lk_client_builder_build(builder.ptr, &mut client, error));
    Handle::new(client, lk_client_free)
}

fn session_builder(client: &Handle<lk_client_t>) -> Handle<lk_session_builder_t> {
    let builder = Handle::new(lk_session_builder_new(client.ptr), lk_session_builder_free);
    assert_eq!(
        lk_session_builder_set_http1_only(builder.ptr),
        lk_status_t::LK_OK
    );
    builder
}

fn build_session(builder: &Handle<lk_session_builder_t>) -> Handle<lk_session_t> {
    let mut session = ptr::null_mut();
    ok(|error| lk_session_builder_build(builder.ptr, &mut session, error));
    Handle::new(session, lk_session_free)
}

fn session(cap: Option<u64>, retries: u32) -> Handle<lk_session_t> {
    let builder = builder();
    if let Some(cap) = cap {
        ok(|error| lk_client_builder_set_extra_http_attempt_limit(builder.ptr, cap, error));
    }
    let client = build_client(&builder);
    let builder = session_builder(&client);
    assert_eq!(
        lk_session_builder_set_retry_fixed(builder.ptr, retries, 0),
        lk_status_t::LK_OK
    );
    build_session(&builder)
}

fn request(session: &Handle<lk_session_t>, url: &str, observe: bool) -> Handle<lk_request_t> {
    let mut request = ptr::null_mut();
    ok(|error| {
        lk_request_new(
            session.ptr,
            c"GET".as_ptr(),
            3,
            url.as_ptr().cast(),
            url.len(),
            &mut request,
            error,
        )
    });
    let request = Handle::new(request, lk_request_free);
    if observe {
        ok(|error| lk_request_enable_attempt_summary(request.ptr, true, error));
    }
    request
}

type CopySummary<'a> = dyn Fn(*mut u8, usize, *mut usize, *mut *mut lk_error_t) -> lk_status_t + 'a;
type ReadLimit<'a> = dyn Fn(*mut lk_attempt_limit_view_t, *mut *mut lk_error_t) -> lk_status_t + 'a;

fn summary(copy: &CopySummary<'_>) -> Value {
    let mut required = 0;
    ok(|error| copy(ptr::null_mut(), 0, &mut required, error));
    assert!(required > 0);
    // Active snapshots can grow between calls. Leave enough space for all counters.
    let capacity = required + 1024;
    let mut bytes = vec![SENTINEL; capacity + 8];
    ok(|error| copy(bytes.as_mut_ptr(), capacity, &mut required, error));
    assert!(required <= capacity);
    assert!(bytes[required..].iter().all(|byte| *byte == SENTINEL));
    serde_json::from_slice(&bytes[..required]).unwrap()
}

enum Payload {
    Buffered(Handle<lk_response_t>),
    Streaming(Handle<lk_streaming_response_t>),
}

impl Payload {
    fn copy(
        &self,
        buffer: *mut u8,
        capacity: usize,
        required: *mut usize,
        error: *mut *mut lk_error_t,
    ) -> lk_status_t {
        match self {
            Self::Buffered(handle) => {
                lk_response_copy_attempt_summary_json(handle.ptr, buffer, capacity, required, error)
            }
            Self::Streaming(handle) => lk_streaming_response_copy_attempt_summary_json(
                handle.ptr, buffer, capacity, required, error,
            ),
        }
    }

    fn summary(&self) -> Value {
        summary(&|buffer, capacity, required, error| self.copy(buffer, capacity, required, error))
    }

    fn status(&self) -> u16 {
        match self {
            Self::Buffered(handle) => lk_response_status(handle.ptr),
            Self::Streaming(handle) => lk_streaming_response_status(handle.ptr),
        }
    }
}

fn send_sync(
    request: &Handle<lk_request_t>,
    streaming: bool,
) -> Result<Payload, Handle<lk_error_t>> {
    let mut error = ptr::null_mut();
    if streaming {
        let mut response = ptr::null_mut();
        let status = lk_request_send_streaming(request.ptr, &mut response, &mut error);
        if status == lk_status_t::LK_OK {
            assert!(error.is_null());
            Ok(Payload::Streaming(Handle::new(
                response,
                lk_streaming_response_free,
            )))
        } else {
            assert!(response.is_null());
            Err(Handle::new(error, lk_error_free))
        }
    } else {
        let mut response = ptr::null_mut();
        let status = lk_request_send(request.ptr, &mut response, &mut error);
        if status == lk_status_t::LK_OK {
            assert!(error.is_null());
            Ok(Payload::Buffered(Handle::new(response, lk_response_free)))
        } else {
            assert!(response.is_null());
            Err(Handle::new(error, lk_error_free))
        }
    }
}

fn start_async(request: &Handle<lk_request_t>, streaming: bool) -> Handle<lk_op_t> {
    let mut op = ptr::null_mut();
    ok(|error| {
        if streaming {
            lk_request_send_streaming_async(request.ptr, &mut op, error)
        } else {
            lk_request_send_async(request.ptr, &mut op, error)
        }
    });
    Handle::new(op, lk_op_free)
}

fn take_payload(op: &Handle<lk_op_t>, streaming: bool) -> Payload {
    assert_eq!(lk_op_wait(op.ptr, 5_000), lk_op_state_t::LK_OP_COMPLETED_OK);
    if streaming {
        let mut response = ptr::null_mut();
        ok(|error| lk_op_take_streaming_response(op.ptr, &mut response, error));
        Payload::Streaming(Handle::new(response, lk_streaming_response_free))
    } else {
        let mut response = ptr::null_mut();
        ok(|error| lk_op_take_response(op.ptr, &mut response, error));
        Payload::Buffered(Handle::new(response, lk_response_free))
    }
}

fn op_summary(op: &Handle<lk_op_t>) -> Value {
    summary(&|buffer, capacity, required, error| {
        lk_op_copy_attempt_summary_json(op.ptr, buffer, capacity, required, error)
    })
}

fn error_summary(error: &Handle<lk_error_t>) -> Value {
    summary(&|buffer, capacity, required, out_error| {
        lk_error_copy_attempt_summary_json(error.ptr, buffer, capacity, required, out_error)
    })
}

fn assert_summary(summary: &Value, outcome: &str, total: u64, extra: u64) {
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["started"], true);
    assert_eq!(summary["outcome"], outcome);
    assert_eq!(
        summary["final"],
        outcome != "active" && outcome != "pending"
    );
    assert_eq!(summary["http_submissions"], total);
    assert_eq!(summary["extra_http_submissions"], extra);
    let redirects = summary["redirects"].as_u64().unwrap();
    assert!(total <= 1 + redirects + extra);
}

fn read_view(
    call: impl FnOnce(*mut lk_attempt_limit_view_t, *mut *mut lk_error_t) -> lk_status_t,
) -> lk_attempt_limit_view_t {
    let mut view = lk_attempt_limit_view_t {
        configured_present: true,
        configured: 123,
        effective_present: true,
        effective: 456,
        scope: lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_REQUEST,
    };
    ok(|error| call(&mut view, error));
    view
}

fn assert_view(
    view: lk_attempt_limit_view_t,
    configured: Option<u64>,
    effective: Option<u64>,
    scope: lk_attempt_limit_scope_t,
) {
    assert_eq!(view.configured_present, configured.is_some());
    assert_eq!(view.configured, configured.unwrap_or(0));
    assert_eq!(view.effective_present, effective.is_some());
    assert_eq!(view.effective, effective.unwrap_or(0));
    assert_eq!(view.scope, scope);
}

struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    release: Arc<(Mutex<bool>, Condvar)>,
    arrived: mpsc::Receiver<String>,
    paths: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (arrived_tx, arrived) = mpsc::channel();
        let worker_stop = stop.clone();
        let worker_release = release.clone();
        let worker_paths = paths.clone();
        let thread = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept failed: {error}"),
                };
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                loop {
                    let mut bytes = Vec::new();
                    let mut byte = [0];
                    while !bytes.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).is_err() {
                            break;
                        }
                        bytes.push(byte[0]);
                        assert!(bytes.len() < 64 * 1024);
                    }
                    if !bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    let request = String::from_utf8(bytes).unwrap();
                    let path = request.split_whitespace().nth(1).unwrap().to_owned();
                    worker_paths.lock().unwrap().push(path.clone());
                    let _ = arrived_tx.send(path.clone());
                    if path == "/hold" {
                        let (lock, wake) = &*worker_release;
                        let released = lock.lock().unwrap();
                        drop(
                            wake.wait_timeout_while(released, WAIT, |released| !*released)
                                .unwrap(),
                        );
                    }
                    let response = match path.as_str() {
                    "/fail" => break,
                    "/keep" => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    "/truncated" => "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nx",
                    "/busy" => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy",
                    "/redirect" => "HTTP/1.1 302 Found\r\nLocation: /busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    _ => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                };
                    if stream.write_all(response.as_bytes()).is_err() || path != "/keep" {
                        break;
                    }
                }
            }
        });
        Self {
            addr,
            stop,
            release,
            arrived,
            paths,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn wait_for_request(&self, path: &str) {
        assert_eq!(self.arrived.recv_timeout(WAIT).unwrap(), path);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let (lock, wake) = &*self.release;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(thread) = self.thread.take() {
            if let Err(error) = thread.join() {
                if !thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}

#[test]
fn feature_discovery_and_all_limit_levels_preserve_inheritance_and_atomic_failure() {
    use lk_attempt_limit_scope_t::*;
    assert!(lk_feature_supported(c"extra-http-attempt-limit".as_ptr()));
    assert!(lk_feature_supported(c"attempt-summary".as_ptr()));
    let builder = builder();
    assert_view(
        read_view(|view, error| {
            lk_client_builder_get_extra_http_attempt_limit(builder.ptr, view, error)
        }),
        None,
        None,
        LK_ATTEMPT_LIMIT_UNSET,
    );
    for limit in [0, 8, u64::MAX] {
        ok(|error| lk_client_builder_set_extra_http_attempt_limit(builder.ptr, limit, error));
        assert_view(
            read_view(|view, error| {
                lk_client_builder_get_extra_http_attempt_limit(builder.ptr, view, error)
            }),
            Some(limit),
            Some(limit),
            LK_ATTEMPT_LIMIT_CLIENT,
        );
    }
    ok(|error| lk_client_builder_clear_extra_http_attempt_limit(builder.ptr, error));
    assert_view(
        read_view(|view, error| {
            lk_client_builder_get_extra_http_attempt_limit(builder.ptr, view, error)
        }),
        None,
        None,
        LK_ATTEMPT_LIMIT_UNSET,
    );
    ok(|error| lk_client_builder_set_extra_http_attempt_limit(builder.ptr, 8, error));
    let client = build_client(&builder);
    assert_view(
        read_view(|view, error| lk_client_get_extra_http_attempt_limit(client.ptr, view, error)),
        Some(8),
        Some(8),
        LK_ATTEMPT_LIMIT_CLIENT,
    );
    let session_builder = session_builder(&client);
    assert_view(
        read_view(|view, error| {
            lk_session_builder_get_extra_http_attempt_limit(session_builder.ptr, view, error)
        }),
        None,
        Some(8),
        LK_ATTEMPT_LIMIT_CLIENT,
    );
    ok(|error| lk_session_builder_set_extra_http_attempt_limit(session_builder.ptr, 3, error));
    for invalid in [9, u64::MAX] {
        let error = failure(|error| {
            lk_session_builder_set_extra_http_attempt_limit(session_builder.ptr, invalid, error)
        });
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_CONFIG
        );
        assert_view(
            read_view(|view, error| {
                lk_session_builder_get_extra_http_attempt_limit(session_builder.ptr, view, error)
            }),
            Some(3),
            Some(3),
            LK_ATTEMPT_LIMIT_SESSION,
        );
    }
    ok(|error| lk_session_builder_clear_extra_http_attempt_limit(session_builder.ptr, error));
    assert_view(
        read_view(|view, error| {
            lk_session_builder_get_extra_http_attempt_limit(session_builder.ptr, view, error)
        }),
        None,
        Some(8),
        LK_ATTEMPT_LIMIT_CLIENT,
    );
    ok(|error| lk_session_builder_set_extra_http_attempt_limit(session_builder.ptr, 3, error));
    let session = build_session(&session_builder);
    assert_view(
        read_view(|view, error| lk_session_get_extra_http_attempt_limit(session.ptr, view, error)),
        Some(3),
        Some(3),
        LK_ATTEMPT_LIMIT_SESSION,
    );
    let request = request(&session, "http://127.0.0.1/", false);
    assert_view(
        read_view(|view, error| lk_request_get_extra_http_attempt_limit(request.ptr, view, error)),
        None,
        Some(3),
        LK_ATTEMPT_LIMIT_SESSION,
    );
    ok(|error| lk_request_set_extra_http_attempt_limit(request.ptr, 3, error));
    assert_view(
        read_view(|view, error| lk_request_get_extra_http_attempt_limit(request.ptr, view, error)),
        Some(3),
        Some(3),
        LK_ATTEMPT_LIMIT_SESSION,
    );
    ok(|error| lk_request_set_extra_http_attempt_limit(request.ptr, 0, error));
    for invalid in [4, u64::MAX] {
        let error =
            failure(|error| lk_request_set_extra_http_attempt_limit(request.ptr, invalid, error));
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_CONFIG
        );
        assert_view(
            read_view(|view, error| {
                lk_request_get_extra_http_attempt_limit(request.ptr, view, error)
            }),
            Some(0),
            Some(0),
            LK_ATTEMPT_LIMIT_REQUEST,
        );
    }
    ok(|error| lk_request_clear_extra_http_attempt_limit(request.ptr, error));
    assert_view(
        read_view(|view, error| lk_request_get_extra_http_attempt_limit(request.ptr, view, error)),
        None,
        Some(3),
        LK_ATTEMPT_LIMIT_SESSION,
    );
}

#[test]
fn zero_and_max_are_finite_across_ffi_builders() {
    use lk_attempt_limit_scope_t::*;
    for cap in [0, u64::MAX] {
        let builder = builder();
        ok(|error| lk_client_builder_set_extra_http_attempt_limit(builder.ptr, cap, error));
        let client = build_client(&builder);
        let builder = session_builder(&client);
        ok(|error| lk_session_builder_set_extra_http_attempt_limit(builder.ptr, cap, error));
        let session = build_session(&builder);
        let request = request(&session, "http://127.0.0.1/", false);
        ok(|error| lk_request_set_extra_http_attempt_limit(request.ptr, cap, error));
        assert_view(
            read_view(|view, error| {
                lk_request_get_extra_http_attempt_limit(request.ptr, view, error)
            }),
            Some(cap),
            Some(cap),
            LK_ATTEMPT_LIMIT_CLIENT,
        );
        if cap == 0 {
            let error = failure(|error| {
                lk_session_builder_set_extra_http_attempt_limit(builder.ptr, 1, error)
            });
            assert_eq!(
                lk_error_code(error.ptr),
                lk_error_code_t::LK_ERR_INVALID_CONFIG
            );
            let error =
                failure(|error| lk_request_set_extra_http_attempt_limit(request.ptr, 1, error));
            assert_eq!(
                lk_error_code(error.ptr),
                lk_error_code_t::LK_ERR_INVALID_CONFIG
            );
            assert_view(
                read_view(|view, error| {
                    lk_request_get_extra_http_attempt_limit(request.ptr, view, error)
                }),
                Some(0),
                Some(0),
                LK_ATTEMPT_LIMIT_CLIENT,
            );
        }
    }
}

#[test]
fn summaries_are_disabled_by_default_and_can_be_disabled_again() {
    for streaming in [false, true] {
        for asynchronous in [false, true] {
            let server = Server::start();
            let session = session(None, 0);
            let request = request(&session, &server.url("/ok"), false);
            if asynchronous {
                ok(|error| lk_request_enable_attempt_summary(request.ptr, true, error));
                ok(|error| lk_request_enable_attempt_summary(request.ptr, false, error));
            }
            let op = asynchronous.then(|| start_async(&request, streaming));
            let payload = match &op {
                Some(op) => take_payload(op, streaming),
                None => send_sync(&request, streaming)
                    .unwrap_or_else(|error| panic!("{}", error_text(error.ptr))),
            };
            let mut required = 777;
            let mut bytes = [SENTINEL; 32];
            let error = failure(|error| {
                payload.copy(bytes.as_mut_ptr(), bytes.len(), &mut required, error)
            });
            assert_eq!(
                lk_error_code(error.ptr),
                lk_error_code_t::LK_ERR_INVALID_ARGUMENT
            );
            assert_eq!(required, 0);
            assert_eq!(bytes, [SENTINEL; 32]);
            if let Some(op) = op {
                let error = failure(|error| {
                    lk_op_copy_attempt_summary_json(
                        op.ptr,
                        ptr::null_mut(),
                        0,
                        &mut required,
                        error,
                    )
                });
                assert_eq!(
                    lk_error_code(error.ptr),
                    lk_error_code_t::LK_ERR_INVALID_ARGUMENT
                );
            }
        }
    }
}

#[test]
fn connect_limits_preserve_inheritance_atomic_failure_and_independent_http_limits() {
    use lk_attempt_limit_scope_t::*;
    assert!(lk_feature_supported(c"connect-attempt-limit".as_ptr()));
    let builder = builder();
    ok(|error| lk_client_builder_set_extra_http_attempt_limit(builder.ptr, 7, error));
    for cap in [0, u64::MAX] {
        ok(|error| lk_client_builder_set_connect_attempt_limit(builder.ptr, cap, error));
        assert_view(
            read_view(|view, error| {
                lk_client_builder_get_connect_attempt_limit(builder.ptr, view, error)
            }),
            Some(cap),
            Some(cap),
            LK_ATTEMPT_LIMIT_CLIENT,
        );
        let client = build_client(&builder);
        let session_builder = session_builder(&client);
        ok(|error| lk_session_builder_set_connect_attempt_limit(session_builder.ptr, cap, error));
        let session = build_session(&session_builder);
        let request = request(&session, "http://127.0.0.1/", false);
        ok(|error| lk_request_set_connect_attempt_limit(request.ptr, cap, error));
        assert_view(
            read_view(|view, error| lk_request_get_connect_attempt_limit(request.ptr, view, error)),
            Some(cap),
            Some(cap),
            LK_ATTEMPT_LIMIT_CLIENT,
        );
        assert_view(
            read_view(|view, error| {
                lk_request_get_extra_http_attempt_limit(request.ptr, view, error)
            }),
            None,
            Some(7),
            LK_ATTEMPT_LIMIT_CLIENT,
        );
    }
    ok(|error| lk_client_builder_clear_connect_attempt_limit(builder.ptr, error));
    assert_view(
        read_view(|view, error| {
            lk_client_builder_get_connect_attempt_limit(builder.ptr, view, error)
        }),
        None,
        None,
        LK_ATTEMPT_LIMIT_UNSET,
    );
    ok(|error| lk_client_builder_set_connect_attempt_limit(builder.ptr, 4, error));
    let client = build_client(&builder);
    assert_view(
        read_view(|view, error| lk_client_get_connect_attempt_limit(client.ptr, view, error)),
        Some(4),
        Some(4),
        LK_ATTEMPT_LIMIT_CLIENT,
    );
    let session_builder = session_builder(&client);
    ok(|error| lk_session_builder_set_connect_attempt_limit(session_builder.ptr, 2, error));
    ok(|error| lk_session_builder_set_extra_http_attempt_limit(session_builder.ptr, 3, error));
    for invalid in [5, u64::MAX] {
        let error = failure(|error| {
            lk_session_builder_set_connect_attempt_limit(session_builder.ptr, invalid, error)
        });
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_CONFIG
        );
        assert_view(
            read_view(|view, error| {
                lk_session_builder_get_connect_attempt_limit(session_builder.ptr, view, error)
            }),
            Some(2),
            Some(2),
            LK_ATTEMPT_LIMIT_SESSION,
        );
    }
    ok(|error| lk_session_builder_clear_connect_attempt_limit(session_builder.ptr, error));
    assert_view(
        read_view(|view, error| {
            lk_session_builder_get_connect_attempt_limit(session_builder.ptr, view, error)
        }),
        None,
        Some(4),
        LK_ATTEMPT_LIMIT_CLIENT,
    );
    ok(|error| lk_session_builder_set_connect_attempt_limit(session_builder.ptr, 2, error));
    let session = build_session(&session_builder);
    assert_view(
        read_view(|view, error| lk_session_get_connect_attempt_limit(session.ptr, view, error)),
        Some(2),
        Some(2),
        LK_ATTEMPT_LIMIT_SESSION,
    );
    let request = request(&session, "http://127.0.0.1/", false);
    ok(|error| lk_request_set_connect_attempt_limit(request.ptr, 0, error));
    ok(|error| lk_request_set_extra_http_attempt_limit(request.ptr, 1, error));
    for invalid in [3, u64::MAX] {
        let error =
            failure(|error| lk_request_set_connect_attempt_limit(request.ptr, invalid, error));
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_CONFIG
        );
        assert_view(
            read_view(|view, error| lk_request_get_connect_attempt_limit(request.ptr, view, error)),
            Some(0),
            Some(0),
            LK_ATTEMPT_LIMIT_REQUEST,
        );
    }
    ok(|error| lk_request_clear_connect_attempt_limit(request.ptr, error));
    assert_view(
        read_view(|view, error| lk_request_get_connect_attempt_limit(request.ptr, view, error)),
        None,
        Some(2),
        LK_ATTEMPT_LIMIT_SESSION,
    );
    assert_view(
        read_view(|view, error| lk_request_get_extra_http_attempt_limit(request.ptr, view, error)),
        Some(1),
        Some(1),
        LK_ATTEMPT_LIMIT_REQUEST,
    );
    ok(|error| lk_request_clear_extra_http_attempt_limit(request.ptr, error));
    assert_view(
        read_view(|view, error| lk_request_get_connect_attempt_limit(request.ptr, view, error)),
        None,
        Some(2),
        LK_ATTEMPT_LIMIT_SESSION,
    );
}

#[test]
fn connect_limit_denial_is_visible_for_sync_async_buffered_and_streaming_requests() {
    for asynchronous in [false, true] {
        for streaming in [false, true] {
            let server = Server::start();
            let session = session(None, 0);
            let request = request(&session, &server.url("/ok"), true);
            ok(|error| lk_request_set_connect_attempt_limit(request.ptr, 0, error));
            let op = asynchronous.then(|| start_async(&request, streaming));
            let error = match &op {
                Some(op) => {
                    assert_eq!(
                        lk_op_wait(op.ptr, 5_000),
                        lk_op_state_t::LK_OP_COMPLETED_ERR
                    );
                    let mut error = ptr::null_mut();
                    assert_eq!(lk_op_take_error(op.ptr, &mut error), lk_status_t::LK_OK);
                    Handle::new(error, lk_error_free)
                }
                None => match send_sync(&request, streaming) {
                    Ok(_) => panic!("zero connection allowance unexpectedly sent a request"),
                    Err(error) => error,
                },
            };
            assert_eq!(
                lk_error_code(error.ptr),
                lk_error_code_t::LK_ERR_RESOURCE_LIMIT_EXCEEDED
            );
            let observed = error_summary(&error);
            assert_summary(&observed, "failed", 0, 0);
            assert_eq!(observed["connect_initiations"], 0);
            assert_eq!(observed["denial_reason"], "connect_limit");
            assert_eq!(observed["effective_limits"]["connect_attempts"], 0);
            assert_eq!(observed["effective_limits"]["connect_scope"], "request");
            assert_eq!(observed["probe_suppressed_by_connect_limit"], false);
            assert!(server.paths.lock().unwrap().is_empty());
            assert_view(
                read_view(|view, error| {
                    lk_request_get_connect_attempt_limit(request.ptr, view, error)
                }),
                Some(0),
                Some(0),
                lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_REQUEST,
            );
            let setter_error =
                failure(|error| lk_request_clear_connect_attempt_limit(request.ptr, error));
            assert_eq!(
                lk_error_code(setter_error.ptr),
                lk_error_code_t::LK_ERR_INVALID_ARGUMENT
            );
            drop(error);
            drop(request);
            if let Some(op) = op {
                assert_eq!(lk_op_poll(op.ptr), lk_op_state_t::LK_OP_CONSUMED);
                assert_eq!(op_summary(&op), observed);
            }
        }
    }
}

#[test]
fn zero_connect_limit_reuses_an_existing_connection_and_retains_consumed_op_summary() {
    let server = Server::start();
    let session = session(Some(0), 0);
    let warm = request(&session, &server.url("/keep"), true);
    ok(|error| lk_request_set_connect_attempt_limit(warm.ptr, 1, error));
    let response =
        send_sync(&warm, false).unwrap_or_else(|error| panic!("{}", error_text(error.ptr)));
    assert_eq!(response.status(), 200);
    assert_eq!(response.summary()["connect_initiations"], 1);
    drop(response);

    let reused = request(&session, &server.url("/keep"), true);
    ok(|error| lk_request_set_connect_attempt_limit(reused.ptr, 0, error));
    let op = start_async(&reused, false);
    let response = take_payload(&op, false);
    let observed = response.summary();
    assert_summary(&observed, "succeeded", 1, 0);
    assert_eq!(observed["connect_initiations"], 0);
    assert_eq!(observed["denial_reason"], Value::Null);
    assert_eq!(observed["effective_limits"]["extra_http_attempts"], 0);
    assert_eq!(observed["effective_limits"]["connect_attempts"], 0);
    drop(response);
    drop(reused);
    assert_eq!(op_summary(&op), observed);
    assert_eq!(server.paths.lock().unwrap().len(), 2);
}

#[test]
fn sync_and_async_buffered_limits_enforce_caps_and_keep_consumed_op_summaries() {
    for asynchronous in [false, true] {
        for (cap, expected) in [(Some(0), 1), (Some(1), 2), (None, 4)] {
            let server = Server::start();
            let session = session(cap, 3);
            for _ in 0..2 {
                let request = request(&session, &server.url("/busy"), true);
                let op = asynchronous.then(|| start_async(&request, false));
                let payload = match &op {
                    Some(op) => take_payload(op, false),
                    None => send_sync(&request, false)
                        .unwrap_or_else(|error| panic!("{}", error_text(error.ptr))),
                };
                assert_eq!(payload.status(), 503);
                let observed = payload.summary();
                assert_summary(&observed, "succeeded", expected, expected - 1);
                assert_eq!(observed["recoveries"], expected - 1);
                assert_eq!(
                    observed["effective_limits"]["extra_http_attempts"],
                    serde_json::json!(cap)
                );
                assert_eq!(
                    observed["effective_limits"]["extra_http_scope"],
                    serde_json::json!(cap.map(|_| "client"))
                );
                assert_eq!(
                    observed["denial_reason"],
                    serde_json::json!(cap.map(|_| "extra_http_limit"))
                );
                let error =
                    failure(|error| lk_request_set_extra_http_attempt_limit(request.ptr, 0, error));
                assert_eq!(
                    lk_error_code(error.ptr),
                    lk_error_code_t::LK_ERR_INVALID_ARGUMENT
                );
                let error =
                    failure(|error| lk_request_enable_attempt_summary(request.ptr, false, error));
                assert_eq!(
                    lk_error_code(error.ptr),
                    lk_error_code_t::LK_ERR_INVALID_ARGUMENT
                );
                drop(request);
                drop(payload);
                if let Some(op) = op {
                    assert_eq!(lk_op_poll(op.ptr), lk_op_state_t::LK_OP_CONSUMED);
                    assert_eq!(op_summary(&op), observed);
                }
            }
            assert_eq!(server.paths.lock().unwrap().len() as u64, expected * 2);
        }
    }
}

#[test]
fn request_override_and_clear_change_actual_retry_work() {
    let server = Server::start();
    let session = session(Some(2), 4);
    for clear in [false, true] {
        let request = request(&session, &server.url("/redirect"), true);
        ok(|error| lk_request_set_extra_http_attempt_limit(request.ptr, 0, error));
        if clear {
            ok(|error| lk_request_clear_extra_http_attempt_limit(request.ptr, error));
        }
        let payload =
            send_sync(&request, false).unwrap_or_else(|error| panic!("{}", error_text(error.ptr)));
        assert_eq!(payload.status(), 503);
        let observed = payload.summary();
        let extra = if clear { 2 } else { 0 };
        assert_summary(&observed, "succeeded", 2 * (extra + 1), extra);
        assert_eq!(observed["redirects"], extra + 1);
        assert_eq!(
            observed["effective_limits"]["extra_http_scope"],
            if clear { "client" } else { "request" }
        );
    }
    assert_eq!(server.paths.lock().unwrap().len(), 8);
}

#[test]
fn sync_and_async_streaming_publication_has_an_independent_final_summary() {
    for asynchronous in [false, true] {
        let server = Server::start();
        let session = session(Some(0), 3);
        let request = request(&session, &server.url("/busy"), true);
        let op = asynchronous.then(|| start_async(&request, true));
        let payload = match &op {
            Some(op) => take_payload(op, true),
            None => send_sync(&request, true)
                .unwrap_or_else(|error| panic!("{}", error_text(error.ptr))),
        };
        assert_eq!(payload.status(), 503);
        let observed = payload.summary();
        assert_summary(&observed, "succeeded", 1, 0);
        assert_eq!(observed["denial_reason"], Value::Null);
        drop(request);
        drop(payload);
        if let Some(op) = op {
            assert_eq!(lk_op_poll(op.ptr), lk_op_state_t::LK_OP_CONSUMED);
            assert_eq!(op_summary(&op), observed);
        }
        assert_eq!(server.paths.lock().unwrap().as_slice(), ["/busy"]);
    }
}

#[test]
fn failures_preserve_summary_on_error_and_after_async_result_consumption() {
    for streaming in [false, true] {
        for asynchronous in [false, true] {
            let server = Server::start();
            let session = session(Some(0), 3);
            let request = request(&session, &server.url("/fail"), true);
            let op = asynchronous.then(|| start_async(&request, streaming));
            let error = if let Some(op) = &op {
                assert_eq!(
                    lk_op_wait(op.ptr, 5_000),
                    lk_op_state_t::LK_OP_COMPLETED_ERR
                );
                let mut error = ptr::null_mut();
                assert_eq!(lk_op_take_error(op.ptr, &mut error), lk_status_t::LK_OK);
                Handle::new(error, lk_error_free)
            } else {
                match send_sync(&request, streaming) {
                    Ok(_) => panic!("expected transport failure"),
                    Err(error) => error,
                }
            };
            assert_ne!(
                lk_error_code(error.ptr),
                lk_error_code_t::LK_ERR_RESOURCE_LIMIT_EXCEEDED
            );
            let observed = error_summary(&error);
            assert_summary(&observed, "failed", 1, 0);
            assert_eq!(
                observed["denial_reason"],
                if streaming {
                    Value::Null
                } else {
                    serde_json::json!("extra_http_limit")
                }
            );
            drop(request);
            drop(error);
            if let Some(op) = op {
                assert_eq!(lk_op_poll(op.ptr), lk_op_state_t::LK_OP_CONSUMED);
                assert_eq!(op_summary(&op), observed);
            }
        }
    }
}

#[test]
fn async_active_cancel_and_timeout_have_distinct_final_summaries() {
    for streaming in [false, true] {
        let server = Server::start();
        let session = session(Some(1), 0);
        let request = request(&session, &server.url("/hold"), true);
        let op = start_async(&request, streaming);
        drop(request);
        server.wait_for_request("/hold");
        assert_eq!(lk_op_poll(op.ptr), lk_op_state_t::LK_OP_IN_PROGRESS);
        assert_summary(&op_summary(&op), "active", 1, 0);
        assert_eq!(lk_op_cancel(op.ptr), lk_status_t::LK_OK);
        assert_eq!(lk_op_wait(op.ptr, 5_000), lk_op_state_t::LK_OP_CANCELLED);
        let deadline = Instant::now() + WAIT;
        let cancelled = loop {
            let observed = op_summary(&op);
            if observed["final"] == true {
                break observed;
            }
            assert!(
                Instant::now() < deadline,
                "cancelled task did not release its execution root"
            );
            thread::sleep(Duration::from_millis(2));
        };
        assert_summary(&cancelled, "cancelled", 1, 0);
        assert_eq!(cancelled["denial_reason"], "cancelled");
        assert_eq!(op_summary(&op), cancelled);
    }
    let server = Server::start();
    let session = session(None, 0);
    let request = request(&session, &server.url("/hold"), true);
    assert_eq!(lk_request_set_timeout(request.ptr, 500), lk_status_t::LK_OK);
    let op = start_async(&request, false);
    server.wait_for_request("/hold");
    assert_eq!(
        lk_op_wait(op.ptr, 5_000),
        lk_op_state_t::LK_OP_COMPLETED_ERR
    );
    let mut error = ptr::null_mut();
    assert_eq!(lk_op_take_error(op.ptr, &mut error), lk_status_t::LK_OK);
    let error = Handle::new(error, lk_error_free);
    assert_eq!(lk_error_code(error.ptr), lk_error_code_t::LK_ERR_TIMEOUT);
    let observed = error_summary(&error);
    assert_summary(&observed, "failed", 1, 0);
    assert_eq!(observed["denial_reason"], "deadline");
    assert_eq!(op_summary(&op), observed);
}

fn copyout_contract(copy: &CopySummary<'_>) {
    let mut required = usize::MAX;
    ok(|error| copy(ptr::null_mut(), 0, &mut required, error));
    let size = required;
    assert!(size > 1);
    let mut bytes = vec![SENTINEL; size + 8];
    let error = failure(|error| copy(bytes.as_mut_ptr(), size - 1, &mut required, error));
    assert_eq!(
        lk_error_code(error.ptr),
        lk_error_code_t::LK_ERR_INVALID_ARGUMENT
    );
    assert_eq!(required, size);
    assert!(bytes.iter().all(|byte| *byte == SENTINEL));
    let error = failure(|error| copy(bytes.as_mut_ptr(), 0, &mut required, error));
    assert_eq!(
        lk_error_code(error.ptr),
        lk_error_code_t::LK_ERR_INVALID_ARGUMENT
    );
    assert_eq!(required, size);
    assert!(bytes.iter().all(|byte| *byte == SENTINEL));
    let error = failure(|error| copy(ptr::null_mut(), size, &mut required, error));
    assert_eq!(
        lk_error_code(error.ptr),
        lk_error_code_t::LK_ERR_INVALID_ARGUMENT
    );
    assert!(bytes.iter().all(|byte| *byte == SENTINEL));
    let error = failure(|error| copy(bytes.as_mut_ptr(), bytes.len(), ptr::null_mut(), error));
    assert_eq!(
        lk_error_code(error.ptr),
        lk_error_code_t::LK_ERR_INVALID_ARGUMENT
    );
    assert!(bytes.iter().all(|byte| *byte == SENTINEL));
    ok(|error| copy(bytes.as_mut_ptr(), size, &mut required, error));
    assert_eq!(required, size);
    assert!(
        bytes[size..].iter().all(|byte| *byte == SENTINEL),
        "copyout must not append a NUL or overwrite the guard bytes"
    );
    let copied: Value = serde_json::from_slice(&bytes[..size]).unwrap();
    assert_eq!(copied, summary(copy));
}

#[test]
fn every_summary_handle_obeys_copyout_boundaries() {
    let server = Server::start();
    let session = session(None, 0);
    for streaming in [false, true] {
        let request = request(&session, &server.url("/ok"), true);
        let op = start_async(&request, streaming);
        let payload = take_payload(&op, streaming);
        copyout_contract(&|buffer, capacity, required, error| {
            payload.copy(buffer, capacity, required, error)
        });
        copyout_contract(&|buffer, capacity, required, error| {
            lk_op_copy_attempt_summary_json(op.ptr, buffer, capacity, required, error)
        });
    }
    let request = request(&session, "not a URL", true);
    let error = match send_sync(&request, false) {
        Ok(_) => panic!("expected URL failure"),
        Err(error) => error,
    };
    assert_summary(&error_summary(&error), "failed", 0, 0);
    copyout_contract(&|buffer, capacity, required, out_error| {
        lk_error_copy_attempt_summary_json(error.ptr, buffer, capacity, required, out_error)
    });
}

#[test]
fn null_handles_and_outputs_fail_without_overwriting_buffers_or_limit_views() {
    let mut view = lk_attempt_limit_view_t {
        configured_present: true,
        configured: 123,
        effective_present: true,
        effective: 456,
        scope: lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_REQUEST,
    };
    let getters: [&ReadLimit<'_>; 10] = [
        &|view, error| lk_client_builder_get_extra_http_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_session_builder_get_extra_http_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_request_get_extra_http_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_client_get_extra_http_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_session_get_extra_http_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_client_builder_get_connect_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_session_builder_get_connect_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_request_get_connect_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_client_get_connect_attempt_limit(ptr::null(), view, error),
        &|view, error| lk_session_get_connect_attempt_limit(ptr::null(), view, error),
    ];
    for getter in getters {
        let error = failure(|error| getter(&mut view, error));
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            (
                view.configured_present,
                view.configured,
                view.effective_present,
                view.effective,
                view.scope
            ),
            (
                true,
                123,
                true,
                456,
                lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_REQUEST
            )
        );
    }
    let copies: [&CopySummary<'_>; 4] = [
        &|buffer, capacity, required, error| {
            lk_response_copy_attempt_summary_json(ptr::null(), buffer, capacity, required, error)
        },
        &|buffer, capacity, required, error| {
            lk_streaming_response_copy_attempt_summary_json(
                ptr::null(),
                buffer,
                capacity,
                required,
                error,
            )
        },
        &|buffer, capacity, required, error| {
            lk_error_copy_attempt_summary_json(ptr::null(), buffer, capacity, required, error)
        },
        &|buffer, capacity, required, error| {
            lk_op_copy_attempt_summary_json(ptr::null(), buffer, capacity, required, error)
        },
    ];
    for copy in copies {
        let mut bytes = [SENTINEL; 64];
        let mut required = 123;
        let error = failure(|error| copy(bytes.as_mut_ptr(), bytes.len(), &mut required, error));
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_ARGUMENT
        );
        assert_eq!(bytes, [SENTINEL; 64]);
    }
    let builder = builder();
    let client = build_client(&builder);
    let session_builder = session_builder(&client);
    let session = build_session(&session_builder);
    let request = request(&session, "http://127.0.0.1/", false);
    let getters: [&ReadLimit<'_>; 10] = [
        &|view, error| lk_client_builder_get_extra_http_attempt_limit(builder.ptr, view, error),
        &|view, error| {
            lk_session_builder_get_extra_http_attempt_limit(session_builder.ptr, view, error)
        },
        &|view, error| lk_client_get_extra_http_attempt_limit(client.ptr, view, error),
        &|view, error| lk_session_get_extra_http_attempt_limit(session.ptr, view, error),
        &|view, error| lk_request_get_extra_http_attempt_limit(request.ptr, view, error),
        &|view, error| lk_client_builder_get_connect_attempt_limit(builder.ptr, view, error),
        &|view, error| {
            lk_session_builder_get_connect_attempt_limit(session_builder.ptr, view, error)
        },
        &|view, error| lk_client_get_connect_attempt_limit(client.ptr, view, error),
        &|view, error| lk_session_get_connect_attempt_limit(session.ptr, view, error),
        &|view, error| lk_request_get_connect_attempt_limit(request.ptr, view, error),
    ];
    for getter in getters {
        let error = failure(|error| getter(ptr::null_mut(), error));
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_ARGUMENT
        );
    }
    let setters: [extern "C" fn(*mut lk_request_t, *mut *mut lk_error_t) -> lk_status_t; 2] = [
        lk_request_clear_extra_http_attempt_limit,
        lk_request_clear_connect_attempt_limit,
    ];
    for setter in setters {
        let error = failure(|error| setter(ptr::null_mut(), error));
        assert_eq!(
            lk_error_code(error.ptr),
            lk_error_code_t::LK_ERR_INVALID_ARGUMENT
        );
    }
}

#[test]
fn published_stream_summary_stays_frozen_on_sync_and_async_body_failure() {
    for asynchronous in [false, true] {
        let server = Server::start();
        let session = session(Some(0), 0);
        let request = request(&session, &server.url("/truncated"), true);
        let payload =
            send_sync(&request, true).unwrap_or_else(|error| panic!("{}", error_text(error.ptr)));
        let observed = payload.summary();
        assert_summary(&observed, "succeeded", 1, 0);
        let Payload::Streaming(stream) = &payload else {
            unreachable!()
        };
        let mut final_error = None;
        for _ in 0..4 {
            if asynchronous {
                let mut read_op = ptr::null_mut();
                ok(|error| lk_stream_read_async(stream.ptr, &mut read_op, error));
                let read_op = Handle::new(read_op, lk_op_free);
                let state = lk_op_wait(read_op.ptr, 5_000);
                assert_eq!(op_summary(&read_op), observed);
                if state == lk_op_state_t::LK_OP_COMPLETED_ERR {
                    let mut error = ptr::null_mut();
                    assert_eq!(
                        lk_op_take_error(read_op.ptr, &mut error),
                        lk_status_t::LK_OK
                    );
                    final_error = Some(Handle::new(error, lk_error_free));
                    assert_eq!(op_summary(&read_op), observed);
                    break;
                }
                assert_eq!(state, lk_op_state_t::LK_OP_COMPLETED_OK);
                let mut chunk = lk_chunk_view_t::default();
                ok(|error| lk_op_take_chunk(read_op.ptr, &mut chunk, error));
                assert!(!chunk.is_final, "truncated body must not report clean EOF");
            } else {
                let mut chunk = lk_chunk_view_t::default();
                let mut error = ptr::null_mut();
                let status = lk_stream_read(stream.ptr, &mut chunk, &mut error);
                if status == lk_status_t::LK_ERR {
                    final_error = Some(Handle::new(error, lk_error_free));
                    break;
                }
                assert!(error.is_null());
                assert!(!chunk.is_final, "truncated body must not report clean EOF");
            }
        }
        let error = final_error.expect("truncated response must fail while reading its body");
        assert_eq!(error_summary(&error), observed);
        assert_eq!(payload.summary(), observed);
        let mut chunk = lk_chunk_view_t::default();
        let repeated_error = failure(|error| lk_stream_read(stream.ptr, &mut chunk, error));
        assert_eq!(error_summary(&repeated_error), observed);
    }
}
