use super::TestServer;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn accepts_delayed_request_bytes() {
    let mut server = TestServer::start();
    let result = (|| -> std::io::Result<Vec<u8>> {
        let mut socket = TcpStream::connect(server.addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        thread::sleep(Duration::from_millis(100));
        socket.write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\n")?;
        thread::sleep(Duration::from_millis(100));
        socket.write_all(b"Connection: close\r\n\r\n")?;
        let mut response = Vec::new();
        socket.read_to_end(&mut response)?;
        Ok(response)
    })();
    server.stop.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(server.addr);
    let joined = server.thread.take().unwrap().join();
    assert!(
        joined.is_ok(),
        "test server panicked before receiving delayed bytes"
    );
    let response = result.expect("delayed request must succeed");
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
}

#[test]
fn cleanup_preserves_original_panic() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "server_regressions::cleanup_unwind_child",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cleanup aborted child: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cleanup_reports_server_failure_without_active_unwind() {
    let failure = std::panic::catch_unwind(|| {
        drop(TestServer {
            addr: "127.0.0.1:0".parse().unwrap(),
            stop: Arc::new(AtomicBool::new(false)),
            thread: Some(thread::spawn(|| panic!("server failure"))),
        });
    });
    assert!(
        failure.is_err(),
        "server-side assertions must not be suppressed"
    );
}

#[test]
#[ignore = "subprocess fixture invoked by cleanup_preserves_original_panic"]
fn cleanup_unwind_child() {
    let failure = std::panic::catch_unwind(|| {
        let _server = TestServer {
            addr: "127.0.0.1:0".parse().unwrap(),
            stop: Arc::new(AtomicBool::new(false)),
            thread: Some(thread::spawn(|| panic!("server failure"))),
        };
        panic!("original test failure");
    })
    .expect_err("test panic must propagate");
    assert_eq!(
        failure.downcast_ref::<&str>(),
        Some(&"original test failure")
    );
}
