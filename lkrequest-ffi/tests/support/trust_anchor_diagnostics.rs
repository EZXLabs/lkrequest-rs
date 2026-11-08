use lkrequest_ffi::*;
use std::{
    ffi::{CStr, CString},
    io::{Read, Write},
    net::TcpListener,
    ptr,
    sync::Arc,
    time::Duration,
};

#[allow(dead_code)]
#[path = "../../../lkrequest/tests/support/trust_anchor_peer.rs"]
mod peer;

fn run(fail_second: bool) -> serde_json::Value {
    let trusted = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Untrusted FFI TAI CA");
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let other = rcgen::CertifiedKey {
        cert: params.self_signed(&signing_key).unwrap(),
        signing_key,
    };
    let id = lkrequest::TrustAnchorId::from_hex("81fd5901").unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![trusted.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(trusted.signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = CString::new(format!("https://{}/test", listener.local_addr().unwrap())).unwrap();
    let server_id = id.clone();
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        for attempt in 0..2 {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("FFI TAI accept: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let hello = peer::read_hello(&mut socket);
            if attempt == 0 || fail_second {
                socket
                    .write_all(&peer::rejected_chain_flight(
                        &hello,
                        &other,
                        std::slice::from_ref(&server_id),
                    ))
                    .unwrap();
                continue;
            }
            assert_eq!(peer::ids(&hello), vec![server_id.clone()]);
            let mut connection = rustls::ServerConnection::new(tls.clone()).unwrap();
            connection
                .read_tls(&mut std::io::Cursor::new(hello))
                .unwrap();
            connection.process_new_packets().unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
                assert!(head.len() < 4096);
            }
            assert!(head.starts_with(b"POST /test HTTP/1.1"));
            let mut body = [0; 7];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"payload");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            stream.flush().unwrap();
        }
    });
    let builder = lk_client_builder_new();
    assert_eq!(
        lk_client_builder_set_preset(builder, c"chrome_157".as_ptr()),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_add_ca_cert_memory(
            builder,
            trusted.cert.der().as_ptr(),
            trusted.cert.der().len()
        ),
        lk_status_t::LK_OK
    );
    let anchor =
        lkrequest::lktls::verify::certchain::parse_trust_anchor_from_der(trusted.cert.der())
            .unwrap();
    let binding = serde_json::to_string(&lkrequest::TrustAnchorBinding {
        anchor_identity: lkrequest::lktls::trust_anchor::anchor_identity(&anchor),
        id,
    })
    .unwrap();
    assert_eq!(
        lk_client_builder_add_trust_anchor_binding_json(
            builder,
            binding.as_ptr().cast(),
            binding.len()
        ),
        lk_status_t::LK_OK
    );
    let policy = r#"{"recovery":"once"}"#;
    assert_eq!(
        lk_client_builder_set_trust_anchor_policy_json(
            builder,
            policy.as_ptr().cast(),
            policy.len()
        ),
        lk_status_t::LK_OK
    );
    let mut client = ptr::null_mut();
    let mut error = ptr::null_mut();
    assert_eq!(
        lk_client_builder_build(builder, &mut client, &mut error),
        lk_status_t::LK_OK
    );
    lk_client_builder_free(builder);
    let session_builder = lk_session_builder_new(client);
    assert_eq!(
        lk_session_builder_set_http1_only(session_builder),
        lk_status_t::LK_OK
    );
    let mut session = ptr::null_mut();
    assert_eq!(
        lk_session_builder_build(session_builder, &mut session, &mut error),
        lk_status_t::LK_OK
    );
    lk_session_builder_free(session_builder);
    let mut request = ptr::null_mut();
    assert_eq!(
        lk_request_new(
            session,
            c"POST".as_ptr(),
            4,
            url.as_ptr(),
            url.as_bytes().len(),
            &mut request,
            &mut error
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_request_set_body_bytes(request, b"payload".as_ptr(), 7),
        lk_status_t::LK_OK
    );
    let mut response = ptr::null_mut();
    let status = lk_request_send(request, &mut response, &mut error);
    let mut json = ptr::null();
    if fail_second {
        assert_ne!(status, lk_status_t::LK_OK);
        assert!(response.is_null());
        assert_eq!(
            lk_error_get_diagnostics_json(error, &mut json),
            lk_status_t::LK_OK
        );
    } else {
        assert_eq!(status, lk_status_t::LK_OK);
        assert_eq!(lk_response_status(response), 200);
        assert_eq!(
            lk_response_get_diagnostics_json(response, &mut json),
            lk_status_t::LK_OK
        );
    }
    let diagnostic: serde_json::Value =
        serde_json::from_str(unsafe { CStr::from_ptr(json) }.to_str().unwrap()).unwrap();
    let tai = &diagnostic["trust_anchor"];
    assert_eq!(tai["requested_ids"], serde_json::json!(["81fd5901"]));
    assert_eq!(tai["recovered"], !fail_second);
    assert_eq!(tai["authenticated"], !fail_second);
    assert_eq!(
        tai["previous_attempt"]["available_ids"],
        serde_json::json!(["81fd5901"])
    );
    assert_eq!(tai["previous_attempt"]["authenticated"], false);
    assert!(tai["previous_attempt"]["failure"].is_string());
    lk_request_free(request);
    lk_response_free(response);
    lk_error_free(error);
    lk_session_free(session);
    lk_client_free(client);
    server.join().unwrap();
    diagnostic
}

#[test]
fn tai_ffi_recovery_success_exposes_both_attempts() {
    let diagnostic = run(false);
    assert!(diagnostic["trust_anchor"]["verified_anchor"].is_string());
}

#[test]
fn tai_ffi_recovery_failure_exposes_both_causes() {
    let diagnostic = run(true);
    assert!(diagnostic["trust_anchor"]["failure"].is_string());
}
