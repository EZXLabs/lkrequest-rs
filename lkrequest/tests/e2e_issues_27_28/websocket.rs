use std::net::Ipv4Addr;
use std::sync::Arc;

use base64::Engine;
use lkrequest::ws::WsMessage;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use super::support::{bounded, client, header, read_headers, server_tls};

// RFC 7692 section 7.2.3.1: raw DEFLATE payload for "Hello", without the sync tail.
const COMPRESSED_HELLO: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

#[test]
fn control_rfc7692_compressed_fixture_decodes() {
    let mut input = COMPRESSED_HELLO.to_vec();
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
    let mut inflater = flate2::Decompress::new(false);
    let mut output = [0u8; 64];
    inflater
        .decompress(&input, &mut output, flate2::FlushDecompress::Sync)
        .unwrap();
    assert_eq!(&output[..inflater.total_out() as usize], b"Hello");
}

async fn receive(offered: bool, compressed: bool, fragmented: bool) -> WsMessage {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = format!("wss://{}/ws", listener.local_addr().unwrap());
        let acceptor = TlsAcceptor::from(Arc::new(server_tls(&[b"http/1.1"])));
        let (done, wait_done) = oneshot::channel::<()>();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let request = read_headers(&mut tls).await;
            let offer = header(&request, "sec-websocket-extensions");
            assert_eq!(offer, offered.then_some("permessage-deflate; client_max_window_bits"));
            let key = header(&request, "sec-websocket-key").unwrap();
            let digest = aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
            );
            let accept = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
            let extension = if offered { "Sec-WebSocket-Extensions: permessage-deflate\r\n" } else { "" };
            tls.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{extension}\r\n").as_bytes()).await.unwrap();
            let payload = if compressed { COMPRESSED_HELLO } else { b"Hello" };
            let mut wire = Vec::new();
            if fragmented {
                wire.extend_from_slice(&[if compressed { 0x41 } else { 0x01 }, 3]);
                wire.extend_from_slice(&payload[..3]);
                wire.extend_from_slice(&[0x80, (payload.len()-3) as u8]);
                wire.extend_from_slice(&payload[3..]);
            } else {
                wire.extend_from_slice(&[if compressed { 0xc1 } else { 0x81 }, payload.len() as u8]);
                wire.extend_from_slice(payload);
            }
            tls.write_all(&wire).await.unwrap();
            tls.flush().await.unwrap();
            let _ = wait_done.await;
        });
        let session = client().session().build();
        let mut builder = session.websocket(&url);
        if offered { builder = builder.extension("permessage-deflate; client_max_window_bits"); }
        let ws = builder.connect().await.expect("the local upgrade must succeed");
        let message = ws.recv().await;
        let _ = done.send(());
        peer.await.expect("WSS peer panicked");
        eprintln!("offered={offered} compressed={compressed} fragmented={fragmented} received={message:?}");
        message.unwrap()
    }).await
}

#[tokio::test]
async fn control_websocket_without_extension_receives_plain_text() {
    assert!(matches!(receive(false, false, false).await, WsMessage::Text(text) if text == "Hello"));
}
#[tokio::test]
async fn control_websocket_negotiated_deflate_allows_plain_message() {
    assert!(matches!(receive(true, false, false).await, WsMessage::Text(text) if text == "Hello"));
}
#[tokio::test]
async fn issue27_6_negotiated_deflate_receives_compressed_text() {
    assert!(matches!(receive(true, true, false).await, WsMessage::Text(text) if text == "Hello"));
}
#[tokio::test]
async fn issue27_6_negotiated_deflate_receives_fragmented_compressed_text() {
    assert!(matches!(receive(true, true, true).await, WsMessage::Text(text) if text == "Hello"));
}
