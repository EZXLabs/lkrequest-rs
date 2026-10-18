//! Shared-connection WebSocket sends must progress while recv is pending.

mod support;

use std::future::{poll_fn, Future};
use std::task::Poll;
use std::time::Duration;

use lkrequest::ws::WsMessage;
use lkrequest::Client;

fn client() -> Client {
    Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .verify(false)
        .build()
}

#[tokio::test]
async fn ws_pending_recv_allows_send() {
    let wss = support::local_wss::start_local_wss_server().await;
    let session = client().session().http1_only().build();
    let ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("connect");
    fn assert_shareable<T: Send + Sync>(_: &T) {}
    assert_shareable(&ws);
    let pending_recv = ws.recv();
    tokio::pin!(pending_recv);
    poll_fn(|cx| {
        assert!(pending_recv.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    tokio::time::timeout(Duration::from_secs(2), ws.send_text("sent during recv"))
        .await
        .expect("send must not wait for recv")
        .expect("send");
    let reply = tokio::time::timeout(Duration::from_secs(2), pending_recv)
        .await
        .expect("echo timeout")
        .expect("recv");
    assert!(matches!(reply, WsMessage::Text(text) if text == "sent during recv"));
}

#[tokio::test]
async fn ws_pending_recv_allows_close() {
    let wss = support::local_wss::start_local_wss_server().await;
    let session = client().session().http1_only().build();
    let ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("connect");
    let pending_recv = ws.recv();
    tokio::pin!(pending_recv);
    poll_fn(|cx| {
        assert!(pending_recv.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    tokio::time::timeout(Duration::from_secs(2), ws.close(Some((1000, "done"))))
        .await
        .expect("close must not wait for recv")
        .expect("close");
    let reply = tokio::time::timeout(Duration::from_secs(2), pending_recv)
        .await
        .expect("close reply timeout")
        .expect("recv close");
    assert!(matches!(reply, WsMessage::Close(Some(1000), _)));
}
