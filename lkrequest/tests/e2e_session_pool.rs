//! Session pool tests — local HTTPS server (Tier 0).

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

async fn marked_session_cookies(pool: lkrequest::SessionPool) -> (Option<String>, Option<String>) {
    let guard = pool.acquire().await;
    guard.set_cookie("https://127.0.0.1/", "pool_identity", "discard-me");
    let before = guard.get_cookie("https://127.0.0.1/", "pool_identity");
    pool.mark_bad(&guard);
    drop(guard);
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    let next = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
        .await
        .expect("discarded guard must release the sole pool permit");
    (
        before,
        next.get_cookie("https://127.0.0.1/", "pool_identity"),
    )
}

#[tokio::test]
async fn user_issue_4_mark_bad_discards_static_session() {
    let pool = lkrequest::SessionPool::builder()
        .client(&chrome_client())
        .proxies(vec![
            lkrequest::proxy::ProxyConfig::parse("http://127.0.0.1:19001").unwrap(),
            lkrequest::proxy::ProxyConfig::parse("http://127.0.0.1:19002").unwrap(),
        ])
        .max_sessions(1)
        .bad_proxy_config(lkrequest::BadProxyConfig {
            failure_threshold: 1,
            ..lkrequest::BadProxyConfig::default()
        })
        .build();
    assert_eq!(
        marked_session_cookies(pool).await,
        (Some("discard-me".to_owned()), None)
    );
}

#[tokio::test]
async fn user_issue_4_mark_bad_discards_dynamic_session() {
    let pool = lkrequest::SessionPool::builder()
        .client(&chrome_client())
        .proxy_fn(|| "http://127.0.0.1:19001".to_owned())
        .max_sessions(1)
        .build();
    assert_eq!(
        marked_session_cookies(pool).await,
        (Some("discard-me".to_owned()), None)
    );
}

#[test]
fn user_issue_5_session_pool_builds_without_runtime() {
    let pool = lkrequest::SessionPool::builder()
        .client(&chrome_client())
        .max_sessions(1)
        .build();
    assert_eq!(pool.proxy_pool().max_concurrent(), 1);
}

#[test]
fn user_issue_5_session_mark_bad_without_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (pool, guard) = runtime.block_on(async {
        let pool = lkrequest::SessionPool::builder()
            .client(&chrome_client())
            .proxies(vec![lkrequest::proxy::ProxyConfig::parse(
                "http://127.0.0.1:19001",
            )
            .unwrap()])
            .build();
        let guard = pool.acquire().await;
        (pool, guard)
    });
    guard.set_cookie("https://127.0.0.1/", "pool_identity", "discard-me");
    pool.mark_bad(&guard);
    drop(guard);
    assert_eq!(runtime.block_on(pool.stats()).idle_sessions, 0);
    let next = runtime.block_on(pool.acquire());
    assert_eq!(next.get_cookie("https://127.0.0.1/", "pool_identity"), None);
}

#[tokio::test]
async fn user_issue_4_healthy_session_return_wakes_capacity_waiter() {
    let pool = lkrequest::SessionPool::builder()
        .client(&chrome_client())
        .max_sessions(1)
        .build();
    let first = pool.acquire().await;
    first.set_cookie("https://127.0.0.1/", "pool_identity", "keep-me");
    let next = pool.acquire();
    tokio::pin!(next);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut next)
            .await
            .is_err()
    );
    drop(first);
    let next = tokio::time::timeout(std::time::Duration::from_secs(1), next)
        .await
        .expect("idle return must wake a capacity waiter");
    assert_eq!(
        next.get_cookie("https://127.0.0.1/", "pool_identity"),
        Some("keep-me".to_owned())
    );
}

#[tokio::test]
async fn user_issue_4_idle_session_with_newly_bad_proxy_is_not_reused() {
    let first_proxy = lkrequest::proxy::ProxyConfig::parse("http://127.0.0.1:19001").unwrap();
    let identity = first_proxy.identity();
    let pool = lkrequest::SessionPool::builder()
        .client(&chrome_client())
        .proxies(vec![
            first_proxy,
            lkrequest::proxy::ProxyConfig::parse("http://127.0.0.1:19002").unwrap(),
        ])
        .max_sessions(1)
        .bad_proxy_config(lkrequest::BadProxyConfig {
            failure_threshold: 1,
            ..lkrequest::BadProxyConfig::default()
        })
        .build();
    let first = pool.acquire().await;
    first.set_cookie("https://127.0.0.1/", "pool_identity", "discard-idle");
    drop(first);
    pool.proxy_pool().mark_bad_proxy(&identity);
    let next = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire())
        .await
        .expect("an unusable idle entry must release its permit");
    assert_eq!(next.get_cookie("https://127.0.0.1/", "pool_identity"), None);
}

#[test]
fn user_issue_5_healthy_guard_returns_without_runtime() {
    let pool = lkrequest::SessionPool::builder()
        .client(&chrome_client())
        .max_sessions(1)
        .build();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let guard = runtime.block_on(pool.acquire());
    guard.set_cookie("https://127.0.0.1/", "pool_identity", "keep-me");
    drop(guard);
    assert_eq!(runtime.block_on(pool.stats()).idle_sessions, 1);
    let next = runtime.block_on(pool.acquire());
    assert_eq!(
        next.get_cookie("https://127.0.0.1/", "pool_identity"),
        Some("keep-me".to_owned())
    );
    drop(next);
    drop(runtime);
    drop(pool);
}

#[tokio::test]
async fn test_concurrent_sessions_independent() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let url = url_join(&srv.base_url, "/get");

    let guard = client.session().build();
    let guard2 = client.session().build();

    let (a, b) = tokio::join!(async { guard.get(&url).send().await }, async {
        guard2.get(&url).send().await
    },);

    assert_eq!(a.expect("a").status().as_u16(), 200);
    assert_eq!(b.expect("b").status().as_u16(), 200);
}

#[tokio::test]
async fn test_session_pool_stress() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let url = url_join(&srv.base_url, "/get");

    // Few concurrent handshakes: local BoringSSL server can reject under burst load.
    let mut handles = vec![];
    for _ in 0..3 {
        let c = client.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move {
            let s = c.session().build();
            s.get(&u).send().await
        }));
    }

    for h in handles {
        let r = h.await.expect("join");
        assert_eq!(r.expect("req").status().as_u16(), 200);
    }
}
