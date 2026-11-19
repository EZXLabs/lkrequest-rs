use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lkrequest::proxy::{
    BufferedProxyProvider, FnProxyProvider, ProxyAuthenticator, ProxyConfig, ProxyProvider,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use super::support::{bounded, client, header, read_headers};

#[test]
fn issue27_2_failed_proxy_fn_has_bounded_retry_rate() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = FnProxyProvider::new({
        let calls = calls.clone();
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            "not a proxy url".into()
        }
    });
    let buffered = BufferedProxyProvider::new(Box::new(provider), 4);
    let started = std::time::Instant::now();
    while calls.load(Ordering::SeqCst) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "filler thread never ran"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let before = calls.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(200));
    drop(buffered);
    let count = calls.load(Ordering::SeqCst) - before;
    eprintln!("failed proxy_fn calls in approximately 200ms={count}");
    assert!(count <= 20, "failed provider is spinning: {count} calls");
}

struct EmptyStaticProvider(Arc<AtomicUsize>);

impl ProxyProvider for EmptyStaticProvider {
    fn next_proxy(&self) -> Option<ProxyConfig> {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }
    fn len(&self) -> usize {
        0
    }
}

#[test]
fn issue27_2_empty_static_provider_does_not_start_filler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let buffered = BufferedProxyProvider::new(Box::new(EmptyStaticProvider(calls.clone())), 4);
    std::thread::sleep(Duration::from_millis(100));
    drop(buffered);
    let count = calls.load(Ordering::SeqCst);
    eprintln!("empty static provider background calls={count}");
    assert_eq!(
        count, 0,
        "an empty static source has nothing to pre-generate"
    );
}

#[test]
fn control_buffered_provider_returns_valid_proxy() {
    let provider = FnProxyProvider::new(|| "http://127.0.0.1:9".into());
    let buffered = BufferedProxyProvider::new(Box::new(provider), 4);
    assert!(buffered.next_proxy().is_some());
}

struct Target {
    url: String,
    hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Target {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = format!("http://{}/direct", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let hits = hits.clone();
            async move {
                let mut handlers = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut stream, _) = accepted.unwrap();
                            // Count the connection too: even a connection without a request leaks routing.
                            hits.fetch_add(1, Ordering::SeqCst);
                            handlers.spawn(async move {
                                let _ = read_headers(&mut stream).await;
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                            });
                        }
                        Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                            result.unwrap();
                        }
                    }
                }
            }
        });
        Self { url, hits, task }
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn issue27_3_invalid_session_proxy_never_connects_direct() {
    let target = Target::start().await;
    let session = client().session().proxy("htp://127.0.0.1:9").build();
    let mut errors = Vec::new();
    for _ in 0..2 {
        errors.push(
            bounded(session.get(&target.url).send())
                .await
                .err()
                .map(|e| e.to_string()),
        );
    }
    let hits = target.hits.load(Ordering::SeqCst);
    eprintln!("invalid session proxy: errors={errors:?} direct_connections={hits}");
    assert_eq!(hits, 0, "invalid proxy silently allowed direct connections");
    assert!(errors.iter().all(Option::is_some));
}

#[tokio::test]
async fn control_invalid_request_proxy_is_rejected() {
    let target = Target::start().await;
    let session = client().session().build();
    let error = bounded(session.get(&target.url).proxy("htp://127.0.0.1:9").send())
        .await
        .unwrap_err();
    assert!(
        matches!(error, lkrequest::error::Error::InvalidConfig(_)),
        "{error}"
    );
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
}

struct Tokens(AtomicUsize);

impl ProxyAuthenticator for Tokens {
    fn identity_fragment(&self) -> String {
        "poc-one-time-tokens".into()
    }
    fn authorization_value(&self) -> Option<String> {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Some(format!("Bearer token-{n}"))
    }
}

async fn auth_attempt(challenge: Option<&'static str>) -> (usize, Vec<Option<String>>) {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let seen = seen.clone();
            async move {
                for index in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let headers = read_headers(&mut stream).await;
                    assert!(headers.starts_with("CONNECT target.test:443 HTTP/1.1\r\n"));
                    seen.lock().unwrap().push(header(&headers, "proxy-authorization").map(str::to_string));
                    let response = match (index, challenge) {
                        (0, Some(challenge)) => format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                        _ => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            }
        });
        let tokens = Arc::new(Tokens(AtomicUsize::new(0)));
        let proxy = ProxyConfig::parse(&format!("http://{addr}"))
            .unwrap().with_custom_auth(tokens.clone()).unwrap();
        let result = proxy.connect("target.test", 443, None, &lkrequest::dns::SystemDns).await;
        assert!(result.is_err(), "the scripted proxy always refuses the tunnel");
        task.abort();
        let _ = task.await;
        let calls = tokens.0.load(Ordering::SeqCst);
        let seen = seen.lock().unwrap().clone();
        eprintln!("challenge={challenge:?} credential_calls={calls} wire_credentials={seen:?} result={:?}", result.err());
        (calls, seen)
    }).await
}

#[tokio::test]
async fn issue27_5_basic_challenge_does_not_consume_unsent_token() {
    let (calls, seen) = auth_attempt(Some("Basic realm=\"proxy\"")).await;
    assert_eq!(seen.len(), 2, "Basic retry positive control");
    assert_eq!(
        calls, 2,
        "one authorization callback per actual CONNECT attempt"
    );
    assert_eq!(
        seen,
        vec![Some("Bearer token-1".into()), Some("Bearer token-2".into())]
    );
}

#[tokio::test]
async fn issue27_5_non_basic_challenge_does_not_consume_unsent_token() {
    let (calls, seen) =
        auth_attempt(Some("PrivateToken challenge=\"AAE\", token-key=\"AAE\"")).await;
    assert!(calls <= 2);
    assert_eq!(
        calls,
        seen.len(),
        "computed a token that was never transmitted"
    );
}

#[tokio::test]
async fn issue27_5_custom_auth_can_retry_non_basic_challenge() {
    let (_, seen) = auth_attempt(Some("PrivateToken challenge=\"AAE\", token-key=\"AAE\"")).await;
    assert_eq!(
        seen.len(),
        2,
        "custom authentication must not be restricted to Basic challenges"
    );
}

#[tokio::test]
async fn control_proxy_without_challenge_uses_one_token() {
    let (calls, seen) = auth_attempt(None).await;
    assert_eq!(calls, 1);
    assert_eq!(seen, vec![Some("Bearer token-1".into())]);
}

struct ChallengeAuth {
    initial: AtomicUsize,
    challenges: Mutex<Vec<Vec<String>>>,
    answer: Option<&'static str>,
}

impl ProxyAuthenticator for ChallengeAuth {
    fn identity_fragment(&self) -> String {
        "challenge-fixture".into()
    }
    fn authorization_value(&self) -> Option<String> {
        self.initial.fetch_add(1, Ordering::SeqCst);
        None
    }
    fn authorization_for_challenge(&self, challenges: &[&str]) -> Option<String> {
        self.challenges
            .lock()
            .unwrap()
            .push(challenges.iter().map(|s| s.to_string()).collect());
        self.answer.map(str::to_owned)
    }
}

#[tokio::test]
async fn challenge_callback_receives_all_fields_once_and_can_decline() {
    bounded(async {
        for answer in [Some("PrivateToken response"), None, Some("Bad\r\nInjected: value")] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut first, _) = listener.accept().await.unwrap();
                let first_headers = read_headers(&mut first).await;
                assert!(header(&first_headers, "proxy-authorization").is_none());
                first.write_all(b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Digest realm=\"a,b\", nonce=\"abc\"\r\nProxy-Authenticate: PrivateToken challenge=\"AAE\"\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                drop(first);
                let (mut second, _) = listener.accept().await.unwrap();
                if answer == Some("PrivateToken response") {
                    let request = read_headers(&mut second).await;
                    assert_eq!(header(&request, "proxy-authorization"), answer);
                    second.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                } else {
                    let mut data = Vec::new();
                    second.read_to_end(&mut data).await.unwrap();
                    assert!(data.is_empty(), "declined/invalid authorization sent bytes");
                }
            });
            let auth = Arc::new(ChallengeAuth { initial: AtomicUsize::new(0), challenges: Mutex::new(Vec::new()), answer });
            let proxy = ProxyConfig::parse(&format!("http://{addr}")).unwrap().with_custom_auth(auth.clone()).unwrap();
            let result = proxy.connect("target.test", 443, None, &lkrequest::dns::SystemDns).await;
            assert_eq!(result.is_ok(), answer == Some("PrivateToken response"));
            assert_eq!(auth.initial.load(Ordering::SeqCst), 1);
            assert_eq!(*auth.challenges.lock().unwrap(), vec![vec!["Digest realm=\"a,b\", nonce=\"abc\"", "PrivateToken challenge=\"AAE\""]]);
            server.await.unwrap();
        }
    }).await;
}

#[tokio::test]
async fn invalid_session_proxy_rejects_streaming_preconnect_and_websocket() {
    let target = Target::start().await;
    let session = client().session().proxy("htp://127.0.0.1:9").build();
    assert!(bounded(session.get(&target.url).send_streaming())
        .await
        .is_err());
    assert!(bounded(session.preconnect(&target.url)).await.is_err());
    assert!(bounded(
        session
            .websocket(&target.url.replace("http://", "ws://"))
            .connect()
    )
    .await
    .is_err());
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
}
