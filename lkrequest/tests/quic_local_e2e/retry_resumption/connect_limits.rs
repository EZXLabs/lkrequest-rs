use super::*;
use lkrequest::{AttemptDenialReason, AttemptLimits, AttemptOutcome};

#[tokio::test]
async fn resumed_handshake_failure_survives_denied_tcp_fallback() {
    let events = Arc::new(EarlyEvents::default());
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(ObserveEarly(events.clone())),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        for cap in [2, 1] {
            let ready_before = events.ready.load(Ordering::SeqCst);
            let (mut peer, mut tcp) = paired_peer(ResumeAction::CloseHandshake);
            let port = peer.endpoint.local_addr().unwrap().port();
            let url = format!("https://localhost:{port}");
            let client = lkrequest::Client::builder()
                .preset(lkrequest::preset::chrome_155())
                .tls_session_cache_partition_policy(lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned)
                .dns_resolver(Arc::new(AdvertisedH3Dns { port }))
                .retry_on_connection_close(false)
                .timeout_config(lkrequest::TimeoutConfig::default()
                    .with_quic_connect_timeout(Duration::from_secs(2))
                    .with_ttfb_timeout(Duration::from_secs(3))
                    .with_total_timeout(Duration::from_secs(4)))
                .verify(false).build();
            let warm = client.session().http3_only().build();
            assert_eq!(warm.get(&format!("{url}/warm")).send().await.unwrap().bytes(), b"complete");
            drop(warm);
            let session = client.session().http3_with_fallback()
                .protocol_policy(ProtocolPolicy::chrome_standard()
                    .with_acquisition(AcquisitionPolicy::EstablishBestAvailable)
                    .with_upgrade(UpgradePolicy::Off)
                    .with_fallback(FallbackPolicy::AllowFallback))
                .max_connections(1).build();
            let mut request = Box::pin(session.get(&format!("{url}/case"))
                .attempt_limits(AttemptLimits::default().with_connect_attempts(cap))
                .send_with_attempt_summary());
            tokio::select! {
                result = &mut request => panic!("resumed handshake completed before release: {result:?}"),
                _ = async {
                    while peer.connections.load(Ordering::SeqCst) < 2
                        || events.ready.load(Ordering::SeqCst) == ready_before
                    {
                        tokio::task::yield_now().await;
                    }
                } => {},
            }
            peer.release_resume.take().unwrap().send(()).unwrap();
            let (result, summary) = request.await;
            assert_eq!(events.ready.load(Ordering::SeqCst), ready_before + 1);
            assert_eq!(peer.connections.load(Ordering::SeqCst), 2);
            assert_eq!(*peer.requests.lock().unwrap(), [(0, "/warm".to_owned())]);
            assert_eq!(summary.connect_initiations(), cap);
            if cap == 2 {
                let response = result.unwrap();
                assert_eq!(response.version(), lkrequest::HttpVersion::Http11);
                assert_eq!(response.bytes(), b"tcp-complete");
                assert_eq!(*tcp.requests.lock().unwrap(), ["/case"]);
                assert_eq!(summary.outcome(), AttemptOutcome::Succeeded);
                assert_eq!(summary.denial_reason(), None);
            } else {
                let error = result.unwrap_err();
                assert!(error.is_quic_handshake_failure(), "original QUIC failure: {error:?}");
                assert!(error.to_string().contains("aborted by peer"), "{error}");
                assert!(tcp.requests.lock().unwrap().is_empty());
                assert_eq!(summary.outcome(), AttemptOutcome::Failed);
                assert_eq!(summary.denial_reason(), Some(AttemptDenialReason::ConnectLimit));
            }
            drop(session);
            drop(client);
            peer.endpoint.close(0u32.into(), b"connect limit fixture complete");
            peer.endpoint.wait_idle().await;
            (&mut peer.task).await.unwrap();
            tcp.stop.take().unwrap().send(()).unwrap();
            (&mut tcp.task).await.unwrap();
        }
    }).await.expect("bounded resumed handshake limit fixture");
}
