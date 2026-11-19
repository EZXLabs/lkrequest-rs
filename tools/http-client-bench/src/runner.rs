use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Barrier};
use tokio::task::JoinSet;

use crate::allocations::Measurement;
use crate::client::{BenchmarkClient, ObservedProtocol, ResponseSample};
use crate::config::{Lifecycle, Protocol, RunConfig};
use crate::fixture_server::ServerSnapshot;
use crate::metrics::{process_usage, unix_time_ms, BenchmarkReport, ReportInput, ServerEvidence};

struct WorkerResult {
    latencies_us: Vec<u64>,
    successful_requests: u64,
    failed_requests: u64,
    response_bytes: u64,
    connection_ids: Vec<u64>,
    observed_protocols: [u64; 3],
    errors: Vec<String>,
}

pub async fn run(config: RunConfig) -> Result<(), Box<dyn Error>> {
    let before_warmup = read_server_snapshot(&config, unix_time_ms()).await?;
    let mut clients = Vec::with_capacity(config.sessions);
    for _ in 0..config.sessions {
        let client = BenchmarkClient::build(&config).await?;
        warm_up(&client, &config).await?;
        clients.push(client);
    }

    let next_request = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(config.concurrency + 1));
    let (start, start_receiver) = watch::channel(false);
    let mut workers = JoinSet::new();

    for worker_index in 0..config.concurrency {
        let client = clients[worker_index % clients.len()].clone();
        let config = config.clone();
        let next_request = next_request.clone();
        let barrier = barrier.clone();
        let start_receiver = start_receiver.clone();
        workers.spawn(async move {
            run_worker(client, config, next_request, barrier, start_receiver).await
        });
    }

    let mut results = Vec::with_capacity(config.concurrency);
    barrier.wait().await;
    let before_measured = read_server_snapshot(&config, unix_time_ms()).await?;
    let usage_before = process_usage();
    let started_unix_ms = unix_time_ms();
    let started = Instant::now();
    let measurement = Measurement::start(config.allocations);
    start.send_replace(true);
    while let Some(result) = workers.join_next().await {
        results.push(result?);
    }
    let allocations = measurement.finish();
    let elapsed = started.elapsed();
    let usage_after = process_usage();
    let after_measured = read_server_snapshot(&config, unix_time_ms()).await?;

    let server_evidence = match (before_warmup, before_measured, after_measured) {
        (Some(first), Some(second), Some(last)) => Some(ServerEvidence {
            instance_id: last.instance_id.clone(),
            address: last.address.expect("validated snapshot address"),
            warmup: second.since(&first)?,
            measured: last.since(&second)?,
        }),
        (None, None, None) => None,
        _ => return Err("incomplete benchmark server statistics".into()),
    };
    let race_starts_verified = if config.protocol == Protocol::Race {
        Some(verify_race_starts(
            server_evidence.as_ref().unwrap(),
            config.lifecycle,
        ))
    } else {
        None
    };

    let mut latencies_us = Vec::with_capacity(config.requests as usize);
    let mut successful_requests = 0;
    let mut failed_requests = 0;
    let mut response_bytes = 0;
    let mut connection_ids = BTreeSet::new();
    let mut observed_protocols = BTreeMap::new();
    let mut errors = Vec::new();

    for result in results {
        latencies_us.extend(result.latencies_us);
        successful_requests += result.successful_requests;
        failed_requests += result.failed_requests;
        response_bytes += result.response_bytes;
        connection_ids.extend(result.connection_ids);
        for (index, protocol) in [
            ObservedProtocol::H1,
            ObservedProtocol::H2,
            ObservedProtocol::H3,
        ]
        .into_iter()
        .enumerate()
        {
            if result.observed_protocols[index] > 0 {
                *observed_protocols.entry(protocol).or_insert(0) +=
                    result.observed_protocols[index];
            }
        }
        for error in result.errors {
            if errors.len() < 20 {
                errors.push(error);
            }
        }
    }
    if race_starts_verified == Some(false) {
        errors.push("race was not qualified: both TCP accepts and QUIC Initial arrivals are required in the selected window".into());
    }

    let report = BenchmarkReport::build(
        &config,
        ReportInput {
            started_unix_ms,
            elapsed,
            latencies_us,
            successful_requests,
            failed_requests,
            response_bytes,
            connection_ids,
            usage_before,
            usage_after,
            allocations,
            observed_protocols,
            server_evidence,
            race_starts_verified,
            errors,
        },
    );

    print_report(&report);
    if let Some(path) = &config.output {
        write_report(path, &report)?;
    }
    if report.failed_requests > 0 {
        return Err(format!("{} benchmark requests failed", report.failed_requests).into());
    }
    if report.race_starts_verified == Some(false) {
        return Err(
            "benchmark did not demonstrate both race transport starts; report is unqualified"
                .into(),
        );
    }
    Ok(())
}

async fn warm_up(client: &BenchmarkClient, config: &RunConfig) -> Result<(), Box<dyn Error>> {
    for _ in 0..config.warmup_requests {
        let sample = client
            .get(&config.url)
            .await
            .map_err(|error| error.to_string())?;
        validate_sample(&sample, config.expected_bytes, config.protocol).map_err(|error| {
            format!(
                "warm-up response validation failed for {}: {error}",
                config.client
            )
        })?;
    }
    Ok(())
}

async fn run_worker(
    client: BenchmarkClient,
    config: RunConfig,
    next_request: Arc<AtomicU64>,
    barrier: Arc<Barrier>,
    mut start: watch::Receiver<bool>,
) -> WorkerResult {
    let expected_per_worker = config.requests as usize / config.concurrency + 1;
    let mut result = WorkerResult {
        latencies_us: Vec::with_capacity(expected_per_worker),
        successful_requests: 0,
        failed_requests: 0,
        response_bytes: 0,
        connection_ids: Vec::with_capacity(expected_per_worker),
        observed_protocols: [0; 3],
        errors: Vec::new(),
    };
    barrier.wait().await;
    if start.wait_for(|started| *started).await.is_err() {
        return result;
    }

    loop {
        let request_index = next_request.fetch_add(1, Ordering::Relaxed);
        if request_index >= config.requests {
            break;
        }
        let started = Instant::now();
        let sample = client.get(&config.url).await;
        let elapsed_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        result.latencies_us.push(elapsed_us);

        match sample {
            Ok(sample) => match validate_sample(&sample, config.expected_bytes, config.protocol) {
                Ok(()) => {
                    result.successful_requests += 1;
                    result.response_bytes += sample.body_bytes as u64;
                    if let Some(connection_id) = sample.connection_id {
                        result.connection_ids.push(connection_id);
                    }
                    let index = match sample.protocol {
                        ObservedProtocol::H1 => 0,
                        ObservedProtocol::H2 => 1,
                        ObservedProtocol::H3 => 2,
                    };
                    result.observed_protocols[index] += 1;
                }
                Err(error) => record_error(&mut result, request_index, error),
            },
            Err(error) => record_error(&mut result, request_index, error.to_string()),
        }
    }

    result
}

fn validate_sample(
    sample: &ResponseSample,
    expected_bytes: usize,
    protocol: Protocol,
) -> Result<(), String> {
    if sample.status != 200 {
        return Err(format!("unexpected HTTP status {}", sample.status));
    }
    let matches_protocol = matches!(
        (protocol, sample.protocol),
        (Protocol::H1, ObservedProtocol::H1)
            | (Protocol::H2c, ObservedProtocol::H2)
            | (Protocol::H3, ObservedProtocol::H3)
            | (Protocol::Race, ObservedProtocol::H2 | ObservedProtocol::H3)
    );
    if !matches_protocol {
        return Err(format!(
            "unexpected {:?} response for {}",
            sample.protocol,
            protocol.report_name()
        ));
    }
    if sample.body_bytes != expected_bytes {
        return Err(format!(
            "expected {expected_bytes} response bytes, received {}",
            sample.body_bytes
        ));
    }
    if sample.connection_id.is_none() {
        return Err("response has no valid x-bench-connection-id".into());
    }
    Ok(())
}

fn record_error(result: &mut WorkerResult, request_index: u64, error: String) {
    result.failed_requests += 1;
    if result.errors.len() < 5 {
        result
            .errors
            .push(format!("request {request_index}: {error}"));
    }
}

fn print_report(report: &BenchmarkReport) {
    println!(
        "{} {} {:?}: {:.1} req/s, {:.1} MiB/s, p50={} us, p95={} us, p99={} us, failures={}, connections={}",
        report.client,
        report.protocol,
        report.lifecycle,
        report.requests_per_second,
        report.mebibytes_per_second,
        report.latency.p50_us,
        report.latency.p95_us,
        report.latency.p99_us,
        report.failed_requests,
        report.observed_connection_count
    );
    println!(
        "CPU user/system: {:.3}/{:.3} s, peak RSS: {:.1} MiB",
        report.user_cpu_seconds,
        report.system_cpu_seconds,
        report.peak_rss_bytes as f64 / (1024.0 * 1024.0)
    );
    if let Some(allocations) = &report.allocations {
        println!(
            "Allocation sample: alloc={}, realloc={}, requested bytes={}",
            allocations.allocation_calls,
            allocations.reallocation_calls,
            allocations.requested_bytes
        );
    }
}

fn verify_race_starts(evidence: &ServerEvidence, lifecycle: Lifecycle) -> bool {
    let tcp = evidence.measured.tcp_accepts;
    let quic = evidence.measured.quic_incoming;
    match lifecycle {
        Lifecycle::Cold => tcp > 0 && quic > 0,
        Lifecycle::Warm => {
            (tcp > 0 || evidence.warmup.tcp_accepts > 0)
                && (quic > 0 || evidence.warmup.quic_incoming > 0)
        }
    }
}

async fn read_server_snapshot(
    config: &RunConfig,
    after_ms: u128,
) -> Result<Option<ServerSnapshot>, Box<dyn Error>> {
    let Some(path) = &config.server_stats else {
        return Ok(None);
    };
    let uri: http::Uri = config.url.parse()?;
    let address = std::net::SocketAddr::new(
        crate::config::loopback_address(&uri).ok_or("statistics URL must be loopback")?,
        uri.port_u16()
            .unwrap_or(if config.protocol.uses_tls() { 443 } else { 80 }),
    );
    let mut last_error = String::new();
    for _ in 0..40 {
        let read = std::fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<ServerSnapshot>(&bytes).map_err(|error| error.to_string())
            });
        match read {
            Ok(snapshot)
                if snapshot.sampled_unix_ms > after_ms
                    && snapshot.protocol == config.protocol
                    && snapshot.address == Some(address) =>
            {
                return Ok(Some(snapshot))
            }
            Ok(snapshot) => {
                last_error = format!(
                    "stale or mismatched snapshot: {:?} {:?} at {}",
                    snapshot.protocol, snapshot.address, snapshot.sampled_unix_ms
                )
            }
            Err(error) => last_error = error,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!(
        "could not read fresh server statistics from {}: {last_error}",
        path.display()
    )
    .into())
}

fn write_report(path: &Path, report: &BenchmarkReport) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_server::ServerActivity;

    #[test]
    fn validates_negotiation_and_physical_connection_identity() {
        let mut sample = ResponseSample {
            status: 200,
            body_bytes: 1024,
            connection_id: Some(1),
            protocol: ObservedProtocol::H2,
        };
        assert!(validate_sample(&sample, 1024, Protocol::Race).is_ok());
        assert!(validate_sample(&sample, 1024, Protocol::H3).is_err());
        sample.protocol = ObservedProtocol::H3;
        assert!(validate_sample(&sample, 1024, Protocol::Race).is_ok());
        sample.protocol = ObservedProtocol::H1;
        assert!(validate_sample(&sample, 1024, Protocol::Race).is_err());
        sample.connection_id = None;
        assert!(validate_sample(&sample, 1024, Protocol::H1).is_err());
    }

    #[test]
    fn cold_race_cannot_be_qualified_by_warmup_or_h3_only() {
        let mut evidence = ServerEvidence {
            instance_id: "test".into(),
            address: "127.0.0.1:18481".parse().unwrap(),
            warmup: ServerActivity {
                tcp_accepts: 1,
                quic_incoming: 1,
                ..Default::default()
            },
            measured: ServerActivity::default(),
        };
        assert!(verify_race_starts(&evidence, Lifecycle::Warm));
        assert!(!verify_race_starts(&evidence, Lifecycle::Cold));
        evidence.measured.quic_incoming = 10;
        evidence.measured.h3_requests = 10;
        assert!(!verify_race_starts(&evidence, Lifecycle::Cold));
        evidence.measured.tcp_accepts = 10;
        assert!(verify_race_starts(&evidence, Lifecycle::Cold));
    }
}
