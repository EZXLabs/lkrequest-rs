use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Barrier;
use tokio::task::JoinSet;

use crate::client::{BenchmarkClient, ResponseSample};
use crate::config::RunConfig;
use crate::metrics::{process_usage, unix_time_ms, BenchmarkReport, ReportInput};

struct WorkerResult {
    latencies_us: Vec<u64>,
    successful_requests: u64,
    failed_requests: u64,
    response_bytes: u64,
    connection_ids: BTreeSet<u64>,
    errors: Vec<String>,
}

pub async fn run(config: RunConfig) -> Result<(), Box<dyn Error>> {
    let mut clients = Vec::with_capacity(config.sessions);
    for _ in 0..config.sessions {
        let client = BenchmarkClient::build(config.client, &config.url).await?;
        warm_up(&client, &config).await?;
        clients.push(client);
    }

    let next_request = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(config.concurrency + 1));
    let mut workers = JoinSet::new();

    for worker_index in 0..config.concurrency {
        let client = clients[worker_index % clients.len()].clone();
        let config = config.clone();
        let next_request = next_request.clone();
        let barrier = barrier.clone();
        workers.spawn(async move {
            barrier.wait().await;
            run_worker(client, config, next_request).await
        });
    }

    let usage_before = process_usage();
    let started_unix_ms = unix_time_ms();
    let started = Instant::now();
    barrier.wait().await;

    let mut latencies_us = Vec::with_capacity(config.requests as usize);
    let mut successful_requests = 0;
    let mut failed_requests = 0;
    let mut response_bytes = 0;
    let mut connection_ids = BTreeSet::new();
    let mut errors = Vec::new();

    while let Some(result) = workers.join_next().await {
        let result = result?;
        latencies_us.extend(result.latencies_us);
        successful_requests += result.successful_requests;
        failed_requests += result.failed_requests;
        response_bytes += result.response_bytes;
        connection_ids.extend(result.connection_ids);
        for error in result.errors {
            if errors.len() < 20 {
                errors.push(error);
            }
        }
    }

    let report = BenchmarkReport::build(
        &config,
        ReportInput {
            started_unix_ms,
            elapsed: started.elapsed(),
            latencies_us,
            successful_requests,
            failed_requests,
            response_bytes,
            connection_ids,
            usage_before,
            usage_after: process_usage(),
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
    Ok(())
}

async fn warm_up(client: &BenchmarkClient, config: &RunConfig) -> Result<(), Box<dyn Error>> {
    for _ in 0..config.warmup_requests {
        let sample = client
            .get(&config.url)
            .await
            .map_err(|error| error.to_string())?;
        validate_sample(&sample, config.expected_bytes).map_err(|error| {
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
) -> WorkerResult {
    let expected_per_worker = config.requests as usize / config.concurrency + 1;
    let mut result = WorkerResult {
        latencies_us: Vec::with_capacity(expected_per_worker),
        successful_requests: 0,
        failed_requests: 0,
        response_bytes: 0,
        connection_ids: BTreeSet::new(),
        errors: Vec::new(),
    };

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
            Ok(sample) => match validate_sample(&sample, config.expected_bytes) {
                Ok(()) => {
                    result.successful_requests += 1;
                    result.response_bytes += sample.body_bytes as u64;
                    if let Some(connection_id) = sample.connection_id {
                        result.connection_ids.insert(connection_id);
                    }
                }
                Err(error) => record_error(&mut result, request_index, error),
            },
            Err(error) => record_error(&mut result, request_index, error.to_string()),
        }
    }

    result
}

fn validate_sample(sample: &ResponseSample, expected_bytes: usize) -> Result<(), String> {
    if sample.status != 200 {
        return Err(format!("unexpected HTTP status {}", sample.status));
    }
    if !sample.is_http2 {
        return Err("response was not HTTP/2".into());
    }
    if sample.body_bytes != expected_bytes {
        return Err(format!(
            "expected {expected_bytes} response bytes, received {}",
            sample.body_bytes
        ));
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
        "{} h2c: {:.1} req/s, {:.1} MiB/s, p50={} us, p95={} us, p99={} us, failures={}, connections={}",
        report.client,
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
