use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::RunConfig;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessUsage {
    pub user_cpu: Duration,
    pub system_cpu: Duration,
    pub peak_rss_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct LatencySummary {
    pub min_us: u64,
    pub mean_us: f64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[derive(Debug, Serialize)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub started_unix_ms: u128,
    pub client: crate::config::ClientName,
    pub client_version: &'static str,
    pub tokio_version: &'static str,
    pub benchmark_version: &'static str,
    pub url: String,
    pub protocol: &'static str,
    pub requests: u64,
    pub concurrency: usize,
    pub sessions: usize,
    pub warmup_requests: u64,
    pub runtime_workers: usize,
    pub expected_body_bytes: usize,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub response_bytes: u64,
    pub elapsed_seconds: f64,
    pub requests_per_second: f64,
    pub mebibytes_per_second: f64,
    pub latency: LatencySummary,
    pub observed_connection_ids: BTreeSet<u64>,
    pub observed_connection_count: usize,
    pub user_cpu_seconds: f64,
    pub system_cpu_seconds: f64,
    pub peak_rss_bytes: u64,
    pub os: &'static str,
    pub architecture: &'static str,
    pub errors: Vec<String>,
}

pub struct ReportInput {
    pub started_unix_ms: u128,
    pub elapsed: Duration,
    pub latencies_us: Vec<u64>,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub response_bytes: u64,
    pub connection_ids: BTreeSet<u64>,
    pub usage_before: ProcessUsage,
    pub usage_after: ProcessUsage,
    pub errors: Vec<String>,
}

impl BenchmarkReport {
    pub fn build(config: &RunConfig, input: ReportInput) -> Self {
        let latency = summarize_latencies(input.latencies_us);
        let elapsed_seconds = input.elapsed.as_secs_f64();
        let requests_per_second = input.successful_requests as f64 / elapsed_seconds;
        let mebibytes_per_second =
            input.response_bytes as f64 / (1024.0 * 1024.0) / elapsed_seconds;
        let observed_connection_count = input.connection_ids.len();

        Self {
            schema_version: 1,
            started_unix_ms: input.started_unix_ms,
            client: config.client,
            client_version: client_version(config.client),
            tokio_version: env!("BENCH_TOKIO_VERSION"),
            benchmark_version: env!("CARGO_PKG_VERSION"),
            url: config.url.clone(),
            protocol: "h2c-prior-knowledge",
            requests: config.requests,
            concurrency: config.concurrency,
            sessions: config.sessions,
            warmup_requests: config.warmup_requests,
            runtime_workers: config.runtime_workers,
            expected_body_bytes: config.expected_bytes,
            successful_requests: input.successful_requests,
            failed_requests: input.failed_requests,
            response_bytes: input.response_bytes,
            elapsed_seconds,
            requests_per_second,
            mebibytes_per_second,
            latency,
            observed_connection_ids: input.connection_ids,
            observed_connection_count,
            user_cpu_seconds: input
                .usage_after
                .user_cpu
                .saturating_sub(input.usage_before.user_cpu)
                .as_secs_f64(),
            system_cpu_seconds: input
                .usage_after
                .system_cpu
                .saturating_sub(input.usage_before.system_cpu)
                .as_secs_f64(),
            peak_rss_bytes: input.usage_after.peak_rss_bytes,
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            errors: input.errors,
        }
    }
}

fn client_version(client: crate::config::ClientName) -> &'static str {
    match client {
        crate::config::ClientName::Lkrequest | crate::config::ClientName::LkrequestBatch64 => {
            env!("BENCH_LKREQUEST_VERSION")
        }
        crate::config::ClientName::LkrequestTransport => env!("BENCH_LKREQUEST_VERSION"),
        crate::config::ClientName::Lkh2
        | crate::config::ClientName::Lkh2Drain64
        | crate::config::ClientName::Lkh2Batch64 => {
            env!("BENCH_LKH2_VERSION")
        }
        crate::config::ClientName::Hyper => env!("BENCH_HYPER_VERSION"),
        crate::config::ClientName::Reqwest => env!("BENCH_REQWEST_VERSION"),
    }
}

pub fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn summarize_latencies(mut values: Vec<u64>) -> LatencySummary {
    if values.is_empty() {
        return LatencySummary {
            min_us: 0,
            mean_us: 0.0,
            p50_us: 0,
            p90_us: 0,
            p95_us: 0,
            p99_us: 0,
            max_us: 0,
        };
    }

    values.sort_unstable();
    let total: u128 = values.iter().map(|value| *value as u128).sum();
    LatencySummary {
        min_us: values[0],
        mean_us: total as f64 / values.len() as f64,
        p50_us: percentile(&values, 50),
        p90_us: percentile(&values, 90),
        p95_us: percentile(&values, 95),
        p99_us: percentile(&values, 99),
        max_us: values[values.len() - 1],
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let rank = (percentile * values.len()).div_ceil(100);
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

#[cfg(windows)]
pub fn process_usage() -> ProcessUsage {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    unsafe {
        let process = GetCurrentProcess();
        let mut creation: FILETIME = zeroed();
        let mut exit: FILETIME = zeroed();
        let mut kernel: FILETIME = zeroed();
        let mut user: FILETIME = zeroed();
        let mut counters: PROCESS_MEMORY_COUNTERS = zeroed();
        let _ = GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user);
        let _ = GetProcessMemoryInfo(
            process,
            &mut counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        );
        ProcessUsage {
            user_cpu: filetime_duration(user),
            system_cpu: filetime_duration(kernel),
            peak_rss_bytes: counters.PeakWorkingSetSize as u64,
        }
    }
}

#[cfg(windows)]
fn filetime_duration(value: windows_sys::Win32::Foundation::FILETIME) -> Duration {
    let ticks = ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64;
    Duration::from_nanos(ticks.saturating_mul(100))
}

#[cfg(unix)]
pub fn process_usage() -> ProcessUsage {
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        let _ = libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        let peak_rss_bytes = if cfg!(target_os = "macos") {
            usage.ru_maxrss as u64
        } else {
            (usage.ru_maxrss as u64).saturating_mul(1024)
        };
        ProcessUsage {
            user_cpu: timeval_duration(usage.ru_utime),
            system_cpu: timeval_duration(usage.ru_stime),
            peak_rss_bytes,
        }
    }
}

#[cfg(unix)]
fn timeval_duration(value: libc::timeval) -> Duration {
    Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec.max(0) as u64)
}

#[cfg(not(any(unix, windows)))]
pub fn process_usage() -> ProcessUsage {
    ProcessUsage::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_nearest_rank_percentiles() {
        let summary = summarize_latencies((1..=100).collect());
        assert_eq!(summary.p50_us, 50);
        assert_eq!(summary.p95_us, 95);
        assert_eq!(summary.p99_us, 99);
    }
}
