use std::env;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientName {
    Lkrequest,
    #[serde(rename = "lkrequest-batch64")]
    LkrequestBatch64,
    #[serde(rename = "lkrequest-transport")]
    LkrequestTransport,
    #[serde(rename = "lkrequest-streaming")]
    LkrequestStreaming,
    Lkh2,
    #[serde(rename = "lkh2-drain64")]
    Lkh2Drain64,
    #[serde(rename = "lkh2-batch64")]
    Lkh2Batch64,
    Hyper,
    Reqwest,
}

impl fmt::Display for ClientName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lkrequest => formatter.write_str("lkrequest"),
            Self::LkrequestBatch64 => formatter.write_str("lkrequest-batch64"),
            Self::LkrequestTransport => formatter.write_str("lkrequest-transport"),
            Self::LkrequestStreaming => formatter.write_str("lkrequest-streaming"),
            Self::Lkh2 => formatter.write_str("lkh2"),
            Self::Lkh2Drain64 => formatter.write_str("lkh2-drain64"),
            Self::Lkh2Batch64 => formatter.write_str("lkh2-batch64"),
            Self::Hyper => formatter.write_str("hyper"),
            Self::Reqwest => formatter.write_str("reqwest"),
        }
    }
}

impl FromStr for ClientName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lkrequest" => Ok(Self::Lkrequest),
            "lkrequest-batch64" => Ok(Self::LkrequestBatch64),
            "lkrequest-transport" => Ok(Self::LkrequestTransport),
            "lkrequest-streaming" => Ok(Self::LkrequestStreaming),
            "lkh2" => Ok(Self::Lkh2),
            "lkh2-drain64" => Ok(Self::Lkh2Drain64),
            "lkh2-batch64" => Ok(Self::Lkh2Batch64),
            "hyper" => Ok(Self::Hyper),
            "reqwest" => Ok(Self::Reqwest),
            _ => Err(format!(
                "unknown client `{value}`; expected lkrequest, lkrequest-batch64, lkrequest-transport, lkrequest-streaming, lkh2, lkh2-drain64, lkh2-batch64, hyper, or reqwest"
            )),
        }
    }
}

impl ClientName {
    pub fn is_lkrequest(self) -> bool {
        matches!(
            self,
            Self::Lkrequest
                | Self::LkrequestBatch64
                | Self::LkrequestTransport
                | Self::LkrequestStreaming
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    H1,
    #[default]
    H2c,
    H3,
    Race,
}

impl Protocol {
    pub fn report_name(self) -> &'static str {
        match self {
            Self::H1 => "http1-cleartext",
            Self::H2c => "h2c-prior-knowledge",
            Self::H3 => "h3",
            Self::Race => "tls-h2-quic-h3-race",
        }
    }

    pub fn uses_tls(self) -> bool {
        matches!(self, Self::H3 | Self::Race)
    }

    fn validate_feature(self) -> Result<(), Box<dyn Error>> {
        if self.uses_tls() && !cfg!(feature = "quic-h3") {
            return Err(
                "h3/race requires building http-client-bench with --features quic-h3".into(),
            );
        }
        Ok(())
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "h1" => Ok(Self::H1),
            "h2c" => Ok(Self::H2c),
            "h3" => Ok(Self::H3),
            "race" => Ok(Self::Race),
            _ => Err(format!(
                "unknown protocol `{value}`; expected h1, h2c, h3, or race"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    #[default]
    Warm,
    Cold,
}

impl FromStr for Lifecycle {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "warm" => Ok(Self::Warm),
            "cold" => Ok(Self::Cold),
            _ => Err(format!(
                "unknown lifecycle `{value}`; expected warm or cold"
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunConfig {
    pub client: ClientName,
    pub url: String,
    pub requests: u64,
    pub concurrency: usize,
    pub sessions: usize,
    pub warmup_requests: u64,
    pub expected_bytes: usize,
    pub output: Option<PathBuf>,
    pub runtime_workers: usize,
    pub protocol: Protocol,
    pub lifecycle: Lifecycle,
    pub allocations: bool,
    pub server_stats: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ServeConfig {
    pub listen: SocketAddr,
    pub body_size: usize,
    pub runtime_workers: usize,
    pub protocol: Protocol,
    pub stats_output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum Command {
    Run(RunConfig),
    Serve(ServeConfig),
    Help,
}

impl Command {
    pub fn parse() -> Result<Self, Box<dyn Error>> {
        let mut arguments = env::args().skip(1);
        let Some(subcommand) = arguments.next() else {
            return Ok(Self::Help);
        };
        let values: Vec<String> = arguments.collect();

        match subcommand.as_str() {
            "run" => Ok(Self::Run(parse_run(&values)?)),
            "serve" => Ok(Self::Serve(parse_serve(&values)?)),
            "help" | "--help" | "-h" => Ok(Self::Help),
            _ => Err(format!("unknown command `{subcommand}`").into()),
        }
    }

    pub fn runtime_workers(&self) -> usize {
        match self {
            Self::Run(config) => config.runtime_workers,
            Self::Serve(config) => config.runtime_workers,
            Self::Help => 1,
        }
    }
}

fn parse_run(arguments: &[String]) -> Result<RunConfig, Box<dyn Error>> {
    let mut client: Option<ClientName> = None;
    let mut url = "http://127.0.0.1:18481/".to_owned();
    let mut requests = 10_000;
    let mut concurrency = 32;
    let mut sessions = 1;
    let mut warmup_requests = 100;
    let mut expected_bytes = 1_024;
    let mut output = None;
    let mut runtime_workers = 1;
    let mut protocol = Protocol::H2c;
    let mut lifecycle = Lifecycle::Warm;
    let mut allocations = false;
    let mut server_stats = None;

    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        let value = arguments
            .get(index)
            .ok_or_else(|| format!("missing value for `{flag}`"))?;
        index += 1;

        match flag.as_str() {
            "--client" => client = Some(value.parse()?),
            "--url" => url = value.clone(),
            "--requests" => requests = parse_positive(value, flag)?,
            "--concurrency" => concurrency = parse_positive(value, flag)?,
            "--sessions" => sessions = parse_positive(value, flag)?,
            "--warmup-requests" => warmup_requests = value.parse()?,
            "--expected-bytes" => expected_bytes = value.parse()?,
            "--output" => output = Some(PathBuf::from(value)),
            "--runtime-workers" => runtime_workers = parse_positive(value, flag)?,
            "--protocol" => protocol = value.parse()?,
            "--lifecycle" => lifecycle = value.parse()?,
            "--allocations" => allocations = value.parse()?,
            "--server-stats" => server_stats = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown run option `{flag}`").into()),
        }
    }

    let client = client.ok_or("`run` requires --client")?;
    protocol.validate_feature()?;
    if !client.is_lkrequest() && (protocol != Protocol::H2c || lifecycle != Lifecycle::Warm) {
        return Err("non-lkrequest clients support only --protocol h2c --lifecycle warm".into());
    }
    let uri: http::Uri = url.parse()?;
    let required_scheme = if protocol.uses_tls() { "https" } else { "http" };
    if uri.scheme_str() != Some(required_scheme) || uri.host().is_none() {
        return Err(format!(
            "{} requires an absolute {required_scheme}:// URL",
            protocol.report_name()
        )
        .into());
    }
    if protocol.uses_tls() && loopback_address(&uri).is_none() {
        return Err("h3/race fixtures require localhost or a loopback IP address".into());
    }
    if protocol == Protocol::Race && server_stats.is_none() {
        return Err("race requires --server-stats PATH to verify both transport starts".into());
    }
    if server_stats.is_some() && loopback_address(&uri).is_none() {
        return Err("--server-stats requires a loopback fixture URL".into());
    }
    if sessions > concurrency {
        return Err("--sessions cannot exceed --concurrency".into());
    }

    Ok(RunConfig {
        client,
        url,
        requests,
        concurrency,
        sessions,
        warmup_requests,
        expected_bytes,
        output,
        runtime_workers,
        protocol,
        lifecycle,
        allocations,
        server_stats,
    })
}

fn parse_serve(arguments: &[String]) -> Result<ServeConfig, Box<dyn Error>> {
    let mut listen: SocketAddr = "127.0.0.1:18481".parse()?;
    let mut body_size = 1_024;
    let mut runtime_workers = 2;
    let mut protocol = Protocol::H2c;
    let mut stats_output = None;

    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        let value = arguments
            .get(index)
            .ok_or_else(|| format!("missing value for `{flag}`"))?;
        index += 1;

        match flag.as_str() {
            "--listen" => listen = value.parse()?,
            "--body-size" => body_size = value.parse()?,
            "--runtime-workers" => runtime_workers = parse_positive(value, flag)?,
            "--protocol" => protocol = value.parse()?,
            "--stats-output" => stats_output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown serve option `{flag}`").into()),
        }
    }

    protocol.validate_feature()?;
    if protocol.uses_tls() && !listen.ip().is_loopback() {
        return Err("h3/race fixture servers must listen on a loopback address".into());
    }
    Ok(ServeConfig {
        listen,
        body_size,
        runtime_workers,
        protocol,
        stats_output,
    })
}

pub fn loopback_address(uri: &http::Uri) -> Option<std::net::IpAddr> {
    let host = uri.host()?.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return Some(std::net::Ipv4Addr::LOCALHOST.into());
    }
    host.parse::<std::net::IpAddr>()
        .ok()
        .filter(|ip| ip.is_loopback())
}

fn parse_positive<T>(value: &str, flag: &str) -> Result<T, Box<dyn Error>>
where
    T: FromStr + PartialEq + Default,
    T::Err: Error + 'static,
{
    let parsed = value.parse::<T>()?;
    if parsed == T::default() {
        return Err(format!("`{flag}` must be greater than zero").into());
    }
    Ok(parsed)
}

pub fn print_help() {
    println!(concat!(
        "http-client-bench\n\n",
        "Server:\n  http-client-bench serve [server options]\n\n",
        "Client:\n  http-client-bench run --client CLIENT [run options]\n\n",
        "Clients:\n  lkrequest, lkrequest-batch64, lkrequest-transport, lkrequest-streaming, ",
        "lkh2, lkh2-drain64, lkh2-batch64, hyper, reqwest\n\n",
        "Run options:\n  --url URL --requests N --concurrency N --sessions N\n",
        "  --warmup-requests N --expected-bytes N --runtime-workers N\n",
        "  --protocol h1|h2c|h3|race --lifecycle warm|cold\n",
        "  --allocations true|false --server-stats PATH --output PATH\n\n",
        "Server options:\n  --listen ADDR --body-size N --runtime-workers N\n",
        "  --protocol h1|h2c|h3|race --stats-output PATH"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_run_configuration() {
        let arguments = vec![
            "--client".into(),
            "hyper".into(),
            "--requests".into(),
            "42".into(),
            "--concurrency".into(),
            "4".into(),
        ];
        let config = parse_run(&arguments).unwrap();
        assert_eq!(config.client, ClientName::Hyper);
        assert_eq!(config.requests, 42);
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.protocol, Protocol::H2c);
        assert_eq!(config.lifecycle, Lifecycle::Warm);
        assert!(!config.allocations);
    }

    #[test]
    fn rejects_https_in_h2c_runner() {
        let arguments = vec![
            "--client".into(),
            "lkrequest".into(),
            "--url".into(),
            "https://localhost/".into(),
        ];
        assert!(parse_run(&arguments).is_err());
    }

    #[test]
    fn rejects_more_sessions_than_workers() {
        let arguments = vec![
            "--client".into(),
            "lkrequest".into(),
            "--concurrency".into(),
            "4".into(),
            "--sessions".into(),
            "5".into(),
        ];
        assert!(parse_run(&arguments).is_err());
    }

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn accepts_cold_h1_and_separate_allocation_sample() {
        let config = parse_run(&arguments(&[
            "--client",
            "lkrequest",
            "--protocol",
            "h1",
            "--lifecycle",
            "cold",
            "--warmup-requests",
            "0",
            "--allocations",
            "true",
        ]))
        .unwrap();
        assert_eq!(config.protocol, Protocol::H1);
        assert_eq!(config.lifecycle, Lifecycle::Cold);
        assert_eq!(config.warmup_requests, 0);
        assert!(config.allocations);
    }

    #[test]
    fn streaming_client_accepts_all_available_protocols_and_lifecycles() {
        for protocol in ["h1", "h2c", "h3", "race"] {
            for lifecycle in ["warm", "cold"] {
                let tls = matches!(protocol, "h3" | "race");
                let config = parse_run(&arguments(&[
                    "--client",
                    "lkrequest-streaming",
                    "--protocol",
                    protocol,
                    "--lifecycle",
                    lifecycle,
                    "--url",
                    if tls {
                        "https://localhost:18481/"
                    } else {
                        "http://127.0.0.1:18481/"
                    },
                    "--server-stats",
                    "stats.json",
                ]));
                if tls && !cfg!(feature = "quic-h3") {
                    assert!(config
                        .unwrap_err()
                        .to_string()
                        .contains("--features quic-h3"));
                } else {
                    let config = config.unwrap();
                    assert_eq!(config.client, ClientName::LkrequestStreaming);
                    assert_eq!(config.client.to_string(), "lkrequest-streaming");
                    assert_eq!(
                        serde_json::to_string(&config.client).unwrap(),
                        "\"lkrequest-streaming\""
                    );
                    assert_eq!(config.protocol, protocol.parse().unwrap());
                    assert_eq!(config.lifecycle, lifecycle.parse().unwrap());
                }
            }
        }
    }

    #[test]
    fn rejects_unsupported_comparator_workloads() {
        for (flag, value) in [("--protocol", "h1"), ("--lifecycle", "cold")] {
            let error = parse_run(&arguments(&["--client", "hyper", flag, value])).unwrap_err();
            assert!(error.to_string().contains("non-lkrequest clients"));
        }
    }

    #[test]
    fn rejects_ambiguous_allocation_flag_and_missing_stats_identity() {
        assert!(parse_run(&arguments(&[
            "--client",
            "lkrequest",
            "--allocations",
            "yes"
        ]))
        .is_err());
        assert!(parse_run(&arguments(&[
            "--client",
            "lkrequest",
            "--url",
            "http://example.com/",
            "--server-stats",
            "stats.json",
        ]))
        .is_err());
    }

    #[test]
    fn resolves_fixture_loopback_without_losing_ipv6() {
        assert_eq!(
            loopback_address(&"https://localhost:18481/".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            loopback_address(&"https://[::1]:18481/".parse().unwrap()),
            Some("::1".parse().unwrap())
        );
        assert_eq!(
            loopback_address(&"https://192.0.2.1/".parse().unwrap()),
            None
        );
    }

    #[cfg(not(feature = "quic-h3"))]
    #[test]
    fn rejects_quic_mode_without_feature() {
        let error = parse_run(&arguments(&[
            "--client",
            "lkrequest",
            "--protocol",
            "h3",
            "--url",
            "https://localhost/",
        ]))
        .unwrap_err();
        assert!(error.to_string().contains("--features quic-h3"));
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn race_requires_evidence_and_local_tls_fixture() {
        let mut args = arguments(&[
            "--client",
            "lkrequest",
            "--protocol",
            "race",
            "--url",
            "https://localhost:18481/",
        ]);
        assert!(parse_run(&args)
            .unwrap_err()
            .to_string()
            .contains("--server-stats"));
        args.extend(arguments(&["--server-stats", "stats.json"]));
        let config = parse_run(&args).unwrap();
        assert_eq!(config.protocol, Protocol::Race);
        args[5] = "https://example.com/".into();
        assert!(parse_run(&args).is_err());
        assert!(parse_serve(&arguments(&[
            "--protocol",
            "race",
            "--listen",
            "0.0.0.0:18481"
        ]))
        .is_err());
    }
}
