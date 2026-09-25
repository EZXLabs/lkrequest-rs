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
            "lkh2" => Ok(Self::Lkh2),
            "lkh2-drain64" => Ok(Self::Lkh2Drain64),
            "lkh2-batch64" => Ok(Self::Lkh2Batch64),
            "hyper" => Ok(Self::Hyper),
            "reqwest" => Ok(Self::Reqwest),
            _ => Err(format!(
                "unknown client `{value}`; expected lkrequest, lkrequest-batch64, lkrequest-transport, lkh2, lkh2-drain64, lkh2-batch64, hyper, or reqwest"
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
}

#[derive(Clone, Debug)]
pub struct ServeConfig {
    pub listen: SocketAddr,
    pub body_size: usize,
    pub runtime_workers: usize,
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
    let mut client = None;
    let mut url = "http://127.0.0.1:18481/".to_owned();
    let mut requests = 10_000;
    let mut concurrency = 32;
    let mut sessions = 1;
    let mut warmup_requests = 100;
    let mut expected_bytes = 1_024;
    let mut output = None;
    let mut runtime_workers = 1;

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
            _ => return Err(format!("unknown run option `{flag}`").into()),
        }
    }

    let client = client.ok_or("`run` requires --client")?;
    if !url.starts_with("http://") {
        return Err("the initial benchmark supports h2c URLs beginning with http://".into());
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
    })
}

fn parse_serve(arguments: &[String]) -> Result<ServeConfig, Box<dyn Error>> {
    let mut listen = "127.0.0.1:18481".parse()?;
    let mut body_size = 1_024;
    let mut runtime_workers = 2;

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
            _ => return Err(format!("unknown serve option `{flag}`").into()),
        }
    }

    Ok(ServeConfig {
        listen,
        body_size,
        runtime_workers,
    })
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
        "Clients:\n  lkrequest, lkrequest-batch64, lkrequest-transport, ",
        "lkh2, lkh2-drain64, lkh2-batch64, hyper, reqwest\n\n",
        "Run options:\n  --url URL --requests N --concurrency N --sessions N\n",
        "  --warmup-requests N --expected-bytes N --runtime-workers N\n",
        "  --output PATH"
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
}
