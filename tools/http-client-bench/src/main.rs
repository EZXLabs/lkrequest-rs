mod client;
mod config;
mod metrics;
mod runner;
mod server;

use std::error::Error;

use config::Command;

fn main() -> Result<(), Box<dyn Error>> {
    let command = Command::parse()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(command.runtime_workers())
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        match command {
            Command::Run(config) => runner::run(config).await,
            Command::Serve(config) => server::serve(config).await,
            Command::Help => {
                config::print_help();
                Ok(())
            }
        }
    })
}
