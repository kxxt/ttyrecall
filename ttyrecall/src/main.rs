use std::io::stdout;

use clap::{CommandFactory, Parser};
use cli::{Command, CommandLine};
use color_eyre::eyre::bail;
use daemon::Daemon;

mod cli;
mod daemon;
mod manager;
mod session;

#[tokio::main(worker_threads = 2)]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init();
    let cmdline = cli::CommandLine::parse();
    match cmdline.command {
        Command::Daemon { config } => {
            Daemon::new(toml::from_str(&std::fs::read_to_string(config)?)?)?
                .run()
                .await?;
        }
        Command::GenerateCompletion { shell } => {
            let mut cmd = CommandLine::command();
            clap_complete::generate(shell, &mut cmd, env!("CARGO_CRATE_NAME"), &mut stdout())
        }
        _ => {
            bail!("Sorry, this feature hasn't been implemented.");
        }
    };
    Ok(())
}
