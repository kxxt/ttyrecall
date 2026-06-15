use std::io::stdout;

use clap::{CommandFactory, Parser};
use cli::{Command, CommandLine};
use color_eyre::eyre::bail;
use daemon::Daemon;

mod asciicast;
mod catalog;
mod cli;
mod config;
mod daemon;
mod manager;
mod player;
mod search;
mod session;
mod tui;
mod web;

#[tokio::main(worker_threads = 2)]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init();
    let cmdline = cli::CommandLine::parse();
    match cmdline.command {
        Command::Daemon { config } => {
            Daemon::new(config::load_required(config)?.daemon)?
                .run()
                .await?;
        }
        Command::GenerateCompletion { shell } => {
            let mut cmd = CommandLine::command();
            clap_complete::generate(shell, &mut cmd, env!("CARGO_CRATE_NAME"), &mut stdout())
        }
        Command::Play { files } => {
            player::play(files).await?;
        }
        Command::WebService { config } => {
            web::run(web::WebMode::Service, config, false).await?;
        }
        Command::Web { open, config } => {
            let mode = web::current_user_mode()?;
            web::run(mode, config, open).await?;
        }
        Command::Browse { config } => {
            tui::run(config)?;
        }
        _ => {
            bail!("Sorry, this feature hasn't been implemented.");
        }
    };
    Ok(())
}
