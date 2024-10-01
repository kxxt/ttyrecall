use clap::Parser;
use cli::Command;
use color_eyre::eyre::bail;
use daemon::Daemon;

mod cli;
mod daemon;
mod session;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    env_logger::init();
    let cmdline = cli::CommandLine::parse();
    let Command::Daemon { config } = cmdline.command else {
        bail!("Sorry, this feature hasn't been implemented.");
    };
    Daemon::new(toml::from_str(&std::fs::read_to_string(config)?)?)
        .run()
        .await
}
