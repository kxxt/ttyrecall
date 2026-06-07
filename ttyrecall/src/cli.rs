use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

#[derive(Debug, Clone, Parser)]
pub struct CommandLine {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    #[clap(about = "1984 is now! Big brother is watching!")]
    Telescreen,
    #[clap(about = "Run ttyrecall daemon")]
    Daemon {
        #[clap(
            long,
            help = "Path to config file, /etc/ttyrecall/config.toml by default"
        )]
        config: Option<PathBuf>,
    },
    #[clap(about = "Run ttyrecall full-text search indexer service")]
    Indexer {
        #[clap(
            long,
            help = "Path to config file, /etc/ttyrecall/config.toml by default"
        )]
        config: Option<PathBuf>,
    },
    #[clap(about = "Play recorded file(s)")]
    Play {
        #[arg(last = true, required = true, help = "files to play")]
        files: Vec<PathBuf>,
    },
    #[clap(about = "Browse recorded file(s)")]
    Browse {
        #[clap(
            long,
            help = "Path to config file; by default loads /etc/ttyrecall/config.toml with user overrides from $XDG_CONFIG_HOME/ttyrecall/config.toml"
        )]
        config: Option<PathBuf>,
    },
    // We want to support two kinds of web interfaces,
    // One that could be configured by sysadmin as a service to be used by all users,
    // and one that a user could launch to view their own archive.
    #[clap(about = "Run ttyrecall web interface service")]
    WebService {
        #[clap(
            long,
            help = "Path to config file, /etc/ttyrecall/config.toml by default"
        )]
        config: Option<PathBuf>,
    },
    #[clap(about = "Run ttyrecall web interface without privilege")]
    Web {
        #[clap(long, help = "Open the web interface in your browser")]
        open: bool,
        #[clap(
            long,
            help = "Path to config file; by default loads /etc/ttyrecall/config.toml with user overrides from $XDG_CONFIG_HOME/ttyrecall/config.toml"
        )]
        config: Option<PathBuf>,
    },
    #[clap(about = "Generate shell completion file")]
    GenerateCompletion { shell: Shell },
}
