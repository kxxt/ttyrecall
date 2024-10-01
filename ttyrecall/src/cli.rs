use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
            help = "Path to configuration, /etc/ttyrecall/daemon.toml by default"
        )]
        config: Option<PathBuf>,
    },
    #[clap(about = "Play recorded file(s)")]
    Play {
        #[arg(last = true, required = true, help = "files to play")]
        files: Vec<PathBuf>,
    },
    #[clap(about = "Browse recorded file(s)")]
    Browse {},
    // We want to support two kinds of web interfaces,
    // One that could be configured by sysadmin as a service to be used by all users,
    // and one that a user could launch to view their own archive.
    #[clap(about = "Run ttyrecall web interface without previllege")]
    WebService {
        #[clap(long, help = "Path to config file, /etc/ttyrecall/web.toml by default")]
        config: Option<PathBuf>,
    },
    #[clap(about = "Run ttyrecall web interface without previllege")]
    Web {
        #[clap(long, help = "Open the web interface in your browser")]
        open: bool,
        #[clap(
            long,
            help = "Path to config file, $XDG_CONFIG_HOME/ttyrecall/web.toml by default"
        )]
        config: Option<PathBuf>,
    },
}
