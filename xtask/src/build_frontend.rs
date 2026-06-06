use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    /// Skip installing frontend dependencies before building
    #[clap(long)]
    pub skip_frontend_deps: bool,
}

pub fn build_frontend(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("frontend");
    if !dir.exists() {
        anyhow::bail!("frontend directory not found");
    }

    if !opts.skip_frontend_deps && !dir.join("node_modules").exists() {
        run_npm(&dir, &["ci"]).context("failed to install frontend deps")?;
    }

    run_npm(&dir, &["run", "build"]).context("failed to build frontend")?;
    Ok(())
}

fn run_npm(dir: &Path, args: &[&str]) -> Result<(), anyhow::Error> {
    let status = Command::new("npm").current_dir(dir).args(args).status()?;
    if !status.success() {
        anyhow::bail!("npm {} failed", args.join(" "));
    }
    Ok(())
}
