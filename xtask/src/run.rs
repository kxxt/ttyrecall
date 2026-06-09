use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::{
    build::{build, Options as BuildOptions},
    build_ebpf::{Architecture, Backend},
};

#[derive(Debug, Parser)]
pub struct Options {
    /// Select which eBPF implementation to build and run
    #[clap(default_value = "libbpf", long)]
    pub backend: Backend,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    #[clap(long)]
    pub disable_resource_saving: bool,
    /// Skip building the web frontend
    #[clap(long)]
    pub skip_frontend: bool,
    /// Skip installing frontend dependencies before building
    #[clap(long)]
    pub skip_frontend_deps: bool,
    /// Extra cargo features to activate for the userspace build, comma or space
    /// separated. May be repeated. The backend feature is selected by
    /// `--backend` and does not need to be listed here.
    #[clap(long, value_delimiter = ',')]
    pub features: Vec<String>,
    /// Build the userspace binary without the crate's default cargo features
    /// (e.g. to link against a system libbpf instead of the vendored one)
    #[clap(long)]
    pub no_default_features: bool,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // Build our ebpf program and the project
    build(BuildOptions {
        backend: opts.backend,
        bpf_target: opts.bpf_target,
        release: opts.release,
        disable_resource_saving: opts.disable_resource_saving,
        skip_frontend: opts.skip_frontend,
        skip_frontend_deps: opts.skip_frontend_deps,
        features: opts.features.clone(),
        no_default_features: opts.no_default_features,
    })
    .context("Error while building project")?;

    // profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/ttyrecall");

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // run the command
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    if !status.success() {
        anyhow::bail!("Failed to run `{}`", args.join(" "));
    }
    Ok(())
}
