use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::{
    build_ebpf::{build_ebpf, Architecture, Backend, Options as BuildOptions},
    build_frontend::{build_frontend, Options as FrontendOptions},
};

#[derive(Debug, Parser)]
pub struct Options {
    /// Select which eBPF implementation to build
    #[clap(default_value = "libbpf", long)]
    pub backend: Backend,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    #[clap(long)]
    pub disable_resource_saving: bool,
    /// Skip building the web frontend
    #[clap(long)]
    pub skip_frontend: bool,
    /// Skip installing frontend dependencies before building
    #[clap(long)]
    pub skip_frontend_deps: bool,
}

/// Build the project
fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    if opts.backend == Backend::Aya {
        args.extend(["--no-default-features", "--features", "ebpf-aya"]);
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build our ebpf program and the project
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        backend: opts.backend,
        target: opts.bpf_target,
        release: opts.release,
        disable_resource_saving: opts.disable_resource_saving,
    })
    .context("Error while building eBPF program")?;
    if !opts.skip_frontend {
        build_frontend(FrontendOptions {
            skip_frontend_deps: opts.skip_frontend_deps,
        })
        .context("Error while building frontend")?;
    }
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}
