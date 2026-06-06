use std::{fs, path::PathBuf, process::Command};

use clap::Parser;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Backend {
    Libbpf,
    Aya,
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "libbpf" => Self::Libbpf,
            "aya" => Self::Aya,
            _ => return Err("invalid backend; expected `libbpf` or `aya`".to_owned()),
        })
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Libbpf => "libbpf",
            Self::Aya => "aya",
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Select which eBPF implementation to build
    #[clap(default_value = "libbpf", long)]
    pub backend: Backend,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
    #[clap(long)]
    pub disable_resource_saving: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    match opts.backend {
        Backend::Libbpf => build_libbpf_ebpf(opts),
        Backend::Aya => build_aya_ebpf(opts),
    }
}

fn build_aya_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("ttyrecall-ebpf");
    let target = format!("--target={}", opts.target);
    let mut args = vec!["build", target.as_str(), "-Z", "build-std=core"];
    if opts.release {
        args.push("--release")
    }
    if opts.disable_resource_saving {
        args.push("--no-default-features");
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}

fn build_libbpf_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    if !matches!(opts.target, Architecture::BpfEl) {
        anyhow::bail!("libbpf backend currently builds only bpfel objects");
    }

    let profile = if opts.release { "release" } else { "debug" };
    let out_dir = PathBuf::from("target/libbpf").join(profile);
    fs::create_dir_all(&out_dir)?;

    let vmlinux = out_dir.join("vmlinux.h");
    let output = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("failed to run bpftool");
    if !output.status.success() {
        anyhow::bail!(
            "bpftool failed to generate vmlinux.h: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::write(&vmlinux, output.stdout)?;

    let mut args = vec![
        "-target".to_string(),
        "bpfel".to_string(),
        format!("-D{}", target_arch_define()?),
        "-g".to_string(),
        "-O2".to_string(),
        "-I".to_string(),
        out_dir.to_string_lossy().into_owned(),
        "-c".to_string(),
        "ttyrecall-ebpf/src/libbpf/ttyrecall.bpf.c".to_string(),
        "-o".to_string(),
        out_dir
            .join("ttyrecall.bpf.o")
            .to_string_lossy()
            .into_owned(),
    ];
    if !opts.disable_resource_saving {
        args.push("-DTTYRECALL_RESOURCE_SAVING".to_string());
    }
    if !opts.release {
        args.push("-DTTYRECALL_DEBUG".to_string());
    }

    let status = Command::new("clang")
        .args(&args)
        .status()
        .expect("failed to build libbpf eBPF program");
    assert!(status.success());
    Ok(())
}

fn target_arch_define() -> Result<&'static str, anyhow::Error> {
    match std::env::consts::ARCH {
        "x86" | "x86_64" => Ok("__TARGET_ARCH_x86"),
        "aarch64" => Ok("__TARGET_ARCH_arm64"),
        "arm" => Ok("__TARGET_ARCH_arm"),
        "powerpc64" => Ok("__TARGET_ARCH_powerpc"),
        "riscv64" => Ok("__TARGET_ARCH_riscv"),
        "s390x" => Ok("__TARGET_ARCH_s390"),
        arch => anyhow::bail!("unsupported host architecture for libbpf BPF_PROG macros: {arch}"),
    }
}
