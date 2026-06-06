# Install

## Packages

- AUR: `ttyrecall-git`(Uses git main branch)

## Prerequisites

- Rust toolchain (optional)
- clang, bpftool, and libbpf headers (necessary for the default libbpf CO-RE eBPF backend).
- Rust nightly toolchain with rust source (necessary only for the optional Aya eBPF backend).
- bpf-linker: `cargo install bpf-linker` or `pacman -S bpf-linker` (Arch Linux; necessary only for the optional Aya eBPF backend).

## Build

```bash
cargo xtask build --release
```

The libbpf CO-RE backend is built by default. To build the Aya backend instead:

```bash
cargo xtask build --backend aya --release
```

Set env `ZSTD_SYS_USE_PKG_CONFIG=1` to dynamically link to system zstd library.

## Config

`etc/daemon.toml` provides a sample daemon config file.

See the `ttyrecall-git` AUR package for a simple systemd service.
