# Install

## Prerequisites

- Rust toolchain (optional)
- Rust nightly toolchain with rust source (necessary for building eBPF).
- bpf-linker: `cargo install bpf-linker` or `pacman -S bpf-linker` (Arch Linux).

## Build

```bash
cargo xtask build --release
```

Set env `ZSTD_SYS_USE_PKG_CONFIG=1` to dynamically link to system zstd library.

## Config

`etc/daemon.toml` provides a sample daemon config file.

See the `ttyrecall-git` AUR package for a simple systemd service.
