# Install

## Packages

- AUR: `ttyrecall-git`(Uses git main branch)

## Prerequisites

- Rust toolchain (optional)
- clang, bpftool, and libbpf headers (necessary for the default libbpf CO-RE eBPF backend).
- Node.js and npm (necessary for building the web frontend).
- Rust nightly toolchain with rust source (necessary only for the optional Aya eBPF backend).
- bpf-linker: `cargo install bpf-linker` or `pacman -S bpf-linker` (Arch Linux; necessary only for the optional Aya eBPF backend).

## Build

```bash
cargo xtask build --release
```

This builds the eBPF program, the web frontend in `frontend/dist`, and the `ttyrecall` userspace binary. If `frontend/node_modules` is missing, the xtask build runs `npm ci` before `npm run build`.

The libbpf CO-RE backend is built by default. To build the Aya backend instead:

```bash
cargo xtask build --backend aya --release
```

To build only the frontend:

```bash
cargo xtask build-frontend
```

To skip the frontend during a Rust/eBPF-only build:

```bash
cargo xtask build --skip-frontend --release
```

Use `--skip-frontend-deps` when dependencies are already prepared by your packaging environment and the build should not run `npm ci`.

Set env `ZSTD_SYS_USE_PKG_CONFIG=1` to dynamically link to system zstd library.

## Config

`etc/daemon.toml` provides a sample daemon config file.

See the `ttyrecall-git` AUR package for a simple systemd service.
