# Install

## Packages

- AUR: `ttyrecall-git`(Uses git main branch)

## Prerequisites

- Rust toolchain (optional)
- clang, bpftool, and libbpf headers (necessary for the default libbpf CO-RE eBPF backend).
- Node.js and npm (necessary for building the web frontend).
- ripgrep (necessary only when `[search].enabled = true`).
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

The libbpf backend vendors its own copy of libbpf by default. To link against the system libbpf instead, drop the default features:

```bash
cargo xtask build --release --no-default-features
```

`--no-default-features` keeps the backend selected by `--backend` enabled while dropping the vendored libbpf. Pass additional cargo features with `--features` (comma or space separated, repeatable), e.g. `--features static`. These flags are also accepted by `cargo xtask run`.

Set env `ZSTD_SYS_USE_PKG_CONFIG=1` to dynamically link to system zstd library.

## Config

`etc/config.toml` provides a sample shared config file for daemon, web, and TUI subcommands. The system-wide runtime path is `/etc/ttyrecall/config.toml`.

For `ttyrecall web` and `ttyrecall browse`, user config is also loaded from `$XDG_CONFIG_HOME/ttyrecall/config.toml` or `~/.config/ttyrecall/config.toml`. Values in the user config override system-wide values field by field. `ttyrecall daemon` and `ttyrecall web-service` use the system-wide config only.

Recordings can contain secrets printed to terminals, including tokens, keys, and command output. Keep the storage root and web access controls restricted, and replay `.cast` files only when you trust their source because raw terminal playback can include terminal escape sequences.

See the `ttyrecall-git` AUR package for a simple systemd service.
