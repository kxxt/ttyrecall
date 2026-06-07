{
  pkgs,
  lib,
  crane,
}:
{
  cargoExtraArgs ? "--locked -p ttyrecall --no-default-features --features ttyrecall/ebpf-libbpf",
  bpfClang ? pkgs.buildPackages.clang.cc,
  kernel,
}:
let
  craneLib = crane.mkLib pkgs;
  sourceRoot = builtins.toString ./..;
  frontendDistRoot = "${sourceRoot}/frontend/dist";
  cFilter = path: _type: builtins.match ".*\\.[ch]$" path != null;
  frontendDistFilter =
    path: _type:
    lib.hasPrefix frontendDistRoot (builtins.toString path);
  rustFilter =
    path: type:
    let
      base = baseNameOf path;
      parentDir = baseNameOf (dirOf path);
    in
    type == "directory"
    || (
      lib.any (suffix: lib.hasSuffix suffix base) [
        ".rs"
        ".toml"
      ]
      && (base != "config.toml" || parentDir != ".cargo")
    )
    || base == "Cargo.lock";
  sourceFilter =
    path: type:
    (cFilter path type)
    || (rustFilter path type)
    || (frontendDistFilter path type);
  targetArchDefine =
    let
      system = pkgs.stdenv.hostPlatform.system;
    in
    if system == "x86_64-linux" then
      "__TARGET_ARCH_x86"
    else if system == "aarch64-linux" then
      "__TARGET_ARCH_arm64"
    else if system == "riscv64-linux" then
      "__TARGET_ARCH_riscv"
    else
      builtins.abort "unsupported ttyrecall libbpf target ${system}";
  baseArgs = {
    src = lib.cleanSourceWith {
      src = ./..;
      filter = sourceFilter;
      name = "source";
    };
  };
  commonArgs = baseArgs // {
    pname = "ttyrecall";
    version = "0.1.0";
    inherit cargoExtraArgs;
    strictDeps = true;
    doCheck = false;
    buildInputs = with pkgs; [
      elfutils
      linux-pam
      zlib
    ];
    nativeBuildInputs = [
      pkgs.buildPackages.rustPlatform.bindgenHook
      pkgs.buildPackages.pkg-config
    ];
  };
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      doCheck = false;
    }
  );
in
craneLib.buildPackage (commonArgs // {
  inherit cargoArtifacts;
  nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
    pkgs.buildPackages.bpftools
    bpfClang
  ];

  cargoBuildCommand = "cargo build --release";

  preBuild = ''
    mkdir -p target/libbpf/release
    bpftool btf dump file ${kernel.dev}/vmlinux format c > target/libbpf/release/vmlinux.h
    clang \
      -target bpfel \
      -D${targetArchDefine} \
      -DTTYRECALL_RESOURCE_SAVING \
      -g \
      -O2 \
      -I target/libbpf/release \
      -I ${pkgs.libbpf}/include \
      -isystem ${pkgs.linuxHeaders}/include \
      -c ttyrecall-ebpf/src/libbpf/ttyrecall.bpf.c \
      -o target/libbpf/release/ttyrecall.bpf.o
  '';

  postInstall = ''
    if [ -d frontend/dist ]; then
      mkdir -p $out/share/ttyrecall/web
      cp -r frontend/dist/. $out/share/ttyrecall/web/
    fi
  '';
})
