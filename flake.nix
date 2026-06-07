{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    inputs@{
      flake-parts,
      crane,
      nixpkgs,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { flake-parts-lib, ... }:
      let
        inherit (flake-parts-lib) importApply;
        ukci.default = importApply ./nix/ukci.nix {
          inherit nixpkgs crane;
        };
      in
      {
        imports = [
          ukci.default
        ];
        systems = [
          "x86_64-linux"
          "aarch64-linux"
          "riscv64-linux"
        ];
        perSystem =
          {
            self',
            lib,
            pkgs,
            system,
            ...
          }:
          let
            defaultShell = pkgs.mkShell {
              name = "Development Shell";
              packages =
                [
                  pkgs.clang
                  pkgs.libclang
                  pkgs.libelf
                  pkgs.libbpf
                  pkgs.llvm
                  pkgs.nixfmt
                  pkgs.pkg-config
                  pkgs.zlib
                  self'.packages.ukci
                  self'.packages.run-qemu
                  self'.packages.test-qemu
                ];
            };
          in
          {
            packages.default = self'.packages.ttyrecall;
            devShells.default = defaultShell;
            devShells.extended = pkgs.mkShell {
              inputsFrom = [ defaultShell ];
              packages =
                lib.optionals (system != "aarch64-linux") [
                  self'.packages.ukci-aarch64
                  self'.packages.run-qemu-aarch64
                  self'.packages.test-qemu-aarch64
                ]
                ++ lib.optionals (system != "x86_64-linux") [
                  self'.packages.ukci-x86_64
                  self'.packages.run-qemu-x86_64
                  self'.packages.test-qemu-x86_64
                ]
                ++ lib.optionals (system != "riscv64-linux") [
                  self'.packages.ukci-riscv64
                  self'.packages.run-qemu-riscv64
                  self'.packages.test-qemu-riscv64
                ];
            };
          };
      }
    );
}
