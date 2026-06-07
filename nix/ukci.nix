localFlake:

{
  lib,
  self,
  inputs,
  ...
}:
{
  perSystem =
    {
      self',
      system,
      pkgs,
      ...
    }:
    {
      packages =
        let
          getArch =
            systemString:
            let
              split = lib.strings.splitString "-" systemString;
            in
            if builtins.length split != 2 then
              builtins.abort "Invalid system type ${systemString}"
            else
              builtins.elemAt split 0;
          isAarch64 = system == "aarch64-linux";
          isX86_64 = system == "x86_64-linux";
          isRiscv64 = system == "riscv64-linux";
          gnutlsOverlay = final: prev: {
            gnutls = prev.gnutls.overrideAttrs (prevAttrs: {
              postPatch = (prevAttrs.postPatch or "") + ''
                touch doc/stamp_error_codes
              '';
            });
          };
          pkgsWithOverlay = pkgs.extend gnutlsOverlay;
          nativeTargetSystems = [ system ];
          crossTargetSystems =
            if isX86_64 then
              [
                "aarch64-linux"
                "riscv64-linux"
              ]
            else if isAarch64 then
              [
                "x86_64-linux"
                "riscv64-linux"
              ]
            else if isRiscv64 then
              [
                "x86_64-linux"
                "aarch64-linux"
              ]
            else
              [ ];
          pkgsForTarget =
            targetSystem:
            if targetSystem == system then
              pkgs
            else if targetSystem == "x86_64-linux" then
              pkgsWithOverlay.pkgsCross.gnu64
            else if targetSystem == "aarch64-linux" then
              pkgsWithOverlay.pkgsCross.aarch64-multiplatform
            else if targetSystem == "riscv64-linux" then
              pkgsWithOverlay.pkgsCross.riscv64
            else
              builtins.abort "Unsupported cross target ${targetSystem} on host ${system}";
          vmSshPort = "10022";
          sourcesFor =
            targetSystem:
            let
              isTargetAarch64 = targetSystem == "aarch64-linux";
              isTargetX86_64 = targetSystem == "x86_64-linux";
              isTargetRiscv64 = targetSystem == "riscv64-linux";
              riscv64BpfLocalStorageFix = {
                name = "riscv64-bpf-local-storage-fix";
                patch = ./patches/6.19-riscv64-fix-task-local-storage.patch;
              };
            in
            [
              {
                name = "6.1lts";
                tag = "6.1.168";
                source = "mirror";
                test_exe = "ttyrecall";
                sha256 = "sha256-4IVv5R5ESYZCWIZTPruR2FQBiegMPwNlx25L63Q5d24=";
                kernelPatches = [ ];
                extraMakeFlags = [ ];
              }
              {
                name = "6.6lts";
                tag = "6.6.134";
                source = "mirror";
                test_exe = "ttyrecall";
                sha256 = "sha256-Y3hpezY3a/TnJ6R0Av7jQMpOOxRtW0B9N1PL/zAPN78=";
                kernelPatches = [ ];
                extraMakeFlags = [ ];
              }
              {
                name = "6.12lts";
                tag = "6.12.81";
                source = "mirror";
                test_exe = "ttyrecall";
                sha256 = "sha256-wrCcNkOUanCXxTceHcsSPGZQXqMPr9Cwoi3B1fAiiEc=";
                kernelPatches = [ ];
                extraMakeFlags = [ ];
              }
              {
                name = "6.18lts";
                tag = "6.18.22";
                source = "mirror";
                test_exe = "ttyrecall";
                sha256 = "sha256-ojyS+vNlc4XCxrX07dj4G4CJB+vmA/owaZ6uIk2lX1k=";
                kernelPatches = [ ];
                extraMakeFlags = [ ];
              }
              {
                name = "7.0";
                tag = "v7.0";
                version = "7.0.0";
                source = "linus";
                test_exe = "ttyrecall";
                sha256 = "sha256-EOr/mr2n/jZwcTk+0n5Wwbvjb8j7cZpA5+B7e/ZTj+0=";
                kernelPatches = [ riscv64BpfLocalStorageFix ];
                extraMakeFlags = [ ];
              }
            ] ++ (lib.optionals (!isTargetRiscv64) [
              {
                name = "bpf-next";
                tag = "bpf-next-7.1";
                version = "7.0.0-rc6";
                source = "bpf-next";
                test_exe = "ttyrecall";
                sha256 = "sha256-z9S4y2YCgsPoInlUTErvgJOj7OSy1c6xP443HXFPc/c=";
                kernelPatches = [ ];
                extraMakeFlags = [ ];
              }
            ]);
          sourcesForTargets =
            targetSystems:
            lib.concatMap (
              targetSystem: map (source: source // { inherit targetSystem; }) (sourcesFor targetSystem)
            ) targetSystems;
          inherit (localFlake) nixpkgs crane;
          llvmVersions = [ 20 21 22 ];
          ttyrecallForKernelClang =
            targetPkgs: kernel: llvmVer:
            let
              bpfClang = targetPkgs.buildPackages.${"llvmPackages_${toString llvmVer}"}.clang.cc;
            in
            (import ./ttyrecall-package.nix {
              inherit (targetPkgs) lib;
              inherit crane;
              pkgs = targetPkgs;
            })
              { inherit bpfClang kernel; };
          initramfsForTarget =
            targetSystem:
            let
              targetPkgs = pkgsForTarget targetSystem;
              buildInitramfs = targetPkgs.callPackage ./initramfs.nix { };
            in
            buildInitramfs {
              extraBin = {
                strace = "${targetPkgs.strace}/bin/strace";
                nix-store = "${targetPkgs.nix}/bin/nix";
              };
              storePaths = [ ];
            };
          mkKernels =
            targetSystems:
            let
              sources = sourcesForTargets targetSystems;
              useArchSuffix = builtins.length targetSystems > 1;
              initramfsMap = builtins.listToAttrs (
                map (ts: {
                  name = ts;
                  value = initramfsForTarget ts;
                }) (lib.unique (map (s: s.targetSystem) sources))
              );
              buildKernelForSource =
                source:
                let
                  inherit (source) targetSystem;
                  targetPkgs = pkgsForTarget targetSystem;
                  targetArch = getArch targetSystem;
                  kernelNixConfig = s: targetPkgs.callPackage ./kernel-source.nix s;
                  configureKernel = targetPkgs.callPackage ./kernel-configure.nix { };
                  buildKernel = targetPkgs.callPackage ./kernel-build.nix { stdenv = targetPkgs.gcc14Stdenv; };
                  config = kernelNixConfig source;
                  inherit (config) kernelArgs kernelConfig;
                  configfile = configureKernel {
                    inherit (kernelConfig)
                      generateConfigFlags
                      structuredExtraConfig
                      ;
                    inherit kernel nixpkgs;
                  };
                  linuxDev = targetPkgs.linuxPackagesFor kernelDrv;
                  inherit (linuxDev) kernel;
                  kernelDrv = buildKernel {
                    inherit (kernelArgs)
                      src
                      modDirVersion
                      version
                      ;
                    inherit (source) kernelPatches extraMakeFlags;
                    inherit configfile nixpkgs;
                  };
                  baseName = if useArchSuffix then "${source.name}-${targetArch}" else source.name;
                in
                {
                  inherit kernel targetSystem targetArch baseName;
                  inherit (source) test_exe;
                };
              builtKernels = map buildKernelForSource sources;
              mkEntry =
                builtKernel: llvmVer:
                let
                  targetPkgs = pkgsForTarget builtKernel.targetSystem;
                  testPackage = ttyrecallForKernelClang targetPkgs builtKernel.kernel llvmVer;
                in
                {
                  inherit (builtKernel)
                    kernel
                    targetSystem
                    targetArch
                    test_exe
                    ;
                  inherit testPackage;
                  name = "${builtKernel.baseName}-clang${toString llvmVer}";
                  initramfs = initramfsMap.${builtKernel.targetSystem};
                };
            in
            lib.concatMap (bk: map (mkEntry bk) llvmVersions) builtKernels;
          kernelsNative = mkKernels nativeTargetSystems;
          kernelsCross = mkKernels crossTargetSystems;
          targetSystemsAll = nativeTargetSystems ++ crossTargetSystems;
          mkScripts =
            {
              nameSuffix ? "",
              kernels,
            }:
            let
              runQemuName = "run-qemu${nameSuffix}";
              testQemuName = "test-qemu${nameSuffix}";
              ukciName = "ukci${nameSuffix}";
              shellCases = lib.concatMapStrings (
                {
                  name,
                  kernel,
                  initramfs,
                  targetArch,
                  ...
                }:
                ''
                  ${name})
                    kernel="${kernel}"
                    initrd="${initramfs}"
                    arch="${targetArch}"
                  ;;
                ''
              ) kernels;
              platforms = lib.concatMapStringsSep " " (
                {
                  name,
                  targetSystem,
                  test_exe,
                  testPackage,
                  ...
                }:
                "${name}:${targetSystem}:${test_exe}:${testPackage}"
              ) kernels;
              defaultPackage = if kernels == [ ] then "" else (builtins.head kernels).testPackage;
              ukciSummaryHeader =
                "| Kernel \\ Clang | "
                + lib.concatStringsSep " | " (map (v: "clang ${toString v}") llvmVersions)
                + " |";
              ukciSummarySep =
                "| --- | "
                + lib.concatStringsSep " | " (map (_: "---") llvmVersions)
                + " |";
              llvmVersionsSpaceSep = lib.concatStringsSep " " (map toString llvmVersions);
              runQemuDrv = pkgs.writeScriptBin runQemuName ''
                #!/usr/bin/env bash

                case "$1" in
                  ${shellCases}
                  *)
                    echo "Invalid argument!"
                    exit 1
                esac
                port="''${2:-${vmSshPort}}"

                case "$arch" in
                  aarch64)
                    archSpecificArgs=(-machine virt -cpu neoverse-n2 -append "console=ttyAMA0")
                    kernelImageFile="Image"
                    ;;
                  riscv64)
                    archSpecificArgs=(-machine virt -append "console=ttyS0 earlycon")
                    kernelImageFile="Image"
                    ;;
                  x86_64)
                    archSpecificArgs=(-enable-kvm -append "console=ttyS0")
                    kernelImageFile="bzImage"
                    ;;
                  *)
                    archSpecificArgs=()
                    kernelImageFile="Image"
                    ;;
                esac

                use_kvm=0
                for arg in "''${archSpecificArgs[@]}"; do
                  if [ "$arg" = "-enable-kvm" ]; then
                    use_kvm=1
                    break
                  fi
                done

                echo "Booting $kernel with $initrd in qemu"

                qemu_cmd=("${pkgs.qemu}/bin/qemu-system-$arch")
                if [ "$use_kvm" = "1" ] && [ -e /dev/kvm ] && [ ! -w /dev/kvm ]; then
                  qemu_cmd=(sudo "''${qemu_cmd[@]}")
                fi

                "''${qemu_cmd[@]}" \
                  -m 4G \
                  -smp cores=4 \
                  -kernel "$kernel/$kernelImageFile" \
                  -initrd "$initrd"/initrd.gz \
                  -device e1000,netdev=net0 \
                  -netdev user,id=net0,hostfwd=::"$port"-:22 \
                  -nographic \
                  "''${archSpecificArgs[@]}"
              '';
              testQemuDrv = pkgs.writeScriptBin testQemuName ''
                #!/usr/bin/env sh
                test_exe="$1"
                package="$2"
                port="''${3:-${vmSshPort}}"
                poweroff="''${4:-0}"
                ssh="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 -p $port"
                if [ "$poweroff" = "1" ]; then
                  cleanup() {
                    $ssh poweroff -f >/dev/null 2>&1 || true
                  }
                  trap cleanup EXIT INT TERM
                fi

                for i in $(seq 1 100); do
                  [ $i -gt 1 ] && sleep 5
                  $ssh true && break
                done

                $ssh uname -a
                export NIX_SSHOPTS="-p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                if [ -z "$package" ]; then
                  package="${defaultPackage}"
                fi
                case "$test_exe" in
                  ttyrecall) : ;;
                  *)
                    echo "Unrecognized executable!"
                    exit 1
                    ;;
                esac
                if [ -z "$package" ]; then
                  echo "Missing package path!"
                  exit 1
                fi
                ${pkgs.nix}/bin/nix copy --to ssh://root@127.0.0.1 "$package"
                $ssh "PACKAGE=$package sh -s" <<'EOF'
                set -eu
                mkdir -p /tmp/ttyrecall
                touch /etc/group
                cat > /tmp/ttyrecall-ukci.toml <<'CONFIG'
                root = "/tmp/ttyrecall"

                [daemon]
                compress = "none"
                mode = "allowlist"
                users = []
                uids = [0]
                excluded_comms = []
                soft_budget = 0
                CONFIG

                rm -f /tmp/ttyrecall-ukci.log
                RUST_LOG=info "$PACKAGE/bin/ttyrecall" daemon --config /tmp/ttyrecall-ukci.toml > /tmp/ttyrecall-ukci.log 2>&1 &
                pid=$!
                for i in $(seq 1 100); do
                  if grep -q "Waiting for Ctrl-C" /tmp/ttyrecall-ukci.log; then
                    kill -TERM "$pid"
                    wait "$pid"
                    cat /tmp/ttyrecall-ukci.log
                    exit 0
                  fi
                  if ! kill -0 "$pid" >/dev/null 2>&1; then
                    cat /tmp/ttyrecall-ukci.log
                    wait "$pid"
                    exit $?
                  fi
                  sleep 0.2
                done
                cat /tmp/ttyrecall-ukci.log
                kill -TERM "$pid" >/dev/null 2>&1 || true
                wait "$pid" >/dev/null 2>&1 || true
                echo "ttyrecall daemon did not report readiness"
                exit 1
                EOF
              '';
              ukciDrv = pkgs.writeScriptBin ukciName ''
                #!/usr/bin/env bash

                set -e

                logs_dir="$(mktemp -d)"
                results_dir="$(mktemp -d)"
                lock_dir="$logs_dir/.lock"
                status=0
                running=0
                if command -v nproc >/dev/null 2>&1; then
                  max_parallel="''${UKCI_MAX_PARALLEL:-$(nproc)}"
                else
                  max_parallel="''${UKCI_MAX_PARALLEL:-$(getconf _NPROCESSORS_ONLN)}"
                fi
                if [ -z "$max_parallel" ] || [ "$max_parallel" -lt 1 ]; then
                  max_parallel=1
                fi
                if [ -t 1 ]; then
                  RED="$(printf '\033[31m')"
                  GREEN="$(printf '\033[32m')"
                  YELLOW="$(printf '\033[33m')"
                  BLUE="$(printf '\033[34m')"
                  BOLD="$(printf '\033[1m')"
                  RESET="$(printf '\033[0m')"
                else
                  RED=""
                  GREEN=""
                  YELLOW=""
                  BLUE=""
                  BOLD=""
                  RESET=""
                fi
                idx=0
                for platform in ${platforms}; do
                  IFS=: read -r kernel target_system test_exe package <<< "$platform"
                  port=$(( ${vmSshPort} + idx ))
                  name="$kernel"
                  qemu_log="$logs_dir/$name.qemu.log"
                  test_log="$logs_dir/$name.test.log"
                  (
                    set +e
                    max_vm_attempts="''${UKCI_VM_TEST_ATTEMPTS:-5}"
                    attempt=1
                    test_status=1
                    while [ "$attempt" -le "$max_vm_attempts" ]; do
                      if [ "$attempt" -gt 1 ]; then
                        echo "''${YELLOW}''${BOLD}Retrying full VM test ''${name} (attempt $attempt/$max_vm_attempts)...''${RESET}" >&2
                        sleep 3
                      fi
                      ${runQemuDrv}/bin/${runQemuName} "$kernel" "$port" >"$qemu_log" 2>&1 &
                      qemu_pid=$!
                      ${pkgs.coreutils}/bin/timeout 600s \
                        ${testQemuDrv}/bin/${testQemuName} "$test_exe" "$package" "$port" "1" >"$test_log" 2>&1
                      test_status=$?
                      if kill -0 "$qemu_pid" >/dev/null 2>&1; then
                        kill "$qemu_pid" >/dev/null 2>&1 || true
                      fi
                      wait "$qemu_pid" 2>/dev/null || true
                      if [ "$test_status" -eq 0 ]; then
                        break
                      fi
                      if [ "$attempt" -ge "$max_vm_attempts" ]; then
                        break
                      fi
                      attempt=$((attempt + 1))
                    done
                    while ! mkdir "$lock_dir" 2>/dev/null; do
                      sleep 0.1
                    done
                    echo "''${BLUE}''${BOLD}===> $name (qemu)''${RESET}"
                    cat "$qemu_log" || true
                    echo "''${BLUE}''${BOLD}===> $name (test)''${RESET}"
                    cat "$test_log" || true
                    if [ "$test_status" -eq 124 ] || [ "$test_status" -eq 137 ]; then
                      echo "''${RED}''${BOLD}FAIL:''${RESET} ''${name} timed out after 600s"
                    elif [ "$test_status" -ne 0 ]; then
                      echo "''${RED}''${BOLD}FAIL:''${RESET} ''${name} exited with status ''${test_status}"
                    else
                      echo "''${GREEN}''${BOLD}PASS:''${RESET} ''${name}"
                    fi
                    printf '%s\n' "$test_status" > "$results_dir/$name"
                    rmdir "$lock_dir"
                    rm -f "$qemu_log" "$test_log"
                    exit "$test_status"
                  ) &
                  running=$(( running + 1 ))
                  if [ "$running" -ge "$max_parallel" ]; then
                    if ! wait -n; then
                      status=1
                    fi
                    running=$(( running - 1 ))
                  fi
                  idx=$(( idx + 1 ))
                done

                while [ "$running" -gt 0 ]; do
                  if ! wait -n; then
                    status=1
                  fi
                  running=$(( running - 1 ))
                done

                if [ "$status" -ne 0 ]; then
                  echo "''${YELLOW}''${BOLD}One or more tests failed.''${RESET}"
                fi

                summary_title="''${UKCI_SUMMARY_TITLE:-UKCI}"
                render_summary_table() {
                  echo "## $summary_title"
                  echo ""
                  echo "${ukciSummaryHeader}"
                  echo "${ukciSummarySep}"
                  declare -A seen_row=
                  row_order=()
                  for platform in ${platforms}; do
                    IFS=: read -r pname _ts _te _pkg <<< "$platform"
                    row_key="''${pname%-clang*}"
                    if [ -z "''${seen_row[$row_key]+x}" ]; then
                      seen_row[$row_key]=1
                      row_order+=("$row_key")
                    fi
                  done
                  for row_key in "''${row_order[@]}"; do
                    line="| $row_key |"
                    for llvm_ver in ${llvmVersionsSpaceSep}; do
                      cell_name="$row_key-clang$llvm_ver"
                      f="$results_dir/$cell_name"
                      if [ -f "$f" ]; then
                        ts="$(cat "$f")"
                        if [ "$ts" -eq 0 ]; then
                          cell="PASS"
                        elif [ "$ts" -eq 124 ] || [ "$ts" -eq 137 ]; then
                          cell="TIMEOUT"
                        elif [ "$ts" -eq 143 ]; then
                          cell="TERM"
                        else
                          cell="FAIL ($ts)"
                        fi
                      else
                        cell="--"
                      fi
                      line="$line $cell |"
                    done
                    echo "$line"
                  done
                  echo ""
                }
                set +e
                render_summary_table
                if [ -n "''${GITHUB_STEP_SUMMARY:-}" ]; then
                  render_summary_table >> "$GITHUB_STEP_SUMMARY"
                fi
                set -e

                rm -rf "$logs_dir" "$results_dir"
                exit "$status"
              '';
            in
            {
              run-qemu = runQemuDrv;
              test-qemu = testQemuDrv;
              ukci = ukciDrv;
            };
          nativeScripts = mkScripts { kernels = kernelsNative; };
          mkTargetScriptAttrs =
            targetSystem:
            let
              arch = getArch targetSystem;
              scripts = mkScripts {
                nameSuffix = "-${arch}";
                kernels = mkKernels [ targetSystem ];
              };
            in
            lib.listToAttrs [
              (lib.nameValuePair "run-qemu-${arch}" scripts.run-qemu)
              (lib.nameValuePair "test-qemu-${arch}" scripts.test-qemu)
              (lib.nameValuePair "ukci-${arch}" scripts.ukci)
            ];
          perTargetScripts = lib.foldl' lib.recursiveUpdate { } (map mkTargetScriptAttrs targetSystemsAll);
          firstNativeKernel = builtins.head kernelsNative;
        in
        rec {
          ttyrecall = firstNativeKernel.testPackage;
          inherit (nativeScripts) run-qemu test-qemu ukci;
        }
        // perTargetScripts;
    };
}
