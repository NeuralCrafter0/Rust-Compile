# Proofline Isolation Model

This document specifies the active isolation boundaries enforced across the Proofline crates as established in [RFC-001](../rfcs/0001-threat-model-system-boundaries-verification-contract.md).

## 1. Zero-Trust Repository Ingestion (`proofline-intelligence`)
- `IngestionEngine::inspect_repository` performs read-only traversal (`WalkDir::follow_links(false)` sorted deterministically by filename) without executing build scripts (`Makefile`, `build.rs`, `setup.py`, `package.json`).
- **Symlink Traversal Defense**: Both resolving and dangling symlinks are lexically normalized and ancestor-checked against the canonical repository root; any link escaping the boundary fails closed with `ProoflineError::IsolationViolation`.
- **Resource Exhaustion Defense**: File counts (`50,000`), per-file sizes (`10 MB`), and aggregate repository sizes (`500 MB`) are bounded, and reads are capped via `.take(max_file_size + 1)` on opened file handles verified as regular files (preventing TOCTOU swaps or FIFOs).
- **Content-Bound Root Hashing**: `root_hash_blake3` hashes each entry's relative path, byte length, and full BLAKE3 content digest, and `.git/HEAD` is read directly as plain files inside the canonical root without spawning `git`.

## 2. Isolated Execution (`proofline-sandbox`)
- **Tier 1 — Hardware MicroVMs (`FirecrackerSandboxRunner` + `proofline-guest-agent`)**:
  - Boots Linux (`vmlinux-6.1.102`) under KVM (`Firecracker v1.18.0`) with zero network devices (`network-interfaces: []`), immutable read-only `ext4` rootfs (`is_read_only: true`, built via `scripts/build-guest-rootfs.sh`), and host-initiated `virtio-vsock` (`CONNECT 5050` -> `OK <port>` + length-prefixed JSON framing up to `32 MiB`).
  - Guest PID-1 `proofline-guest-agent` verifies `/sys/class/net` contains only `lo` before accepting jobs, enforces wall-clock timeouts, strips ANSI CSI/OSC sequences, and cleans ephemeral `/tmp/proofline-ws-*` staging directories on exit.
  - Host workspace transfer (`stage_workspace_files`) rejects symlinks, enforces bounded counts/sizes (`16 MiB` / `256` files), re-validates normal path components inside the guest, and translates `/workspace/...` arguments safely.
- **Tier 2 — Rootless Container Sandbox (`PodmanSandboxRunner`)**:
  - Enforces `--network=none` for `NetworkPolicy::Denied` and `NetworkPolicy::IsolatedLoopback`. `NetworkPolicy::HermeticProxyOnly` fails closed (never exposing host loopback).
  - Drops all Linux capabilities (`--cap-drop=ALL`), enforces `--security-opt=no-new-privileges`, `--read-only` rootfs with `tmpfs` `/tmp` (`noexec,nosuid`), cgroup memory/CPU/`--pids-limit=256`, and wall-clock timeouts.
  - Rejects flag-injected image names, `:`, NUL, and newline path delimiters, and attaches binary/NUL payloads safely via `attach_input_payload` (`stdin_input` + `PROOFLINE_INPUT_PAYLOAD_B64`).
- **Explicit Downgrade Policy (`AdaptiveSandboxRunner`)**: Prefers `FirecrackerKvm` when `/dev/kvm` and VM artifacts exist, and emits `SECURITY_ISOLATION_DOWNGRADED_WARNING` when falling back to rootless Podman.

## 3. Terminal & Trace Sanitization (`proofline-core`, `proofline-fuzzer`)
- `sanitize_terminal_trace` strips ANSI CSI/OSC escape sequences and dangerous C0 control characters from captured stdout/stderr, logs, and SARIF/Markdown outputs.
- `CrashOracle::evaluate_trace` inspects `stderr` strictly for sanitizer violations (ASan, LSan, TSan, MSan, UBSan) and requires non-zero exit codes for native signals and panics, preventing untrusted `stdout` output from spoofing crashes.
