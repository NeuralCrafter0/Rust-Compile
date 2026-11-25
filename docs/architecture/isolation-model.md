# Proofline Isolation Model

This document specifies the active isolation boundaries enforced across the Proofline crates as established in [RFC-001](../rfcs/0001-threat-model-system-boundaries-verification-contract.md).

## 1. Zero-Trust Repository Ingestion (`proofline-intelligence`)
- `IngestionEngine::inspect_repository` performs read-only traversal (`WalkDir::follow_links(false)` sorted deterministically by filename).
- **Symlink Traversal Defense**: Both resolving and dangling symlinks are lexically normalized and ancestor-checked against the canonical repository root; any link escaping the boundary fails closed with `ProoflineError::IsolationViolation`.
- **Resource Exhaustion Defense**: File counts, per-file sizes, and aggregate repository sizes are strictly bounded, and reads are capped via `.take(max_file_size + 1)` on opened file handles verified as regular files (preventing TOCTOU swaps or FIFOs).
- **Content-Bound Root Hashing**: `root_hash_blake3` hashes each entry's relative path, byte length, and full BLAKE3 content digest.

## 2. Isolated Execution (`proofline-sandbox`)
- **Container Sandbox (`PodmanSandboxRunner`)**:
  - Network is disabled (`--network=none`) for `NetworkPolicy::Denied` and `NetworkPolicy::IsolatedLoopback`. `NetworkPolicy::HermeticProxyOnly` fails closed unless an explicit isolated proxy is configured (no host loopback exposure).
  - Drops all Linux capabilities (`--cap-drop=ALL`), enforces `--security-opt=no-new-privileges`, applies cgroup memory/CPU/`--pids-limit=256`, and enforces wall-clock timeouts (`--timeout` plus Rust deadline watcher killing overdue processes).
  - Validates container image names (rejecting leading `-`), working directory paths (rejecting `:`, NUL, newlines), and environment variable keys/values.
  - Binary payloads are attached via `attach_input_payload` (`stdin_input` + `PROOFLINE_INPUT_PAYLOAD_B64`), preventing NUL-byte `execve` failures and UTF-8 lossy corruption.
- **MicroVM Config (`FirecrackerVmConfig`)**: Builds air-gapped KVM microVM configurations with read-only rootfs, virtio-vsock IPC, and zero network devices.

## 3. Terminal & Trace Sanitization (`proofline-core`, `proofline-fuzzer`)
- `sanitize_terminal_trace` strips ANSI CSI/OSC escape sequences and dangerous C0 control characters from captured stdout/stderr and SARIF/bundle logs.
- `CrashOracle::evaluate_trace` inspects `stderr` for sanitizer violations (ASan, LSan, TSan, MSan, UBSan) and requires non-zero exit codes for native signals and panics, preventing untrusted `stdout` output from spoofing crashes.
