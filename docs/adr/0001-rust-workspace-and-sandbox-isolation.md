# ADR-0001: Rust Workspace & Hardware-Oriented Sandbox Isolation

- **Status**: Accepted
- **Date**: 2026-11-25

## Context
Proofline parses untrusted source repositories, inspects complex CPGs, handles raw crash bytes, and orchestrates untrusted builds and test binaries. Building the orchestrator in a memory-unsafe language risks memory corruption in the verifier itself.

## Decision
1. Implement all core subsystems (`proofline-core` through `proofline-cli`) as a modular Cargo workspace in memory-safe Rust.
2. Separate zero-execution static ingestion (`proofline-intelligence`) from isolated dynamic execution (`proofline-sandbox`), enforcing network-denied rootless Podman execution (`--network=none`, `--cap-drop=ALL`, wall-clock timeouts) and air-gapped `FirecrackerVmConfig` KVM specifications.

## Trade-offs & Consequences
- **Benefits**: Eliminates spatial/temporal memory corruption in Proofline parsers and orchestrator; clean crate boundaries prevent circular trust dependencies.
- **Trade-offs**: Longer compile times; Firecracker KVM execution requires `/dev/kvm` on host (Podman rootless container isolation serves as the portable fallback when KVM is unavailable).
- **Failure Detection**: `tests/adversarial_ingestion.rs` and `proofline-sandbox` unit tests enforce fail-closed behavior against symlink escapes, flag/mount injection, timeouts, and network leaks.
