# Changelog

All notable changes to Project Proofline are documented in this file.

## [0.1.0] - 2026-11-26

### Core Platform & Architecture
- Defined epistemic confidence model (`EpistemicTier`), declarative `VerificationContract` (`PVC-*`), ANSI/CSI/OSC trace sanitization (`sanitize_terminal_trace`), and tamper-evident `EvidenceBundle` manifests (`proofline-core`).
- Implemented non-executing, traversal-safe repository ingestion (`IngestionEngine`) with resolving/dangling symlink checks, TOCTOU file-handle bounds, CycloneDX 1.5 SBOM export, and content-bound `BLAKE3` hashing (`proofline-intelligence`, `proofline-supplychain`).

### Program Analysis & Verification
- Built multi-file interprocedural `CodePropertyGraph` infrastructure (`ProjectCpgBuilder`) backed by real Tree-sitter parsers for **C, Python, Rust, JavaScript, TypeScript/TSX, Go, and Java** (`proofline-cpg`).
- Added interprocedural dataflow reachability, attacker-model gating (`ExploitabilityEvaluator`), AST-extracted C array/ingress bounds synthesis (`SmtPathConstraintGenerator`), and `Z3` + bounded native SMT solving (`TaintAnalysisEngine::analyze_with_smt` in `proofline-analysis`).

### Sandboxed Reproduction & Differential Verification
- Built air-gapped **Firecracker v1.18.0 KVM** microVM execution (`FirecrackerSandboxRunner`, `proofline-guest-agent` over `virtio-vsock`, host->guest `stage_workspace_files`) alongside rootless **Podman** container isolation (`PodmanSandboxRunner`) and explicit downgrade reporting (`AdaptiveSandboxRunner` in `proofline-sandbox`).
- Implemented multi-oracle stderr crash classification (`ASan`/`UBSan`/`TSan`/`MSan`/signals/panics), N-run determinism verification (`ReproducerSynthesizer`), and mutation fuzzing (`MutationFuzzer` in `proofline-fuzzer`).
- Built 4-stage `V_vuln` vs `V_patch` differential verification (`DifferentialVerificationEngine`) with `AdversarialMutator` bypass discovery and golden regression divergence detection (`proofline-differential`).

### Supply-Chain Attestation, AI Boundaries & CLI
- Added RFC 8785 JCS Ed25519 signing, DSSE in-toto v1.0 & SLSA provenance generation, `TrustedIdentityPolicy` separation, OASIS SARIF v2.1.0 reporting, deterministic traversal-safe USTAR archives with domain-separated BLAKE3 Merkle CAS roots, bit-for-bit build diffing, and self-contained `--replay` bundle packaging (`proofline-supplychain`).
- Added CSPRNG nonce-isolated XML prompt boundaries, `AiVerificationGate`, human approval gates, and hash-chained `AiAuditLog` (`proofline-ai`).
- Exposed unified workflows through `proofline` CLI (`inspect`, `analyze`, `analyze-repo`, `keygen`, `reproduce`, `verify-patch`, `verify-bundle`, `verify-contract`, `verify-builds`) with `--sandbox <podman|firecracker|auto>`.
