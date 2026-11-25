# Project Proofline

**Evidence-grounded security verification, deterministic vulnerability reproduction, differential patch verification, and cryptographically signed attestation bundles.**

> *Claim != Fact; Alert != Vulnerability; Test Passes != Security Verified*

For the full threat model, trust boundaries, epistemic tiers, and design specification, see [RFC-001](docs/rfcs/0001-threat-model-system-boundaries-verification-contract.md).

## Workspace Crates

| Crate | Responsibility |
| :--- | :--- |
| `proofline-core` | Epistemic confidence tiers (`EpistemicTier`), `VerificationContract`, `EvidenceBundle`, error types, ANSI trace sanitization |
| `proofline-intelligence` | Zero-trust repository ingestion, symlink-traversal & resource-limit defenses, manifest inspection, content-bound BLAKE3 root hashing |
| `proofline-sandbox` | Isolated execution via rootless `PodmanSandboxRunner`, `FirecrackerSandboxRunner` (`/dev/kvm` + `virtio-vsock`), and `AdaptiveSandboxRunner` |
| `proofline-cpg` | Multi-file interprocedural `CodePropertyGraph` builder (`ProjectCpgBuilder`) for C, Python, Rust, JS/TS, Go, and Java |
| `proofline-analysis` | Interprocedural dataflow reachability, `ExploitabilityEvaluator`, SMT-LIB2 + bounded native / `z3` solving (`SmtSolverBackend`) |
| `proofline-fuzzer` | `CrashOracle`, N-run determinism (`ReproducerSynthesizer`), `MutationFuzzer`, and `SanitizedBuildPipeline` |
| `proofline-differential` | Dual-branch `V_vuln` vs `V_patch` verification, `AdversarialMutator` bypass discovery, and golden regression invariance checks |
| `proofline-supplychain` | Ed25519 DSSE / in-toto v1.0 & SLSA v1.0 provenance, trust-policy & Rekor validation, SARIF v2.1.0, CycloneDX 1.5 SBOM, Merkle CAS `.tar`/dir Evidence Bundles & replay |
| `proofline-ai` | Non-oracle AI research subsystem: random-nonce XML prompt isolation, deterministic verification gate, human approval gate, BLAKE3 hash-chained audit log |
| `proofline-cli` | `proofline` CLI entry point (`inspect`, `analyze`, `analyze-repo`, `reproduce`, `keygen`, `verify-contract`, `verify-patch`, `verify-bundle`, `verify-builds`) |

## Building & Testing

If your host environment lacks system glibc development headers, run builds and tests inside the `docker.io/library/rust:alpine` container via Podman:

```bash
podman run --rm \
  -v "$(pwd):/workspace:Z" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry:Z" \
  -w /workspace \
  docker.io/library/rust:alpine \
  cargo test --workspace --offline
```

Otherwise, standard `cargo test --workspace` and `cargo build --release -p proofline-cli` work directly.

## CLI Quickstart

```bash
# 1. Inspect a repository safely and emit a CycloneDX 1.5 SBOM
proofline inspect ./path/to/repo --sbom sbom.cdx.json

# 2. Analyze source code reachability and emit SARIF v2.1.0
proofline analyze ./src/handler.c --sarif report.sarif.json

# 3. Generate an Ed25519 attestation keypair
proofline keygen --out-dir ./keys

# 4. Run isolated differential patch verification and package a signed Evidence Bundle
proofline verify-patch \
  --workdir ./target-repo \
  --vuln-cmd /workspace/build-vuln/app \
  --patch-cmd /workspace/build-patch/app \
  --reproducer ./poc.bin \
  --regression ./good_req.bin \
  --signing-key ./keys/proofline.key.json \
  --bundle-out ./evidence.tar \
  --sarif-out ./verification.sarif.json

# 5. Independently verify an Evidence Bundle on a clean machine (add --replay or --trust-policy)
proofline verify-bundle --bundle ./evidence.tar --pubkey ./keys/proofline.pub.json

# 6. Fuzz-reproduce an unverified binary, validate contracts, or compare two build artifacts
proofline reproduce --workdir ./target-repo --budget 64 --out-poc ./poc.bin -- /workspace/app
proofline verify-contract --contract ./tests/integration/sample-contract.json
proofline verify-builds ./build-a/app ./build-b/app
```

## Architecture, Research & Governance

- [Isolation Model](docs/architecture/isolation-model.md)
- [Evidence Bundle Specification](docs/architecture/evidence-specification.md)
- [Research Challenges & Literature Review](docs/research/literature-review.md)
- [Benchmarking Methodology](docs/evaluation/benchmarking-methodology.md)
- Architecture Decision Records: [ADR-0001](docs/adr/0001-rust-workspace-and-sandbox-isolation.md), [ADR-0002](docs/adr/0002-deterministic-ustar-and-ed25519-dsse.md), [ADR-0003](docs/adr/0003-epistemic-confidence-tiers-and-ai-boundary.md)
- [Security Policy](SECURITY.md) & [Contributing Guide](CONTRIBUTING.md)
- Schemas: [verification-contract](schemas/verification-contract.schema.json), [evidence-bundle](schemas/evidence-bundle.schema.json), [attestation-statement](schemas/attestation-statement.schema.json), [code-property-graph](schemas/code-property-graph.schema.json)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
