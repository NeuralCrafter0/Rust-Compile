# Proofline Research Challenges & Literature Review

This document investigates the ten core research challenges defined in the Project Proofline mission specification, comparing established academic and industry approaches, their documented limitations, and Proofline's engineering direction.

---

## Challenge 1: Cross-Language Data-Flow Analysis
- **Existing Approaches**: Joern (Yamaguchi et al., IEEE S&P 2014) models AST/CFG/PDG edges in a unified Code Property Graph; CodeQL compiles language frontends into relational Datalog databases; Semgrep uses language-specific AST pattern matching with lightweight intra-procedural taint.
- **Limitations**: Cross-language boundaries (e.g., Python calling native C extensions via `ctypes`/FFI, or Rust `extern "C"` blocks) lose static type/alias continuity because each language frontend produces incompatible IRs.
- **Proofline Approach & Current State**: `proofline-cpg` normalizes source programs into a shared `CodePropertyGraph` schema (`SecurityIngress`, `Assignment`, `SanitizerGuard`, `SecuritySink`, `DataFlow`, `CfgNext`, `CallEdge`). `CSourceParser`, `PythonSourceParser`, and `RustSourceParser` parse real AST/CST trees via `tree-sitter-c`, `tree-sitter-python`, and `tree-sitter-rust`; `JsTsSourceParser`, `GoSourceParser`, and `JavaSourceParser` provide structured multi-language coverage, while Tree-sitter upgrades for those remaining languages and LLVM IR lowering across FFI boundaries remain future extensions.

## Challenge 2: Mutual Refinement Between Static Analysis and Runtime Evidence
- **Existing Approaches**: Hybrid fuzzers such as Driller (Stephens et al., NDSS 2016) and QSYM (Yun et al., USENIX Security 2018) pair concolic execution with AFL to pass magic-byte branches; static reachability filters prune fuzz targets.
- **Limitations**: Pure static analysis suffers false positives from unmodeled sanitizers and dead paths, while blind fuzzers stall on deep semantic preconditions.
- **Proofline Approach & Current State**: `TaintAnalysisEngine` (`proofline-analysis`) feeds `SmtPathConstraintGenerator` and `WitnessSeedSynthesizer` to seed dynamic execution in `proofline-fuzzer`. Runtime results never retroactively alter static graph edges; instead, findings are promoted along strict `EpistemicTier` boundaries (`StaticallyTainted` -> `ConfirmedReproduced`) only when `CrashOracle` observes deterministic faults across N clean sandbox runs.

## Challenge 3: Focusing Symbolic Execution on Security-Relevant Paths
- **Existing Approaches**: KLEE (Cadar et al., OSDI 2008) and angr (Shoshitaishvili et al., IEEE S&P 2016) explore feasible paths symbolically; directed symbolic execution (Ma et al., SAS 2011; Katch) guides exploration toward target sink lines.
- **Limitations**: Unbounded path explosion in loops, library syscalls, and string-heavy parsers makes full symbolic execution intractable at repository scale.
- **Proofline Approach & Current State**: Proofline restricts path-condition generation (`SmtPathConstraintGenerator`) to CPG-reachable ingress-to-sink slices (`find_dataflow_path`) rather than whole-program exploration, emitting bounded SMT-LIB2 theories (`QF_BV`, `QF_SLIA`) with explicit timeout fallback to `EpistemicTier::Inconclusive`.

## Challenge 4: Distinguishing Genuine Exploitability from Theoretical Reachability
- **Existing Approaches**: SAST taint engines flag source-to-sink flows regardless of caller authentication or input exposure; call-graph reachability scanners (e.g., DepClean/Eclipse Steady) check whether a vulnerable library symbol is called.
- **Limitations**: A statically reachable sink behind `@login_required` or admin authorization is not directly exploitable under an anonymous network attacker model.
- **Proofline Approach & Current State**: `ExploitabilityEvaluator` (`proofline-analysis`) evaluates CPG traces against `VerificationContract` attacker models (`IngressBoundary`, `AttackerAuthTier`), distinguishing `ExploitableUnderAttackerModel` from `GatedByAuthenticationBoundary` and requiring isolated runtime reproduction (`proofline-fuzzer`) before issuing `ConfirmedReproduced`.

## Challenge 5: Evaluating Patches Against Unknown Attack Variants & Bypasses
- **Existing Approaches**: Unit regression suites verify the single reported PoC fails to crash; DiffKemp compares LLVM IR semantics in C subsystems; Csmith generates random programs for compiler differential testing.
- **Limitations**: Maintainer patches frequently block only the exact syntactic exploit string (e.g., blocking `../` while missing `..%2f`, `..;/`, or SQL comment obfuscation), or silently alter normal application outputs (`FM-6`).
- **Proofline Approach & Current State**: `DifferentialVerificationEngine` (`proofline-differential`) runs a 4-stage loop: (1) confirm crash on `V_vuln`, (2) confirm mitigation on `V_patch`, (3) mutate the reproducer via `AdversarialMutator` against `V_patch` to uncover encoding/boundary bypasses, and (4) compare exit codes and stdout BLAKE3 digests across `V_vuln` and `V_patch` for golden regression inputs. *Honest limitation*: mutation coverage is bounded by mutation budget and cannot prove universal absence of all bypasses (RFC-001 Non-Objective 1).

## Challenge 6: Reliability Across Compilers, Runtimes, and Build Configurations
- **Existing Approaches**: Sanitizers (ASan/UBSan/TSan/MSan) instrument native binaries; Miri checks Rust `unsafe` UB; deterministic containers pin toolchains.
- **Limitations**: Compiler optimizations (`-O2`/`-O3`) can elide undefined behavior checks or alter memory layouts; flaky race conditions vary across runs.
- **Proofline Approach & Current State**: `SanitizerKind` standardizes `-fsanitize=... -fno-omit-frame-pointer -g -O1` flags, and `ReproducerSynthesizer` enforces N-run determinism (`successful_runs == required_runs`), downgrading non-deterministic crashes to `EpistemicTier::Inconclusive`.

## Challenge 7: Independent Software Provenance Verification
- **Existing Approaches**: SLSA v1.0, in-toto v1.0 Attestations, DSSE envelopes, and Sigstore Rekor/Fulcio establish signed build provenance; Reproducible Builds compare independent rebuild outputs.
- **Limitations**: A valid cryptographic signature only proves possession of a private key—it does not establish whether the signing key or builder identity is trustworthy, nor whether the built artifact is vulnerability-free.
- **Proofline Approach & Current State**: `proofline-supplychain` packages Evidence Bundles with RFC 8785 JCS canonicalization (`serde_jcs`), domain-separated BLAKE3 Merkle CAS trees, and Ed25519 DSSE envelopes (`verify_strict`), and implements `TrustedIdentityPolicy` (`evaluate_trust_policy`) to separate `ValidSignatureUntrustedSigner` from `TrustedIdentityAndBuilder`.

## Challenge 8: Analyzing Hostile Code Without Compromising Analysis Infrastructure
- **Existing Approaches**: Rootless containers (Podman), syscall-filtering user kernels (gVisor), and KVM hardware microVMs (Firecracker, Agache et al., NSDI 2020).
- **Limitations**: Naive ingestion on the host risks symlink escapes, zip/tar bombs, terminal escape injection, and malicious `Makefile`/`build.rs` execution; shared-kernel containers remain exposed to host kernel vulnerabilities.
- **Proofline Approach & Current State**:
  - `proofline-intelligence` performs static ingestion without executing build scripts, rejects resolving & dangling symlinks escaping the canonical root, caps file counts/sizes with TOCTOU handle checks, and hashes full file contents.
  - `proofline-sandbox` enforces network-denied (`--network=none`) rootless Podman execution with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, memory/PID limits, wall-clock timeout enforcement, fail-closed `HermeticProxyOnly`, and hardware-virtualized `FirecrackerSandboxRunner` (`/dev/kvm` + `virtio-vsock` -> `proofline-guest-agent` inside read-only `ext4` rootfs images built via `scripts/build-guest-rootfs.sh`).
  - `proofline-core` sanitizes ANSI CSI/OSC escape sequences; `proofline-supplychain` uses a pure-Rust USTAR parser rejecting symlinks/hardlinks/`..` traversal/tar bombs.

## Challenge 9: Turning AI Hypotheses into Reproducible Verification Procedures
- **Existing Approaches**: LLM security assistants output unstructured explanations or unverified patches directly to developers.
- **Limitations**: LLMs hallucinate exploitability, fall prey to indirect prompt injection inside source comments (`// [PROMPT OVERRIDE...]`), and cannot provide cryptographic evidence.
- **Proofline Approach & Current State**: `proofline-ai` isolates untrusted code inside per-invocation random-nonce XML `<UNTRUSTED_DATA nonce="...">` tags with XML escaping, restricts AI outputs to unverified `AiHypothesisProposal` variants (`EpistemicTier::HeuristicHypothesis`), routes every reproducer or candidate patch through `AiVerificationGate` (deterministic `ReproducerSynthesizer` / `DifferentialVerificationEngine`), logs all actions in a BLAKE3 hash-chained `AiAuditLog`, and requires explicit `HumanApprovalStatus::Approved` before acceptance.

## Challenge 10: Independent End-to-End Auditability
- **Existing Approaches**: SAST tools emit PDF/JSON dashboards or unverified SARIF files without replay inputs or cryptographic binding.
- **Limitations**: Third-party engineers cannot re-run or verify claims without recreating fragile environments or trusting the reporter blindly.
- **Proofline Approach & Current State**: Every verification run emits a deterministic `.tar` or directory Evidence Bundle containing `manifest.json`, `verification-contract.json`, `attestation.in-toto.json`, `sarif.json`, `harness/`, sanitized `traces/`, and `cas/blake3/`, verifiable and replayable on an independent machine via `proofline verify-bundle --bundle ... --pubkey ... --replay`.
