# Proofline Benchmarking & Evaluation Methodology

## Objectives
Evaluate Proofline empirically across static reachability accuracy, deterministic crash reproduction, differential patch soundness & bypass detection, adversarial ingestion safety, hardware microVM isolation, and independent Evidence Bundle verification/replay.

## Controlled Evaluation Suites (`crates/proofline-cli/tests/benchmark_eval.rs`)
1. **Static Reachability Corpus (`benchmark_static_reachability_precision_recall`)**:
   - Measures true positives, false positives, true negatives, and false negatives across C (`strcpy`, `memcpy`, `strcat`, guarded `sizeof` bounds, bogus constant guards, clean literal copies) and Python (`request.args.get` -> `cursor.execute`, `os.system`, sanitized paths, clean reassignments).
2. **Historical Patch-Bypass Corpus (`benchmark_historical_patch_bypass_corpus`)**:
   - Evaluates detection of incomplete patches across CWE-22 (`..%2f` URL encoding, `..;/` semicolon path params), CWE-89 (`/**/` SQL comment whitespace bypass), and CWE-78 (`${IFS}` command separator bypass).
3. **Compiled Native C Reproduction & Differential Suite (`benchmark_real_compiled_c_reproduction_and_differential_patch`)**:
   - Compiles real C binaries (`vuln.c` vs `patch.c` vs `naive_patch.c`) via `gcc` when available, runs N-run determinism checks (5/5 runs), and verifies differential mitigation, bypass discovery, and regression equivalence.
4. **Six-Class Compiled CVE Patch-Verification Corpus (`crates/proofline-cli/tests/cve_corpus_eval.rs`)**:
   - Compiles and tests CWE-22 path traversal (`../` vs `..%2f` incomplete patch bypass), CWE-120 unbounded copy, CWE-190 integer multiplication wraparound, CWE-134 format string crash + signed `.tar` Evidence Bundle replay, CWE-158 embedded raw NUL-byte payload handling, and FM-6 semantic invariant drift.
5. **Adversarial & Supply-Chain Self-Tests**:
   - `crates/proofline-intelligence/tests/adversarial_ingestion.rs`: Hostile `Makefile`, file-count resource exhaustion, resolving/dangling symlink escapes, content-hash sensitivity.
   - `crates/proofline-ai/tests/prompt_injection_defense.rs`: XML boundary escape, unauthorized verdict rejection, tamper-evident audit chain.
   - `crates/proofline-supplychain/tests/bundle_verification.rs`: Tampered artifact, rogue file injection, wrong signer key, untrusted builder policy, tar symlink/traversal rejection, and replay verification.
   - `crates/proofline-cpg/tests/treesitter_ast.rs`: Multi-line C/Python/Rust Tree-sitter AST parsing and comment-trap immunity (`/* ... */`, `# ...`, `// ...`).

## Real-World Upstream Evaluation (`DaveGamble/cJSON`), Z3 & Live KVM Runs
Executed against upstream `DaveGamble/cJSON` commits compiled with Alpine `clang 17.0.6 -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g` inside network-denied `localhost/proofline-sandbox:latest`:

1. **Upstream Repository Inspection & Static Analysis (`DaveGamble/cJSON`, commit `fb16e5cf358798aabb049655975cde8427101056`)**:
   - `proofline inspect` ingested 230 files (1,282,274 bytes, root BLAKE3 `82fe4ffb8ce6c0ac6905b6dc4b99d138ce33531af29fb8edac517e1403289428`, build systems `[CMake, Makefile, Npm]`) and emitted a CycloneDX 1.5 SBOM.
   - `proofline analyze-repo` constructed Tree-sitter C CPGs across the repository with 0 false-positive taint findings (`No tainted interprocedural paths detected`). *(Static scope note: C pointer-lifetime/use-after-free typestate is not modeled statically as libc `SecurityIngress -> SecuritySink` taint and is instead verified dynamically under ASan/UBSan.)*
2. **Heap Use-After-Free Sound Patch (`DaveGamble/cJSON` #1065 — `cJSONUtils_MergePatch`)**:
   - **Revisions**: `V_vuln` = `fb16e5cf358798aabb049655975cde8427101056`, `V_patch` = `6d9f2443ab071f86e5d9b43025a40929ec41c46c`.
   - **Observed Behavior**: `V_vuln` failed deterministically (3/3 runs) under `AddressSanitizer: heap-use-after-free` (4-byte read at `0x506000000098`). `proofline verify-patch` verified mitigation (`VerifiedMitigation`), evaluated 3 bypass mutations (0 bypasses), observed 0 golden regression divergences, and issued signed bundle `EVD-2026-F590A49906F34297B330AF150C1CD1E4` (8 CAS artifacts, BLAKE3 Merkle root `fd1030e15806c78cb436474159c4da4547ffc3ee0d9bbb7e1f39f505bf41dea8`).
   - **Trust Policy Check**: `proofline verify-bundle` rejected an unmatched `builder_id` policy (`Trust policy rejected`) and accepted the matching key/builder pair (`TRUSTED`).
3. **Incomplete Recursion Fix Detection (`DaveGamble/cJSON` #984 — `cJSON_Print`)**:
   - **Revisions**: `V_vuln` = `a29814f285cc531c00223743ad3c55cd38c0dc56`, `V_patch` = `5cc0e39f42dfe28cb8541f95fa2c513f0d550210` (with 1 MiB stack limit).
   - **Observed Behavior**: Both `V_vuln` and `V_patch` crashed under `AddressSanitizer: stack-overflow` at depth `150000` (`V_patch` stopped inside `cJSON_PrintUnformatted` with `printed=0`, then overflowed the stack inside `cJSON_Delete`). `proofline verify-patch` rejected `VerifiedMitigation`, classified `ConfirmedReproduced` (`Original Reproducer Mitigated on V_patch: false`, exit code `2`), and recorded negative evidence in `EVD-2026-8CC97854E5A344A3B966BA7A3E80E738`.
4. **External SMT Solver (`Z3 4.13.0`)**:
   - `SmtSolverBackend::solve_smt_lib2` (`proofline-analysis` `test_bounded_native_smt_solver_sat_and_unsat`) and standalone `z3 -in -T:2` ran against `Z3 4.13.0` inside network-denied `localhost/proofline-sandbox:latest`, solving generated `QF_BV` constraints (`sat`, `SymbolicallySatisfiable`).
5. **Hardware MicroVM Execution (`Firecracker v1.18.0` on `/dev/kvm`)**:
   - `crates/proofline-sandbox/tests/firecracker_kvm_live.rs` booted two sequential air-gapped `Firecracker v1.18.0` KVM microVMs (`vmlinux-6.1.102`, read-only 64 MiB Alpine `rootfs.ext4` via `scripts/build-guest-rootfs.sh`, `proofline-guest-agent --vsock-port 5050` over `virtio-vsock`, 0 NICs) in `0.36s` total, confirming `/sys/class/net == ["lo"]`, read-only `/` enforcement, ANSI CSI sanitization, and fault exit code `42` propagation.

## Known Limitations
- Upstream real-world validation currently covers selected `DaveGamble/cJSON` CVEs alongside the synthetic/compiled multi-CVE suite rather than a full-scale multi-repository corpus campaign (e.g., Juliet 64k or OSS-Fuzz/Magma across OpenSSL/libpng/sqlite3).
- `proofline-cpg` uses real Tree-sitter parsers for C, Python, and Rust, while JS/TS, Go, and Java frontends remain structured parsers and static taint analysis does not model C heap lifetime / use-after-free typestate statically.
- External benchmark campaigns should execute inside dedicated KVM/Podman CI runners and report exact commit SHAs, compiler flags, and hardware specs alongside signed Evidence Bundles.
