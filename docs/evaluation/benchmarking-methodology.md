# Proofline Benchmarking & Evaluation Methodology

## Objectives
Evaluate Proofline empirically across static reachability accuracy, deterministic crash reproduction, differential patch soundness & bypass detection, adversarial ingestion safety, and independent Evidence Bundle verification/replay.

## Current Controlled Evaluation Suites (`crates/proofline-cli/tests/benchmark_eval.rs`)
1. **Static Reachability Corpus (`benchmark_static_reachability_precision_recall`)**:
   - Measures true positives, false positives, true negatives, and false negatives across C (`strcpy`, `memcpy`, `strcat`, guarded `sizeof` bounds, bogus constant guards, clean literal copies) and Python (`request.args.get` -> `cursor.execute`, `os.system`, sanitized paths, clean reassignments).
2. **Historical Patch-Bypass Corpus (`benchmark_historical_patch_bypass_corpus`)**:
   - Evaluates detection of incomplete patches across CWE-22 (`..%2f` URL encoding, `..;/` semicolon path params), CWE-89 (`/**/` SQL comment whitespace bypass), and CWE-78 (`${IFS}` command separator bypass).
3. **Compiled Native C Reproduction & Differential Suite (`benchmark_real_compiled_c_reproduction_and_differential_patch`)**:
   - Compiles real C binaries (`vuln.c` vs `patch.c`) via `gcc` when available, runs N-run determinism checks (5/5 runs), and verifies differential mitigation and regression equivalence.
4. **Adversarial & Supply-Chain Self-Tests**:
   - `crates/proofline-intelligence/tests/adversarial_ingestion.rs`: Hostile `Makefile`, file-count resource exhaustion, resolving/dangling symlink escapes, content-hash sensitivity.
   - `crates/proofline-ai/tests/prompt_injection_defense.rs`: XML boundary escape, unauthorized verdict rejection, tamper-evident audit chain.
   - `crates/proofline-supplychain/tests/bundle_verification.rs`: Tampered artifact, rogue file injection, wrong signer key, untrusted builder policy, tar symlink/traversal rejection, and replay verification.

## Known Limitations
- The current controlled benchmark suite covers small synthetic and compiled C/Python cases rather than full-scale external datasets (Juliet 64k / Magma OpenSSL/libpng/sqlite3). External dataset integrations should be executed inside dedicated KVM/Podman CI runners and reported separately with exact commit SHAs and hardware specs.
