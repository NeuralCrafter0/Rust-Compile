# Contributing to Project Proofline

## Engineering Principles
1. **Evidence before confidence**: Never elevate an `EpistemicTier` without deterministic execution evidence or strict verification.
2. **Fail-closed security boundaries**: Any missing artifact, checksum mismatch, symlink escape, network configuration ambiguity, or timeout must fail closed (`Err(...)` or `EpistemicTier::Inconclusive`).
3. **No un-sandboxed untrusted execution**: Production code must execute untrusted inputs strictly inside `PodmanSandboxRunner` or configured microVM isolation.
4. **No fabricated benchmarks or claims**: Document only observed test outputs and real limitations.

## Local Development & Testing
Run the full workspace test suite inside the `rust:alpine` toolchain container (or directly via `cargo test --workspace` on systems with native C/glibc development toolchains):

```bash
podman run --rm \
  -v "$(pwd):/workspace:Z" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry:Z" \
  -w /workspace \
  docker.io/library/rust:alpine \
  cargo test --workspace --offline
```

## Pull Request Checklist
- All existing and new unit/integration tests pass without warnings (`cargo test --workspace`).
- Security-sensitive changes include negative/adversarial tests (tampering, traversal, bypass, or injection).
- Documentation and schemas remain synchronized with Rust types (`schemas/*.json`).
