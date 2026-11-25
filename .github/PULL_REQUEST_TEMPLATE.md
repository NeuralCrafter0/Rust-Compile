## Summary
<!-- Describe the change, target crate(s), and rationale. -->

## Related Architecture / RFC
- Reference [RFC-001](docs/rfcs/0001-threat-model-system-boundaries-verification-contract.md) or ADR if applicable.

## Security & Verification Checklist
- [ ] All changes uphold **fail-closed** security boundaries (missing keys, symlink escapes, NUL/traversal payloads, timeouts).
- [ ] No untrusted repository code or test inputs run outside `PodmanSandboxRunner` / `FirecrackerSandboxRunner`.
- [ ] No AI proposal bypasses deterministic verification (`EpistemicTier` invariants preserved).
- [ ] Workspace tests pass (`cargo test --workspace --locked`) with zero compiler warnings.
- [ ] Relevant adversarial/negative tests and documentation/schema updates are included.
