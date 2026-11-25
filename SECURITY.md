# Security Policy

## Threat Model & Disclosure Scope
Project Proofline processes untrusted source repositories, exploit payloads, and candidate patches. Security boundaries are documented in [RFC-001](docs/rfcs/0001-threat-model-system-boundaries-verification-contract.md) and [Isolation Model](docs/architecture/isolation-model.md).

High-priority vulnerability classes in Proofline itself include:
- Sandbox escapes (container/microVM breakouts, mount/flag injection, network leaks).
- Ingestion traversal or resource-exhaustion bypasses (`proofline-intelligence`, `proofline-supplychain::archive`).
- Cryptographic verification bypasses or signature malleability (`proofline-supplychain`, `proofline-core`).
- Prompt-injection or oracle bypasses allowing unverified AI claims (`proofline-ai`).
- Terminal escape injection in logs or reports (`sanitize_terminal_trace`).

## Reporting a Vulnerability
Do **not** open public GitHub issues for unpatched security vulnerabilities in Proofline.
1. Send an encrypted or private report to `security@proofline.dev` including a minimal deterministic reproducer and impacted crate/commit.
2. Include only benign proof-of-concept payloads (never exfiltrate third-party data or run tests against unauthorized hosts).
3. Maintainers acknowledge reports within 72 hours and follow coordinated disclosure with an independently verifiable Evidence Bundle attached to the security advisory.
