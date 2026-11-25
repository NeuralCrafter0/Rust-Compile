# ADR-0002: Pure-Rust Deterministic USTAR Archives & Ed25519 DSSE Attestations

- **Status**: Accepted
- **Date**: 2026-11-25

## Context
Evidence Bundles must be independently verifiable and replayable on clean machines without trusting external `tar` CLI flags or non-canonical JSON serialization.

## Decision
1. Implement a hardened pure-Rust USTAR `.tar` writer/reader (`proofline-supplychain::archive`) with fixed timestamps/UIDs/GIDs, sorted entries, and strict rejection of symlinks, hardlinks, `..` traversal, duplicate entries, and archive bombs.
2. Canonicalize `manifest.json` signable fields and `in-toto` v1.0 statements with RFC 8785 JCS (`serde_jcs`), sign using Ed25519 (`ed25519-dalek` with `verify_strict`), bind artifacts under a domain-separated binary BLAKE3 Merkle tree, and verify signer/builder trust via `TrustedIdentityPolicy`.

## Trade-offs & Consequences
- **Benefits**: Zero external archive-tool attack surface; bit-for-bit reproducible `.tar` bundles; strict immunity to JSON whitespace/key-ordering malleability and Ed25519 signature malleability.
- **Trade-offs**: Pure-Rust USTAR restricts entry path lengths to 255 bytes (155 prefix + 100 name) and stores uncompressed `.tar` (sufficient for compact evidence artifacts and trivial to verify).
