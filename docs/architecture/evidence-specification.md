# Proofline Evidence Specification

## 1. Evidence Bundle Structure
Packaged by `proofline-supplychain::EvidenceBundlePackager` (to a directory or deterministic USTAR `.tar` archive):

```text
evidence-bundle/
├── manifest.json                 # Signed manifest (schemas/evidence-bundle.schema.json)
├── verification-contract.json    # Serialized VerificationContract
├── attestation.in-toto.json      # Ed25519 DSSE envelope wrapping in-toto v1.0 Statement
├── sarif.json                    # OASIS SARIF v2.1.0 report
├── harness/
│   ├── build.sh                  # Hermetic build script
│   ├── run.sh                    # Self-contained execution harness script
│   ├── reproducer.bin            # Raw reproducer payload bytes
│   └── bin/                      # Optional embedded target executable (0755, <= 16 MiB)
├── traces/
│   ├── execution.log             # ANSI-sanitized execution log
│   └── sanitizer.log             # ANSI-sanitized fault/sanitizer trace
└── cas/
    └── blake3/
        ├── sha256_tree.json      # Per-artifact SHA-256 map
        └── artifact_digests.json # Sorted BLAKE3 CAS artifact index
```

## 2. Cryptographic Integrity & Attestation
1. **Binary BLAKE3 Merkle Root (`compute_cas_merkle_root`)**: Domain-separated (`0x00` leaf, `0x01` internal node) Merkle tree over all sorted `(path, size_bytes, blake3_digest)` leaves.
2. **Manifest Signature**: Canonicalized using RFC 8785 JCS (`serde_jcs`) and signed with Ed25519 (`ed25519-dalek` strict verification).
3. **in-toto v1.0 DSSE Envelope**: Canonical statement (`https://in-toto.io/Statement/v1`) binding subject digests (`blake3` CAS Merkle root + `sha256` manifest digest) and verification predicate (`https://proofline.dev/attestation/verification/v1`) via `DSSEv1` PAE.
4. **Signer vs Trust Policy Separation (`TrustedIdentityPolicy`)**: `EvidenceBundleVerifier::evaluate_trust_policy` separates cryptographic signature validity from authorization of `key_id` and `builder_id` (`TrustedIdentityAndBuilder` vs `ValidSignatureUntrustedSigner`).
5. **Independent Verification & Replay (`EvidenceBundleVerifier`)**: Rejects tar traversal, symlinks/hardlinks, duplicate entries, missing files, unattested extra files, digest/Merkle mismatches, key-id mismatches, and invalid Ed25519 signatures, and replays `harness/run.sh` + `harness/reproducer.bin` inside an isolated Podman or Firecracker sandbox via `verify_and_replay`.
