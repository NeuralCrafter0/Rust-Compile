# ADR-0003: Epistemic Confidence Tiers & Non-Oracle AI Boundary

- **Status**: Accepted
- **Date**: 2026-11-25

## Context
Security tools routinely conflate heuristic matches, unverified LLM claims, and passing unit tests with verified security properties.

## Decision
1. Classify every finding into mutually exclusive `EpistemicTier` levels (`ConfirmedReproduced`, `SymbolicallySatisfiable`, `StaticallyTainted`, `HeuristicHypothesis`, `VerifiedMitigation`, `Inconclusive`).
2. Isolate all AI interactions in `proofline-ai`: untrusted inputs are XML-escaped inside random-nonce `<UNTRUSTED_DATA>` boundaries, LLM outputs deserialize strictly into unverified `AiHypothesisProposal` variants (`HeuristicHypothesis`), deterministic verification runs exclusively through `AiVerificationGate`, and candidate patches always require explicit `HumanApprovalStatus::Approved` sign-off (`auto_push_permitted = false`).

## Trade-offs & Consequences
- **Benefits**: Mathematically prevents prompt injections or LLM hallucinations from marking vulnerabilities resolved or pushing unreviewed patches.
- **Trade-offs**: Adds human review latency before patch deployment, by deliberate security design.
