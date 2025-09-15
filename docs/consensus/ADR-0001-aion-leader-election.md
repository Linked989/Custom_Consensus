# ADR-0001: AION Leader Election Wiring

Status: Proposed

Context

- We are introducing AION, a leader election mechanism for IoT Cells, with commit-before-challenge, VRF binding, entropy weighting, and a 5-epoch leadership window.
- Consensus invariants (block structure, hashing, signatures, Merkle, wire formats) must remain unchanged unless a versioned upgrade is executed.

Decision

- Add a feature-flagged gate in the block builder that consults an AION leadership predicate before producing a block. The gate is disabled by default.
- Provide an `internal/aion` module with:
  - Slot/epoch schedule utilities (logging-only).
  - Commit/reveal and challenge derivation helpers.
  - Fixed-point weighting and rank comparison.
  - A process-local toggle to indicate current leadership (dev-only).

Rationale

- This wiring enables integrating AION without changing block hashing/signature paths. With the gate disabled, behavior is identical to current production.
- Once network-wide AION state distribution (commitments, reveals, VRF outputs, entropy proofs) is implemented over gossip and/or on-chain, the leadership toggle will be driven by verifiable inputs.

Compatibility

- Default: No behavior change. `-aion-leader` must be explicitly set to enable the gate, and additional dev-only flags can force leader/follower locally.
- Wire formats, block header/body, and verification remain unchanged.

Migration Plan

1) Implement gossip schemas for AION commitments/reveals/VRF and audits (versioned topics).
2) Implement VRF with audited library and deterministic bindings.
3) Add on-chain commitment inclusion and slashing hooks.
4) Drive the builder gate from verified, network-wide state; publish selection results with proofs.
5) Ship upgrade as a versioned release with clear activation height/epoch and rollback plan.

Security Considerations

- Commit-before-challenge prevents grinding. Entropy floors/caps and moving average mitigate dominance and noise.
- Secrets must never be logged; use constant-time comparisons where relevant.

