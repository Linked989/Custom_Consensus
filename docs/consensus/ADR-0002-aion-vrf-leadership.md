# ADR-0002: AION Verifiable Leader Election (VRF + Commit/Reveal)

Status: Proposed

Context

- ADR-0001 wired AION leadership as a local, feature-flag predicate without changing consensus paths. It enabled experimentation but leadership could not be verified network‑wide.
- To make AION actionable, leaders must be elected using verifiable inputs that every validator can check deterministically.
- We must not change existing block hashing/signature paths and wire formats without a versioned upgrade and migration.

Goals

- Introduce verifiable AION leadership using: commit‑before‑challenge, VRF binding, and entropy weighting.
- Define versioned gossip topics and message schemas for commitments, reveals, VRF outputs, and audits.
- Specify validator rules to accept/reject blocks based on leadership proofs, without yet changing block headers (proofs circulate on gossip initially).

Non‑Goals

- No change to block header/body fields in this ADR.
- No finality gadget (covered by ADR‑0003).

Decision

- Adopt a VRF‑based selection driven by per‑epoch challenge and entropy‑weighted ranking.
- Distribute inputs and proofs on versioned gossip topics; validators maintain a rolling view of the latest verifiable state and gate block acceptance by epoch leader.
- Keep block structure unchanged; leadership proof accompanies the proposed block on a parallel gossip channel and is cached prior to block validation.

Protocol Overview

- Epoch: e = floor((height-1)/EpochLength). Challenge: C_e = H(last_finalized_hash || be64(e)).
- Seed Commit: at or before e-1, each producer commits S_e via Com_e = H(S_e).
- Reveal + VRF: at epoch e, reveal S_e and compute VRF_y,π = VRF(S_e || C_e). Verify π.
- Entropy Weighting: Use H_norm from audited inputs (see Audits) and fixed‑point weight W_e = 1 + α·MA4(H_norm).
- Rank: R = VRF_y / W_e. Smallest R wins; for practical gating, compare prefix bits of R to threshold.

Gossip Topics (versioned)

- aion/commit/1.0.0
  - Fields: { pubkey, epoch, commit: [32], ts }
  - Rule: only one commit per (pubkey, epoch). Validators store latest valid.
- aion/reveal/1.0.0
  - Fields: { pubkey, epoch, seed, commit: [32], proofCT }
  - Rule: H(seed) == commit; commitment must predate challenge epoch by ≥1.
- aion/vrf/1.0.0
  - Fields: { pubkey, epoch, input_hash: [32], y: [32], pi: bytes }
  - Rule: Verify VRF over (seed || challenge) with network VRF.
- aion/audit/1.0.0
  - Fields: { pubkey, epoch, h_norm_q16: u32, sample_count: u32, witness: bytes }
  - Rule: Optional; provides auditable H_norm evidence. Absent audits default to conservative H_norm.

Validator Rules (no header change)

- For a received block B at height h and epoch e:
  - Reconstruct C_e from the local finalized tip and e.
  - Require a cached leadership bundle for B.ProducerPub at epoch e: {commit, reveal(seed), vrf(y,π)} where Verify(reveal, commit) and VerifyVRF(seed||C_e, y,π) hold.
  - Compute W_e from audited H_norm (or default bound), then R = y/W_e.
  - Accept B only if the producer is elected under the configured threshold for e and is the first valid leader observed for that slot/epoch.
  - Otherwise, reject B as not‑leader.

Data Retention

- Maintain sliding windows of commitments, reveals, VRFs, and audits for the last N epochs (N ≥ LeadershipWindow + safety margin).

Determinism & Security

- All inputs hashed with SHA‑256 and big‑endian epoch encoding; no wall‑clock in consensus paths.
- VRF must be constant‑time, audited, and consistent network‑wide (algorithm + encodings fixed in ADR text upon selection).
- Commit‑before‑challenge enforces unpredictability; audits mitigate entropy manipulation.

Compatibility

- No block header/body changes. New gossip topics are versioned.
- Activation guarded by a network parameter: until quorum enables, validators do not enforce leader proofs.

Migration Plan

1) Implement topics and in‑memory caches for commit/reveal/vrf/audit.
2) Ship nodes that publish and verify, but do not yet enforce gating.
3) Enable soft‑validation: log/warn on non‑leader blocks while still accepting them.
4) Governance vote to activate enforcement at a future epoch E_act, published via release notes.
5) Post‑activation: validators reject blocks without valid leadership for epoch e ≥ E_act.

VRF Algorithm

- For this phase, use Ed25519 signature as a verifiable function:
  - Input I_e = seed_e || C_e, where seed_e is private, deterministic per node and epoch.
  - Proof π = Ed25519-Sign(sk, I_e); Output y = SHA256(π).
  - Verify with producer pubkey and recompute y.
  - seed_e is derived deterministically as seed_e = SHA256(Ed25519-Sign(sk, "aion-seed"||be64(e))).

Open Questions

- Threshold calibration and multi‑leader tie‑breaks if multiple pass; tie‑break: smallest y/W_e, then pubkey lexicographic.
- Audit witness format for H_norm.

---

# Appendix A: Fixed‑Point Definitions

- H_norm in Q16.16 = min(H_lb, 128)/128.
- W_e = 1 + α·MA4(H_norm).
- Rank compares r = floor((y << 16)/W_e) as big‑endian bytes.
