# L3 to-do list
[[x]] a) Add constants:
[x] L3_MIN_CELLS: how many different Cells must confirm a block before it’s final at L3
[x] L3_HORIZON_EPOCHS: how long we wait to collect these attestations before declaring L3 finality.
[x] DA_SAMPLES_PER_CELL: how many random data chunks each Cell checks to prove the block’s data is actually available.
[x] DA_CHALLENGE_WINDOW: how long a Cell has to answer an extra audit challenge from validators (e.g., 5 seconds).
[x] quorum = 2/3 stake: the validator rule — at least two-thirds of all validator voting power must agree on descendants.

[[x]] b) Add registries:
[x] Cell registry (CellID, gateway BLS pubkey, RegionID, bond, status): list of all Cells, their gateway public keys (so we can verify their signatures) and their current status (active, slashed, offline).
[x] Without these registries, you can’t check who’s allowed to sign or whether they should be trusted.

[[x]] c) Add block metadata storage: BlockID, height, parent, epoch, DA commitment, QC info (who signed descendants).
[x] Each block needs a little sidecar of information to track L3 progress:
[x] Its ID, height, and parent (normal blockchain stuff).
[x] Which epoch it belongs to.
[x] DA commitment: a cryptographic root of the block’s data chunks, so Cells can later prove they checked them.
[x] QC info: which validators signed for descendants, so we can measure whether ≥2/3 stake has accumulated on top of this block.

[[x]] d) Add sampling plan function: DeriveSampleIndices(blockID, cellID, epoch) using epoch beacon → deterministic set of chunk indices.
[x] You need a way for each Cell to know which random pieces of the block’s data to check.
[x] DeriveSampleIndices(blockID, cellID, epoch) → outputs a list of indices (chunk numbers).
[x] It uses randomness from the epoch beacon so no one can predict the samples ahead of time.
[x] This prevents Cells from faking — they must really download those random pieces.

[[x]] e) Add P2P topics:
[x] da/attestation: Cells publish “I checked the data for this block, and it’s available.”
[x] da/challenge: Validators can challenge a Cell to check more pieces.
[x] da/response: Cells answer those challenges.
[x] finality/envelope: Once enough conditions are met, validators publish a “this block is now L3-final” message.

[[x]] f) Add Cell DA attestation format:
[x] This defines exactly what a Cell sends when it claims a block’s data is available. It must include:
[x] Which block it checked.
[x] Which Cell sent it, and from which region.
[x] Which epoch it belongs to.
[x] Which sample indices it checked and the proofs.
[x] The block head it agrees with (so it can’t attest to multiple forks).
[x] A signature from the Cell’s gateway key.
[x] This is the basic vote message for L3.

[[x]] g) Add validator intake path: On attestation:
[x] When a validator receives an attestation, it must:
[x] Check that the Cell is real and active.
[x] Verify the signature is correct.
[x] Reject duplicates (a Cell can’t attest twice for the same block).
[x] Make sure the block is on the validator’s canonical chain.
[x] Check the proofs against the DA commitment.
[x] Update counters: how many distinct Cells and distinct regions have attested to this block.
[x] This keeps the system clean and prevents fake or double votes.

[[x]] h) Add descendant weight tracker: For each block, track QCs on recent descendants; expose HasTwoThirdsWeightOnDescendants(block, horizon).
[x] For L3, we need to know if validators really support a block.
[x] Track how many validator QCs (≥2/3 stake signatures) exist on descendants of a block.
[x] If enough validator weight has built on top of a block within the horizon, that part of the condition is satisfied.

[[x]] i) Add L3 eligibility check: IsL3Ready(block) returns true iff:
[x] This is the final decision function:
[x] IsL3Ready(block) = true only if:
[x] The block is already L2-committed.
[x] Its descendants have ≥2/3 validator stake support within the horizon.
[x] At least L3_MIN_CELLS distinct Cells from L3_MIN_REGIONS confirmed its data.
[x] All those attestations passed audits or were self-verifiable.
[x] If all green, the block can be marked L3-final.

[[ ]] j) Add Finality Envelope (FE) builder: Package {BlockIDCommitted, descendant QC refs, CellBitmap, RegionBitmap, AggSigCells, AggSigValidators, Horizon}; sign/aggregate as needed.
[x] Once a block qualifies, build a certificate for light clients and other nodes:
[x] The block’s ID.
[x] References to descendant QCs.
[x] Which Cells and regions attested (in compressed form).
[ ] Aggregate signatures from Cells and validators. (Pending aggregation support.)
[x] Horizon info (time spanned).
[x] This envelope is broadcast so everyone can agree the block is L3-final.

[[x]] k) Add light-client API: QueryL3Status(BlockID) → NONE | PENDING | FINAL; GetFinalityEnvelope(BlockID).
[x] Expose simple queries:
[x] QueryL3Status(blockID) → is this block not final, pending, or final?
[x] GetFinalityEnvelope(blockID) → returns the proof that it is final.
[x] This makes it easy for wallets and IoT apps to know how safe a block is.

[[x]] l) Add ops/metrics: Per-block counts (Cells, regions), audit pass/fail rates, slashing events, time-to-L3.
[x] Track system health:
[x] How many Cells and regions attested per block.
[x] Audit pass/fail rates.
[ ] Slashing events. (Quarantine flow active; dedicated metric pending.)
[x] Average time it takes for a block to reach L3 finality.
[x] Operators need this to monitor the network.

[[x]] m) Add fail-safes: If Cell attestations are scarce, keep L2 running; do not block consensus on L3. Quarantine misbehaving Cells automatically.
[x] If IoT participation is weak (not enough attestations), don’t block the blockchain
[x] The chain keeps running at L2.
[x] Mark L3 as “pending” but never reached.
[x] Quarantine (ignore) Cells that misbehave often.
[x] This ensures liveness: the network never halts just because IoT devices are flaky.
