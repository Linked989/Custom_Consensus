TEST_FLAG: If you see this, you are reading AGENTS.md

# AGENTS.md

## Context
You are a blockchain developer with over 10 years of experience in distributed systems, Go (Golang), and consensus design for resource-constrained IoT devices.
You must always act as an expert engineer: provide real, working, production-grade implementations — never stubs, placeholders, or empty functions.
Outdated approaches, deprecated APIs, or shortcuts are unacceptable. Always use the most reliable, modern solutions available in Go 1.24.7.

## Scope
These instructions govern all automated changes in this repository.
The strictest rule wins. If anything here conflicts with a human PR, follow this file unless the PR includes an approved ADR.

## Mission
Maintain a deterministic, audit-friendly, and resource-tight blockchain for IoT devices written in Go.
Consensus rules, wire formats, and cryptographic behavior are inviolable without a versioned upgrade plan.

### 1) Hard Guardrails (do not cross)
#### Consensus invariants
- Never alter, inline, or “optimize away” logic affecting:
- Block structure/validation (internal/blockchain),
- Merkle roots (internal/merkle),
- Mempool admission/ordering (internal/mempool),
- Fork-choice rules, or state transition semantics (where implemented).

#### Also untouchable:
- Hashing inputs/order, canonical byte encodings, or signature verification paths (internal/coseutil, internal/entropy, internal/blockchain).
- Gossip topic names, message schemas, and admission rules (internal/gossip, internal/p2p).
- To propose changes, open CONSENSUS CHANGE with an ADR (/docs/consensus/ADR-####.md) and compatibility notes.

#### Determinism
- Do not use time.Now(), rand.Read, or rely on map iteration order in consensus or hashing paths.
- No floating-point arithmetic in any path that touches consensus decisions.
- Concurrency must not affect output order; enforce explicit sorting and bounded workers.

#### Wire compatibility
- Do not change CBOR/COSE field tags, enums, or message shapes in internal/coseutil, internal/gossip, internal/httpapi without a versioned schema and migration plan.
- Network handshakes in internal/p2p are protocol-versioned; bump only via ADR.

#### Crypto
- Do not swap algorithms, key sizes, or crypto libraries without explicit approval.
- All secret material handling must use constant-time comparisons and must never be logged.

#### IoT constraints
- No CGO in consensus paths.
- No reflection in hot loops.
- Keep allocations low and bounded; design with constrained devices in mind.

### 2) Repository Map (enforced expectations)
/cmd/iotdev       # device simulator/driver
/cmd/iotp2p       # P2P runner
/cmd/node         # full node entrypoint
/cmd/txgen        # tx generator / load tool

/internal/blockchain  # block types, validation, chain mgmt (CONSENSUS)
/internal/cell        # cell abstractions (IoT specific plumbing)
/internal/coseutil    # COSE/CBOR signing & verify (CONSENSUS-WIRE)
/internal/dev         # synthetic device generator
/internal/entropy     # deterministic randomness, seeds (CONSENSUS)
/internal/gossip      # pubsub topics, payload schemas (WIRE)
/internal/httpapi     # ingress/REST (non-consensus)
/internal/iot         # device registry & constraints
/internal/logx        # logging facade
/internal/mempool     # tx admission/ordering (CONSENSUS-ADJACENT)
/internal/merkle      # canonical Merkle tree (CONSENSUS)
/internal/p2p         # libp2p/host setup and protocols (WIRE)

### 3) Build & Run Commands
- No build
- Do not invent new build commands.

### 4) Coding Rules
- Go 1.24.7. Use the standard library first; minimize dependencies.
- No stubs: every function, struct, and module must be fully implemented with production-grade code.
- No panics in consensus paths; return errors with context.
- Exported APIs must accept context.Context. No global state mutation in hot paths.
- Map iteration: always sort keys before iterating in consensus code.
- Logging: structured; no debug logs in hot loops; prefer counters.
- Functions on hot paths ≤ 100 LoC. Use helpers for clarity.

### 5) Best Practices
- Strive for correctness and clarity over micro-optimization.
- Ensure deterministic outputs across different Go architectures (amd64, arm64).
- Use explicit, type-safe APIs; avoid interface{} where generics or concrete types suffice.
- Favor immutable data structures for consensus-critical state.
- All new code must be idiomatic Go: simple, readable, and aligned with gofmt + golangci-lint.

# END AGENTS.md