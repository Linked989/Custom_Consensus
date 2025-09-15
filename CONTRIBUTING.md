# Repository Guidelines

## Project Structure & Module Organization
- Entrypoints in `cmd/`: `cmd/node` (full node), `cmd/iotp2p` (P2P runner), `cmd/iotdev` (device simulator), `cmd/txgen` (load generator).
- Core logic in `internal/*` (e.g., `internal/blockchain`, `internal/mempool`, `internal/merkle`).
- Tests live next to code as `*_test.go`. Keep fixtures minimal and deterministic.

## Build, Test, and Development Commands
- Toolchain: Go 1.24.7. Use the standard `go` CLI; Makefile provides wrappers.
- Build: `make build` (builds `./cmd/node`).
- Run seed node: `make run-seed BIND=127.0.0.1 SEED_PORT=4001 SWARM=swarm.key`.
- Run peer: `make run-peer BIND=127.0.0.1 SWARM=swarm.key`.
- Generate swarm key: `make gen-swarm` (writes `swarm.key`).
- Format/Tidy: `make fmt`, `make tidy`.
- Tests: `go test ./...` (with race: `go test -race ./...`).

## Coding Style & Naming Conventions
- Format with `go fmt`; prefer `golangci-lint run` if available.
- Packages: short, lower-case; no underscores or stutter.
- Identifiers: exported `PascalCase`, unexported `camelCase`; avoid one-letter names.
- Public APIs accept `context.Context` as first argument when applicable.
- Determinism in hot paths: no `time.Now()`, `rand.Read`, or map-order reliance.

## Testing Guidelines
- Use Go’s `testing` package and table-driven tests; keep tests deterministic.
- Name by unit and behavior, e.g., `TestMerkle_ComputeRoot_Deterministic`.
- Include negative tests for validation errors and boundary cases.
- Prefer `t.Parallel()` where safe; run `go test -race ./...` before PRs.

## Commit & Pull Request Guidelines
- Commits: imperative mood with scope, e.g., `mempool: bound admission queue`.
- PRs: include motivation, approach, risks, and linked issues.
- Any consensus/wire change requires an ADR at `docs/consensus/ADR-####.md` with compatibility notes.

## Security & Configuration Tips
- Never log secrets; use constant-time comparisons for secret material.
- No CGO in consensus paths; avoid reflection in hot loops.
- Keep allocations bounded; prefer immutable state in consensus-critical code.

