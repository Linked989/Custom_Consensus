# Blockchain Operations Runbook

This guide covers the current node process, multi-machine deployment, transaction
generation, IoT simulation, monitoring, and HTTP data collection interfaces.

## Requirements

- Go `1.24.7` (`go.mod` selects this toolchain).
- The same repository checkout on each node machine.
- TCP connectivity between validators on the chosen libp2p port.
- HTTP connectivity to any node used for transaction submission or monitoring.
- For a private libp2p network, the same `swarm.key` file on every node.

Use three validator nodes for HELIOS L2 finality. Node startup can pass preflight
with two connected nodes, but L2 quorum has a minimum of three validators.

## Important Runtime Behavior

- `cmd/node` is the validator/node process.
- A node waits before starting blockchain services until it has a peer and enough
  locally registered IoT devices.
- `-iot-max-devices N` sets both local device capacity and the local cell threshold.
- If `-iot-max-devices` is omitted or `0`, the effective cell threshold defaults to `2`.
- `-http` must be enabled on nodes that receive transactions, IoT registrations, or API queries.
- All participating nodes must use the same `-chain-id`; the default is `iotnet-main`.
- `-mdns=true` is convenient on one LAN; explicit `-bootstrap` addresses are appropriate
  between machines or across subnets.

## Quick Local Three-Node Lab

The bundled tmux scripts contain machine-specific IP defaults. Review their
constants before use. They also still pass the deprecated `-cell-min-devices`
flag; for new manual runs, use `-iot-max-devices`.

Generate one private-network key:

```bash
go run ./cmd/node -gen-swarm-key swarm.key
```

Terminal 1:

```bash
go run ./cmd/node \
  -port 4101 -http :14001 -pnet swarm.key -mdns=true \
  -chain-id iotnet-main -iot-max-devices 2 -data-dir .data/node1 \
  -verbose -log-mempool=true
```

Terminal 2:

```bash
go run ./cmd/node \
  -port 4102 -http :14002 -pnet swarm.key -mdns=true \
  -chain-id iotnet-main -iot-max-devices 2 -data-dir .data/node2 \
  -verbose -log-mempool=true
```

Terminal 3:

```bash
go run ./cmd/node \
  -port 4103 -http :14003 -pnet swarm.key -mdns=true \
  -chain-id iotnet-main -iot-max-devices 2 -data-dir .data/node3 \
  -verbose -log-mempool=true
```

Register two telemetry devices per node and continuously submit their readings
through node 1:

```bash
go run ./cmd/iotdev \
  -devices 6 \
  -reg-bases http://localhost:14001,http://localhost:14002,http://localhost:14003 \
  -reg-caps 2,2,2 \
  -tx-base http://localhost:14001 \
  -interval 1500ms -jitter 500ms
```

Check startup and progress:

```bash
curl -s http://localhost:14001/status
curl -s http://localhost:14001/network/members
curl -s 'http://localhost:14001/mempool?snapshot=1&limit=10'
curl -s http://localhost:14001/blocks
```

## Three Machines

Example addresses:

| Host | Validator IP | P2P port | HTTP port |
| --- | --- | ---: | ---: |
| Host 1 | `192.168.1.21` | `4101` | `14000` |
| Host 2 | `192.168.1.22` | `4101` | `14000` |
| Host 3 | `192.168.1.23` | `4101` | `14000` |

On Host 1, create `swarm.key`, then securely place the same file on Hosts 2
and 3:

```bash
go run ./cmd/node -gen-swarm-key swarm.key
```

Start Host 1:

```bash
go run ./cmd/node \
  -bind 192.168.1.21 -port 4101 -http :14000 \
  -pnet swarm.key -mdns=false -chain-id iotnet-main \
  -iot-max-devices 2 -data-dir .data/node \
  -verbose -log-blocks=true -log-mempool=true
```

Its startup logs print a libp2p address similar to:

```text
/ip4/192.168.1.21/tcp/4101/p2p/12D3KooW_REPLACE_WITH_HOST1_PEER_ID
```

Use that full address as `BOOTSTRAP_ADDR` below.

Start Host 2:

```bash
go run ./cmd/node \
  -bind 192.168.1.22 -port 4101 -http :14000 \
  -pnet swarm.key -mdns=false -chain-id iotnet-main \
  -iot-max-devices 2 -data-dir .data/node \
  -bootstrap /ip4/192.168.1.21/tcp/4101/p2p/12D3KooW_REPLACE_WITH_HOST1_PEER_ID \
  -verbose -log-blocks=true -log-mempool=true
```

Start Host 3:

```bash
go run ./cmd/node \
  -bind 192.168.1.23 -port 4101 -http :14000 \
  -pnet swarm.key -mdns=false -chain-id iotnet-main \
  -iot-max-devices 2 -data-dir .data/node \
  -bootstrap /ip4/192.168.1.21/tcp/4101/p2p/12D3KooW_REPLACE_WITH_HOST1_PEER_ID \
  -verbose -log-blocks=true -log-mempool=true
```

From any machine that can reach the validators, register the required local
devices and send telemetry transactions through Host 1:

```bash
go run ./cmd/iotdev \
  -devices 6 \
  -reg-bases http://192.168.1.21:14000,http://192.168.1.22:14000,http://192.168.1.23:14000 \
  -reg-caps 2,2,2 \
  -tx-base http://192.168.1.21:14000 \
  -chain iotnet-main
```

## Transaction Generation

### Direct Signed Transaction Load

`cmd/txgen` creates an Ed25519 key, registers its public key through
`/keys/register`, builds signed COSE transactions, and submits them to `/tx`.
It generates transactions, but does not register IoT cell membership; use
`iotdev` first if nodes are still waiting for local device thresholds.

```bash
go run ./cmd/txgen \
  -url http://192.168.1.21:14000/tx \
  -count 100 \
  -interval 200ms \
  -chain iotnet-main
```

Useful variants:

```bash
# Ten transactions to a local node using defaults.
go run ./cmd/txgen

# Faster traffic once the node is ready.
go run ./cmd/txgen -url http://localhost:14001/tx -count 1000 -interval 10ms
```

### Telemetry Device Simulation

`cmd/iotdev` both registers simulated devices and continuously emits signed
sensor telemetry transactions:

```bash
# One node: register two devices, send one reading from each, then exit.
go run ./cmd/iotdev -base http://localhost:14001 -devices 2 -once

# Three nodes: distribute registrations while sending all telemetry to node 1.
go run ./cmd/iotdev \
  -devices 6 \
  -reg-bases http://localhost:14001,http://localhost:14002,http://localhost:14003 \
  -reg-caps 2,2,2 \
  -tx-base http://localhost:14001

# View registered devices on one node.
go run ./cmd/iotdev -base http://localhost:14001 -list
```

### Built-In Node Generator

After node preflight completes, a node can publish synthetic transactions itself:

```bash
go run ./cmd/node \
  -port 4101 -http :14001 -pnet swarm.key -mdns=true \
  -iot-max-devices 2 -data-dir .data/node1 \
  -dev-gen-tx=true -dev-interval 500ms -log-dev=true -verbose
```

The node still needs peer connectivity and registered devices before this
generator is started.

## Monitoring And Dashboards

There is no web dashboard, Grafana configuration, or exposed Prometheus
metrics endpoint in this repository. Monitoring is provided through JSON HTTP
endpoints and logs.

For useful node logs:

```bash
go run ./cmd/node ... \
  -verbose -stats 5s -log-mempool=true \
  -log-blocks=true -log-aion=true -log-l1=true -log-l2=true -log-l3=true \
  -log-http-tx=true -log-iot=true -log-tx=true
```

`info.go` is a separate terminal host-resource display for Linux/Raspberry Pi
systems (CPU, memory, disk, temperature, and network rates). It does not show
blockchain status:

```bash
go run ./info.go
```

## HTTP API And Data Collection

Set an API base once for shell examples:

```bash
BASE=http://localhost:14001
```

### Health, Membership, And Mempool

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/status` | Tip height/hash, peers, node counts, mempool length, and L2 status when initialized. |
| `GET` | `/network/members` | Node directory and online/offline observations. |
| `GET` | `/mempool` | Current pending transaction count. |
| `GET` | `/mempool?snapshot=1&limit=100` | Pending transaction IDs, device IDs, sequence numbers, sizes, and ages. |

```bash
curl -s "$BASE/status"
curl -s "$BASE/network/members"
curl -s "$BASE/mempool?snapshot=1&limit=100"
```

### Blocks And Transactions

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/blocks?n=20` | Recent block hashes and heights. |
| `GET` | `/block/{hash}` | Block contents plus available L1 attestation information. |
| `GET` | `/block/height/{height}` | Redirect to the block at a height. |
| `GET` | `/tx/{txid}` | Find the block and height containing a transaction. |
| `POST` | `/tx` | Submit a signed COSE transaction body (`application/cbor`). |
| `POST` | `/keys/register` | Register an Ed25519 key used to validate external signed transactions. |

```bash
curl -s "$BASE/blocks?n=5"
curl -sL "$BASE/block/height/1"
curl -s "$BASE/tx/REPLACE_WITH_TXID"
```

Use `cmd/txgen` or `cmd/iotdev` for `POST /tx`; each builds the required signed
COSE payload.

### Consensus And Finality

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/aion/status` | Current leader-election/network status after services initialize. |
| `GET` | `/helios/status` | Recent L1 notarization observations. |
| `GET` | `/helios/l2/status` | L2 checkpoint and quorum status. |
| `GET` | `/helios/debug/layers?limit=10` | Combined L1/L2/L3 view for recent tracked blocks. |
| `GET` | `/helios/l3/overview?limit=10` | L3 status and metrics across tracked blocks. |
| `GET` | `/helios/l3/pending` | Highest pending L3 block awaiting device quorum. |
| `GET` | `/helios/l3/status?block={hash}` | Status, readiness, device votes, and audit counts for one block. |
| `GET` | `/helios/l3/envelope?block={hash}` | Finality envelope for a finalized block. |

```bash
curl -s "$BASE/aion/status"
curl -s "$BASE/helios/debug/layers?limit=10"
curl -s "$BASE/helios/l3/overview?limit=10"
curl -s "$BASE/helios/l3/pending"
curl -s "$BASE/helios/l3/status?block=REPLACE_WITH_BLOCK_HASH"
```

Before blockchain services clear preflight, endpoints depending on AION or
HELIOS can return `503 ... not initialized`.

### IoT Cells And Devices

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/iot/capacity` | Node capacity, registered-device count, and P2P addresses. |
| `GET` | `/iot/devices` | Registered devices on this node. |
| `POST` | `/iot/register` | Register a device for local cell membership. |
| `POST` | `/iot/attest` | Submit an L3 device attestation for a block. |
| `GET` | `/cell/status` | Current local cell state. |
| `GET` | `/cell/entropy` | Current entropy summary calculated from mempool samples. |

```bash
curl -s "$BASE/iot/capacity"
curl -s "$BASE/iot/devices"
curl -s "$BASE/cell/status"
curl -s "$BASE/cell/entropy"
```

`cmd/iotdev` is the normal way to create correctly keyed `/iot/register`
requests and telemetry transactions.

## Data Collection Examples

Capture regular operational snapshots as newline-delimited JSON:

```bash
while sleep 5; do
  curl -s "$BASE/status"
done >> status.ndjson
```

Capture finality-layer snapshots:

```bash
while sleep 5; do
  curl -s "$BASE/helios/debug/layers?limit=20"
done >> helios-layers.ndjson
```

Capture pending transaction samples:

```bash
while sleep 2; do
  curl -s "$BASE/mempool?snapshot=1&limit=100"
done >> mempool.ndjson
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Node stays at `preflight waiting` | Confirm it has at least one peer and enough devices registered locally; query `/iot/capacity`. |
| L2 does not commit with two validators | Run at least three validators; the L2 quorum minimum is three. |
| `txgen` cannot register or submit | Ensure target node started with `-http` and its HTTP port is reachable. |
| Submitted telemetry is rejected | Ensure the key was registered on the submitting node; `iotdev` handles this automatically. |
| Peer connection fails in private mode | Confirm every validator has the exact same `swarm.key` and `-chain-id`. |
| Finality endpoints return `503` | Blockchain services have not completed preflight initialization. |

## Current Limitations

- No bundled browser dashboard or `/metrics` Prometheus endpoint is implemented.
- The bundled tmux scripts require local IP edits and use a deprecated device-threshold flag.
- `cmd/iotattester` currently imports `pose/internal/iotsim`, which is absent in
  this checkout; it is not usable until that command is repaired.
