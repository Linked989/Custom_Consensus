# Implementation Tasks
- [x] Review L2 checkpoint code and design HotStuff-style locking + quorum changes
- [x] Implement L2 service updates for safe voting, QC tracking, and commit rules
- [x] Adjust quorum configuration to 2f+1 and run formatting/tests

- [x] Enforce minimum HotStuff quorum of three validators in L2 service

- [x] Design L3 finality scaffolding in helios module
- [x] Implement L3 finality core data structures and flows
- [x] Update L3 to-do list after implementation

- [x] Add HTTP endpoint exposing consolidated L3 finality health
- [x] Add console logging around L3 readiness and envelope broadcasting

- [x] Catalog HTTP endpoints across project
- [x] Summarize HTTP endpoints with descriptions

- [x] Inspect L service status data for debug endpoint
- [x] Implement consolidated L debug endpoint
- [x] Format code if needed

- [x] Review current IoT/cell/node membership flows
- [x] Design updates for device/node behavior
- [x] Implement IoT join/retry/state changes
- [x] Update tests or add new ones if feasible
- [x] Format code and finalize
- [x] Analyze IoT HTTP flows and libp2p support
- [x] Design libp2p protocols for device registration and data
- [x] Implement node-side libp2p handlers for IoT
- [x] Update IoT device client to use libp2p channels
- [x] Remove HTTP-based IoT pathways and validate build

- [x] Review IoT device connection/discovery implementation
- [x] Implement automatic node discovery for IoT devices
- [x] Validate IoT connectivity and update docs/tests if needed
- [x] Restore HTTP registration path for IoT devices with registry limits
- [x] Update IoT device client to use HTTP registration then libp2p telemetry
- [x] Build binaries to verify changes
- [x] Investigate `cellThreshold` handling in `cmd/node/node.go`
- [x] Fix `cellThreshold` usage to respect `-iot-max-devices`
- [x] Verify `iotMax` enforcement when `iot-max-devices` flag changes
- [x] Reproduce missing `-iot-max-devices` effect in `cellThreshold`
- [x] Implement fix so `cellThreshold` honors `iotMax`
- [x] Validate runtime logs reflect configured IoT device limit
- [x] Normalize boolean flag parsing so `-iot-max-devices` is always read
- [x] Design IoT-level orchestrator for simulated device assignments
- [x] Investigate L3 pending status under multi-node deployments
- [x] Evaluate consensus resilience to latency and low-power nodes
- [x] Simplify L3 finality by removing region quorum requirements
- [x] Design lightweight IoT device L3 attestation flow
- [x] Implement IoT-driven finality quorum and device attestation APIs
- [x] Update IoT simulator to submit L3 attestations and report participation

- [x] Design IoT L3 attester goroutines
- [x] Implement IoT L3 attester simulator updates

- [x] Optimize IoT attester latency
- [x] Tighten L3 attestation scheduling loop

- [x] Silence L3 attester console output
- [x] Streamline attester loop for minimal delays

- [x] Track dedicated L3 attester count
- [x] Apply attester-specific quorum thresholds

- [x] Discover L3 attesters across nodes
- [x] Keep attester totals refreshed dynamically

- [x] Auto-discover L3 attesters without flags

- [x] Enrich L3 attester progress reporting

- [x] Allow L3 attesters without consuming IoT capacity

- [x] Ensure IoT attester registration does not consume device slots

- [x] Drain mempool directly during block proposals

- [ ] Investigate empty blocks despite mempool drain

- [x] Add HTTP endpoint exposing mempool stats

- [ ] Confirm IoT telemetry reaches mempool
- [x] Analyze IoT tx submission vs mempool admission
- [x] Fix mempool admission path so IoT tx persist
- [ ] Validate mempool fills when IoT tx arrive
- [x] Broadcast IoT device keys to peers on registration
- [x] Retry mempool admission after key sync
- [x] Split IoT attester simulator into separate binary
- [x] Update iotdev to emit telemetry only
- [x] Implement dedicated attester runner
- [x] Review iotdev behavior for telemetry-only operation
- [x] Update simulator to skip attestation logic for telemetry devices
- [x] Auto-fetch device keys on unknown kid during tx gossip
- [x] Wire node host into gossip tx admission for key fetch
- [x] Add logging flags (-log-aion, -log-l1, -log-l2, -log-l3, -log-blocks, -log-http-tx, -log-iot)
- [x] Gate AION/HELIOS/blockchain/HTTP logs behind flags
- [x] Suppress L2/L3 commit logs unless flags enabled
- [x] Add leader/block summary logs for troubleshooting empty blocks
- [x] Log tx admission failures and retries behind -log-tx
- [x] Investigate IoT handler compilation errors in `internal/p2p/iot.go`
- [x] Fix IoT handler to call in-package AnnounceDeviceKey with valid context
- [x] Drop internal iotsim package and inline iotdev simulator
- [x] Log bold IoT payloads on node admission
- [x] Restore legacy iotdev telemetry+cell formation simulator
- [x] Align iotdev telemetry payloads with dev generator format
