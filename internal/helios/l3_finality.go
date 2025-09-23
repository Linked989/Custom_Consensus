package helios

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/logx"
)

const (
	topicDAAttestation = "helios/da/attestation/1.0.0"
	topicDAChallenge   = "helios/da/challenge/1.0.0"
	topicDAResponse    = "helios/da/response/1.0.0"
	topicL3Envelope    = "helios/finality/envelope/1.0.0"
)

const (
	defaultL3MinCells       = 7
	defaultL3SamplesPerCell = 16
	defaultL3HorizonEpochs  = 4
	defaultL3StakeThreshold = 0.6666667
	defaultMaxMisbehavior   = 3
	defaultChallengeWindow  = 5 * time.Second
)

// L3Params holds configurable knobs for the L3 service.
type L3Params struct {
	MinCells        int
	SamplesPerCell  int
	HorizonEpochs   uint64
	StakeThreshold  float64
	TotalStake      float64
	ChallengeWindow time.Duration
	MaxMisbehavior  int
}

func defaultL3Params() L3Params {
	return L3Params{
		MinCells:        defaultL3MinCells,
		SamplesPerCell:  defaultL3SamplesPerCell,
		HorizonEpochs:   defaultL3HorizonEpochs,
		StakeThreshold:  defaultL3StakeThreshold,
		TotalStake:      1.0,
		ChallengeWindow: defaultChallengeWindow,
		MaxMisbehavior:  defaultMaxMisbehavior,
	}
}

// CellStatus tracks the lifecycle of a registered cell.
type CellStatus uint8

const (
	CellStatusUnknown CellStatus = iota
	CellStatusActive
	CellStatusOffline
	CellStatusSlashed
	CellStatusQuarantined
)

// CellRecord describes a cell and its gateway key.
type CellRecord struct {
	ID      string
	PubKey  []byte
	Bond    uint64
	Status  CellStatus
	Updated time.Time
}

// CellRegistry stores authorized cells for DA attestations.
type CellRegistry struct {
	mu      sync.RWMutex
	records map[string]CellRecord
}

func newCellRegistry() *CellRegistry { return &CellRegistry{records: make(map[string]CellRecord)} }

func (r *CellRegistry) Register(rec CellRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.Status = CellStatusActive
	rec.Updated = time.Now().UTC()
	r.records[rec.ID] = rec
}

func (r *CellRegistry) UpdateStatus(id string, status CellStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[id]
	if !ok {
		return
	}
	rec.Status = status
	rec.Updated = time.Now().UTC()
	r.records[id] = rec
}

func (r *CellRegistry) Lookup(id string) (CellRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[id]
	if !ok {
		return CellRecord{}, false
	}
	return rec, true
}

func (r *CellRegistry) ActiveCells() []CellRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CellRecord, 0, len(r.records))
	for _, rec := range r.records {
		if rec.Status == CellStatusActive {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *CellRegistry) ActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for _, rec := range r.records {
		if rec.Status == CellStatusActive {
			count++
		}
	}
	return count
}

// EpochBeacon exposes randomness per epoch.
type EpochBeacon interface {
	Randomness(epoch uint64) []byte
}

// StaticBeacon returns deterministic zeros when no external beacon is wired.
type StaticBeacon struct{}

func (StaticBeacon) Randomness(epoch uint64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[:8], epoch)
	return buf
}

// DataVerifier verifies DA proofs for sampled chunks.
type DataVerifier interface {
	Verify(blockID []byte, indices []uint32, proofs [][]byte, commitment []byte) bool
}

// NoopVerifier accepts proofs without checking.
type NoopVerifier struct{}

func (NoopVerifier) Verify(_ []byte, _ []uint32, _ [][]byte, _ []byte) bool { return true }

// SamplePlan deterministically derives chunk indices for a cell.
func SamplePlan(beacon EpochBeacon, blockID []byte, cellID string, epoch uint64, count int, totalChunks uint32) []uint32 {
	if count <= 0 || totalChunks == 0 {
		return nil
	}
	seed := sha256.Sum256(append(append(beacon.Randomness(epoch), blockID...), []byte(cellID)...))
	out := make([]uint32, 0, count)
	ctr := uint32(0)
	for len(out) < count {
		hasher := sha256.Sum256(append(seed[:], byte(ctr>>24), byte(ctr>>16), byte(ctr>>8), byte(ctr)))
		for i := 0; i+4 <= len(hasher); i += 4 {
			idx := binary.BigEndian.Uint32(hasher[i:i+4]) % totalChunks
			out = append(out, idx)
			if len(out) == count {
				break
			}
		}
		ctr++
	}
	return out
}

// L3Attestation carries DA confirmation for a block.
type L3Attestation struct {
	BlockID       []byte   `cbor:"0,keyasint"`
	Height        int64    `cbor:"1,keyasint"`
	Epoch         uint64   `cbor:"2,keyasint"`
	CellID        string   `cbor:"3,keyasint"`
	SampleIndices []uint32 `cbor:"4,keyasint"`
	Proofs        [][]byte `cbor:"5,keyasint"`
	HeadID        []byte   `cbor:"6,keyasint"`
	Signature     []byte   `cbor:"7,keyasint"`
	TotalChunks   uint32   `cbor:"8,keyasint"`
}

// L3Challenge requests additional samples from a cell.
type L3Challenge struct {
	BlockID  []byte    `cbor:"0,keyasint"`
	Epoch    uint64    `cbor:"1,keyasint"`
	CellID   string    `cbor:"2,keyasint"`
	Indices  []uint32  `cbor:"3,keyasint"`
	Issuer   []byte    `cbor:"4,keyasint"`
	IssuedAt time.Time `cbor:"5,keyasint"`
}

// L3Response answers a challenge with extra proofs.
type L3Response struct {
	Challenge L3Challenge `cbor:"0,keyasint"`
	Proofs    [][]byte    `cbor:"1,keyasint"`
	Signature []byte      `cbor:"2,keyasint"`
}

// ValidatorQCRef links descendant QCs used for finality.
type ValidatorQCRef struct {
	BlockID   []byte    `cbor:"0,keyasint"`
	Height    int64     `cbor:"1,keyasint"`
	Epoch     uint64    `cbor:"2,keyasint"`
	Weight    float64   `cbor:"3,keyasint"`
	Signers   [][]byte  `cbor:"4,keyasint"`
	CreatedAt time.Time `cbor:"5,keyasint"`
}

// FinalityEnvelope packages the proof of L3 finality.
type FinalityEnvelope struct {
	BlockID         []byte           `cbor:"0,keyasint"`
	Height          int64            `cbor:"1,keyasint"`
	Horizon         uint64           `cbor:"2,keyasint"`
	DescendantQCs   []ValidatorQCRef `cbor:"3,keyasint"`
	CellBitmap      []string         `cbor:"4,keyasint"`
	CellAggSig      []byte           `cbor:"5,keyasint"`
	ValidatorAggSig []byte           `cbor:"6,keyasint"`
	FinalizedAt     time.Time        `cbor:"7,keyasint"`
}

// L3Status enumerates light-client status.
type L3Status uint8

const (
	L3StatusNone L3Status = iota
	L3StatusPending
	L3StatusFinal
)

func (st L3Status) String() string {
	switch st {
	case L3StatusFinal:
		return "final"
	case L3StatusPending:
		return "pending"
	default:
		return "none"
	}
}

type blockCounters struct {
	cells        map[string]struct{}
	attestations map[string]L3Attestation
	deviceVotes  map[string]struct{}
	auditsPassed int
	auditsFailed int
	qcWeight     float64
	qcs          []ValidatorQCRef
	l2Committed  bool
	daCommitment []byte
	parentHex    string
	height       int64
	epoch        uint64
	firstSeen    time.Time
	envelope     *FinalityEnvelope
	status       L3Status
}

// L3Service manages DA attestations and finality envelopes.
type L3Service struct {
	ctx      context.Context
	h        host.Host
	ps       *pubsub.PubSub
	em       cbor.EncMode
	dm       cbor.DecMode
	params   L3Params
	beacon   EpochBeacon
	verifier DataVerifier

	tAtt *pubsub.Topic
	tCh  *pubsub.Topic
	tRsp *pubsub.Topic
	tEnv *pubsub.Topic

	mu        sync.Mutex
	blocks    map[string]*blockCounters
	misbehave map[string]int

	cells *CellRegistry

	devicesTotal int
}

// StartL3Finality configures subscriptions and processing loops.
func StartL3Finality(ctx context.Context, h host.Host, ps *pubsub.PubSub, params L3Params, beacon EpochBeacon, verifier DataVerifier) *L3Service {
	if params.MinCells <= 0 {
		params.MinCells = defaultL3Params().MinCells
	}
	if params.SamplesPerCell <= 0 {
		params.SamplesPerCell = defaultL3Params().SamplesPerCell
	}
	if params.HorizonEpochs == 0 {
		params.HorizonEpochs = defaultL3Params().HorizonEpochs
	}
	if params.StakeThreshold <= 0 {
		params.StakeThreshold = defaultL3Params().StakeThreshold
	}
	if params.TotalStake <= 0 {
		params.TotalStake = defaultL3Params().TotalStake
	}
	if params.ChallengeWindow <= 0 {
		params.ChallengeWindow = defaultL3Params().ChallengeWindow
	}
	if params.MaxMisbehavior <= 0 {
		params.MaxMisbehavior = defaultL3Params().MaxMisbehavior
	}
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
	if beacon == nil {
		beacon = StaticBeacon{}
	}
	if verifier == nil {
		verifier = NoopVerifier{}
	}
	svc := &L3Service{
		ctx:       ctx,
		h:         h,
		ps:        ps,
		em:        em,
		dm:        dm,
		params:    params,
		beacon:    beacon,
		verifier:  verifier,
		blocks:    make(map[string]*blockCounters),
		misbehave: make(map[string]int),
		cells:     newCellRegistry(),
	}
	if ps != nil {
		svc.tAtt, _ = ps.Join(topicDAAttestation)
		svc.tCh, _ = ps.Join(topicDAChallenge)
		svc.tRsp, _ = ps.Join(topicDAResponse)
		svc.tEnv, _ = ps.Join(topicL3Envelope)
		if svc.tAtt != nil {
			if sub, err := svc.tAtt.Subscribe(); err == nil {
				go svc.consumeAttestations(sub)
			}
		}
		if svc.tCh != nil {
			if sub, err := svc.tCh.Subscribe(); err == nil {
				go svc.consumeChallenges(sub)
			}
		}
		if svc.tRsp != nil {
			if sub, err := svc.tRsp.Subscribe(); err == nil {
				go svc.consumeResponses(sub)
			}
		}
		if svc.tEnv != nil {
			if sub, err := svc.tEnv.Subscribe(); err == nil {
				go svc.consumeEnvelopes(sub)
			}
		}
	}
	go svc.runFinalityRechecks()
	return svc
}

// UpdateTotalStake refreshes the expected validator stake for readiness checks.
func (s *L3Service) UpdateTotalStake(stake float64) {
	if stake <= 0 {
		return
	}
	s.mu.Lock()
	s.params.TotalStake = stake
	s.mu.Unlock()
	logx.Info("helios l3 stake update", "total_stake", stake)
}

func (s *L3Service) consumeAttestations(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(s.ctx)
		if err != nil {
			return
		}
		s.onAttestation(msg.Message.GetData(), msg.ReceivedFrom)
	}
}

func (s *L3Service) consumeChallenges(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(s.ctx)
		if err != nil {
			return
		}
		s.onChallenge(msg.Message.GetData(), msg.ReceivedFrom)
	}
}

func (s *L3Service) consumeResponses(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(s.ctx)
		if err != nil {
			return
		}
		s.onResponse(msg.Message.GetData(), msg.ReceivedFrom)
	}
}

func (s *L3Service) consumeEnvelopes(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(s.ctx)
		if err != nil {
			return
		}
		s.onEnvelope(msg.Message.GetData(), msg.ReceivedFrom)
	}
}

func (s *L3Service) ensureBlock(blockHex string) *blockCounters {
	blk, ok := s.blocks[blockHex]
	if ok {
		return blk
	}
	blk = &blockCounters{
		cells:        make(map[string]struct{}),
		attestations: make(map[string]L3Attestation),
		deviceVotes:  make(map[string]struct{}),
		firstSeen:    time.Now().UTC(),
		status:       L3StatusPending,
	}
	s.blocks[blockHex] = blk
	return blk
}

// RecordBlockMeta seeds metadata as new blocks arrive from L2.
func (s *L3Service) RecordBlockMeta(blockID []byte, parent []byte, height int64, epoch uint64, commitment []byte, l2Committed bool) {
	if len(blockID) == 0 {
		return
	}
	hexID := hex.EncodeToString(blockID)
	parentHex := ""
	if len(parent) > 0 {
		parentHex = hex.EncodeToString(parent)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	blk := s.ensureBlock(hexID)
	blk.parentHex = parentHex
	blk.height = height
	blk.epoch = epoch
	blk.daCommitment = append([]byte(nil), commitment...)
	if l2Committed && !blk.l2Committed {
		blk.l2Committed = true
		logx.Info("helios l3 l2 commit", "block", shortHex(hexID), "height", height)
	}
}

// UpdateDeviceTotal refreshes the number of registered IoT devices.
func (s *L3Service) UpdateDeviceTotal(total int) {
	if total < 0 {
		total = 0
	}
	s.mu.Lock()
	s.devicesTotal = total
	s.mu.Unlock()
	logx.Info("helios l3 device total", "devices", total)
}

// RegisterCell exposes cells to the service.
func (s *L3Service) RegisterCell(rec CellRecord) {
	if rec.ID == "" {
		return
	}
	if len(rec.PubKey) > 0 {
		rec.PubKey = append([]byte(nil), rec.PubKey...)
	}
	s.cells.Register(rec)
}

// MarkCellOffline updates state after repeated failures.
func (s *L3Service) MarkCellOffline(id string) {
	s.cells.UpdateStatus(id, CellStatusOffline)
}

func (s *L3Service) quarantineCell(id string, reason string) {
	s.cells.UpdateStatus(id, CellStatusQuarantined)
	logx.Warn("helios l3 cell quarantined", "cell", id, "reason", reason)
}

func (s *L3Service) onAttestation(data []byte, from peer.ID) {
	var att L3Attestation
	if err := s.dm.Unmarshal(data, &att); err != nil {
		logx.Warn("helios l3 attestation decode failed", "err", err)
		return
	}
	rec, ok := s.cells.Lookup(att.CellID)
	if !ok || rec.Status != CellStatusActive {
		logx.Warn("helios l3 attestation ignored", "cell", att.CellID, "status", rec.Status)
		return
	}
	if len(att.SampleIndices) == 0 {
		att.SampleIndices = SamplePlan(s.beacon, att.BlockID, att.CellID, att.Epoch, s.params.SamplesPerCell, att.TotalChunks)
	}
	if len(rec.PubKey) == ed25519.PublicKeySize {
		if !s.verifyAttestationSignature(att, rec.PubKey) {
			s.recordFailure(att.CellID)
			logx.Warn("helios l3 attestation signature failed", "cell", att.CellID)
			return
		}
	} else if len(rec.PubKey) > 0 {
		logx.Warn("helios l3 attestation pubkey unexpected size", "cell", att.CellID, "bytes", len(rec.PubKey))
	}
	s.mu.Lock()
	blk := s.ensureBlock(hex.EncodeToString(att.BlockID))
	commitment := append([]byte(nil), blk.daCommitment...)
	status := blk.status
	_, seen := blk.attestations[att.CellID]
	s.mu.Unlock()
	if status == L3StatusFinal {
		return
	}
	if seen {
		logx.Debug("helios l3 duplicate attestation", "cell", att.CellID)
		return
	}
	if !s.verifier.Verify(att.BlockID, att.SampleIndices, att.Proofs, commitment) {
		s.recordFailure(att.CellID)
		logx.Warn("helios l3 attestation verification failed", "cell", att.CellID, "block", shortHex(hex.EncodeToString(att.BlockID)))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	blk = s.ensureBlock(hex.EncodeToString(att.BlockID))
	if blk.status == L3StatusFinal {
		return
	}
	if _, seen := blk.attestations[att.CellID]; seen {
		return
	}
	blk.attestations[att.CellID] = att
	blk.cells[att.CellID] = struct{}{}
	blk.auditsPassed++
	blk.status = L3StatusPending
	logx.Debug("helios l3 attestation accepted", "cell", att.CellID, "from", from)
	s.maybeFinalizeLocked(hex.EncodeToString(att.BlockID), blk)
}

// RecordDeviceAttestation records a device's vote for a block and returns progress stats.
func (s *L3Service) RecordDeviceAttestation(blockID []byte, deviceID string) (votes int, required int, total int, recorded bool) {
	if len(blockID) == 0 || deviceID == "" {
		return 0, 0, 0, false
	}
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk := s.ensureBlock(hexID)
	if blk.status == L3StatusFinal {
		return len(blk.deviceVotes), requiredDevices(s.devicesTotal), s.devicesTotal, false
	}
	if blk.deviceVotes == nil {
		blk.deviceVotes = make(map[string]struct{})
	}
	if _, seen := blk.deviceVotes[deviceID]; seen {
		return len(blk.deviceVotes), requiredDevices(s.devicesTotal), s.devicesTotal, false
	}
	blk.deviceVotes[deviceID] = struct{}{}
	votes = len(blk.deviceVotes)
	required = requiredDevices(s.devicesTotal)
	total = s.devicesTotal
	recorded = true
	logx.Info("helios l3 device attest", "block", shortHex(hexID), "device", shortDevice(deviceID), "votes", votes, "required", required, "total", total)
	s.maybeFinalizeLocked(hexID, blk)
	return votes, required, total, true
}

func (s *L3Service) verifyAttestationSignature(att L3Attestation, pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(att.Signature) == 0 {
		return false
	}
	var payload L3Attestation
	payload = att
	payload.Signature = nil
	by, err := s.em.Marshal(payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), by, att.Signature)
}

func (s *L3Service) recordFailure(cellID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.misbehave[cellID]++
	if s.misbehave[cellID] >= s.params.MaxMisbehavior {
		s.mu.Unlock()
		s.quarantineCell(cellID, "max failures reached")
		s.mu.Lock()
	}
}

func (s *L3Service) onChallenge(data []byte, from peer.ID) {
	var ch L3Challenge
	if err := s.dm.Unmarshal(data, &ch); err != nil {
		logx.Warn("helios l3 challenge decode failed", "err", err)
		return
	}
	logx.Debug("helios l3 challenge received", "cell", ch.CellID, "from", from, "indices", len(ch.Indices))
}

func (s *L3Service) onResponse(data []byte, from peer.ID) {
	var rsp L3Response
	if err := s.dm.Unmarshal(data, &rsp); err != nil {
		logx.Warn("helios l3 response decode failed", "err", err)
		return
	}
	logx.Debug("helios l3 challenge response", "cell", rsp.Challenge.CellID, "from", from)
}

func (s *L3Service) onEnvelope(data []byte, from peer.ID) {
	var env FinalityEnvelope
	if err := s.dm.Unmarshal(data, &env); err != nil {
		logx.Warn("helios l3 envelope decode failed", "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hexID := hex.EncodeToString(env.BlockID)
	blk := s.ensureBlock(hexID)
	blk.envelope = &env
	blk.status = L3StatusFinal
	logx.Info("helios l3 finality observed", "block", shortHex(hexID), "height", env.Height, "from", from)
}

// RecordDescendantQC updates weight tracking for a block's descendants.
func (s *L3Service) RecordDescendantQC(blockID []byte, ref ValidatorQCRef) {
	if len(blockID) == 0 {
		return
	}
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk := s.ensureBlock(hexID)
	blk.qcs = append(blk.qcs, ref)
	blk.qcWeight += ref.Weight
	var ratio float64
	if s.params.TotalStake > 0 {
		ratio = blk.qcWeight / s.params.TotalStake
	}
	logx.Info("helios l3 qc weight", "block", shortHex(hexID), "weight", blk.qcWeight, "ratio", ratio, "target", s.params.StakeThreshold)
	s.maybeFinalizeLocked(hexID, blk)
}

func (s *L3Service) maybeFinalizeLocked(blockHex string, blk *blockCounters) {
	if blk.l2Committed && blk.status != L3StatusFinal && s.isReadyLocked(blk) {
		env := s.buildEnvelopeLocked(blockHex, blk)
		blk.envelope = env
		blk.status = L3StatusFinal
		logx.Info("helios l3 finalized", "block", shortHex(blockHex), "height", blk.height, "cells", len(blk.cells), "device_votes", len(blk.deviceVotes), "device_total", s.devicesTotal)
		s.broadcastEnvelope(env)
	}
}

func (s *L3Service) isReadyLocked(blk *blockCounters) bool {
	if !blk.l2Committed {
		return false
	}
	activeCells := s.cells.ActiveCount()
	requiredCells := s.params.MinCells
	if requiredCells > activeCells {
		requiredCells = activeCells
	}
	if requiredCells < 0 {
		requiredCells = 0
	}
	grace := s.params.ChallengeWindow
	if grace <= 0 {
		grace = 5 * time.Second
	}
	waited := time.Since(blk.firstSeen)
	effectiveCells := requiredCells
	if effectiveCells > 0 && len(blk.cells) < effectiveCells {
		if waited >= grace {
			majority := (effectiveCells + 1) / 2
			if majority < 1 {
				majority = 1
			}
			if len(blk.cells) == 0 {
				effectiveCells = 0
			} else if len(blk.cells) >= majority {
				effectiveCells = majority
			}
		}
		if len(blk.cells) < effectiveCells {
			return false
		}
	}
	deviceRequired := requiredDevices(s.devicesTotal)
	if deviceRequired > 0 && len(blk.deviceVotes) < deviceRequired {
		return false
	}
	if s.params.TotalStake <= 0 {
		return false
	}
	if blk.qcWeight/s.params.TotalStake < s.params.StakeThreshold {
		return false
	}
	return true
}

func (s *L3Service) buildEnvelopeLocked(blockHex string, blk *blockCounters) *FinalityEnvelope {
	cells := make([]string, 0, len(blk.cells))
	for id := range blk.cells {
		cells = append(cells, id)
	}
	sort.Strings(cells)
	env := &FinalityEnvelope{
		BlockID:       decodeHex(blockHex),
		Height:        blk.height,
		Horizon:       s.params.HorizonEpochs,
		DescendantQCs: append([]ValidatorQCRef(nil), blk.qcs...),
		CellBitmap:    cells,
		FinalizedAt:   time.Now().UTC(),
	}
	return env
}

func decodeHex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		return nil
	}
	return out
}

func (s *L3Service) broadcastEnvelope(env *FinalityEnvelope) {
	if s.tEnv == nil || env == nil {
		return
	}
	payload, err := s.em.Marshal(env)
	if err != nil {
		logx.Warn("helios l3 envelope marshal failed", "err", err)
		return
	}
	logx.Info("helios l3 envelope broadcast", "block", shortHex(hex.EncodeToString(env.BlockID)), "height", env.Height, "cells", len(env.CellBitmap))
	if err := s.tEnv.Publish(s.ctx, payload); err != nil {
		logx.Warn("helios l3 envelope publish failed", "err", err)
	}
}

func (s *L3Service) runFinalityRechecks() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.recheckPending()
		}
	}
}

func (s *L3Service) recheckPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, blk := range s.blocks {
		if blk == nil || blk.status == L3StatusFinal {
			continue
		}
		s.maybeFinalizeLocked(hash, blk)
	}
}

// HasTwoThirdsWeightOnDescendants exposes the normalized check for callers.
func (s *L3Service) HasTwoThirdsWeightOnDescendants(blockID []byte) bool {
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk, ok := s.blocks[hexID]
	if !ok {
		return false
	}
	if s.params.TotalStake <= 0 {
		return false
	}
	return blk.qcWeight/s.params.TotalStake >= s.params.StakeThreshold
}

// IsL3Ready returns true when all guardrails pass.
func (s *L3Service) IsL3Ready(blockID []byte) bool {
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk, ok := s.blocks[hexID]
	if !ok {
		return false
	}
	return s.isReadyLocked(blk)
}

// QueryL3Status reports the light-client view.
func (s *L3Service) QueryL3Status(blockID []byte) L3Status {
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk, ok := s.blocks[hexID]
	if !ok {
		return L3StatusNone
	}
	return blk.status
}

// GetFinalityEnvelope returns the cached envelope if known.
func (s *L3Service) GetFinalityEnvelope(blockID []byte) (*FinalityEnvelope, error) {
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk, ok := s.blocks[hexID]
	if !ok || blk.envelope == nil {
		return nil, errors.New("no envelope")
	}
	cpy := *blk.envelope
	return &cpy, nil
}

// MetricsForBlock returns counts for operators.
func (s *L3Service) MetricsForBlock(blockID []byte) (cells int, deviceVotes int, deviceNeeded int, deviceTotal int, auditsPassed int, auditsFailed int) {
	hexID := hex.EncodeToString(blockID)
	s.mu.Lock()
	defer s.mu.Unlock()
	blk, ok := s.blocks[hexID]
	if !ok {
		return
	}
	return len(blk.cells), len(blk.deviceVotes), requiredDevices(s.devicesTotal), s.devicesTotal, blk.auditsPassed, blk.auditsFailed
}

// L3BlockProgress summarizes tracked blocks for monitoring.
type L3BlockProgress struct {
	Block        string     `json:"block"`
	Height       int64      `json:"height"`
	Epoch        uint64     `json:"epoch"`
	Status       string     `json:"status"`
	Cells        int        `json:"cells"`
	AuditsPassed int        `json:"audits_passed"`
	AuditsFailed int        `json:"audits_failed"`
	L2Committed  bool       `json:"l2_committed"`
	Ready        bool       `json:"ready"`
	QCWeight     float64    `json:"qc_weight"`
	StakeTarget  float64    `json:"stake_target"`
	FirstSeen    time.Time  `json:"first_seen"`
	FinalizedAt  *time.Time `json:"finalized_at,omitempty"`
	DeviceVotes  int        `json:"device_votes"`
	DeviceNeeded int        `json:"device_required"`
	DeviceTotal  int        `json:"device_total"`
}

// Snapshot returns up to limit block progress entries ordered by height desc.
func (s *L3Service) Snapshot(limit int) []L3BlockProgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]L3BlockProgress, 0, len(s.blocks))
	target := s.params.StakeThreshold * s.params.TotalStake
	for hash, blk := range s.blocks {
		progress := L3BlockProgress{
			Block:        hash,
			Height:       blk.height,
			Epoch:        blk.epoch,
			Status:       blk.status.String(),
			Cells:        len(blk.cells),
			AuditsPassed: blk.auditsPassed,
			AuditsFailed: blk.auditsFailed,
			L2Committed:  blk.l2Committed,
			Ready:        s.isReadyLocked(blk),
			QCWeight:     blk.qcWeight,
			StakeTarget:  target,
			FirstSeen:    blk.firstSeen,
			DeviceVotes:  len(blk.deviceVotes),
			DeviceNeeded: requiredDevices(s.devicesTotal),
			DeviceTotal:  s.devicesTotal,
		}
		if blk.envelope != nil {
			final := blk.envelope.FinalizedAt
			progress.FinalizedAt = &final
		}
		items = append(items, progress)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Height == items[j].Height {
			return items[i].FirstSeen.After(items[j].FirstSeen)
		}
		return items[i].Height > items[j].Height
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

// Short helper for logs.
func shortHex(in string) string {
	if len(in) <= 8 {
		return in
	}
	return fmt.Sprintf("%s…%s", in[:4], in[len(in)-2:])
}

func shortDevice(id string) string {
	if len(id) <= 12 {
		return id
	}
	return fmt.Sprintf("%s…%s", id[:6], id[len(id)-4:])
}

func requiredDevices(total int) int {
	if total <= 0 {
		return 0
	}
	return (2*total + 2) / 3
}
