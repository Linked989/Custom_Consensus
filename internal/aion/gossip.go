package aion

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/blockchain"
	"pose/internal/cell"
	"pose/internal/entropy"
	"pose/internal/logx"
)

const (
	topicCommit  = "aion/commit/1.0.0"
	topicReveal  = "aion/reveal/1.0.0"
	topicVRF     = "aion/vrf/1.0.0"
	topicEntropy = "aion/entropy/1.0.0"
)

// Wire types (CBOR)
type msgCommit struct {
	Pub    []byte `cbor:"0,keyasint"`
	Epoch  uint64 `cbor:"1,keyasint"`
	Commit []byte `cbor:"2,keyasint"`
}
type msgReveal struct {
	Pub    []byte `cbor:"0,keyasint"`
	Epoch  uint64 `cbor:"1,keyasint"`
	Seed   []byte `cbor:"2,keyasint"`
	Commit []byte `cbor:"3,keyasint"`
}
type msgVRF struct {
	Pub   []byte `cbor:"0,keyasint"`
	Epoch uint64 `cbor:"1,keyasint"`
	Input []byte `cbor:"2,keyasint"`
	Y     []byte `cbor:"3,keyasint"`
	Proof []byte `cbor:"4,keyasint"`
}

// msgEntropy carries a node's per-epoch normalized cell entropy (Q16.16)
// so that election can compare cell entropies across nodes.
type msgEntropy struct {
	Pub   []byte `cbor:"0,keyasint"`
	Epoch uint64 `cbor:"1,keyasint"`
	HNorm uint32 `cbor:"2,keyasint"`
}

// Service holds AION state and gossip handles.
type Service struct {
	mu       sync.Mutex
	params   Params
	chainID  string
	h        host.Host
	ps       *pubsub.PubSub
	em       cbor.EncMode
	dm       cbor.DecMode
	epochLen uint64
	cellMgr  *cell.Manager

	// local seeds and commits
	seeds   map[uint64][]byte   // epoch -> seed
	commits map[uint64][32]byte // epoch -> commit

	// caches from network
	cmt map[uint64]map[string][32]byte // epoch -> pubhex -> commit
	rev map[uint64]map[string][]byte   // epoch -> pubhex -> seed
	vrf map[uint64]map[string]struct {
		y     [32]byte
		proof []byte
	}
	ent map[uint64]map[string]uint32 // epoch -> pubhex -> cell entropy q16

	// elected leaders per epoch
	leader map[uint64]string // epoch -> pubhex

	// lifecycle: mark once leader elected to announce counters start
	started bool
}

// NetStatus is a snapshot of AION election state for the current epoch.
type NetStatus struct {
	Epoch              uint64    `json:"epoch"`
	Candidates         int       `json:"candidates"`
	WeightQ16          uint32    `json:"weight_q16"`
	EntropyNormPrevQ16 [4]uint32 `json:"entropy_norm_prev_q16"`
	LeaderPub          string    `json:"leader_pub_hex"`
	LocalIsLeader      bool      `json:"local_is_leader"`
	BestRank16         uint16    `json:"best_rank16"`
	Slot               uint64    `json:"slot"`
	EpochSlotOffset    uint64    `json:"epoch_slot_offset"`
	TipHeight          int64     `json:"tip_height"`
	SlotEpoch          uint64    `json:"slot_epoch"`
	SlotDurationMS     uint64    `json:"slot_duration_ms"`
	ReadyToProduce     bool      `json:"ready_to_produce"`
}

// GetNetStatus returns a best-effort status for the current epoch.
func (s *Service) GetNetStatus() NetStatus {
	// Determine current epoch (bootstrap to 0)
	h, _ := blockchain.CurrentTip(s.chainID)
	var e uint64
	if s.epochLen == 0 {
		e = 0
	} else if h > 0 {
		e = uint64(h-1) / s.epochLen
	} else {
		e = 0
	}
	// Weight and previous entropy normals
	wt, hnorm := s.weightForEpoch(e)
	// Candidates and leader
	s.mu.Lock()
	entries := s.vrf[e]
	leader := s.leader[e]
	s.mu.Unlock()
	cand := len(entries)
	// Recompute best rank for observability
	var best [33]byte
	var bestInit bool
	for pubhex, rec := range entries {
		r := RankValue(rec.y, wt)
		if !bestInit || CmpRank(r, best) < 0 || (CmpRank(r, best) == 0 && pubhex < leader) {
			best, bestInit = r, true
		}
	}
	var r16 uint16
	if bestInit {
		r16 = binary.BigEndian.Uint16(best[0:2])
	}
	// Local leader check
	pub := s.getPubBytes()
	var local bool
	if len(pub) > 0 {
		local = s.IsLeader(e, pub)
	}
	// Slot info (non-consensus diagnostic)
	now := time.Now().UTC()
	slot := s.params.CurrentSlot(now)
	off := s.params.EpochSlotOffset(slot)
	se := s.params.Epoch(slot)
	sdms := uint64(s.params.SlotDuration / time.Millisecond)
	ready := s.AllowProduceSlot()
	return NetStatus{Epoch: e, Candidates: cand, WeightQ16: wt, EntropyNormPrevQ16: hnorm, LeaderPub: leader, LocalIsLeader: local, BestRank16: r16, Slot: uint64(slot), EpochSlotOffset: off, TipHeight: h, SlotEpoch: se, SlotDurationMS: sdms, ReadyToProduce: ready}
}

// AllowProduceSlot returns true if this node should produce a block for the current epoch/slot.
// Policy: must be elected leader locally AND either (a) seen >=2 VRF candidates for this epoch,
// or (b) have no connected peers (single-node test setup).
func (s *Service) AllowProduceSlot() bool {
	if s.epochLen == 0 {
		return false
	}
	// Compute current epoch from chain height
	h, _ := blockchain.CurrentTip(s.chainID)
	var e uint64
	if h > 0 {
		e = uint64(h-1) / s.epochLen
	} else {
		e = 0
	}
	pub := s.getPubBytes()
	if len(pub) == 0 {
		return false
	}
	if !s.IsLeader(e, pub) {
		return false
	}
	// Require at least two VRF candidates to avoid split production at epoch start.
	s.mu.Lock()
	cand := len(s.vrf[e])
	s.mu.Unlock()
	if cand >= 2 {
		return true
	}
	// If we're alone (no peers), allow production to avoid stalling demos.
	if len(s.h.Network().Peers()) == 0 {
		return true
	}
	return false
}

// StartAIONService starts gossip handlers and periodic publisher.
func StartAIONService(ctx context.Context, h host.Host, ps *pubsub.PubSub, chainID string, params Params, cm *cell.Manager) *Service {
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
	s := &Service{params: params, chainID: chainID, h: h, ps: ps, em: em, dm: dm, epochLen: params.EpochLength, cellMgr: cm,
		seeds: make(map[uint64][]byte), commits: make(map[uint64][32]byte), cmt: make(map[uint64]map[string][32]byte), rev: make(map[uint64]map[string][]byte), vrf: make(map[uint64]map[string]struct {
			y     [32]byte
			proof []byte
		}), ent: make(map[uint64]map[string]uint32), leader: make(map[uint64]string)}
	s.run(ctx)
	return s
}

func (s *Service) run(ctx context.Context) {
	// Topics
	tC, _ := s.ps.Join(topicCommit)
	tR, _ := s.ps.Join(topicReveal)
	tV, _ := s.ps.Join(topicVRF)
	tE, _ := s.ps.Join(topicEntropy)
	subC, _ := tC.Subscribe()
	subR, _ := tR.Subscribe()
	subV, _ := tV.Subscribe()
	subE, _ := tE.Subscribe()

	// Subscribers
	go func() {
		for {
			msg, err := subC.Next(ctx)
			if err != nil {
				return
			}
			s.onCommit(msg.Message.GetData())
		}
	}()
	go func() {
		for {
			msg, err := subR.Next(ctx)
			if err != nil {
				return
			}
			s.onReveal(msg.Message.GetData())
		}
	}()
	go func() {
		for {
			msg, err := subV.Next(ctx)
			if err != nil {
				return
			}
			s.onVRF(msg.Message.GetData())
		}
	}()
	go func() {
		for {
			msg, err := subE.Next(ctx)
			if err != nil {
				return
			}
			s.onEntropy(msg.Message.GetData())
		}
	}()

	// Publisher: poll chain tip and publish at epoch boundaries
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		var lastEpoch int64 = -1
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				height, _ := blockchain.CurrentTip(s.chainID)
				if s.epochLen == 0 {
					continue
				}
				// Bootstrap: if no blocks yet, operate at epoch 0 with current tip (may be empty)
				var e int64
				if height > 0 {
					e = int64(uint64(height-1) / s.epochLen)
				} else {
					e = 0
				}
				if e != lastEpoch {
					// New epoch: ensure commit for current e (bootstrap), also publish commit for e+1, then reveal+vrf for e
					s.publishCommit(ctx, tC, uint64(e))
					s.publishCommit(ctx, tC, uint64(e+1))
					s.publishRevealAndVRF(ctx, tR, tV, uint64(e))
					// On epoch boundary, compute and log cell entropy for previous epoch window if cell is active
					if s.cellMgr != nil {
						c := s.cellMgr.Status()
						if c != nil && c.Active {
							win := int64(s.params.EpochLength)
							score, used := entropy.ComputeCellEntropyFromChain(s.chainID, c, win)
							if used > 0 {
								logx.Info("cell entropy", "cell_id", c.ID, "devices", len(c.Devices), "tx_samples", used, "entropy_bits_per_byte", score)
							}
							// publish normalized entropy for this epoch restricted to our cell
							hcell := EpochEntropyForCellQ16(s.chainID, uint64(e), s.epochLen, c)
							s.publishEntropy(ctx, tE, uint64(e), hcell)
						}
					}
					lastEpoch = e
				}
			}
		}
	}()
}

func (s *Service) getPubBytes() []byte {
	pub := s.h.Peerstore().PubKey(s.h.ID())
	if pub == nil {
		return nil
	}
	b, _ := crypto.MarshalPublicKey(pub)
	return b
}

// seedForEpoch derives a deterministic seed from the node's secret without using RNG.
func (s *Service) seedForEpoch(e uint64) []byte {
	s.mu.Lock()
	if seed, ok := s.seeds[e]; ok {
		s.mu.Unlock()
		return seed
	}
	s.mu.Unlock()
	// Derive seed = SHA256(Sign("aion-seed"||be64(e))) so it's secret, deterministic, and commit-before-challenge friendly.
	var be [8]byte
	for i := 0; i < 8; i++ {
		be[7-i] = byte(e >> (8 * uint(i)))
	}
	msg := append([]byte("aion-seed"), be[:]...)
	priv := s.h.Peerstore().PrivKey(s.h.ID())
	sig, _ := priv.Sign(msg)
	sum := sha256.Sum256(sig)
	out := make([]byte, 32)
	copy(out, sum[:])
	s.mu.Lock()
	s.seeds[e] = out
	s.mu.Unlock()
	return out
}

func (s *Service) publishCommit(ctx context.Context, t *pubsub.Topic, e uint64) {
	pub := s.getPubBytes()
	if len(pub) == 0 {
		return
	}
	seed := s.seedForEpoch(e)
	c := CommitSeed(seed)
	s.mu.Lock()
	s.commits[e] = c
	s.mu.Unlock()
	msg := msgCommit{Pub: pub, Epoch: e, Commit: c[:]}
	by, _ := s.em.Marshal(msg)
	_ = t.Publish(ctx, by)
	logx.Info("aion commit", "epoch", e)
}

func (s *Service) publishRevealAndVRF(ctx context.Context, tR, tV *pubsub.Topic, e uint64) {
	pub := s.getPubBytes()
	if len(pub) == 0 {
		return
	}
	seed := s.seedForEpoch(e)
	// Ensure we had a commit cached (best effort)
	if c, ok := s.commits[e]; ok {
		msg := msgReveal{Pub: pub, Epoch: e, Seed: seed, Commit: c[:]}
		by, _ := s.em.Marshal(msg)
		_ = tR.Publish(ctx, by)
	}
	// VRF over input = seed || challenge where challenge is derived from
	// the canonical epoch boundary block to avoid divergence across nodes.
	ch := s.challengeForEpoch(e)
	input := append(append([]byte{}, seed...), ch[:]...)
	vrf := newEd25519VRF(s.h.Peerstore().PrivKey(s.h.ID()))
	y, proof, err := vrf.Evaluate(input)
	if err != nil {
		return
	}
	msgV := msgVRF{Pub: pub, Epoch: e, Input: input, Y: y[:], Proof: proof}
	by, _ := s.em.Marshal(msgV)
	_ = tV.Publish(ctx, by)
	logx.Info("aion reveal+vrf", "epoch", e)
}

func (s *Service) publishEntropy(ctx context.Context, tE *pubsub.Topic, e uint64, hnorm uint32) {
	pub := s.getPubBytes()
	if len(pub) == 0 {
		return
	}
	msg := msgEntropy{Pub: pub, Epoch: e, HNorm: hnorm}
	by, _ := s.em.Marshal(msg)
	_ = tE.Publish(ctx, by)
}

// challengeForEpoch returns a deterministic epoch challenge independent of local chain state.
// Using only the epoch number avoids divergence if nodes' boundary blocks differ due to forks.
func (s *Service) challengeForEpoch(e uint64) [32]byte {
	return Challenge(nil, e)
}

func (s *Service) onCommit(by []byte) {
	var m msgCommit
	if s.dm.Unmarshal(by, &m) != nil {
		return
	}
	if len(m.Pub) == 0 || len(m.Commit) != 32 {
		return
	}
	ph := hex.EncodeToString(m.Pub)
	s.mu.Lock()
	if s.cmt[m.Epoch] == nil {
		s.cmt[m.Epoch] = make(map[string][32]byte)
	}
	var c [32]byte
	copy(c[:], m.Commit)
	s.cmt[m.Epoch][ph] = c
	s.mu.Unlock()
}

func (s *Service) onReveal(by []byte) {
	var m msgReveal
	if s.dm.Unmarshal(by, &m) != nil {
		return
	}
	if len(m.Pub) == 0 || len(m.Seed) == 0 || len(m.Commit) != 32 {
		return
	}
	// verify reveal matches commit if we have it
	ph := hex.EncodeToString(m.Pub)
	s.mu.Lock()
	c, ok := s.cmt[m.Epoch][ph]
	s.mu.Unlock()
	if ok && !VerifyReveal(c, m.Seed) {
		return
	}
	s.mu.Lock()
	if s.rev[m.Epoch] == nil {
		s.rev[m.Epoch] = make(map[string][]byte)
	}
	s.rev[m.Epoch][ph] = append([]byte(nil), m.Seed...)
	s.mu.Unlock()
}

func (s *Service) onVRF(by []byte) {
	var m msgVRF
	if s.dm.Unmarshal(by, &m) != nil {
		return
	}
	if len(m.Pub) == 0 || len(m.Input) == 0 || len(m.Y) != 32 || len(m.Proof) == 0 {
		return
	}
	// check reveal present and input prefix matches seed
	ph := hex.EncodeToString(m.Pub)
	s.mu.Lock()
	var seed []byte
	if rmap := s.rev[m.Epoch]; rmap != nil {
		seed = rmap[ph]
	}
	s.mu.Unlock()
	if len(seed) == 0 || len(m.Input) < len(seed) {
		return
	}
	for i := range seed {
		if m.Input[i] != seed[i] {
			return
		}
	}
	pub, err := crypto.UnmarshalPublicKey(m.Pub)
	if err != nil {
		return
	}
	var y32 [32]byte
	copy(y32[:], m.Y)
	v := ed25519VRF{pub: pub}
	if !v.Verify(m.Input, y32, m.Proof) {
		return
	}
	// cache
	s.mu.Lock()
	if s.vrf[m.Epoch] == nil {
		s.vrf[m.Epoch] = make(map[string]struct {
			y     [32]byte
			proof []byte
		})
	}
	s.vrf[m.Epoch][ph] = struct {
		y     [32]byte
		proof []byte
	}{y: y32, proof: append([]byte(nil), m.Proof...)}
	s.mu.Unlock()
	// update leader
	s.updateLeader(m.Epoch)
}

func (s *Service) onEntropy(by []byte) {
	var m msgEntropy
	if s.dm.Unmarshal(by, &m) != nil {
		return
	}
	if len(m.Pub) == 0 {
		return
	}
	ph := hex.EncodeToString(m.Pub)
	s.mu.Lock()
	if s.ent[m.Epoch] == nil {
		s.ent[m.Epoch] = make(map[string]uint32)
	}
	s.ent[m.Epoch][ph] = m.HNorm
	s.mu.Unlock()
	s.updateLeader(m.Epoch)
}

func (s *Service) weightForEpoch(e uint64) (uint32, [4]uint32) {
	// Use moving average of previous 4 epochs' normalized entropy
	if s.epochLen == 0 {
		return qOne, [4]uint32{}
	}
	var h [4]uint32
	for i := 0; i < 4; i++ {
		if e == 0 || e <= uint64(i) {
			h[i] = 0
			continue
		}
		h[i] = EpochEntropyQ16(s.chainID, e-1-uint64(i), s.epochLen)
	}
	return WeightQ16(uint32(s.params.AlphaQ16), h[0], h[1], h[2], h[3]), h
}

func (s *Service) updateLeader(e uint64) {
	wt, hnorm := s.weightForEpoch(e)
	// iterate over all vrf entries and pick minimum rank with pubkey tiebreaker
	s.mu.Lock()
	entries := s.vrf[e]
	// ents := s.ent[e]
	candCount := len(entries)
	s.mu.Unlock()
	// Require at least two VRF candidates; entropy is optional for ranking.
	if candCount < 2 {
		return
	}
	var bestPub string
	var bestRank [33]byte
	var init bool
	for pubhex, rec := range entries {
		r := RankValue(rec.y, wt)
		if !init {
			if s.ent[e] != nil {
				if _, ok := s.ent[e][pubhex]; !ok {
					continue
				}
			}
			bestPub, bestRank, init = pubhex, r, true
			continue
		}
		if s.ent[e] != nil {
			eb := s.ent[e][bestPub]
			ec := s.ent[e][pubhex]
			if ec > eb || (ec == eb && (CmpRank(r, bestRank) < 0 || (CmpRank(r, bestRank) == 0 && pubhex < bestPub))) {
				bestPub, bestRank = pubhex, r
			}
		} else if CmpRank(r, bestRank) < 0 || (CmpRank(r, bestRank) == 0 && pubhex < bestPub) {
			bestPub, bestRank = pubhex, r
		}
	}
	if init {
		s.mu.Lock()
		first := !s.started
		s.leader[e] = bestPub
		if first {
			s.started = true
		}
		s.mu.Unlock()
		rank16 := binary.BigEndian.Uint16(bestRank[0:2])
		cand := len(entries)
		tipH, _ := blockchain.CurrentTip(s.chainID)
		// Try to compute leader peer ID from pubkey
		leaderID := ""
		if b, err := hex.DecodeString(bestPub); err == nil {
			if pk, err := crypto.UnmarshalPublicKey(b); err == nil {
				if pid, err := peer.IDFromPublicKey(pk); err == nil {
					leaderID = pid.String()
				}
			}
		}
		// Colors
		const green = "\x1b[32m"
		const red = "\x1b[31m"
		const cyan = "\x1b[36m"
		const yellow = "\x1b[33m"
		const reset = "\x1b[0m"
		// Election header
		logx.Info(cyan+"AION ELECTION"+reset, "epoch", e, "candidates", cand)
		// Candidates detail
		for pubhex, rec := range entries {
			r := RankValue(rec.y, wt)
			r16 := binary.BigEndian.Uint16(r[0:2])
			col := red
			if pubhex == bestPub {
				col = green
			}
			var hcell uint32
			if s.ent[e] != nil {
				hcell = s.ent[e][pubhex]
			}
			// derive peer ID from pub for human-readable mapping
			candPeer := ""
			if b, err := hex.DecodeString(pubhex); err == nil {
				if pk, err := crypto.UnmarshalPublicKey(b); err == nil {
					if pid, err := peer.IDFromPublicKey(pk); err == nil {
						candPeer = pid.String()
					}
				}
			}
			logx.Info(col+"candidate"+reset, "peer_id", candPeer, "pub", pubhex, "rank16", r16, "cell_entropy_q16", hcell)
		}
		// Result line
		var hwin uint32
		if s.ent[e] != nil {
			hwin = s.ent[e][bestPub]
		}
		logx.Info(yellow+"leader elected"+reset, "epoch", e, "leader_peer_id", leaderID, "leader_pub", bestPub, "weight_q16", wt, "best_rank16", rank16, "tip_height", tipH, "leader_cell_entropy_q16", hwin, "entropy_norm_prev_q16", []uint32{hnorm[0], hnorm[1], hnorm[2], hnorm[3]})
		if first {
			logx.Info(green+"AION START: leader elected; counters active"+reset, "epoch", e)
		}
	}
}

// IsLeader returns true if the given pubkey is elected leader for epoch e.
func (s *Service) IsLeader(e uint64, pub []byte) bool {
	ph := hex.EncodeToString(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leader[e] == ph
}

// AcceptProducer returns true if there is no known leader for epoch e yet,
// or if the provided producer pubkey matches the known leader. This avoids
// premature rejection at epoch boundaries before election converges.
func (s *Service) AcceptProducer(e uint64, pub []byte) bool {
	ph := hex.EncodeToString(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.leader[e]; ok && v != "" {
		return v == ph
	}
	// No leader known yet for this epoch: accept provisionally
	return true
}

// LocalIsLeader reports if this node is leader for the epoch of the current chain tip.
func (s *Service) LocalIsLeader() bool {
	h, _ := blockchain.CurrentTip(s.chainID)
	if s.epochLen == 0 {
		return false
	}
	var e uint64
	if h > 0 {
		e = uint64(h-1) / s.epochLen
	} else {
		e = 0
	}
	pub := s.getPubBytes()
	if len(pub) == 0 {
		return false
	}
	return s.IsLeader(e, pub)
}

// LeaderForEpoch returns the elected leader's pubkey hex if known.
func (s *Service) LeaderForEpoch(e uint64) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.leader[e]
	return v, ok
}
