package aion

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"

	"pose/internal/blockchain"
	"pose/internal/cell"
	"pose/internal/entropy"
	"pose/internal/logx"
	"pose/internal/mempool"
)

// LeaderService evaluates a local AION-inspired leadership predicate periodically
// and toggles process-local leadership accordingly. This is dev-only wiring and
// does not affect consensus hashing/signature paths.
type LeaderService struct {
	mu       sync.Mutex
	params   Params
	chainID  string
	h        host.Host
	pool     *mempool.Pool
	cellMgr  *cell.Manager
	denom    uint16 // targeting ~1/denom slots selected before weighting
	interval time.Duration

	// history of normalized entropy (Q16.16), most recent first
	hist [4]uint32

	// leadership window tracking
	leaderEpoch  int64
	leaderActive bool

	// last computed diagnostics
	lastEpoch      uint64
	lastEntropyBPB float64
	lastHb         uint16
	lastHnormQ16   uint32
	lastWtQ16      uint32
	lastRank16     uint16
	lastThr16      uint16
}

// StartLeaderService launches the background evaluator.
// - denom controls the raw selection rate: smaller => more frequent leaders.
// - interval should typically match the block builder interval.
func StartLeaderService(ctx context.Context, h host.Host, pool *mempool.Pool, chainID string, cm *cell.Manager, params Params, interval time.Duration, denom uint16) *LeaderService {
	if denom < 1 {
		denom = 1
	}
	s := &LeaderService{params: params, chainID: chainID, h: h, pool: pool, cellMgr: cm, denom: denom, interval: interval}
	// seed history with mid-level entropy to avoid start-up bias
	mid := NormalizeEntropyQ16(64) // 0.5 normalized
	s.hist = [4]uint32{mid, mid, mid, mid}
	go s.loop(ctx)
	return s
}

func (s *LeaderService) loop(ctx context.Context) {
	if s.interval <= 0 {
		s.interval = 2 * time.Second
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.evalOnce()
		}
	}
}

// evalOnce performs one evaluation and toggles leadership as needed.
func (s *LeaderService) evalOnce() {
	// Pull current cell status
	c := s.cellMgr.Status()
	if c == nil || !c.Active {
		SetLeaderActive(false)
		s.mu.Lock()
		s.leaderActive = false
		s.mu.Unlock()
		return
	}
	// Compute entropy lower bounds over current mempool snapshot for the cell
	entries := s.pool.Snapshot()
	// Build device set for quick membership checks
	ids := make(map[string]struct{}, len(c.Devices))
	for _, d := range c.Devices {
		ids[d.DeviceID] = struct{}{}
	}
	// Accumulate histogram over IoT data bytes for devices in this cell
	var freq [256]uint64
	var n uint64
	for _, e := range entries {
		if _, ok := ids[e.DevID]; !ok {
			continue
		}
		if dataPart, ok := entropy.ExtractIoTDataSection(e.Bytes); ok && len(dataPart) > 0 {
			for _, b := range dataPart {
				freq[int(b)]++
				n++
			}
		}
	}
	// Compute H_min and H2 lower bounds in bits (capped to 128)
	var maxCnt uint64
	var sumSq uint64
	for i := 0; i < 256; i++ {
		c := freq[i]
		if c > maxCnt {
			maxCnt = c
		}
		sumSq += c * c
	}
	hmin := HMinBits(n, maxCnt, 128)
	h2 := HRenyi2Bits(n, sumSq, 128)
	hb := HLowerBoundBits(hmin, h2)
	hq := NormalizeEntropyQ16(hb)
	// Shift history: most recent at index 0
	s.mu.Lock()
	s.hist = [4]uint32{hq, s.hist[0], s.hist[1], s.hist[2]}
	s.lastEntropyBPB = 0 // reserved; lower bound used instead
	s.lastHb = hb
	s.lastHnormQ16 = hq
	s.mu.Unlock()

	// Compute current epoch from chain tip height (deterministic across nodes)
	height, tip := blockchain.CurrentTip(s.chainID)
	var epoch uint64
	if height > 0 && s.params.EpochLength > 0 {
		epoch = uint64(height-1) / s.params.EpochLength
	}

	// Leadership window check: if active, stay active for the configured window
	s.mu.Lock()
	if s.leaderActive {
		curEpoch := int64(epoch)
		if s.leaderEpoch >= 0 && curEpoch < s.leaderEpoch+int64(s.params.LeadershipWindow) {
			s.mu.Unlock()
			// Maintain
			SetLeaderActive(true)
			return
		}
		// window elapsed, fall through to re-evaluate
	}
	s.mu.Unlock()

	// Derive challenge from tip and epoch
	ch := Challenge(tip, epoch)
	// Compute node-distinct y using SHA256(challenge || producerPub)
	pub := s.h.Peerstore().PubKey(s.h.ID())
	var pubBytes []byte
	if pub != nil {
		if b, err := crypto.MarshalPublicKey(pub); err == nil {
			pubBytes = b
		}
	}
	hh := sha256.New()
	hh.Write(ch[:])
	hh.Write(pubBytes)
	var y [32]byte
	copy(y[:], hh.Sum(nil))

	// Compute weight
	s.mu.Lock()
	wt := WeightQ16(uint32(s.params.AlphaQ16), s.hist[0], s.hist[1], s.hist[2], s.hist[3])
	s.lastWtQ16 = wt
	s.mu.Unlock()
	r := RankValue(y, wt)

	// Selection rule: compare the first 2 bytes (big-endian) of rank against a threshold
	// threshold = floor(65535 / denom)
	thr := uint16(0xFFFF) / s.denom
	val := binary.BigEndian.Uint16(r[0:2])
	s.mu.Lock()
	s.lastThr16 = thr
	s.lastRank16 = val
	s.lastEpoch = epoch
	s.mu.Unlock()
	elected := val < thr

	if elected {
		SetLeaderActive(true)
		s.mu.Lock()
		s.leaderActive = true
		s.leaderEpoch = int64(epoch)
		s.mu.Unlock()
		if LogAION {
			logx.Info("aion elected", "epoch", epoch, "thr", thr, "rank16", val)
		}
	} else {
		SetLeaderActive(false)
		s.mu.Lock()
		s.leaderActive = false
		s.mu.Unlock()
	}
}

// Status is a snapshot of the last AION evaluation.
type Status struct {
	Active             bool    `json:"active"`
	Epoch              uint64  `json:"epoch"`
	WindowEndEpoch     uint64  `json:"window_end_epoch"`
	Denom              uint16  `json:"denom"`
	AlphaQ16           uint32  `json:"alpha_q16"`
	WeightQ16          uint32  `json:"weight_q16"`
	EntropyBitsPerByte float64 `json:"entropy_bits_per_byte"`
	EntropyNormQ16     uint32  `json:"entropy_norm_q16"`
	Rank16             uint16  `json:"rank16"`
	Threshold16        uint16  `json:"threshold16"`
}

// GetStatus returns the last known AION status.
func (s *LeaderService) GetStatus() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	curEpoch := s.lastEpoch
	var winEnd uint64
	if s.leaderActive && s.leaderEpoch >= 0 {
		winEnd = uint64(s.leaderEpoch) + s.params.LeadershipWindow
	}
	return Status{
		Active:             s.leaderActive,
		Epoch:              curEpoch,
		WindowEndEpoch:     winEnd,
		Denom:              s.denom,
		AlphaQ16:           uint32(s.params.AlphaQ16),
		WeightQ16:          s.lastWtQ16,
		EntropyBitsPerByte: s.lastEntropyBPB,
		EntropyNormQ16:     s.lastHnormQ16,
		Rank16:             s.lastRank16,
		Threshold16:        s.lastThr16,
	}
}
