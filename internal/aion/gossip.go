package aion

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"

    cbor "github.com/fxamacker/cbor/v2"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    crypto "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/host"

    "pose/internal/blockchain"
    "pose/internal/logx"
)

const (
    topicCommit = "aion/commit/1.0.0"
    topicReveal = "aion/reveal/1.0.0"
    topicVRF    = "aion/vrf/1.0.0"
)

// Wire types (CBOR)
type msgCommit struct { Pub []byte `cbor:"0,keyasint"`; Epoch uint64 `cbor:"1,keyasint"`; Commit []byte `cbor:"2,keyasint"` }
type msgReveal struct { Pub []byte `cbor:"0,keyasint"`; Epoch uint64 `cbor:"1,keyasint"`; Seed []byte `cbor:"2,keyasint"`; Commit []byte `cbor:"3,keyasint"` }
type msgVRF    struct { Pub []byte `cbor:"0,keyasint"`; Epoch uint64 `cbor:"1,keyasint"`; Input []byte `cbor:"2,keyasint"`; Y []byte `cbor:"3,keyasint"`; Proof []byte `cbor:"4,keyasint"` }

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

    // local seeds and commits
    seeds   map[uint64][]byte      // epoch -> seed
    commits map[uint64][32]byte    // epoch -> commit

    // caches from network
    cmt map[uint64]map[string][32]byte // epoch -> pubhex -> commit
    rev map[uint64]map[string][]byte   // epoch -> pubhex -> seed
    vrf map[uint64]map[string]struct{ y [32]byte; proof []byte }

    // elected leaders per epoch
    leader map[uint64]string // epoch -> pubhex
}

// StartAIONService starts gossip handlers and periodic publisher.
func StartAIONService(ctx context.Context, h host.Host, ps *pubsub.PubSub, chainID string, params Params) *Service {
    em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
    dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
    s := &Service{params: params, chainID: chainID, h: h, ps: ps, em: em, dm: dm, epochLen: params.EpochLength,
        seeds: make(map[uint64][]byte), commits: make(map[uint64][32]byte), cmt: make(map[uint64]map[string][32]byte), rev: make(map[uint64]map[string][]byte), vrf: make(map[uint64]map[string]struct{ y [32]byte; proof []byte }), leader: make(map[uint64]string)}
    s.run(ctx)
    return s
}

func (s *Service) run(ctx context.Context) {
    // Topics
    tC, _ := s.ps.Join(topicCommit)
    tR, _ := s.ps.Join(topicReveal)
    tV, _ := s.ps.Join(topicVRF)
    subC, _ := tC.Subscribe()
    subR, _ := tR.Subscribe()
    subV, _ := tV.Subscribe()

    // Subscribers
    go func() { for { msg, err := subC.Next(ctx); if err != nil { return }; s.onCommit(msg.Message.GetData()) } }()
    go func() { for { msg, err := subR.Next(ctx); if err != nil { return }; s.onReveal(msg.Message.GetData()) } }()
    go func() { for { msg, err := subV.Next(ctx); if err != nil { return }; s.onVRF(msg.Message.GetData()) } }()

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
                height, tip := blockchain.CurrentTip(s.chainID)
                if height <= 0 || s.epochLen == 0 { continue }
                e := int64(uint64(height-1) / s.epochLen)
                if e != lastEpoch {
                    // New epoch: publish reveal+vrf for e if we have commit; publish commit for e+1
                    s.publishCommit(ctx, tC, uint64(e+1))
                    s.publishRevealAndVRF(ctx, tR, tV, uint64(e), tip)
                    lastEpoch = e
                }
            }
        }
    }()
}

func (s *Service) getPubBytes() []byte {
    pub := s.h.Peerstore().PubKey(s.h.ID())
    if pub == nil { return nil }
    b, _ := crypto.MarshalPublicKey(pub)
    return b
}

// seedForEpoch derives a deterministic seed from the node's secret without using RNG.
func (s *Service) seedForEpoch(e uint64) []byte {
    s.mu.Lock(); if seed, ok := s.seeds[e]; ok { s.mu.Unlock(); return seed }; s.mu.Unlock()
    // Derive seed = SHA256(Sign("aion-seed"||be64(e))) so it's secret, deterministic, and commit-before-challenge friendly.
    var be [8]byte
    for i := 0; i < 8; i++ { be[7-i] = byte(e >> (8*uint(i))) }
    msg := append([]byte("aion-seed"), be[:]...)
    priv := s.h.Peerstore().PrivKey(s.h.ID())
    sig, _ := priv.Sign(msg)
    sum := sha256.Sum256(sig)
    out := make([]byte, 32); copy(out, sum[:])
    s.mu.Lock(); s.seeds[e] = out; s.mu.Unlock()
    return out
}

func (s *Service) publishCommit(ctx context.Context, t *pubsub.Topic, e uint64) {
    pub := s.getPubBytes(); if len(pub) == 0 { return }
    seed := s.seedForEpoch(e)
    c := CommitSeed(seed)
    s.mu.Lock(); s.commits[e] = c; s.mu.Unlock()
    msg := msgCommit{Pub: pub, Epoch: e, Commit: c[:]}
    by, _ := s.em.Marshal(msg)
    _ = t.Publish(ctx, by)
}

func (s *Service) publishRevealAndVRF(ctx context.Context, tR, tV *pubsub.Topic, e uint64, lastTip []byte) {
    pub := s.getPubBytes(); if len(pub) == 0 { return }
    seed := s.seedForEpoch(e)
    // Ensure we had a commit cached (best effort)
    if c, ok := s.commits[e]; ok {
        msg := msgReveal{Pub: pub, Epoch: e, Seed: seed, Commit: c[:]}
        by, _ := s.em.Marshal(msg)
        _ = tR.Publish(ctx, by)
    }
    // VRF over input = seed || challenge
    ch := Challenge(lastTip, e)
    input := append(append([]byte{}, seed...), ch[:]...)
    vrf := newEd25519VRF(s.h.Peerstore().PrivKey(s.h.ID()))
    y, proof, err := vrf.Evaluate(input)
    if err != nil { return }
    msgV := msgVRF{Pub: pub, Epoch: e, Input: input, Y: y[:], Proof: proof}
    by, _ := s.em.Marshal(msgV)
    _ = tV.Publish(ctx, by)
}

func (s *Service) onCommit(by []byte) {
    var m msgCommit
    if s.dm.Unmarshal(by, &m) != nil { return }
    if len(m.Pub) == 0 || len(m.Commit) != 32 { return }
    ph := hex.EncodeToString(m.Pub)
    s.mu.Lock()
    if s.cmt[m.Epoch] == nil { s.cmt[m.Epoch] = make(map[string][32]byte) }
    var c [32]byte; copy(c[:], m.Commit); s.cmt[m.Epoch][ph] = c
    s.mu.Unlock()
}

func (s *Service) onReveal(by []byte) {
    var m msgReveal
    if s.dm.Unmarshal(by, &m) != nil { return }
    if len(m.Pub) == 0 || len(m.Seed) == 0 || len(m.Commit) != 32 { return }
    // verify reveal matches commit if we have it
    ph := hex.EncodeToString(m.Pub)
    s.mu.Lock()
    c, ok := s.cmt[m.Epoch][ph]
    s.mu.Unlock()
    if ok && !VerifyReveal(c, m.Seed) { return }
    s.mu.Lock()
    if s.rev[m.Epoch] == nil { s.rev[m.Epoch] = make(map[string][]byte) }
    s.rev[m.Epoch][ph] = append([]byte(nil), m.Seed...)
    s.mu.Unlock()
}

func (s *Service) onVRF(by []byte) {
    var m msgVRF
    if s.dm.Unmarshal(by, &m) != nil { return }
    if len(m.Pub) == 0 || len(m.Input) == 0 || len(m.Y) != 32 || len(m.Proof) == 0 { return }
    // check reveal present and input prefix matches seed
    ph := hex.EncodeToString(m.Pub)
    s.mu.Lock()
    var seed []byte
    if rmap := s.rev[m.Epoch]; rmap != nil { seed = rmap[ph] }
    s.mu.Unlock()
    if len(seed) == 0 || len(m.Input) < len(seed) { return }
    for i := range seed { if m.Input[i] != seed[i] { return } }
    pub, err := crypto.UnmarshalPublicKey(m.Pub); if err != nil { return }
    var y32 [32]byte; copy(y32[:], m.Y)
    v := ed25519VRF{pub: pub}
    if !v.Verify(m.Input, y32, m.Proof) { return }
    // cache
    s.mu.Lock()
    if s.vrf[m.Epoch] == nil { s.vrf[m.Epoch] = make(map[string]struct{ y [32]byte; proof []byte }) }
    s.vrf[m.Epoch][ph] = struct{ y [32]byte; proof []byte }{y: y32, proof: append([]byte(nil), m.Proof...)}
    s.mu.Unlock()
    // update leader
    s.updateLeader(m.Epoch)
}

func (s *Service) weightForEpoch(e uint64) uint32 {
    // Use moving average of previous 4 epochs' normalized entropy
    if s.epochLen == 0 { return qOne }
    var h [4]uint32
    for i := 0; i < 4; i++ {
        if e == 0 || e <= uint64(i) { h[i] = 0; continue }
        h[i] = EpochEntropyQ16(s.chainID, e-1-uint64(i), s.epochLen)
    }
    return WeightQ16(uint32(s.params.AlphaQ16), h[0], h[1], h[2], h[3])
}

func (s *Service) updateLeader(e uint64) {
    wt := s.weightForEpoch(e)
    // iterate over all vrf entries and pick minimum rank with pubkey tiebreaker
    s.mu.Lock()
    entries := s.vrf[e]
    s.mu.Unlock()
    var bestPub string
    var bestRank [33]byte
    var init bool
    for pubhex, rec := range entries {
        r := RankValue(rec.y, wt)
        if !init || CmpRank(r, bestRank) < 0 || (CmpRank(r, bestRank) == 0 && pubhex < bestPub) {
            bestPub, bestRank, init = pubhex, r, true
        }
    }
    if init {
        s.mu.Lock(); s.leader[e] = bestPub; s.mu.Unlock()
        logx.Info("aion leader", "epoch", e, "pub", bestPub)
    }
}

// IsLeader returns true if the given pubkey is elected leader for epoch e.
func (s *Service) IsLeader(e uint64, pub []byte) bool {
    ph := hex.EncodeToString(pub)
    s.mu.Lock(); defer s.mu.Unlock()
    return s.leader[e] == ph
}

// LocalIsLeader reports if this node is leader for the epoch of the current chain tip.
func (s *Service) LocalIsLeader() bool {
    h, _ := blockchain.CurrentTip(s.chainID)
    if h <= 0 || s.epochLen == 0 { return false }
    e := uint64(h-1) / s.epochLen
    pub := s.getPubBytes(); if len(pub) == 0 { return false }
    return s.IsLeader(e, pub)
}

// LeaderForEpoch returns the elected leader's pubkey hex if known.
func (s *Service) LeaderForEpoch(e uint64) (string, bool) {
    s.mu.Lock(); defer s.mu.Unlock()
    v, ok := s.leader[e]
    return v, ok
}

