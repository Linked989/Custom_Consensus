package helios

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"

    cbor "github.com/fxamacker/cbor/v2"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "github.com/libp2p/go-libp2p/core/host"
    crypto "github.com/libp2p/go-libp2p/core/crypto"

    "pose/internal/aion"
    "pose/internal/logx"
)

const (
    topicL1Attest   = "helios/l1/attest/1.0.0"
    topicL1Notarize = "helios/l1/notarized/1.0.0"
)

// L1Params configures notarization thresholds (dev-friendly defaults).
type L1Params struct {
    // MinAttesters is the minimum distinct non-leader attestations required to notarize.
    MinAttesters int
    // MaxLatency caps how long we wait to announce notarization (diagnostic only).
    MaxLatency time.Duration
}

func defaultL1Params() L1Params { return L1Params{MinAttesters: 1, MaxLatency: time.Second} }

// l1Attest is an attestation from a non-leader that they observed the block and
// performed a quick data-availability checksum.
type l1Attest struct {
    Epoch   uint64 `cbor:"0,keyasint"`
    Height  int64  `cbor:"1,keyasint"`
    Hash    []byte `cbor:"2,keyasint"` // block hash
    Producer []byte `cbor:"3,keyasint"`
    Attester []byte `cbor:"4,keyasint"`
    Sample  []byte `cbor:"5,keyasint"`
    Sig     []byte `cbor:"6,keyasint"`
}

// l1Notarized announces that enough attestations were observed for a block.
type l1Notarized struct {
    Epoch   uint64 `cbor:"0,keyasint"`
    Height  int64  `cbor:"1,keyasint"`
    Hash    []byte `cbor:"2,keyasint"`
    Count   int    `cbor:"3,keyasint"`
    Attesters [][]byte `cbor:"4,keyasint"`
}

// L1Service performs instant notarization based on attestations from non-leader nodes.
type L1Service struct {
    h      host.Host
    ps     *pubsub.PubSub
    aion   *aion.Service
    em     cbor.EncMode
    dm     cbor.DecMode
    params L1Params
    blockTopic string

    mu sync.Mutex
    // block hash (hex) -> attester pub hex
    seen map[string]map[string]struct{}
    // firstSeen time to compute latency
    first map[string]time.Time
}

// StartL1 launches the L1 notarization service.
func StartL1(ctx context.Context, h host.Host, ps *pubsub.PubSub, a *aion.Service, p L1Params, blockTopicName string) *L1Service {
    if p.MinAttesters <= 0 { p.MinAttesters = defaultL1Params().MinAttesters }
    if p.MaxLatency <= 0 { p.MaxLatency = defaultL1Params().MaxLatency }
    em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
    dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
    s := &L1Service{h: h, ps: ps, aion: a, em: em, dm: dm, params: p, blockTopic: blockTopicName, seen: make(map[string]map[string]struct{}), first: make(map[string]time.Time)}

    // Join topics
    tA, _ := ps.Join(topicL1Attest)
    tN, _ := ps.Join(topicL1Notarize)
    // Subscribe to block topic directly to react quickly
    tB, err := ps.Join(blockTopicName); if err == nil {
        subB, _ := tB.Subscribe()
        logx.Info("HELIOS L1 started", "block_topic", blockTopicName, "min_attesters", p.MinAttesters)
        go func() {
            for {
                msg, err := subB.Next(ctx); if err != nil { return }
                s.onBlock(msg.Message.GetData())
            }
        }()
    }

    subA, _ := tA.Subscribe()
    go func() {
        for {
            msg, err := subA.Next(ctx); if err != nil { return }
            s.onAttest(tN, msg.Message.GetData())
        }
    }()
    return s
}

// OnBlockProposed should be called when a block is observed (e.g., by the local block subscriber).
// Non-leader nodes will attest immediately.
func (s *L1Service) OnBlockProposed(ctx context.Context, epoch uint64, height int64, hash []byte, producerPub []byte, txs [][]byte) {
    // If this node is the leader, it does not attest.
    if s.aion != nil && s.aion.LocalIsLeader() {
        // Leader does not attest; only non-leader nodes do attestation in L1
        return
    }
    // Construct sample checksum deterministically from the txs (first 8 tx SHA256 prefixes)
    hh := sha256.New()
    m := 0
    for i := 0; i < len(txs) && m < 8; i++ {
        sum := sha256.Sum256(txs[i])
        hh.Write(sum[:4])
        m++
    }
    sample := hh.Sum(nil)
    // Sign attestation (CBOR of fields without Sig)
    att := l1Attest{Epoch: epoch, Height: height, Hash: append([]byte(nil), hash...), Producer: append([]byte(nil), producerPub...), Attester: s.pubBytes(), Sample: sample}
    toSign, _ := s.em.Marshal(att)
    sig, _ := s.h.Peerstore().PrivKey(s.h.ID()).Sign(toSign)
    att.Sig = sig
    by, _ := s.em.Marshal(att)
    if err := s.publish(topicL1Attest, by); err == nil { logx.Info("HELIOS L1 attested", "height", height, "epoch", epoch, "hash", short(hex.EncodeToString(hash))) }
}

func (s *L1Service) onBlock(data []byte) {
    // Decode a minimal block header/body to extract fields we need. We avoid importing blockchain
    // here to reduce coupling; rely on CBOR shape used by publisher.
    var blk struct{
        ChainID string `cbor:"1,keyasint"`
        Height  int64  `cbor:"2,keyasint"`
        PrevHash []byte `cbor:"3,keyasint"`
        Timestamp time.Time `cbor:"4,keyasint"`
        ProducerPub []byte `cbor:"6,keyasint"`
        Txs [][]byte `cbor:"8,keyasint"`
        Hash []byte `cbor:"9,keyasint"`
    }
    if s.dm.Unmarshal(data, &blk) != nil { return }
    // Compute epoch like subscriber (height-based, 64 slots per epoch)
    var epoch uint64
    if blk.Height > 0 { epoch = uint64(blk.Height-1) / 64 }
    // attest if non-leader
    s.OnBlockProposed(context.Background(), epoch, blk.Height, blk.Hash, blk.ProducerPub, blk.Txs)
}

func (s *L1Service) onAttest(tN *pubsub.Topic, data []byte) {
    var a l1Attest
    if s.dm.Unmarshal(data, &a) != nil { return }
    if len(a.Hash) == 0 || len(a.Attester) == 0 { return }
    // Track
    key := hex.EncodeToString(a.Hash)
    att := hex.EncodeToString(a.Attester)
    s.mu.Lock()
    if s.seen[key] == nil { s.seen[key] = make(map[string]struct{}); s.first[key] = time.Now() }
    s.seen[key][att] = struct{}{}
    cnt := len(s.seen[key])
    first := s.first[key]
    need := s.params.MinAttesters
    s.mu.Unlock()
    if cnt >= need {
        // Notarize once
        s.mu.Lock(); delete(s.seen, key); delete(s.first, key); s.mu.Unlock()
        out := l1Notarized{Epoch: a.Epoch, Height: a.Height, Hash: append([]byte(nil), a.Hash...), Count: cnt, Attesters: [][]byte{a.Attester}}
        by, _ := s.em.Marshal(out)
        _ = tN.Publish(context.Background(), by)
        dt := time.Since(first)
        logx.Info("HELIOS L1 NOTARIZED", "epoch", a.Epoch, "height", a.Height, "hash", short(key), "attesters", cnt, "latency_ms", dt.Milliseconds())
    }
}

func (s *L1Service) publish(topic string, msg []byte) error {
    t, err := s.ps.Join(topic); if err != nil { return err }
    return t.Publish(context.Background(), msg)
}

func (s *L1Service) pubBytes() []byte {
    pub := s.h.Peerstore().PubKey(s.h.ID())
    if pub == nil { return nil }
    b, _ := crypto.MarshalPublicKey(pub)
    return b
}

func short(h string) string { if len(h) <= 8 { return h }; return h[:8] }
