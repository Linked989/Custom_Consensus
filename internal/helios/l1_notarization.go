package helios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"

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
	Epoch    uint64 `cbor:"0,keyasint"`
	Height   int64  `cbor:"1,keyasint"`
	Hash     []byte `cbor:"2,keyasint"` // block hash
	Producer []byte `cbor:"3,keyasint"`
	Attester []byte `cbor:"4,keyasint"`
	Sample   []byte `cbor:"5,keyasint"`
	Sig      []byte `cbor:"6,keyasint"`
}

// l1Notarized announces that enough attestations were observed for a block.
type l1Notarized struct {
	Epoch     uint64   `cbor:"0,keyasint"`
	Height    int64    `cbor:"1,keyasint"`
	Hash      []byte   `cbor:"2,keyasint"`
	Count     int      `cbor:"3,keyasint"`
	Attesters [][]byte `cbor:"4,keyasint"`
}

// L1Service performs instant notarization based on attestations from non-leader nodes.
type L1Service struct {
	h          host.Host
	ps         *pubsub.PubSub
	aion       *aion.Service
	em         cbor.EncMode
	dm         cbor.DecMode
	params     L1Params
	blockTopic string

	mu sync.Mutex
	// block hash (hex) -> attester pub hex
	seen map[string]map[string]struct{}
	// firstSeen time to compute latency
	first map[string]time.Time
	// raw attestations per block hash (hex)
	attests map[string][][]byte

	// recent records for HTTP status
	recent    []L1Record
	recByHash map[string]int // hashHex -> index in recent
	maxRecent int
	// retain in-memory raw attestations for at least this duration
	retainFor time.Duration

	// topic handles
	tAttest   *pubsub.Topic
	tNotarize *pubsub.Topic
}

// StartL1 launches the L1 notarization service by block topic name.
func StartL1(ctx context.Context, h host.Host, ps *pubsub.PubSub, a *aion.Service, p L1Params, blockTopicName string) *L1Service {
	if p.MinAttesters <= 0 {
		p.MinAttesters = defaultL1Params().MinAttesters
	}
	if p.MaxLatency <= 0 {
		p.MaxLatency = defaultL1Params().MaxLatency
	}
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
	s := &L1Service{h: h, ps: ps, aion: a, em: em, dm: dm, params: p, blockTopic: blockTopicName, seen: make(map[string]map[string]struct{}), first: make(map[string]time.Time), attests: make(map[string][][]byte), recByHash: make(map[string]int), maxRecent: 32, retainFor: 30 * time.Second}

	// Join topics
	tA, _ := ps.Join(topicL1Attest)
	tN, _ := ps.Join(topicL1Notarize)
	s.tAttest, s.tNotarize = tA, tN
	// Subscribe to block topic directly to react quickly
	if tB, err := ps.Join(blockTopicName); err == nil {
		subB, _ := tB.Subscribe()
		if LogL1 {
			logx.Info("HELIOS L1 started", "block_topic", blockTopicName, "min_attesters", p.MinAttesters)
		}
		go func() {
			for {
				msg, err := subB.Next(ctx)
				if err != nil {
					return
				}
				s.onBlock(msg.Message.GetData())
			}
		}()
	} else {
		logx.Warn("HELIOS L1 could not join block topic", "topic", blockTopicName, "err", err)
	}

	subA, _ := tA.Subscribe()
	go func() {
		for {
			msg, err := subA.Next(ctx)
			if err != nil {
				return
			}
			s.onAttest(tN, msg.Message.GetData())
		}
	}()
	return s
}

// StartL1FromTopic launches L1 notarization using an existing block topic handle (preferred).
func StartL1FromTopic(ctx context.Context, h host.Host, ps *pubsub.PubSub, a *aion.Service, p L1Params, blockTopic *pubsub.Topic) *L1Service {
	if p.MinAttesters <= 0 {
		p.MinAttesters = defaultL1Params().MinAttesters
	}
	if p.MaxLatency <= 0 {
		p.MaxLatency = defaultL1Params().MaxLatency
	}
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
	s := &L1Service{h: h, ps: ps, aion: a, em: em, dm: dm, params: p, blockTopic: "", seen: make(map[string]map[string]struct{}), first: make(map[string]time.Time), attests: make(map[string][][]byte), recByHash: make(map[string]int), maxRecent: 32, retainFor: 30 * time.Second}
	// Join L1 topics
	tA, _ := ps.Join(topicL1Attest)
	tN, _ := ps.Join(topicL1Notarize)
	s.tAttest, s.tNotarize = tA, tN
	// Subscribe to existing block topic
	if blockTopic != nil {
		if subB, err := blockTopic.Subscribe(); err == nil {
			if LogL1 {
				logx.Info("HELIOS L1 started", "block_topic", "(existing)", "min_attesters", p.MinAttesters)
			}
			go func() {
				for {
					msg, err := subB.Next(ctx)
					if err != nil {
						return
					}
					s.onBlock(msg.Message.GetData())
				}
			}()
		}
	}
	// L1 attestation subscriber
	if subA, err := tA.Subscribe(); err == nil {
		go func() {
			for {
				msg, err := subA.Next(ctx)
				if err != nil {
					return
				}
				s.onAttest(tN, msg.Message.GetData())
			}
		}()
	}
	return s
}

// OnBlockProposed should be called when a block is observed (e.g., by the local block subscriber).
// Non-leader nodes will attest immediately.
func (s *L1Service) OnBlockProposed(ctx context.Context, epoch uint64, height int64, hash []byte, producerPub []byte, txs [][]byte) {
	// Attest from all nodes (including producer) to increase redundancy.
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
	// Prefer pre-joined topic handle to publish
	var perr error
	if s.tAttest != nil {
		perr = s.tAttest.Publish(ctx, by)
	} else {
		perr = s.publish(topicL1Attest, by)
	}
	if perr == nil {
		if LogL1 {
			logx.Info("HELIOS L1 attested", "height", height, "epoch", epoch, "hash", short(hex.EncodeToString(hash)))
		}
		// Ensure local aggregation sees our attestation even if pubsub doesn't loop back
		if s.tNotarize != nil {
			s.onAttest(s.tNotarize, by)
		}
	}
}

func (s *L1Service) onBlock(data []byte) {
	// Decode a minimal block header/body to extract fields we need. We avoid importing blockchain
	// here to reduce coupling; rely on CBOR shape used by publisher.
	var blk struct {
		ChainID     string    `cbor:"1,keyasint"`
		Height      int64     `cbor:"2,keyasint"`
		PrevHash    []byte    `cbor:"3,keyasint"`
		Timestamp   time.Time `cbor:"4,keyasint"`
		ProducerPub []byte    `cbor:"6,keyasint"`
		Txs         [][]byte  `cbor:"8,keyasint"`
		Hash        []byte    `cbor:"9,keyasint"`
	}
	if s.dm.Unmarshal(data, &blk) != nil {
		return
	}
	// Compute epoch like subscriber using the active AION epoch length.
	var epoch uint64
	if blk.Height > 0 {
		lenSlots := s.aion.EpochLength()
		if lenSlots == 0 {
			lenSlots = 1
		}
		epoch = uint64(blk.Height-1) / lenSlots
	}
	if len(blk.Hash) > 0 {
		s.recordObserved(hex.EncodeToString(blk.Hash), epoch, blk.Height)
	}
	// attest if non-leader
	s.OnBlockProposed(context.Background(), epoch, blk.Height, blk.Hash, blk.ProducerPub, blk.Txs)
}

func (s *L1Service) onAttest(tN *pubsub.Topic, data []byte) {
	var a l1Attest
	if s.dm.Unmarshal(data, &a) != nil {
		return
	}
	if len(a.Hash) == 0 || len(a.Attester) == 0 {
		return
	}
	// Track
	key := hex.EncodeToString(a.Hash)
	att := hex.EncodeToString(a.Attester)
	s.mu.Lock()
	if s.seen[key] == nil {
		s.seen[key] = make(map[string]struct{})
		s.first[key] = time.Now()
	}
	s.seen[key][att] = struct{}{}
	s.attests[key] = append(s.attests[key], append([]byte(nil), data...))
	cnt := len(s.seen[key])
	first := s.first[key]
	need := s.params.MinAttesters
	s.mu.Unlock()
	s.updateAttesters(key, a.Epoch, a.Height, cnt)
	if LogL1 {
		logx.Info("HELIOS L1 attest received", "epoch", a.Epoch, "height", a.Height, "hash", short(key), "attesters", cnt)
	}
	if cnt >= need {
		// Notarize once
		dt := time.Since(first)
		s.recordNotarized(key, a.Epoch, a.Height, cnt, dt)
		// Stop tracking attester set, but keep first-seen time for TTL-based retention
		s.mu.Lock()
		delete(s.seen, key) /* keep s.first[key] */
		s.mu.Unlock()
		out := l1Notarized{Epoch: a.Epoch, Height: a.Height, Hash: append([]byte(nil), a.Hash...), Count: cnt, Attesters: [][]byte{a.Attester}}
		by, _ := s.em.Marshal(out)
		_ = tN.Publish(context.Background(), by)
		if LogL1 {
			logx.Info("HELIOS L1 NOTARIZED", "epoch", a.Epoch, "height", a.Height, "hash", short(key), "attesters", cnt, "latency_ms", dt.Milliseconds())
		}
	}
}

func (s *L1Service) publish(topic string, msg []byte) error {
	t, err := s.ps.Join(topic)
	if err != nil {
		return err
	}
	return t.Publish(context.Background(), msg)
}

func (s *L1Service) pubBytes() []byte {
	pub := s.h.Peerstore().PubKey(s.h.ID())
	if pub == nil {
		return nil
	}
	b, _ := crypto.MarshalPublicKey(pub)
	return b
}

func short(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8]
}

// L1Record is a snapshot for HTTP status.
type L1Record struct {
	Epoch     uint64 `json:"epoch"`
	Height    int64  `json:"height"`
	Hash      string `json:"hash"` // hex
	Notarized bool   `json:"notarized"`
	Attesters int    `json:"attesters"`
	LatencyMS int64  `json:"latency_ms"`
	When      int64  `json:"when_unix_ms"`
}

func (s *L1Service) recordNotarized(hashHex string, epoch uint64, height int64, attesters int, dt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nowms := time.Now().UnixMilli()
	if idx, ok := s.recByHash[hashHex]; ok {
		r := s.recent[idx]
		r.Notarized = true
		r.Attesters = attesters
		r.LatencyMS = dt.Milliseconds()
		r.When = nowms
		s.recent[idx] = r
		s.pruneAttestsLocked()
		return
	}
	rec := L1Record{Epoch: epoch, Height: height, Hash: hashHex, Notarized: true, Attesters: attesters, LatencyMS: dt.Milliseconds(), When: nowms}
	s.recent = append([]L1Record{rec}, s.recent...)
	// reindex
	s.recByHash = make(map[string]int, len(s.recent))
	for i := range s.recent {
		s.recByHash[s.recent[i].Hash] = i
	}
	if len(s.recent) > s.maxRecent {
		s.recent = s.recent[:s.maxRecent]
	}
	s.pruneAttestsLocked()
}

// RecentStatus returns a copy of the recent records.
func (s *L1Service) RecentStatus() []L1Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]L1Record, len(s.recent))
	copy(out, s.recent)
	return out
}

func (s *L1Service) recordObserved(hashHex string, epoch uint64, height int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recByHash[hashHex]; ok {
		return
	}
	rec := L1Record{Epoch: epoch, Height: height, Hash: hashHex, Notarized: false, Attesters: 0, LatencyMS: 0, When: time.Now().UnixMilli()}
	s.recent = append([]L1Record{rec}, s.recent...)
	if len(s.recent) > s.maxRecent {
		s.recent = s.recent[:s.maxRecent]
	}
	s.recByHash = make(map[string]int, len(s.recent))
	for i := range s.recent {
		s.recByHash[s.recent[i].Hash] = i
	}
	s.pruneAttestsLocked()
}

func (s *L1Service) updateAttesters(hashHex string, epoch uint64, height int64, attesters int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, ok := s.recByHash[hashHex]; ok {
		r := s.recent[idx]
		r.Attesters = attesters
		r.When = time.Now().UnixMilli()
		s.recent[idx] = r
		s.pruneAttestsLocked()
		return
	}
	rec := L1Record{Epoch: epoch, Height: height, Hash: hashHex, Notarized: false, Attesters: attesters, When: time.Now().UnixMilli()}
	s.recent = append([]L1Record{rec}, s.recent...)
	if len(s.recent) > s.maxRecent {
		s.recent = s.recent[:s.maxRecent]
	}
	s.recByHash = make(map[string]int, len(s.recent))
	for i := range s.recent {
		s.recByHash[s.recent[i].Hash] = i
	}
	s.pruneAttestsLocked()
}

// pruneAttestsLocked keeps attests entries only for hashes present in recent index.
// Caller must hold s.mu when invoking this function.
func (s *L1Service) pruneAttestsLocked() {
	now := time.Now()
	allow := make(map[string]struct{}, len(s.recByHash))
	for k := range s.recByHash {
		allow[k] = struct{}{}
	}
	for k := range s.attests {
		// keep if in recent index
		if _, ok := allow[k]; ok {
			continue
		}
		// keep if within retention window based on first-seen time
		if t, ok := s.first[k]; ok {
			if now.Sub(t) < s.retainFor {
				continue
			}
		}
		delete(s.attests, k)
		// do not delete s.first here; let it expire naturally
	}
}

// AttestationInfo is a decoded, friendly view of an L1 attestation.
type AttestationInfo struct {
	Epoch     uint64 `json:"epoch"`
	Height    int64  `json:"height"`
	HashHex   string `json:"hash"`
	Attester  string `json:"attester_pub_hex"`
	Producer  string `json:"producer_pub_hex"`
	SampleHex string `json:"sample_hex"`
}

// GetAttestationInfos returns up to max decoded attestation infos for the given block hash.
// If max <= 0, returns all available.
func (s *L1Service) GetAttestationInfos(hash []byte, max int) []AttestationInfo {
	key := hex.EncodeToString(hash)
	s.mu.Lock()
	lst := s.attests[key]
	s.mu.Unlock()
	if len(lst) == 0 {
		return nil
	}
	if max > 0 && len(lst) > max {
		lst = lst[:max]
	}
	out := make([]AttestationInfo, 0, len(lst))
	for _, raw := range lst {
		var a l1Attest
		if s.dm.Unmarshal(raw, &a) != nil {
			continue
		}
		out = append(out, AttestationInfo{
			Epoch:     a.Epoch,
			Height:    a.Height,
			HashHex:   strings.ToLower(hex.EncodeToString(a.Hash)),
			Attester:  strings.ToLower(hex.EncodeToString(a.Attester)),
			Producer:  strings.ToLower(hex.EncodeToString(a.Producer)),
			SampleHex: strings.ToLower(hex.EncodeToString(a.Sample)),
		})
	}
	return out
}

// DecodeRawAttestations decodes raw CBOR-encoded attestations into AttestationInfo.
// If max <= 0, decodes all.
func (s *L1Service) DecodeRawAttestations(list [][]byte, max int) []AttestationInfo {
	if len(list) == 0 {
		return nil
	}
	if max > 0 && len(list) > max {
		list = list[:max]
	}
	out := make([]AttestationInfo, 0, len(list))
	for _, raw := range list {
		var a l1Attest
		if s.dm.Unmarshal(raw, &a) != nil {
			continue
		}
		out = append(out, AttestationInfo{
			Epoch:     a.Epoch,
			Height:    a.Height,
			HashHex:   strings.ToLower(hex.EncodeToString(a.Hash)),
			Attester:  strings.ToLower(hex.EncodeToString(a.Attester)),
			Producer:  strings.ToLower(hex.EncodeToString(a.Producer)),
			SampleHex: strings.ToLower(hex.EncodeToString(a.Sample)),
		})
	}
	return out
}

// GetAttestationsFor returns up to max raw CBOR-encoded L1 attestation messages observed for the given block hash.
// If max <= 0, returns all available. Returned slices are copies safe for use by caller.
func (s *L1Service) GetAttestationsFor(hash []byte, max int) [][]byte {
	key := hex.EncodeToString(hash)
	s.mu.Lock()
	defer s.mu.Unlock()
	lst := s.attests[key]
	if len(lst) == 0 {
		return nil
	}
	if max > 0 && len(lst) > max {
		lst = lst[:max]
	}
	out := make([][]byte, len(lst))
	for i := range lst {
		out[i] = append([]byte(nil), lst[i]...)
	}
	return out
}
