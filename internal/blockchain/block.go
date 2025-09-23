package blockchain

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/coseutil"
	"pose/internal/logx"
	"pose/internal/mempool"
	"pose/internal/merkle"
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
	dataDir string
)

func init() {
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
	encMode, decMode = em, dm
}

// Context key and helper for injecting L1 attestation fetcher into the block builder.
type ctxKeyGetAttest struct{}

// AttestFetcher returns raw CBOR-encoded attestations for a given parent block hash.
type AttestFetcher func(parentHash []byte) [][]byte

// WithAttestationFetcher attaches an attestation fetcher to ctx for consumption by the block builder.
func WithAttestationFetcher(ctx context.Context, fn AttestFetcher) context.Context {
	return context.WithValue(ctx, ctxKeyGetAttest{}, fn)
}

// SetDataDir configures on-disk storage location for blocks and indices.
func SetDataDir(dir string) error {
	if dir == "" {
		dir = ".data"
	}
	dataDir = dir
	return os.MkdirAll(dir, 0o755)
}

func chainDir(chainID string) string  { return filepath.Join(dataDir, sanitize(chainID)) }
func blocksDir(chainID string) string { return filepath.Join(chainDir(chainID), "blocks") }
func indexPath(chainID string) string { return filepath.Join(chainDir(chainID), "index.json") }
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' {
			return '-'
		}
		return r
	}, s)
}

// Block is a simple canonical structure for demonstration.
type Block struct {
	Version     int64     `cbor:"0,keyasint"`
	ChainID     string    `cbor:"1,keyasint"`
	Height      int64     `cbor:"2,keyasint"`
	PrevHash    []byte    `cbor:"3,keyasint"`
	Timestamp   time.Time `cbor:"4,keyasint"`
	ProducerID  string    `cbor:"5,keyasint"`
	ProducerPub []byte    `cbor:"6,keyasint"`
	TxIDs       []string  `cbor:"7,keyasint"`
	Txs         [][]byte  `cbor:"8,keyasint"`
	Hash        []byte    `cbor:"9,keyasint"`
	Signature   []byte    `cbor:"10,keyasint"`
	TxRoot      []byte    `cbor:"11,keyasint"`
	// L1Attestations optionally embeds raw CBOR-encoded HELIOS L1 attestation messages
	// that refer to the parent block (PrevHash), enabling on-chain auditability.
	L1Attestations [][]byte `cbor:"12,keyasint"`
}

// hashForSign returns the hash over the block fields excluding Hash and Signature.
func hashForSign(b *Block) ([]byte, error) {
	tmp := *b
	tmp.Hash = nil
	tmp.Signature = nil
	by, err := encMode.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(by)
	return h[:], nil
}

// Sign fills Hash and Signature using the host's private key.
func Sign(h host.Host, b *Block) error {
	// Ensure producer identity fields are populated BEFORE hashing
	priv := h.Peerstore().PrivKey(h.ID())
	if priv == nil {
		return errors.New("missing host private key")
	}
	pub := priv.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		return err
	}
	b.ProducerPub = pubBytes
	b.ProducerID = h.ID().String()

	// Ensure timestamp is set in header
	if b.Timestamp.IsZero() {
		b.Timestamp = time.Now().UTC()
	}

	// Compute hash over the finalized header/body (excluding Hash/Signature)
	hash, err := hashForSign(b)
	if err != nil {
		return err
	}
	b.Hash = hash

	// Sign the block hash
	sig, err := priv.Sign(hash)
	if err != nil {
		return err
	}
	b.Signature = sig
	return nil
}

// Verify checks the hash and signature; also checks ProducerID matches the producer pubkey's peer ID.
func Verify(b *Block) error {
	// hash
	hash, err := hashForSign(b)
	if err != nil {
		return err
	}
	if len(b.Hash) == 0 || len(b.Signature) == 0 {
		return errors.New("missing block hash/signature")
	}
	if !bytes.Equal(hash, b.Hash) {
		return errors.New("hash mismatch")
	}
	// merkle root over txids
	var leaves [][]byte
	for _, hx := range b.TxIDs {
		if bb, err := hex.DecodeString(hx); err == nil {
			leaves = append(leaves, bb)
		}
	}
	want := merkle.ComputeRoot(leaves)
	if (len(want) == 0 && len(b.TxIDs) > 0) || !bytes.Equal(want, b.TxRoot) {
		return errors.New("txroot mismatch")
	}
	// pubkey
	pub, err := crypto.UnmarshalPublicKey(b.ProducerPub)
	if err != nil {
		return err
	}
	ok, err := pub.Verify(b.Hash, b.Signature)
	if err != nil || !ok {
		return errors.New("signature verify failed")
	}
	// PeerID sanity
	pid, err := peerIDFromPub(pub)
	if err == nil && b.ProducerID != "" && b.ProducerID != pid {
		return errors.New("producer peerID mismatch")
	}
	return nil
}

// peerIDFromPub derives the peer ID string from a libp2p pubkey.
func peerIDFromPub(pub crypto.PubKey) (string, error) {
	pid, err := peerIDFromKey(pub)
	if err != nil {
		return "", err
	}
	return pid, nil
}

// separate small helper to avoid import cycles
func peerIDFromKey(pub crypto.PubKey) (string, error) {
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// ------ In-memory chain state ------

type Chain struct {
	mu        sync.Mutex
	ChainID   string
	TipHeight int64
	TipHash   []byte
	known     map[string]int64    // hex(hash) -> height
	waiting   map[string][]*Block // hex(prevHash) -> children blocks waiting on this prev
	txIndex   map[string]txRef    // txid -> (block hash, height)
}

var chains = struct {
	mu sync.Mutex
	m  map[string]*Chain
}{m: make(map[string]*Chain)}

func getChain(id string) *Chain {
	chains.mu.Lock()
	defer chains.mu.Unlock()
	c := chains.m[id]
	if c == nil {
		c = &Chain{ChainID: id, known: make(map[string]int64), waiting: make(map[string][]*Block), txIndex: make(map[string]txRef)}
		chains.m[id] = c
		// Try load index from disk
		_ = c.loadIndex()
		_ = c.loadTxIndex()
	}
	return c
}

// CurrentTip returns the current tip height and hash for the given chainID.
// The hash slice is a copy safe for use by the caller.
func CurrentTip(chainID string) (int64, []byte) {
	ch := getChain(chainID)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	h := ch.TipHeight
	var hash []byte
	if len(ch.TipHash) > 0 {
		hash = append([]byte(nil), ch.TipHash...)
	}
	return h, hash
}

// recordKnown marks a block hash as known at a given height.
func (c *Chain) recordKnown(hash []byte, height int64) {
	c.known[hex.EncodeToString(hash)] = height
}

func (c *Chain) isKnown(hash []byte) (int64, bool) {
	h, ok := c.known[hex.EncodeToString(hash)]
	return h, ok
}

// queueChild stores a block that depends on prev until prev is processed.
func (c *Chain) queueChild(prev []byte, b *Block) {
	key := hex.EncodeToString(prev)
	c.waiting[key] = append(c.waiting[key], b)
}

// popChildren returns and clears queued children for a given parent hash.
func (c *Chain) popChildren(parent []byte) []*Block {
	key := hex.EncodeToString(parent)
	lst := c.waiting[key]
	if len(lst) > 0 {
		delete(c.waiting, key)
	}
	return lst
}

// waitingKeys returns a snapshot of waiting parent hashes (hex strings).
func (c *Chain) waitingKeys() []string {
	keys := make([]string, 0, len(c.waiting))
	for k := range c.waiting {
		keys = append(keys, k)
	}
	return keys
}

// acceptBlockLocked records, persists, updates tip and cascades children. Caller must hold c.mu.
func (c *Chain) acceptBlockLocked(b *Block) {
	c.recordKnown(b.Hash, b.Height)
	if (c.TipHeight == 0 && b.Height == 1 && len(b.PrevHash) == 0) ||
		(b.Height == c.TipHeight+1 && bytes.Equal(b.PrevHash, c.TipHash)) ||
		(b.Height > c.TipHeight) {
		c.TipHeight = b.Height
		c.TipHash = append(c.TipHash[:0], b.Hash...)
	}
	_ = c.saveBlock(b)
	_ = c.saveIndex()
	// update tx index
	bh := hex.EncodeToString(b.Hash)
	for _, txid := range b.TxIDs {
		if _, exists := c.txIndex[txid]; !exists {
			c.txIndex[txid] = txRef{BlockHash: bh, Height: b.Height}
		}
	}
	_ = c.saveTxIndex()
	children := c.popChildren(b.Hash)
	for _, child := range children {
		if ph, ok := c.isKnown(child.PrevHash); ok && child.Height == ph+1 {
			c.acceptBlockLocked(child)
		} else {
			c.queueChild(child.PrevHash, child)
		}
	}
}

// persistence
func (c *Chain) saveBlock(b *Block) error {
	if dataDir == "" {
		return nil
	}
	if err := os.MkdirAll(blocksDir(c.ChainID), 0o755); err != nil {
		return err
	}
	by, err := encMode.Marshal(b)
	if err != nil {
		return err
	}
	fname := filepath.Join(blocksDir(c.ChainID), hex.EncodeToString(b.Hash)+".cbor")
	return os.WriteFile(fname, by, 0o644)
}

func (c *Chain) saveIndex() error {
	if dataDir == "" {
		return nil
	}
	idx := struct {
		ChainID   string           `json:"chain_id"`
		TipHeight int64            `json:"tip_height"`
		TipHash   string           `json:"tip_hash"`
		Known     map[string]int64 `json:"known"`
	}{ChainID: c.ChainID, TipHeight: c.TipHeight, TipHash: hex.EncodeToString(c.TipHash), Known: c.known}
	by, _ := json.MarshalIndent(idx, "", "  ")
	if err := os.MkdirAll(chainDir(c.ChainID), 0o755); err != nil {
		return err
	}
	return os.WriteFile(indexPath(c.ChainID), by, 0o644)
}

func (c *Chain) loadIndex() error {
	p := indexPath(c.ChainID)
	by, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var idx struct {
		ChainID   string
		TipHeight int64
		TipHash   string
		Known     map[string]int64
	}
	if err := json.Unmarshal(by, &idx); err != nil {
		return err
	}
	c.TipHeight = idx.TipHeight
	if idx.TipHash != "" {
		if h, _ := hex.DecodeString(idx.TipHash); len(h) > 0 {
			c.TipHash = h
		}
	}
	for k, v := range idx.Known {
		c.known[k] = v
	}
	return nil
}

// Public helpers for HTTP API
func GetTip(chainID string) (int64, string) {
	ch := getChain(chainID)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.TipHeight, hex.EncodeToString(ch.TipHash)
}

func LoadBlockByHash(chainID, hashHex string) (*Block, bool) {
	p := filepath.Join(blocksDir(chainID), strings.ToLower(hashHex)+".cbor")
	by, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var blk Block
	if err := decMode.Unmarshal(by, &blk); err != nil {
		return nil, false
	}
	return &blk, true
}

func GetHashByHeight(chainID string, height int64) (string, bool) {
	ch := getChain(chainID)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	for h, ht := range ch.known {
		if ht == height {
			return h, true
		}
	}
	return "", false
}

// ListRecentHashes returns up to n most recent known block hashes with heights, sorted by height desc.
func ListRecentHashes(chainID string, n int) []struct {
	Height int64
	Hash   string
} {
	if n <= 0 {
		n = 20
	}
	ch := getChain(chainID)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	// Collect pairs
	type pair struct {
		H int64
		X string
	}
	arr := make([]pair, 0, len(ch.known))
	for x, h := range ch.known {
		arr = append(arr, pair{H: h, X: x})
	}
	// Sort by height desc
	sort.Slice(arr, func(i, j int) bool { return arr[i].H > arr[j].H })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]struct {
		Height int64
		Hash   string
	}, len(arr))
	for i := range arr {
		out[i] = struct {
			Height int64
			Hash   string
		}{Height: arr[i].H, Hash: arr[i].X}
	}
	return out
}

// loadBlockTimestamp reads a stored block and returns its timestamp.
func loadBlockTimestamp(chainID string, hashHex string) (time.Time, bool) {
	p := filepath.Join(blocksDir(chainID), strings.ToLower(hashHex)+".cbor")
	by, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	var blk Block
	if err := decMode.Unmarshal(by, &blk); err != nil {
		return time.Time{}, false
	}
	return blk.Timestamp, true
}

// ---- Tx index persistence ----
type txRef struct {
	BlockHash string `json:"block_hash"`
	Height    int64  `json:"height"`
}

func txIndexPath(chainID string) string { return filepath.Join(chainDir(chainID), "txindex.json") }

func (c *Chain) saveTxIndex() error {
	if dataDir == "" {
		return nil
	}
	by, _ := json.MarshalIndent(c.txIndex, "", "  ")
	if err := os.MkdirAll(chainDir(c.ChainID), 0o755); err != nil {
		return err
	}
	return os.WriteFile(txIndexPath(c.ChainID), by, 0o644)
}

func (c *Chain) loadTxIndex() error {
	p := txIndexPath(c.ChainID)
	by, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var m map[string]txRef
	if err := json.Unmarshal(by, &m); err != nil {
		return err
	}
	for k, v := range m {
		c.txIndex[k] = v
	}
	return nil
}

func GetBlockByTxID(chainID string, txid string) (hash string, height int64, ok bool) {
	ch := getChain(chainID)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if r, found := ch.txIndex[txid]; found {
		return r.BlockHash, r.Height, true
	}
	return "", 0, false
}

// StartBlockBuilder consumes txs from txTopic, builds blocks every interval with up to maxTxs, and publishes to blockTopic.
func StartBlockBuilder(ctx context.Context, h host.Host, txTopic *pubsub.Topic, blkTopic *pubsub.Topic, chainID string, interval time.Duration, maxTxs int) error {
	// subscribe to txs on existing topic
	txSub, err := txTopic.Subscribe()
	if err != nil {
		return err
	}

	// mempool
	mem := make(chan []byte, 4096)
	go func() {
		for {
			msg, err := txSub.Next(ctx)
			if err != nil {
				return
			}
			// validate tx quickly
			if _, _, _, _, err := coseutil.ValidateCOSETx(msg.Message.GetData()); err != nil {
				continue
			}
			select {
			case mem <- msg.Message.GetData():
			default:
			}
		}
	}()

	var (
		height int64 = 1
		prev   []byte
	)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// drain up to maxTxs
				var batch [][]byte
				for i := 0; i < maxTxs; i++ {
					select {
					case b := <-mem:
						batch = append(batch, b)
					default:
					}
				}
				if len(batch) == 0 {
					continue
				}
				// build block
				blk := Block{Version: 1, ChainID: chainID, Height: height, PrevHash: prev, Timestamp: time.Now().UTC()}
				for _, tx := range batch {
					txid, _, _, _, _ := coseutil.ValidateCOSETx(tx)
					blk.TxIDs = append(blk.TxIDs, txid)
					blk.Txs = append(blk.Txs, tx)
				}
				// compute Merkle root over txids (hex -> bytes)
				var leaves [][]byte
				for _, hx := range blk.TxIDs {
					if b, err := hex.DecodeString(hx); err == nil {
						leaves = append(leaves, b)
					}
				}
				blk.TxRoot = merkle.ComputeRoot(leaves)
				if err := Sign(h, &blk); err != nil {
					logx.Error("block sign", "err", err)
					continue
				}
				// publish
				data, err := encMode.Marshal(blk)
				if err != nil {
					logx.Error("block marshal", "err", err)
					continue
				}
				if err := blkTopic.Publish(ctx, data); err != nil {
					logx.Error("block publish", "err", err)
				}
				prev = blk.Hash
				height++
			}
		}
	}()
	return nil
}

// StartBlockBuilderFromPool builds blocks by draining transactions from a local mempool.
// It aligns the initial height/prev to the current persisted tip for the given chainID.
func StartBlockBuilderFromPool(ctx context.Context, h host.Host, pool *mempool.Pool, blkTopic *pubsub.Topic, chainID string, interval time.Duration, maxTxs int, maxBytes int, allowProduce func() bool) error {
	// initialize from current chain tip if available
	ch := getChain(chainID)
	ch.mu.Lock()
	var height int64 = ch.TipHeight + 1
	prev := append([]byte(nil), ch.TipHash...)
	ch.mu.Unlock()
	if height <= 0 {
		height = 1
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Re-sync builder cursor to the current chain tip before proposing,
				// so we always append to the latest known tip even if remote blocks
				// advanced the chain since the builder started.
				ch := getChain(chainID)
				ch.mu.Lock()
				curTip := ch.TipHeight
				curHash := append([]byte(nil), ch.TipHash...)
				ch.mu.Unlock()
				// If our local cursor is behind or parent hash differs, reset.
				if height != curTip+1 || !bytes.Equal(prev, curHash) {
					height = curTip + 1
					prev = curHash
					if height <= 0 {
						height = 1
					}
				}
				if allowProduce != nil {
					if ok := allowProduce(); !ok {
						// Skip this tick if not currently elected to produce
						continue
					}
				}
				// drain up to maxTxs directly from mempool
				batch := pool.PopBatch(maxTxs)
				// build block with limits (count, bytes)
				blk := Block{Version: 1, ChainID: chainID, Height: height, PrevHash: prev, Timestamp: time.Now().UTC()}
				var total int
				for _, tx := range batch {
					if maxBytes > 0 && total+len(tx) > maxBytes {
						break
					}
					txid, _, _, _, _ := coseutil.ValidateCOSETx(tx)
					blk.TxIDs = append(blk.TxIDs, txid)
					blk.Txs = append(blk.Txs, tx)
					total += len(tx)
					if maxTxs > 0 && len(blk.Txs) >= maxTxs {
						break
					}
				}
				// Allow empty blocks so the chain advances one block per slot.
				// compute Merkle root over txids (hex -> bytes)
				var leaves [][]byte
				for _, hx := range blk.TxIDs {
					if b, err := hex.DecodeString(hx); err == nil {
						leaves = append(leaves, b)
					}
				}
				blk.TxRoot = merkle.ComputeRoot(leaves)
				// L1 attestations for parent (if any) can be injected by the caller via context value
				if v := ctx.Value(ctxKeyGetAttest{}); v != nil {
					if fn, ok := v.(func([]byte) [][]byte); ok {
						if len(prev) > 0 {
							blk.L1Attestations = fn(prev)
						}
					}
				}
				if err := Sign(h, &blk); err != nil {
					logx.Error("block sign", "err", err)
					continue
				}
				// Publish with a colored log and notify HELIOS (if wired by caller)
				const green = "\x1b[32m"
				const cyan = "\x1b[36m"
				const reset = "\x1b[0m"
				logx.Info(cyan+"propose block"+reset, "height", blk.Height, "txs", len(blk.Txs), "mempool_len", pool.Len())
				data, err := encMode.Marshal(blk)
				if err != nil {
					logx.Error("block marshal", "err", err)
					continue
				}
				if err := blkTopic.Publish(ctx, data); err != nil {
					logx.Error("block publish", "err", err)
				}
				prev = blk.Hash
				height++
			}
		}
	}()
	return nil
}

// StartBlockSubscriber subscribes to blockTopic and validates blocks.
// leaderOK, if non-nil, is used to enforce leader-only block acceptance. It receives the epoch and
// the producer's public key bytes and must return true if this producer is elected leader.
// onAccept, if non-nil, is invoked for every block that passes validation and is accepted locally.
func StartBlockSubscriber(ctx context.Context, h host.Host, ps *pubsub.PubSub, blockTopicName string, expectedChain string, logQueue bool, maxTxs int, maxBytes int, leaderOK func(epoch uint64, producerPub []byte) bool, onAccept func(*Block)) (*pubsub.Topic, error) {
	topic, err := ps.Join(blockTopicName)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			var blk Block
			if err := decMode.Unmarshal(msg.Message.GetData(), &blk); err != nil {
				logx.Warn("block bad cbor", "err", err)
				continue
			}
			// Chain ID check
			if blk.ChainID != expectedChain {
				logx.Warn("block wrong chain", "got", blk.ChainID, "want", expectedChain)
				continue
			}
			if err := Verify(&blk); err != nil {
				logx.Warn("block invalid", "err", err)
				continue
			}
			// Enforce leader (if predicate provided)
			if leaderOK != nil {
				var epoch uint64
				if blk.Height > 0 {
					const epochLen = 64
					epoch = uint64(blk.Height-1) / epochLen
				}
				if ok := leaderOK(epoch, blk.ProducerPub); !ok {
					logx.Warn("block rejected: not leader", "height", blk.Height, "epoch", epoch, "producer", blk.ProducerID)
					continue
				}
			}
			// Block limits: count and bytes
			if maxTxs > 0 && len(blk.Txs) > maxTxs {
				logx.Warn("block too many txs", "count", len(blk.Txs), "max", maxTxs)
				continue
			}
			if maxBytes > 0 {
				total := 0
				for _, b := range blk.Txs {
					total += len(b)
				}
				if total > maxBytes {
					logx.Warn("block too many bytes", "bytes", total, "max", maxBytes)
					continue
				}
			}
			// Dedup txids
			seen := make(map[string]struct{}, len(blk.TxIDs))
			dup := false
			for _, id := range blk.TxIDs {
				if _, ok := seen[id]; ok {
					dup = true
					break
				}
				seen[id] = struct{}{}
			}
			if dup {
				logx.Warn("block duplicate txid")
				continue
			}
			// Optional timestamp monotonicity: check against parent if known on disk
			if len(blk.PrevHash) > 0 {
				prevTS, ok := loadBlockTimestamp(expectedChain, hex.EncodeToString(blk.PrevHash))
				if ok && blk.Timestamp.Before(prevTS) {
					logx.Warn("block timestamp before parent", "height", blk.Height)
					continue
				}
			}
			// re-validate txs (basic) with on-demand key fetch
			ok := true
			for _, tx := range blk.Txs {
				if _, _, _, _, err := coseutil.ValidateCOSETx(tx); err != nil {
					if strings.Contains(err.Error(), "unknown kid") {
						if kid, kerr := coseutil.ExtractKid(tx); kerr == nil {
							if fetchAndRegisterKey(ctx, h, kid) {
								if _, _, _, _, err2 := coseutil.ValidateCOSETx(tx); err2 == nil {
									continue
								}
							}
						}
					}
					ok = false
					break
				}
			}
			if !ok {
				logx.Warn("block contains invalid txs")
				continue
			}

			// chain checks with out-of-order tolerance
			ch := getChain(blk.ChainID)
			ch.mu.Lock()
			// helper to accept a block and cascade any queued descendants
			var accept = func(b *Block) { ch.acceptBlockLocked(b) }

			// decide to accept now or queue
			if blk.Height == 1 && len(blk.PrevHash) == 0 {
				const green = "\x1b[32m"
				const reset = "\x1b[0m"
				accept(&blk)
				logx.Info(green+"block accepted"+reset, "height", blk.Height, "txs", len(blk.Txs), "producer", blk.ProducerID)
				snapshot := blk
				ch.mu.Unlock()
				if onAccept != nil {
					onAccept(&snapshot)
				}
				continue
			}
			if ph, ok := ch.isKnown(blk.PrevHash); ok && blk.Height == ph+1 {
				const green = "\x1b[32m"
				const reset = "\x1b[0m"
				accept(&blk)
				logx.Info(green+"block accepted"+reset, "height", blk.Height, "txs", len(blk.Txs), "producer", blk.ProducerID)
				snapshot := blk
				ch.mu.Unlock()
				if onAccept != nil {
					onAccept(&snapshot)
				}
				continue
			}
			// If prev is not yet known, queue and attempt on-demand fetch from peers
			ch.queueChild(blk.PrevHash, &blk)
			go fetchAndInjectParent(ctx, h, blk.ChainID, blk.PrevHash)
			if logQueue {
				logx.Debug("block queued", "height", blk.Height)
			}
			ch.mu.Unlock()
		}
	}()

	// Retry loop: periodically try fetching missing parents for queued blocks
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// ch := getChain("") // not used; we'll iterate all chains
				chains.mu.Lock()
				for _, c := range chains.m {
					c.mu.Lock()
					keys := c.waitingKeys()
					// Copy to avoid holding lock during network fetch
					c.mu.Unlock()
					for _, kh := range keys {
						if parent, err := hex.DecodeString(kh); err == nil {
							go fetchAndInjectParent(ctx, h, c.ChainID, parent)
						}
					}
				}
				chains.mu.Unlock()
			}
		}
	}()
	return topic, nil
}

// StartBlockSubscriberWithMempool wires block acceptance to mempool cleanup by txid.
func StartBlockSubscriberWithMempool(ctx context.Context, h host.Host, ps *pubsub.PubSub, blockTopicName string, expectedChain string, pool *mempool.Pool, logPrune bool, logQueue bool, maxTxs int, maxBytes int, leaderOK func(epoch uint64, producerPub []byte) bool, afterAccept func(*Block)) (*pubsub.Topic, error) {
	hook := func(b *Block) {
		removed := pool.RemoveTxIDs(b.TxIDs)
		if logPrune && removed > 0 {
			logx.Info("mempool pruned", "removed", removed, "height", b.Height)
		}
		if afterAccept != nil {
			afterAccept(b)
		}
	}
	return StartBlockSubscriber(ctx, h, ps, blockTopicName, expectedChain, logQueue, maxTxs, maxBytes, leaderOK, hook)
}

// -------- Block sync over libp2p streams --------

const blockSyncProto = "/pose/blocksync/1.0.0"

type syncReq struct {
	Type    string `json:"type"` // "tip" or "get"
	ChainID string `json:"chain_id"`
	Hash    string `json:"hash,omitempty"` // hex
}
type tipResp struct {
	Ok        bool   `json:"ok"`
	TipHeight int64  `json:"tip_height"`
	TipHash   string `json:"tip_hash"`
}
type getResp struct {
	Ok    bool   `json:"ok"`
	Block string `json:"block,omitempty"`
} // base64

// RegisterBlockSync sets stream handler for block sync RPCs.
func RegisterBlockSync(h host.Host) {
	h.SetStreamHandler(blockSyncProto, func(s network.Stream) {
		defer s.Close()
		r := bufio.NewReader(s)
		line, _ := r.ReadString('\n')
		var req syncReq
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &req); err != nil {
			return
		}
		switch req.Type {
		case "tip":
			ch := getChain(req.ChainID)
			ch.mu.Lock()
			th, thash := ch.TipHeight, hex.EncodeToString(ch.TipHash)
			ch.mu.Unlock()
			resp := tipResp{Ok: true, TipHeight: th, TipHash: thash}
			b, _ := json.Marshal(resp)
			s.Write(append(b, '\n'))
		case "get":
			// read from disk
			path := filepath.Join(blocksDir(req.ChainID), strings.ToLower(req.Hash)+".cbor")
			by, err := os.ReadFile(path)
			if err != nil {
				b, _ := json.Marshal(getResp{Ok: false})
				s.Write(append(b, '\n'))
				return
			}
			b, _ := json.Marshal(getResp{Ok: true, Block: base64.StdEncoding.EncodeToString(by)})
			s.Write(append(b, '\n'))
		case "txproof":
			// Re-parse as tx proof request
			var tpr struct{ Type, ChainID, BlockHash, TxID string }
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &tpr) != nil {
				return
			}
			// Load block file
			path := filepath.Join(blocksDir(tpr.ChainID), strings.ToLower(tpr.BlockHash)+".cbor")
			by, err := os.ReadFile(path)
			if err != nil {
				b, _ := json.Marshal(map[string]any{"ok": false, "error": "block not found"})
				s.Write(append(b, '\n'))
				return
			}
			var blk Block
			if decMode.Unmarshal(by, &blk) != nil {
				b, _ := json.Marshal(map[string]any{"ok": false, "error": "bad block"})
				s.Write(append(b, '\n'))
				return
			}
			// Find index
			idx := -1
			for i, id := range blk.TxIDs {
				if strings.EqualFold(id, tpr.TxID) {
					idx = i
					break
				}
			}
			if idx < 0 {
				b, _ := json.Marshal(map[string]any{"ok": false, "error": "tx not in block"})
				s.Write(append(b, '\n'))
				return
			}
			// Build proof
			leaves := make([][]byte, 0, len(blk.TxIDs))
			for _, hx := range blk.TxIDs {
				bb, err := hex.DecodeString(hx)
				if err != nil {
					b, _ := json.Marshal(map[string]any{"ok": false, "error": "bad txid"})
					s.Write(append(b, '\n'))
					return
				}
				leaves = append(leaves, bb)
			}
			proof, root, err := merkle.ComputeProof(leaves, idx)
			if err != nil {
				b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
				s.Write(append(b, '\n'))
				return
			}
			phex := make([]string, len(proof))
			for i := range proof {
				phex[i] = hex.EncodeToString(proof[i])
			}
			resp := map[string]any{"ok": true, "index": idx, "proof": phex, "tx_root": hex.EncodeToString(root)}
			b, _ := json.Marshal(resp)
			s.Write(append(b, '\n'))
		case "getkey":
			var kreq struct{ Type, Kid string }
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &kreq) != nil {
				return
			}
			kb, err := hex.DecodeString(kreq.Kid)
			if err != nil {
				return
			}
			if pub, ok := coseutil.RegistryGet(kb); ok {
				resp := map[string]any{"ok": true, "kid": strings.ToLower(kreq.Kid), "pub": hex.EncodeToString(pub)}
				b, _ := json.Marshal(resp)
				s.Write(append(b, '\n'))
				return
			}
			b, _ := json.Marshal(map[string]any{"ok": false})
			s.Write(append(b, '\n'))
		default:
			return
		}
	})
}

// fetchAndInjectParent attempts to fetch a missing parent block from connected peers and inject it into local processing.
func fetchAndInjectParent(ctx context.Context, h host.Host, chainID string, parentHash []byte) {
	hashHex := hex.EncodeToString(parentHash)
	for _, pid := range h.Network().Peers() {
		// request
		s, err := h.NewStream(ctx, pid, blockSyncProto)
		if err != nil {
			continue
		}
		req := syncReq{Type: "get", ChainID: chainID, Hash: hashHex}
		b, _ := json.Marshal(req)
		s.Write(append(b, '\n'))
		r := bufio.NewReader(s)
		line, err := r.ReadString('\n')
		s.Close()
		if err != nil {
			continue
		}
		var resp getResp
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &resp) != nil || !resp.Ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(resp.Block)
		if err != nil {
			continue
		}
		// decode + verify + process
		var blk Block
		if decMode.Unmarshal(raw, &blk) != nil {
			continue
		}
		if Verify(&blk) != nil {
			continue
		}
		// inject by calling accept flow directly
		ch := getChain(blk.ChainID)
		ch.mu.Lock()
		if blk.Height == 1 && len(blk.PrevHash) == 0 {
			ch.acceptBlockLocked(&blk)
		} else if ph, ok := ch.isKnown(blk.PrevHash); ok && blk.Height == ph+1 {
			ch.acceptBlockLocked(&blk)
		} else {
			ch.queueChild(blk.PrevHash, &blk)
		}
		ch.mu.Unlock()
		// stop after first success
		return
	}
}

// fetchAndRegisterKey requests a key from peers and registers it locally.
func fetchAndRegisterKey(ctx context.Context, h host.Host, kid []byte) bool {
	hexKid := hex.EncodeToString(kid)
	for _, pid := range h.Network().Peers() {
		s, err := h.NewStream(ctx, pid, blockSyncProto)
		if err != nil {
			continue
		}
		req := map[string]string{"type": "getkey", "kid": strings.ToLower(hexKid)}
		by, _ := json.Marshal(req)
		s.Write(append(by, '\n'))
		r := bufio.NewReader(s)
		line, err := r.ReadString('\n')
		s.Close()
		if err != nil {
			continue
		}
		var resp struct {
			Ok  bool
			Kid string
			Pub string
		}
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &resp) != nil || !resp.Ok {
			continue
		}
		pub, err := hex.DecodeString(resp.Pub)
		if err != nil {
			continue
		}
		coseutil.RegistryRegister(kid, ed25519.PublicKey(pub))
		return true
	}
	return false
}
