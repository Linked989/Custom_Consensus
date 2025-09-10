package blockchain

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
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
    "pose/internal/mempool"
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
		c = &Chain{ChainID: id, known: make(map[string]int64), waiting: make(map[string][]*Block)}
		chains.m[id] = c
		// Try load index from disk
		_ = c.loadIndex()
	}
	return c
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
			if _, _, _, err := coseutil.ValidateCOSETx(msg.Message.GetData()); err != nil {
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
					txid, _, _, _ := coseutil.ValidateCOSETx(tx)
					blk.TxIDs = append(blk.TxIDs, txid)
					blk.Txs = append(blk.Txs, tx)
				}
				if err := Sign(h, &blk); err != nil {
					log.Printf("block: sign: %v", err)
					continue
				}
				// publish
				data, err := encMode.Marshal(blk)
				if err != nil {
					log.Printf("block: marshal: %v", err)
					continue
				}
				if err := blkTopic.Publish(ctx, data); err != nil {
					log.Printf("block: publish: %v", err)
				}
				prev = blk.Hash
				height++
			}
		}
	}()
	return nil
}

// StartBlockSubscriber subscribes to blockTopic and validates blocks.
func StartBlockSubscriber(ctx context.Context, h host.Host, ps *pubsub.PubSub, blockTopicName string) (*pubsub.Topic, error) {
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
				log.Printf("block: bad cbor: %v", err)
				continue
			}
			if err := Verify(&blk); err != nil {
				log.Printf("block: invalid: %v", err)
				continue
			}
			// re-validate txs (basic)
			ok := true
			for _, tx := range blk.Txs {
				if _, _, _, err := coseutil.ValidateCOSETx(tx); err != nil {
					ok = false
					break
				}
			}
			if !ok {
				log.Printf("block: contains invalid txs")
				continue
			}

			// chain checks with out-of-order tolerance
			ch := getChain(blk.ChainID)
			ch.mu.Lock()
			// helper to accept a block and cascade any queued descendants
			var accept = func(b *Block) { ch.acceptBlockLocked(b) }

			// decide to accept now or queue
            if blk.Height == 1 && len(blk.PrevHash) == 0 {
                accept(&blk)
                log.Printf("block: accepted height=%d txs=%d producer=%s", blk.Height, len(blk.Txs), blk.ProducerID)
                ch.mu.Unlock()
                continue
            }
            if ph, ok := ch.isKnown(blk.PrevHash); ok && blk.Height == ph+1 {
                accept(&blk)
                log.Printf("block: accepted height=%d txs=%d producer=%s", blk.Height, len(blk.Txs), blk.ProducerID)
                ch.mu.Unlock()
                continue
            }
			// If prev is not yet known, queue and attempt on-demand fetch from peers
			ch.queueChild(blk.PrevHash, &blk)
			go fetchAndInjectParent(ctx, h, blk.ChainID, blk.PrevHash)
			log.Printf("block: queued height=%d waiting for parent", blk.Height)
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
func StartBlockSubscriberWithMempool(ctx context.Context, h host.Host, ps *pubsub.PubSub, blockTopicName string, pool *mempool.Pool) (*pubsub.Topic, error) {
    topic, err := StartBlockSubscriber(ctx, h, ps, blockTopicName)
    if err != nil { return nil, err }
    // Subscribe again just to observe accepted blocks and prune mempool.
    sub, err := topic.Subscribe()
    if err != nil { return nil, err }
    go func() {
        for {
            msg, err := sub.Next(ctx); if err != nil { return }
            var blk Block
            if decMode.Unmarshal(msg.Message.GetData(), &blk) != nil { continue }
            if Verify(&blk) != nil { continue }
            // Remove txs from local mempool (best-effort)
            removed := pool.RemoveTxIDs(blk.TxIDs)
            if removed > 0 { log.Printf("mempool: removed %d txs included in block height=%d", removed, blk.Height) }
        }
    }()
    return topic, nil
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
