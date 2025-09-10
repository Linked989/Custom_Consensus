package blockchain

import (
    "bytes"
    "context"
    "crypto/sha256"
    "errors"
    "encoding/hex"
    "log"
    "sync"
    "time"

    cbor "github.com/fxamacker/cbor/v2"
    crypto "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    pubsub "github.com/libp2p/go-libp2p-pubsub"

    "pose/internal/coseutil"
)

var (
    encMode cbor.EncMode
    decMode cbor.DecMode
)

func init() {
    em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
    dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
    encMode, decMode = em, dm
}

// Block is a simple canonical structure for demonstration.
type Block struct {
    Version       int64         `cbor:"0,keyasint"`
    ChainID       string        `cbor:"1,keyasint"`
    Height        int64         `cbor:"2,keyasint"`
    PrevHash      []byte        `cbor:"3,keyasint"`
    Timestamp     time.Time     `cbor:"4,keyasint"`
    ProducerID    string        `cbor:"5,keyasint"`
    ProducerPub   []byte        `cbor:"6,keyasint"`
    TxIDs         []string      `cbor:"7,keyasint"`
    Txs           [][]byte      `cbor:"8,keyasint"`
    Hash          []byte        `cbor:"9,keyasint"`
    Signature     []byte        `cbor:"10,keyasint"`
}

// hashForSign returns the hash over the block fields excluding Hash and Signature.
func hashForSign(b *Block) ([]byte, error) {
    tmp := *b
    tmp.Hash = nil
    tmp.Signature = nil
    by, err := encMode.Marshal(tmp)
    if err != nil { return nil, err }
    h := sha256.Sum256(by)
    return h[:], nil
}

// Sign fills Hash and Signature using the host's private key.
func Sign(h host.Host, b *Block) error {
    // Ensure producer identity fields are populated BEFORE hashing
    priv := h.Peerstore().PrivKey(h.ID())
    if priv == nil { return errors.New("missing host private key") }
    pub := priv.GetPublic()
    pubBytes, err := crypto.MarshalPublicKey(pub)
    if err != nil { return err }
    b.ProducerPub = pubBytes
    b.ProducerID = h.ID().String()

    // Compute hash over the finalized header/body (excluding Hash/Signature)
    hash, err := hashForSign(b)
    if err != nil { return err }
    b.Hash = hash

    // Sign the block hash
    sig, err := priv.Sign(hash)
    if err != nil { return err }
    b.Signature = sig
    return nil
}

// Verify checks the hash and signature; also checks ProducerID matches the producer pubkey's peer ID.
func Verify(b *Block) error {
    // hash
    hash, err := hashForSign(b)
    if err != nil { return err }
    if len(b.Hash) == 0 || len(b.Signature) == 0 { return errors.New("missing block hash/signature") }
    if !bytes.Equal(hash, b.Hash) { return errors.New("hash mismatch") }
    // pubkey
    pub, err := crypto.UnmarshalPublicKey(b.ProducerPub)
    if err != nil { return err }
    ok, err := pub.Verify(b.Hash, b.Signature)
    if err != nil || !ok { return errors.New("signature verify failed") }
    // PeerID sanity
    pid, err := peerIDFromPub(pub)
    if err == nil && b.ProducerID != "" && b.ProducerID != pid { return errors.New("producer peerID mismatch") }
    return nil
}

// peerIDFromPub derives the peer ID string from a libp2p pubkey.
func peerIDFromPub(pub crypto.PubKey) (string, error) {
    pid, err := peerIDFromKey(pub)
    if err != nil { return "", err }
    return pid, nil
}

// separate small helper to avoid import cycles
func peerIDFromKey(pub crypto.PubKey) (string, error) {
    id, err := peer.IDFromPublicKey(pub)
    if err != nil { return "", err }
    return id.String(), nil
}

// ------ In-memory chain state ------

type Chain struct {
    mu        sync.Mutex
    ChainID   string
    TipHeight int64
    TipHash   []byte
    known     map[string]int64         // hex(hash) -> height
    waiting   map[string][]*Block      // hex(prevHash) -> children blocks waiting on this prev
}

var chains = struct{ mu sync.Mutex; m map[string]*Chain }{m: make(map[string]*Chain)}

func getChain(id string) *Chain {
    chains.mu.Lock()
    defer chains.mu.Unlock()
    c := chains.m[id]
    if c == nil {
        c = &Chain{ChainID: id, known: make(map[string]int64), waiting: make(map[string][]*Block)}
        chains.m[id] = c
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

// StartBlockBuilder consumes txs from txTopic, builds blocks every interval with up to maxTxs, and publishes to blockTopic.
func StartBlockBuilder(ctx context.Context, h host.Host, txTopic *pubsub.Topic, blkTopic *pubsub.Topic, chainID string, interval time.Duration, maxTxs int) error {
    // subscribe to txs on existing topic
    txSub, err := txTopic.Subscribe()
    if err != nil { return err }

    // mempool
    mem := make(chan []byte, 4096)
    go func() {
        for {
            msg, err := txSub.Next(ctx)
            if err != nil { return }
            // validate tx quickly
            if _, _, _, err := coseutil.ValidateCOSETx(msg.Message.GetData()); err != nil {
                continue
            }
            select { case mem <- msg.Message.GetData(): default: }
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
            select { case <-ctx.Done(): return; case <-ticker.C:
                // drain up to maxTxs
                var batch [][]byte
                for i := 0; i < maxTxs; i++ {
                    select { case b := <-mem: batch = append(batch, b); default: }
                }
                if len(batch) == 0 { continue }
                // build block
                blk := Block{Version: 1, ChainID: chainID, Height: height, PrevHash: prev, Timestamp: time.Now().UTC()}
                for _, tx := range batch {
                    txid, _, _, _ := coseutil.ValidateCOSETx(tx)
                    blk.TxIDs = append(blk.TxIDs, txid)
                    blk.Txs = append(blk.Txs, tx)
                }
                if err := Sign(h, &blk); err != nil { log.Printf("block: sign: %v", err); continue }
                // publish
                data, err := encMode.Marshal(blk)
                if err != nil { log.Printf("block: marshal: %v", err); continue }
                if err := blkTopic.Publish(ctx, data); err != nil { log.Printf("block: publish: %v", err) }
                prev = blk.Hash
                height++
            }
        }
    }()
    return nil
}

// StartBlockSubscriber subscribes to blockTopic and validates blocks.
func StartBlockSubscriber(ctx context.Context, ps *pubsub.PubSub, blockTopicName string) (*pubsub.Topic, error) {
    topic, err := ps.Join(blockTopicName)
    if err != nil { return nil, err }
    sub, err := topic.Subscribe()
    if err != nil { return nil, err }
    go func() {
        for {
            msg, err := sub.Next(ctx)
            if err != nil { return }
            var blk Block
            if err := decMode.Unmarshal(msg.Message.GetData(), &blk); err != nil { log.Printf("block: bad cbor: %v", err); continue }
            if err := Verify(&blk); err != nil { log.Printf("block: invalid: %v", err); continue }
            // re-validate txs (basic)
            ok := true
            for _, tx := range blk.Txs {
                if _, _, _, err := coseutil.ValidateCOSETx(tx); err != nil { ok = false; break }
            }
            if !ok { log.Printf("block: contains invalid txs"); continue }

            // chain checks with out-of-order tolerance
            ch := getChain(blk.ChainID)
            ch.mu.Lock()
            // helper to accept a block and cascade any queued descendants
            var accept func(b *Block)
            accept = func(b *Block) {
                // record known block
                ch.recordKnown(b.Hash, b.Height)
                // tip update if this extends or is higher
                // basic rule: if prev is current tip and height == tip+1 OR height > tip, move tip
                if (ch.TipHeight == 0 && b.Height == 1 && len(b.PrevHash) == 0) ||
                    (b.Height == ch.TipHeight+1 && bytes.Equal(b.PrevHash, ch.TipHash)) ||
                    (b.Height > ch.TipHeight) {
                    ch.TipHeight = b.Height
                    ch.TipHash = append(ch.TipHash[:0], b.Hash...)
                }
                // process any waiting children
                children := ch.popChildren(b.Hash)
                for _, c := range children {
                    // ensure c links to a known parent height
                    if ph, ok := ch.isKnown(c.PrevHash); ok && c.Height == ph+1 {
                        accept(c)
                    } else {
                        // requeue if still not linkable due to race
                        ch.queueChild(c.PrevHash, c)
                    }
                }
            }

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
            // If prev is not yet known, queue and wait for parent to arrive
            ch.queueChild(blk.PrevHash, &blk)
            log.Printf("block: queued height=%d waiting for parent", blk.Height)
            ch.mu.Unlock()
        }
    }()
    return topic, nil
}
