package blockchain

import (
    "bytes"
    "context"
    "crypto/sha256"
    "errors"
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
}

var chains = struct{ mu sync.Mutex; m map[string]*Chain }{m: make(map[string]*Chain)}

func getChain(id string) *Chain {
    chains.mu.Lock()
    defer chains.mu.Unlock()
    c := chains.m[id]
    if c == nil {
        c = &Chain{ChainID: id}
        chains.m[id] = c
    }
    return c
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

            // chain checks: prev hash and height
            ch := getChain(blk.ChainID)
            ch.mu.Lock()
            valid := false
            if ch.TipHeight == 0 {
                // expect genesis prev to be empty and height to start at 1
                if blk.Height == 1 && len(blk.PrevHash) == 0 {
                    valid = true
                }
            } else if blk.Height == ch.TipHeight+1 && bytes.Equal(blk.PrevHash, ch.TipHash) {
                valid = true
            }
            if valid {
                ch.TipHeight = blk.Height
                ch.TipHash = append(ch.TipHash[:0], blk.Hash...)
            }
            ch.mu.Unlock()
            if !valid {
                log.Printf("block: rejected out-of-order or prev mismatch (height=%d)", blk.Height)
                continue
            }
            log.Printf("block: accepted height=%d txs=%d producer=%s", blk.Height, len(blk.Txs), blk.ProducerID)
        }
    }()
    return topic, nil
}
