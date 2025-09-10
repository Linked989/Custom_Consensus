package mempool

import (
    "errors"
    "sync"
    "time"

    "pose/internal/coseutil"
)

// Entry holds a validated transaction kept in the local mempool.
type Entry struct {
    TxID   string
    DevID  string
    Seq    int64
    Bytes  []byte
    Added  time.Time
}

type Pool struct {
    mu       sync.Mutex
    entries  map[string]*Entry // txid -> entry
    order    []string          // FIFO of txids
    capacity int
    ttl      time.Duration
}

// New creates a new mempool with max capacity and a TTL for entries.
func New(capacity int, ttl time.Duration) *Pool {
    return &Pool{entries: make(map[string]*Entry), capacity: capacity, ttl: ttl}
}

// Len returns current number of transactions in the pool.
func (p *Pool) Len() int {
    p.mu.Lock(); defer p.mu.Unlock()
    p.sweepLocked()
    return len(p.entries)
}

// AddValidatedCOSE validates a COSE tx, applies replay rules, and inserts it if new.
func (p *Pool) AddValidatedCOSE(b []byte) (*Entry, error) {
    txid, devID, seq, err := coseutil.ValidateCOSETx(b)
    if err != nil {
        return nil, err
    }
    // replay protection
    if !coseutil.UpdateLastSeq(devID, seq) {
        return nil, errors.New("replay")
    }
    p.mu.Lock(); defer p.mu.Unlock()
    p.sweepLocked()
    if _, ok := p.entries[txid]; ok {
        return nil, errors.New("duplicate")
    }
    // evict oldest if full
    if p.capacity > 0 && len(p.entries) >= p.capacity {
        oldest := p.order[0]
        delete(p.entries, oldest)
        p.order = p.order[1:]
    }
    e := &Entry{TxID: txid, DevID: devID, Seq: seq, Bytes: b, Added: time.Now()}
    p.entries[txid] = e
    p.order = append(p.order, txid)
    return e, nil
}

// PopBatch removes up to max entries (FIFO) and returns their raw bytes.
func (p *Pool) PopBatch(max int) [][]byte {
    p.mu.Lock(); defer p.mu.Unlock()
    p.sweepLocked()
    if max <= 0 { return nil }
    n := max
    if len(p.order) < n { n = len(p.order) }
    if n == 0 { return nil }
    out := make([][]byte, 0, n)
    for i := 0; i < n; i++ {
        txid := p.order[i]
        if e, ok := p.entries[txid]; ok {
            out = append(out, e.Bytes)
            delete(p.entries, txid)
        }
    }
    p.order = p.order[n:]
    return out
}

// RemoveTxIDs removes entries with the given txids from the pool.
// Returns the number of removed transactions.
func (p *Pool) RemoveTxIDs(ids []string) int {
    if len(ids) == 0 { return 0 }
    p.mu.Lock(); defer p.mu.Unlock()
    removed := 0
    rm := make(map[string]struct{}, len(ids))
    for _, id := range ids { rm[id] = struct{}{} }
    for id := range rm {
        if _, ok := p.entries[id]; ok {
            delete(p.entries, id)
            removed++
        }
    }
    if removed > 0 {
        // rebuild order without removed ids
        newOrder := new([]string)
        no := *newOrder
        no = no[:0]
        for _, id := range p.order {
            if _, drop := rm[id]; !drop {
                no = append(no, id)
            }
        }
        p.order = no
    }
    return removed
}

// sweepLocked drops expired entries; caller must hold p.mu.
func (p *Pool) sweepLocked() {
    if p.ttl <= 0 { return }
    now := time.Now()
    if len(p.order) == 0 { return }
    // sweep from the head while expired
    i := 0
    for i < len(p.order) {
        txid := p.order[i]
        e := p.entries[txid]
        if e == nil { i++; continue }
        if now.Sub(e.Added) <= p.ttl { break }
        delete(p.entries, txid)
        i++
    }
    if i > 0 { p.order = p.order[i:] }
}
