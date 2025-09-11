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
    capBytes int
    curBytes int
}

// New creates a new mempool with max capacity, TTL for entries, and optional byte cap.
func New(capacity int, ttl time.Duration, capBytes int) *Pool {
    return &Pool{entries: make(map[string]*Entry), capacity: capacity, ttl: ttl, capBytes: capBytes}
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
    // if bytes cap configured and single tx exceeds it, reject
    if p.capBytes > 0 && len(b) > p.capBytes {
        return nil, errors.New("too_large")
    }
    // evict oldest if full
    for p.capacity > 0 && len(p.entries) >= p.capacity {
        oldest := p.order[0]
        if e := p.entries[oldest]; e != nil { p.curBytes -= len(e.Bytes) }
        delete(p.entries, oldest)
        p.order = p.order[1:]
    }
    // evict to satisfy bytes cap
    if p.capBytes > 0 {
        for p.curBytes+len(b) > p.capBytes && len(p.order) > 0 {
            oldest := p.order[0]
            if e := p.entries[oldest]; e != nil { p.curBytes -= len(e.Bytes) }
            delete(p.entries, oldest)
            p.order = p.order[1:]
        }
        if p.curBytes+len(b) > p.capBytes {
            return nil, errors.New("mempool_full")
        }
    }
    e := &Entry{TxID: txid, DevID: devID, Seq: seq, Bytes: b, Added: time.Now()}
    p.entries[txid] = e
    p.order = append(p.order, txid)
    p.curBytes += len(b)
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
            p.curBytes -= len(e.Bytes)
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
        if e, ok := p.entries[id]; ok {
            p.curBytes -= len(e.Bytes)
            delete(p.entries, id)
            removed++
        }
    }
    if removed > 0 {
        // rebuild order without removed ids
        no := make([]string, 0, len(p.order))
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
        p.curBytes -= len(e.Bytes)
        i++
    }
    if i > 0 { p.order = p.order[i:] }
}
