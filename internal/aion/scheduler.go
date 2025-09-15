package aion

import (
    "context"
    "time"

    "pose/internal/logx"
)

// SlotIndex is the monotonically increasing slot counter from genesis.
type SlotIndex uint64

// Epoch returns the epoch number for a given slot index.
func (p Params) Epoch(s SlotIndex) uint64 { return uint64(s) / p.EpochLength }

// EpochSlotOffset returns the offset of the slot within its epoch [0, EpochLength).
func (p Params) EpochSlotOffset(s SlotIndex) uint64 { return uint64(s) % p.EpochLength }

// SlotAt returns the wall-clock time of a given slot for logging purposes.
func (p Params) SlotAt(s SlotIndex) time.Time {
    return p.Genesis.Add(time.Duration(s) * p.SlotDuration)
}

// CurrentSlot computes the slot index for a given time, for non-consensus logging only.
func (p Params) CurrentSlot(now time.Time) SlotIndex {
    if now.Before(p.Genesis) { return 0 }
    d := now.Sub(p.Genesis)
    if p.SlotDuration <= 0 { return 0 }
    return SlotIndex(d / p.SlotDuration)
}

// StartSlotLogger logs slot/epoch progression at slot boundaries. This is dev-only and
// does not affect consensus decisions.
func StartSlotLogger(ctx context.Context, p Params) {
    if p.SlotDuration <= 0 { return }
    tick := time.NewTicker(p.SlotDuration)
    go func() {
        defer tick.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case t := <-tick.C:
                s := p.CurrentSlot(t)
                e := p.Epoch(s)
                off := p.EpochSlotOffset(s)
                logx.Info("aion slot", "slot", uint64(s), "epoch", e, "offset", off)
            }
        }
    }()
}

