package entropy

import (
    "pose/internal/blockchain"
    "pose/internal/cell"
)

// ComputeCellEntropyFromChain computes Shannon entropy (bits per byte) for the IoT data sections
// of transactions authored by devices in the given cell, scanning the last `window` blocks ending at tip.
// Returns (entropy_bits_per_byte, tx_sample_count).
func ComputeCellEntropyFromChain(chainID string, c *cell.Cell, window int64) (float64, int) {
    if c == nil || !c.Active || window <= 0 { return 0, 0 }
    tipH, _ := blockchain.GetTip(chainID)
    if tipH <= 0 { return 0, 0 }
    start := tipH - window + 1
    if start < 1 { start = 1 }
    // Build device set
    ids := make(map[string]struct{}, len(c.Devices))
    for _, d := range c.Devices { ids[d.DeviceID] = struct{}{} }
    // Accumulate bytes
    var all []byte
    samples := 0
    for h := start; h <= tipH; h++ {
        hh, ok := blockchain.GetHashByHeight(chainID, h)
        if !ok { continue }
        blk, ok := blockchain.LoadBlockByHash(chainID, hh)
        if !ok { continue }
        for _, tx := range blk.Txs {
            devID, by, ok := ExtractDevIDAndData(tx)
            if !ok { continue }
            if _, keep := ids[devID]; !keep { continue }
            if len(by) == 0 { continue }
            all = append(all, by...)
            samples++
        }
    }
    if len(all) == 0 { return 0, 0 }
    return shannon(all), samples
}

// ComputeCellEntropyForEpoch computes Shannon entropy (bits per byte) for the IoT data sections
// of transactions authored by devices in the given cell, scanning the exact block range for the
// provided epoch number. Returns (entropy_bits_per_byte, tx_sample_count).
func ComputeCellEntropyForEpoch(chainID string, c *cell.Cell, epoch uint64, epochLen uint64) (float64, int) {
    if c == nil || !c.Active || epochLen == 0 { return 0, 0 }
    // inclusive heights for the epoch window
    var start int64 = int64(epoch*epochLen) + 1
    var end int64 = int64((epoch + 1) * epochLen)
    if start <= 0 || end < start { return 0, 0 }
    // Build device set
    ids := make(map[string]struct{}, len(c.Devices))
    for _, d := range c.Devices { ids[d.DeviceID] = struct{}{} }
    // Accumulate bytes
    var all []byte
    samples := 0
    for h := start; h <= end; h++ {
        hh, ok := blockchain.GetHashByHeight(chainID, h)
        if !ok { continue }
        blk, ok := blockchain.LoadBlockByHash(chainID, hh)
        if !ok { continue }
        for _, tx := range blk.Txs {
            devID, by, ok := ExtractDevIDAndData(tx)
            if !ok { continue }
            if _, keep := ids[devID]; !keep { continue }
            if len(by) == 0 { continue }
            all = append(all, by...)
            samples++
        }
    }
    if len(all) == 0 { return 0, 0 }
    return shannon(all), samples
}
