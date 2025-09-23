package aion

import (
	cbor "github.com/fxamacker/cbor/v2"

	"pose/internal/blockchain"
	"pose/internal/cell"
	"pose/internal/entropy"
)

// EpochEntropyQ16 computes a deterministic entropy normalization for the given epoch
// by scanning blocks in [startHeight, endHeight] and extracting IoT data bytes
// from all transactions. It uses a lower bound combining H_min and H2, capped to 128 bits,
// then normalizes to Q16.16 with NormalizeEntropyQ16.
func EpochEntropyQ16(chainID string, epoch uint64, epochLen uint64) uint32 {
	if epochLen == 0 {
		return 0
	}
	// map epoch to inclusive heights
	var start int64 = int64(epoch*epochLen) + 1
	var end int64 = int64((epoch + 1) * epochLen)
	if start <= 0 || end < start {
		return 0
	}

	// accumulate histogram (256 symbols)
	var freq [256]uint64
	var n uint64
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	for h := start; h <= end; h++ {
		hashHex, ok := blockchain.GetHashByHeight(chainID, h)
		if !ok {
			continue
		}
		blk, ok := blockchain.LoadBlockByHash(chainID, hashHex)
		if !ok {
			continue
		}
		// extract IoT data bytes from each tx
		for _, tx := range blk.Txs {
			// Ensure payload CBOR map key order does not affect byte content:
			// we marshal the extracted value back to canonical CBOR.
			by, ok := entropy.ExtractIoTDataSection(tx)
			if !ok || len(by) == 0 {
				continue
			}
			// Re-encode to canonical CBOR to ensure consistent byte stream
			// Note: ExtractIoTDataSection already returns CBOR-encoded value.
			// We decode then re-encode to normalized form.
			var val any
			if cbor.Unmarshal(by, &val) == nil {
				if enc, err := em.Marshal(val); err == nil {
					for _, b := range enc {
						freq[int(b)]++
						n++
					}
					continue
				}
			}
			// Fallback: use raw bytes
			for _, b := range by {
				freq[int(b)]++
				n++
			}
		}
	}
	if n == 0 {
		return 0
	}
	// compute stats
	var maxCnt uint64
	var sumSq uint64
	for i := 0; i < 256; i++ {
		c := freq[i]
		if c > maxCnt {
			maxCnt = c
		}
		sumSq += c * c
	}
	hmin := HMinBits(n, maxCnt, 128)
	h2 := HRenyi2Bits(n, sumSq, 128)
	hb := HLowerBoundBits(hmin, h2)
	return NormalizeEntropyQ16(hb)
}

// EpochEntropyForCellQ16 computes normalized entropy (Q16.16) like EpochEntropyQ16
// but restricted to transactions authored by devices that belong to the provided cell.
// If cell is nil or inactive, returns 0.
func EpochEntropyForCellQ16(chainID string, epoch uint64, epochLen uint64, c *cell.Cell) uint32 {
	if c == nil || !c.Active || epochLen == 0 {
		return 0
	}
	var start int64 = int64(epoch*epochLen) + 1
	var end int64 = int64((epoch + 1) * epochLen)
	if start <= 0 || end < start {
		return 0
	}
	// build device set
	ids := make(map[string]struct{}, len(c.Devices))
	for _, d := range c.Devices {
		ids[d.DeviceID] = struct{}{}
	}

	var freq [256]uint64
	var n uint64
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	for h := start; h <= end; h++ {
		hashHex, ok := blockchain.GetHashByHeight(chainID, h)
		if !ok {
			continue
		}
		blk, ok := blockchain.LoadBlockByHash(chainID, hashHex)
		if !ok {
			continue
		}
		for _, tx := range blk.Txs {
			devID, by, ok := entropy.ExtractDevIDAndData(tx)
			if !ok {
				continue
			}
			if _, keep := ids[devID]; !keep {
				continue
			}
			var val any
			if cbor.Unmarshal(by, &val) == nil {
				if enc, err := em.Marshal(val); err == nil {
					for _, b := range enc {
						freq[int(b)]++
						n++
					}
					continue
				}
			}
			for _, b := range by {
				freq[int(b)]++
				n++
			}
		}
	}
	if n == 0 {
		return 0
	}
	var maxCnt uint64
	var sumSq uint64
	for i := 0; i < 256; i++ {
		c := freq[i]
		if c > maxCnt {
			maxCnt = c
		}
		sumSq += c * c
	}
	hmin := HMinBits(n, maxCnt, 128)
	h2 := HRenyi2Bits(n, sumSq, 128)
	hb := HLowerBoundBits(hmin, h2)
	return NormalizeEntropyQ16(hb)
}

// Debug helper to interpret a short hash prefix for logs (non-consensus)
func short(hexHash string) string {
	if len(hexHash) <= 8 {
		return hexHash
	}
	return hexHash[:8]
}
