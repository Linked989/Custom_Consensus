package aion

import (
	"math/bits"
)

// Fixed-point helpers (Q16.16)
const qShift = 16
const qOne uint32 = 1 << qShift

// min128 caps entropy at 128 bits.
func min128(v uint16) uint16 {
	if v > 128 {
		return 128
	}
	return v
}

// NormalizeEntropyQ16 returns H_norm in Q16.16 given H_lb in bits (0..128).
func NormalizeEntropyQ16(HlbBits uint16) uint32 {
	// H_norm = min(H_lb,128)/128
	v := uint32(min128(HlbBits))
	// scale to Q16.16: (v << qShift) / 128
	return (v << qShift) / 128
}

// MovingAvg4Q16 computes a simple moving average over the last 4 epochs.
// Inputs and output are Q16.16.
func MovingAvg4Q16(v0, v1, v2, v3 uint32) uint32 {
	// (v0+v1+v2+v3)/4 with saturation on overflow
	s0 := uint64(v0) + uint64(v1) + uint64(v2) + uint64(v3)
	return uint32(s0 >> 2)
}

// WeightQ16 computes Wt = 1 + alpha * moving_avg(H_norm[0..3]) in Q16.16.
func WeightQ16(alphaQ16 uint32, hnorm0, hnorm1, hnorm2, hnorm3 uint32) uint32 {
	ma := MovingAvg4Q16(hnorm0, hnorm1, hnorm2, hnorm3)
	// alpha * ma (Q16.16 * Q16.16 -> Q32.32, then >>16)
	prod := (uint64(alphaQ16) * uint64(ma)) >> qShift
	wt := uint64(qOne) + prod
	if wt > (1<<32 - 1) {
		return ^uint32(0)
	}
	return uint32(wt)
}

// RankValue computes a comparable integer for Score = y / Wt.
// y must be a 32-byte VRF output (big-endian). We scale y by 2^16 before dividing
// to maintain precision, but callers should only use the returned value for ordering.
func RankValue(y [32]byte, wtQ16 uint32) [33]byte {
	// Represent y as 33-byte big-endian to accommodate left shift by 16 and division.
	var num [33]byte
	// y << 16
	carry := uint32(0)
	for i := 31; i >= 0; i-- {
		v := (uint32(y[i]) << qShift) | carry
		num[i+1] = byte(v & 0xFF)
		carry = v >> 8
	}
	num[0] = byte(carry & 0xFF)
	// Divide by wtQ16 (<= 2^32-1). Perform manual big-endian division.
	var out [33]byte
	rem := uint64(0)
	d := uint64(wtQ16)
	for i := 0; i < len(num); i++ {
		cur := (rem << 8) | uint64(num[i])
		q := cur / d
		rem = cur % d
		out[i] = byte(q)
	}
	return out
}

// CmpRank returns -1, 0, +1 comparing two rank values produced by RankValue.
func CmpRank(a, b [33]byte) int {
	// Compare lexicographically (big-endian)
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// IntLog2Q16 returns floor(log2(x)) in integer and a Q16.16 fractional part approximation.
// x must be > 0. This is used by entropy estimators that need -log2(p).
func IntLog2Q16(x uint64) (ilog int, fracQ16 uint32) {
	if x == 0 {
		return 0, 0
	}
	ilog = bits.Len64(x) - 1
	// Normalize x to [1.0, 2.0) in Q16
	shift := uint(63 - ilog)
	y := x << shift // top bit at 63
	// Extract next 16 bits after the leading 1 as fractional part
	frac := uint32((y >> (63 - qShift)) & ((1 << qShift) - 1))
	return ilog, frac
}
