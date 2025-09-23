package aion

// Estimators for lower-bound entropy in bits, using only integer/fixed-point ops.

// HMinBits returns min-entropy lower bound in bits for a byte histogram: H_inf = -log2(max p_i).
// n is the total sample count; maxCnt is the maximum frequency among symbols.
// Returns a value in [0, 128]. For seeds longer than 16 bytes, cap at 128.
func HMinBits(n uint64, maxCnt uint64, seedBitCap uint16) uint16 {
	if n == 0 || maxCnt == 0 {
		return 0
	}
	// -log2(maxCnt/n) = log2(n/maxCnt)
	ratio := n / maxCnt
	if ratio == 0 {
		return 0
	}
	ilog, _ := IntLog2Q16(ratio)
	v := uint16(ilog)
	if v > seedBitCap {
		v = seedBitCap
	}
	if v > 128 {
		v = 128
	}
	return v
}

// HRenyi2Bits returns Rényi-2 entropy lower bound: H2 = -log2(sum p_i^2).
// We compute s = sum (cnt_i^2), then H2 = -log2(s / n^2) = log2(n^2 / s).
func HRenyi2Bits(n uint64, sumSq uint64, seedBitCap uint16) uint16 {
	if n == 0 || sumSq == 0 {
		return 0
	}
	num := n * n
	if num == 0 {
		return 0
	}
	ratio := num / sumSq
	if ratio == 0 {
		return 0
	}
	ilog, _ := IntLog2Q16(ratio)
	v := uint16(ilog)
	if v > seedBitCap {
		v = seedBitCap
	}
	if v > 128 {
		v = 128
	}
	return v
}

// HLowerBoundBits selects the minimum of the provided estimators.
func HLowerBoundBits(vals ...uint16) uint16 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for i := 1; i < len(vals); i++ {
		if vals[i] < m {
			m = vals[i]
		}
	}
	if m > 128 {
		return 128
	}
	return m
}
