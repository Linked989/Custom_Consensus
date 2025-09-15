package aion

import "testing"

func TestEntropyBounds(t *testing.T) {
    // Min-entropy: if maxCnt == n, entropy = 0
    if got := HMinBits(100, 100, 128); got != 0 {
        t.Fatalf("HMinBits all-same=%d want 0", got)
    }
    // If uniform over 4 symbols with equal counts, min-entropy = log2(4)=2
    if got := HMinBits(100, 25, 128); got != 2 {
        t.Fatalf("HMinBits uniform/4=%d want 2", got)
    }
    // Rényi-2 for uniform over 4 symbols: sum p_i^2 = 4*(1/4)^2=1/4 => H2=2
    if got := HRenyi2Bits(100, 4*25*25, 128); got != 2 {
        t.Fatalf("HRenyi2Bits uniform/4=%d want 2", got)
    }
    // Lower bound selects min
    if got := HLowerBoundBits(5, 7, 3, 9); got != 3 {
        t.Fatalf("HLowerBoundBits=%d want 3", got)
    }
}

