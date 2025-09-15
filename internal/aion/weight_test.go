package aion

import (
    "encoding/hex"
    "testing"
)

func TestNormalizeEntropyQ16(t *testing.T) {
    tests := []struct{ in uint16; want uint32 }{
        {0, 0},
        {64, (64 << qShift) / 128},
        {128, (128 << qShift) / 128},
        {200, (128 << qShift) / 128}, // capped at 128
    }
    for _, tc := range tests {
        got := NormalizeEntropyQ16(tc.in)
        if got != tc.want {
            t.Fatalf("norm(%d)=%d want %d", tc.in, got, tc.want)
        }
    }
}

func TestWeightQ16_MovingAvg(t *testing.T) {
    // alpha = 0.5 in Q16.16
    alpha := uint32(0x00008000)
    one := uint32(qOne)
    // All zeros -> weight = 1.0
    if got := WeightQ16(alpha, 0, 0, 0, 0); got != one {
        t.Fatalf("weight zeros=%d want 1<<16", got)
    }
    // All ones -> weight = 1 + 0.5*1 = 1.5
    if got := WeightQ16(alpha, one, one, one, one); got != one + (one>>1) {
        t.Fatalf("weight ones=%d want 1.5<<16", got)
    }
    // Mixed -> just sanity check monotonicity
    w1 := WeightQ16(alpha, one, 0, 0, 0)
    w2 := WeightQ16(alpha, one, one, 0, 0)
    if !(w1 < w2) {
        t.Fatalf("expected w1 < w2, got %d >= %d", w1, w2)
    }
}

func TestRankValue_Order(t *testing.T) {
    // Two distinct VRF outputs, same weight -> lexicographic compare aligns
    y1Hex := "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    y2Hex := "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    y1b, _ := hex.DecodeString(y1Hex)
    y2b, _ := hex.DecodeString(y2Hex)
    var y1, y2 [32]byte
    copy(y1[:], y1b)
    copy(y2[:], y2b)
    wt := uint32(qOne)
    r1 := RankValue(y1, wt)
    r2 := RankValue(y2, wt)
    if !(CmpRank(r1, r2) < 0) {
        t.Fatalf("expected r1 < r2 for y1<y2")
    }
    // Heavier weight should reduce the rank value (i.e., better rank, smaller)
    rLight := RankValue(y2, wt)
    rHeavy := RankValue(y2, wt + (qOne>>1)) // 1.5x weight
    if !(CmpRank(rHeavy, rLight) < 0) {
        t.Fatalf("expected heavier weight produce smaller rank value")
    }
}

