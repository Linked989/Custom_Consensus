package merkle

import (
    "crypto/sha256"
    "encoding/hex"
    "testing"
)

func h(x string) []byte { b, _ := hex.DecodeString(x); return b }

func TestComputeRootBasic(t *testing.T) {
    // Leaves are already hashed payloads in our pipeline; simulate by sha256 of inputs
    leaves := [][]byte{
        sum([]byte("a")),
        sum([]byte("b")),
        sum([]byte("c")),
    }
    root := ComputeRoot(leaves)
    if len(root) == 0 {
        t.Fatal("empty root")
    }
    // recompute via proof for leaf 2
    proof, r2, err := ComputeProof(leaves, 2)
    if err != nil { t.Fatal(err) }
    if hex.EncodeToString(r2) != hex.EncodeToString(root) {
        t.Fatalf("root mismatch: %x vs %x", r2, root)
    }
    if !VerifyProof(leaves[2], proof, 2, root) {
        t.Fatal("proof verify failed")
    }
}

func TestOddLeafDuplication(t *testing.T) {
    // 1 leaf -> root equals leaf
    l := [][]byte{ sum([]byte("x")) }
    r := ComputeRoot(l)
    if hex.EncodeToString(r) != hex.EncodeToString(l[0]) {
        t.Fatal("single-leaf root mismatch")
    }
    // 3 leaves -> duplication occurs; check proof verifies for index 1
    leaves := [][]byte{ sum([]byte("1")), sum([]byte("2")), sum([]byte("3")) }
    root := ComputeRoot(leaves)
    pr, rr, err := ComputeProof(leaves, 1)
    if err != nil { t.Fatal(err) }
    if hex.EncodeToString(rr) != hex.EncodeToString(root) || !VerifyProof(leaves[1], pr, 1, root) {
        t.Fatal("odd-leaf proof failed")
    }
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

