package merkle

import (
	"crypto/sha256"
	"fmt"
)

// ComputeRoot returns the Merkle root of the provided leaves using
// SHA-256 over concatenated pairs at each level. If the number of nodes
// at a level is odd, the last node is duplicated (Bitcoin-style).
// For a single leaf, the root is that leaf. For zero leaves, returns nil.
func ComputeRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	// Copy to avoid mutating caller slices
	level := make([][]byte, len(leaves))
	for i := range leaves {
		b := make([]byte, len(leaves[i]))
		copy(b, leaves[i])
		level[i] = b
	}
	for len(level) > 1 {
		// If odd, duplicate last
		if len(level)%2 == 1 {
			last := make([]byte, len(level[len(level)-1]))
			copy(last, level[len(level)-1])
			level = append(level, last)
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.Sum256(append(level[i], level[i+1]...))
			hb := make([]byte, len(h))
			copy(hb, h[:])
			next = append(next, hb)
		}
		level = next
	}
	out := make([]byte, len(level[0]))
	copy(out, level[0])
	return out
}

// ComputeProof returns the Merkle proof (list of sibling hashes) for the leaf at index.
// The root is computed with the same rules as ComputeRoot (duplicate last for odd levels).
// The proof is ordered from leaf level up to the root.
func ComputeProof(leaves [][]byte, index int) ([][]byte, []byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, nil, ErrIndexOutOfRange
	}
	// Copy
	level := make([][]byte, len(leaves))
	for i := range leaves {
		b := make([]byte, len(leaves[i]))
		copy(b, leaves[i])
		level[i] = b
	}
	idx := index
	proof := make([][]byte, 0, 32)
	for len(level) > 1 {
		// If odd, duplicate last
		if len(level)%2 == 1 {
			last := make([]byte, len(level[len(level)-1]))
			copy(last, level[len(level)-1])
			level = append(level, last)
			// duplication does not change idx
		}
		// collect sibling
		siblingIdx := idx ^ 1
		sib := make([]byte, len(level[siblingIdx]))
		copy(sib, level[siblingIdx])
		proof = append(proof, sib)
		// compute parent level
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.Sum256(append(level[i], level[i+1]...))
			hb := make([]byte, len(h))
			copy(hb, h[:])
			next = append(next, hb)
		}
		level = next
		idx = idx / 2
	}
	root := make([]byte, len(level[0]))
	copy(root, level[0])
	return proof, root, nil
}

// VerifyProof recomputes the root from a leaf and its proof (ordered from leaf level up)
// using the same duplicate-last rule and returns whether it matches the expected root.
func VerifyProof(leaf []byte, proof [][]byte, index int, expectedRoot []byte) bool {
	hash := make([]byte, len(leaf))
	copy(hash, leaf)
	idx := index
	for _, sib := range proof {
		var combined []byte
		if idx%2 == 0 {
			combined = append(hash, sib...)
		} else {
			combined = append(sib, hash...)
		}
		h := sha256.Sum256(combined)
		hash = h[:]
		idx = idx / 2
	}
	if len(hash) != len(expectedRoot) {
		return false
	}
	for i := range hash {
		if hash[i] != expectedRoot[i] {
			return false
		}
	}
	return true
}

// Errors
var ErrIndexOutOfRange = fmt.Errorf("merkle: index out of range")
