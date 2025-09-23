package aion

import (
	"crypto/sha256"
	"encoding/binary"
)

// CommitSeed computes commit_e = Hash(seed_e) using SHA-256.
func CommitSeed(seed []byte) [32]byte {
	sum := sha256.Sum256(seed)
	return sum
}

// VerifyReveal checks Hash(seed_e) == commit_e.
func VerifyReveal(commit [32]byte, seed []byte) bool {
	sum := sha256.Sum256(seed)
	return sum == commit
}

// Challenge derives the epoch challenge from the last finalized block hash and epoch number.
// challenge = SHA256(last_finalized_hash || be64(epoch)).
func Challenge(lastFinalizedHash []byte, epoch uint64) [32]byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	h := sha256.New()
	// Deterministic concatenation
	_, _ = h.Write(lastFinalizedHash)
	_, _ = h.Write(buf[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
