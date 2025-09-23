package aion

import (
	"crypto/sha256"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
)

// ed25519VRF implements a verifiable function using Ed25519 signatures.
// y = SHA256(signature), proof = signature; verification via Ed25519.
// This is deterministic and publicly verifiable under the producer pubkey.
type ed25519VRF struct {
	priv crypto.PrivKey
	pub  crypto.PubKey
}

func newEd25519VRF(priv crypto.PrivKey) *ed25519VRF {
	return &ed25519VRF{priv: priv, pub: priv.GetPublic()}
}

func (v *ed25519VRF) Evaluate(input []byte) (y [32]byte, proof []byte, err error) {
	sig, err := v.priv.Sign(input)
	if err != nil {
		return y, nil, err
	}
	sum := sha256.Sum256(sig)
	return sum, sig, nil
}

func (v *ed25519VRF) Verify(input []byte, y [32]byte, proof []byte) bool {
	ok, err := v.pub.Verify(input, proof)
	if err != nil || !ok {
		return false
	}
	sum := sha256.Sum256(proof)
	return sum == y
}
