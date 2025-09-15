package aion

// VRF abstracts a verifiable random function used to bind seed and epoch challenge.
// Implementations must be deterministic and constant-time where applicable.
// This package does not ship a concrete VRF to avoid embedding crypto choices.
// Nodes must inject an implementation that is consistent network-wide.
type VRF interface {
    // Evaluate returns y and a proof for input, using the node's secret material.
    Evaluate(input []byte) (y [32]byte, proof []byte, err error)
    // Verify checks that (y, proof) is a valid output for input under the node's public key.
    Verify(input []byte, y [32]byte, proof []byte) bool
}

