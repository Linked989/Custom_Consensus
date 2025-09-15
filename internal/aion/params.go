package aion

import "time"

// Params holds AION timing and weighting parameters.
// All fields are immutable after construction to avoid consensus ambiguity.
type Params struct {
	// SlotDuration is the logical slot length. Not used in consensus math; only for scheduling/logging.
	SlotDuration time.Duration
	// EpochLength is the number of slots in an epoch.
	EpochLength uint64
	// LeadershipWindow is the number of epochs a selected leader serves.
	LeadershipWindow uint64
	// AlphaQ16 is the fixed-point (Q16.16) alpha used in entropy weighting.
	AlphaQ16 uint32
	// Genesis defines the reference start time for slot/epoch calculations in logs.
	Genesis time.Time
}

// DefaultParams returns the canonical AION parameters.
func DefaultParams() Params {
	return Params{
		SlotDuration:     500 * time.Millisecond, // 1.5 seconds
		EpochLength:      10,
		LeadershipWindow: 5,
		AlphaQ16:         0x00008000, // 0.5 in Q16.16 as a sane default; tunable via governance
		Genesis:          time.Now().UTC(),
	}
}
