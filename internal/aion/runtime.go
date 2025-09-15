package aion

import "sync/atomic"

// runtimeLeader is a process-local toggle to gate block production when wiring
// AION into the builder. This is dev/feature-flag only and not consensus.
var runtimeLeader atomic.Bool

// SetLeaderActive toggles whether the local node is currently allowed to produce blocks.
func SetLeaderActive(v bool) { runtimeLeader.Store(v) }

// IsLeaderActive reports if local node is currently allowed to produce blocks.
func IsLeaderActive() bool { return runtimeLeader.Load() }

