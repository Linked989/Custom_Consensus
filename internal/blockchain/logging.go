package blockchain

// LogBlocks toggles block propose/accept info logs.
var LogBlocks bool

func SetLogBlocks(v bool) { LogBlocks = v }
