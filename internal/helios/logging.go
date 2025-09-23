package helios

// Log flags for HELIOS layers
var (
	LogL1 bool
	LogL2 bool
	LogL3 bool
)

func SetLogL1(v bool) { LogL1 = v }
func SetLogL2(v bool) { LogL2 = v }
func SetLogL3(v bool) { LogL3 = v }
