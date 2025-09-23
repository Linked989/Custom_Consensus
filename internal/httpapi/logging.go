package httpapi

// Log toggles for HTTP ingress
var (
	LogHTTPTx bool // POST /tx
	LogIoT    bool // /iot/register and related
)

func SetLogHTTPTx(v bool) { LogHTTPTx = v }
func SetLogIoT(v bool)    { LogIoT = v }
