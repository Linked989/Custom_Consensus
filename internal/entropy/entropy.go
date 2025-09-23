package entropy

import (
	"errors"
	"math"

	cbor "github.com/fxamacker/cbor/v2"

	"pose/internal/cell"
	"pose/internal/mempool"
)

var errInvalid = errors.New("invalid data")

// Stat represents an entropy result with the number of tx samples used.
type Stat struct {
	Entropy float64 `json:"entropy_bits_per_byte"`
	Samples int     `json:"tx_samples"`
}

// ComputeCellEntropy computes a Shannon entropy score over only the IoT data
// section (payload[8]) of transactions from devices that belong to the given cell.
// If no applicable bytes are available, returns 0.
func ComputeCellEntropy(c *cell.Cell, entries []*mempool.Entry) (float64, int) {
	if c == nil || !c.Active || len(entries) == 0 {
		return 0, 0
	}
	ids := make(map[string]struct{}, len(c.Devices))
	for _, d := range c.Devices {
		ids[d.DeviceID] = struct{}{}
	}

	// Collect only payload[8] bytes for entries belonging to the cell's devices.
	var all []byte
	count := 0
	for _, e := range entries {
		if _, ok := ids[e.DevID]; !ok {
			continue
		}
		if dataPart, err := extractDataPart(e.Bytes); err == nil && len(dataPart) > 0 {
			all = append(all, dataPart...)
			count++
		}
	}
	if len(all) == 0 {
		return 0, 0
	}
	return shannon(all), count
}

// ComputePerDeviceEntropy computes entropy per device (for devices in the cell)
// using only each device's IoT data sections.
func ComputePerDeviceEntropy(c *cell.Cell, entries []*mempool.Entry) map[string]Stat {
	out := make(map[string]Stat)
	if c == nil || !c.Active || len(entries) == 0 {
		return out
	}
	ids := make(map[string]struct{}, len(c.Devices))
	for _, d := range c.Devices {
		ids[d.DeviceID] = struct{}{}
	}

	byDev := make(map[string][]byte, len(c.Devices))
	cnt := make(map[string]int, len(c.Devices))
	for _, e := range entries {
		if _, ok := ids[e.DevID]; !ok {
			continue
		}
		if dataPart, err := extractDataPart(e.Bytes); err == nil && len(dataPart) > 0 {
			byDev[e.DevID] = append(byDev[e.DevID], dataPart...)
			cnt[e.DevID]++
		}
	}
	for dev, bytes := range byDev {
		out[dev] = Stat{Entropy: shannon(bytes), Samples: cnt[dev]}
	}
	return out
}

// shannon computes Shannon entropy (bits per byte) for the given bytes.
func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, v := range b {
		freq[int(v)]++
	}
	n := float64(len(b))
	var h float64
	for i := 0; i < 256; i++ {
		if freq[i] == 0 {
			continue
		}
		p := float64(freq[i]) / n
		h -= p * math.Log2(p)
	}
	return h
}

// extractDataPart pulls payload[8] (the IoT data section) from a COSE_Sign1 message
// and CBOR-encodes just that section to bytes.
func extractDataPart(b []byte) ([]byte, error) {
	var tag cbor.Tag
	if err := cbor.Unmarshal(b, &tag); err == nil {
		if tag.Number == 18 {
			if arr, ok := tag.Content.([]interface{}); ok {
				return dataFromArray(arr)
			}
		}
	}
	var arr []interface{}
	if err := cbor.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	return dataFromArray(arr)
}

// ExtractIoTDataSection decodes a COSE_Sign1 payload and extracts the IoT data
// section under key 8. Returns the CBOR-encoded value bytes and true on success.
// The returned bytes are canonical CBOR for deterministic downstream processing.
func ExtractIoTDataSection(b []byte) ([]byte, bool) {
	by, err := extractDataPart(b)
	if err != nil || len(by) == 0 {
		return nil, false
	}
	return by, true
}

func dataFromArray(arr []interface{}) ([]byte, error) {
	if len(arr) != 4 {
		return nil, errInvalid
	}
	var payload []byte
	switch v := arr[2].(type) {
	case []byte:
		payload = v
	case cbor.RawMessage:
		payload = []byte(v)
	default:
		return nil, errInvalid
	}
	// Decode payload into a map, extract key 8, and re-encode just that value
	var pl map[int]interface{}
	if err := cbor.Unmarshal(payload, &pl); err != nil {
		// payload might be an int-keyed map using uint keys; try generic map
		var any map[interface{}]interface{}
		if err2 := cbor.Unmarshal(payload, &any); err2 != nil {
			return nil, err
		}
		// lift key 8 if present
		if v, ok := any[uint64(8)]; ok {
			return cbor.Marshal(v)
		}
		if v, ok := any[int(8)]; ok {
			return cbor.Marshal(v)
		}
		return nil, errInvalid
	}
	if v, ok := pl[8]; ok {
		return cbor.Marshal(v)
	}
	return nil, errInvalid
}

// ExtractDevIDAndData extracts the device ID (payload[3][0]) and the IoT data section (payload[8])
// from a COSE_Sign1 transaction without verifying the signature. The data bytes returned are the
// CBOR encoding of the value under key 8. Returns ok=false on decode errors.
func ExtractDevIDAndData(b []byte) (string, []byte, bool) {
	// Unwrap CBOR Tag(18) if present
	var tag cbor.Tag
	if err := cbor.Unmarshal(b, &tag); err == nil && tag.Number == 18 {
		if arr, ok := tag.Content.([]interface{}); ok {
			return devAndDataFromArray(arr)
		}
	}
	var arr []interface{}
	if err := cbor.Unmarshal(b, &arr); err != nil {
		return "", nil, false
	}
	return devAndDataFromArray(arr)
}

func devAndDataFromArray(arr []interface{}) (string, []byte, bool) {
	if len(arr) != 4 {
		return "", nil, false
	}
	// payload is arr[2]
	var payload []byte
	switch v := arr[2].(type) {
	case []byte:
		payload = v
	case cbor.RawMessage:
		payload = []byte(v)
	default:
		return "", nil, false
	}
	var pl map[int]interface{}
	if err := cbor.Unmarshal(payload, &pl); err != nil {
		return "", nil, false
	}
	devMap, ok := asIntKeyed(pl[3])
	if !ok {
		return "", nil, false
	}
	devID, _ := devMap[0].(string)
	if devID == "" {
		return "", nil, false
	}
	if v, ok := pl[8]; ok {
		by, err := cbor.Marshal(v)
		if err != nil {
			return "", nil, false
		}
		return devID, by, true
	}
	return "", nil, false
}

func asIntKeyed(v interface{}) (map[int]interface{}, bool) {
	switch m := v.(type) {
	case map[int]interface{}:
		return m, true
	case map[int64]interface{}:
		out := make(map[int]interface{}, len(m))
		for k, val := range m {
			out[int(k)] = val
		}
		return out, true
	case map[uint64]interface{}:
		out := make(map[int]interface{}, len(m))
		for k, val := range m {
			out[int(k)] = val
		}
		return out, true
	case map[interface{}]interface{}:
		out := make(map[int]interface{}, len(m))
		for k, val := range m {
			switch kk := k.(type) {
			case int:
				out[kk] = val
			case int64:
				out[int(kk)] = val
			case uint64:
				out[int(kk)] = val
			default:
				return nil, false
			}
		}
		return out, true
	default:
		return nil, false
	}
}
