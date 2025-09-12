package entropy

import (
    "errors"
    "math"

    cbor "github.com/fxamacker/cbor/v2"

    "pose/internal/cell"
    "pose/internal/mempool"
)

var errInvalid = errors.New("invalid data")

// ComputeCellEntropy computes a Shannon entropy score over only the IoT data
// section (payload[8]) of transactions from devices that belong to the given cell.
// If no applicable bytes are available, returns 0.
func ComputeCellEntropy(c *cell.Cell, entries []*mempool.Entry) (float64, int) {
    if c == nil || !c.Active || len(entries) == 0 {
        return 0, 0
    }
    ids := make(map[string]struct{}, len(c.Devices))
    for _, d := range c.Devices { ids[d.DeviceID] = struct{}{} }

    // Collect only payload[8] bytes for entries belonging to the cell's devices.
    var all []byte
    count := 0
    for _, e := range entries {
        if _, ok := ids[e.DevID]; !ok { continue }
        if dataPart, err := extractDataPart(e.Bytes); err == nil && len(dataPart) > 0 {
            all = append(all, dataPart...)
            count++
        }
    }
    if len(all) == 0 { return 0, 0 }
    return shannon(all), count
}

// shannon computes Shannon entropy (bits per byte) for the given bytes.
func shannon(b []byte) float64 {
    if len(b) == 0 { return 0 }
    var freq [256]int
    for _, v := range b { freq[int(v)]++ }
    n := float64(len(b))
    var h float64
    for i := 0; i < 256; i++ {
        if freq[i] == 0 { continue }
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

func dataFromArray(arr []interface{}) ([]byte, error) {
    if len(arr) != 4 { return nil, errInvalid }
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
        if err2 := cbor.Unmarshal(payload, &any); err2 != nil { return nil, err }
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
