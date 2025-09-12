package coseutil

import (
    "context"
    "crypto/ed25519"
    crand "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "time"

    cbor "github.com/fxamacker/cbor/v2"
    "github.com/libp2p/go-libp2p/core/host"
)

var (
    encMode cbor.EncMode
    decMode cbor.DecMode
)

func init() {
    em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
    dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
    encMode, decMode = em, dm
}

// Registry of kid->public key
var keyRegistry = struct {
    mu sync.RWMutex
    m  map[string]ed25519.PublicKey
}{m: make(map[string]ed25519.PublicKey)}

func RegistryRegister(kid []byte, pub ed25519.PublicKey) {
    keyRegistry.mu.Lock()
    keyRegistry.m[hex.EncodeToString(kid)] = pub
    keyRegistry.mu.Unlock()
}
func RegistryGet(kid []byte) (ed25519.PublicKey, bool) {
    keyRegistry.mu.RLock()
    pk, ok := keyRegistry.m[hex.EncodeToString(kid)]
    keyRegistry.mu.RUnlock()
    return pk, ok
}

// Replay window per device id
var devSeq = struct {
    mu sync.Mutex
    m  map[string]int64
}{m: make(map[string]int64)}

func UpdateLastSeq(devID string, seq int64) bool {
    devSeq.mu.Lock()
    last := devSeq.m[devID]
    if seq > last {
        devSeq.m[devID] = seq
        devSeq.mu.Unlock()
        return true
    }
    devSeq.mu.Unlock()
    return false
}

func KidFromPub(pub ed25519.PublicKey) []byte {
    sum := sha256.Sum256(pub)
    return sum[:8]
}

// ValidateCOSETx verifies COSE_Sign1(Ed25519) and returns txid/devID/seq.
func ValidateCOSETx(b []byte) (string, string, int64, error) {
    var tag cbor.Tag
    var arr []interface{}
    if err := decMode.Unmarshal(b, &tag); err == nil && tag.Number == 18 {
        var ok bool
        if arr, ok = tag.Content.([]interface{}); !ok {
            return "", "", 0, fmt.Errorf("cose: bad content")
        }
    } else {
        if err := decMode.Unmarshal(b, &arr); err != nil {
            return "", "", 0, fmt.Errorf("cose: decode: %w", err)
        }
    }
    if len(arr) != 4 { return "", "", 0, fmt.Errorf("cose: array len %d", len(arr)) }

    // protected header as bytes/raw or map
    prot, payload, sig, err := triadFromArray(arr)
    if err != nil { return "", "", 0, err }

    // parse protected map
    var ph map[int]interface{}
    if err := decMode.Unmarshal(prot, &ph); err != nil { return "", "", 0, fmt.Errorf("cose: protected map: %w", err) }
    if alg, ok := ph[1]; !ok || toInt64(alg) != -8 { return "", "", 0, fmt.Errorf("cose: alg != -8") }
    kidv, ok := ph[4]; if !ok { return "", "", 0, fmt.Errorf("cose: missing kid") }
    kid, ok := kidv.([]byte); if !ok { return "", "", 0, fmt.Errorf("cose: kid type") }

    // Sig_structure
    toSign, err := encMode.Marshal([]interface{}{"Signature1", prot, []byte{}, payload})
    if err != nil { return "", "", 0, fmt.Errorf("cose: sig-struct: %w", err) }

    pub, ok := RegistryGet(kid); if !ok { return "", "", 0, fmt.Errorf("registry: unknown kid") }
    if !ed25519.Verify(pub, toSign, sig) { return "", "", 0, fmt.Errorf("signature mismatch") }

    // payload types
    var pl map[int]interface{}
    if err := decMode.Unmarshal(payload, &pl); err != nil { return "", "", 0, fmt.Errorf("payload: decode: %w", err) }
    if _, ok := pl[0].(int64); !ok && !isUint(pl[0]) { return "", "", 0, fmt.Errorf("payload[0] version int") }
    if _, ok := pl[1].(string); !ok { return "", "", 0, fmt.Errorf("payload[1] network_id string") }
    if _, ok := pl[2].(string); !ok { return "", "", 0, fmt.Errorf("payload[2] tx_type string") }
    devMap, ok := asIntKeyedMap(pl[3]); if !ok { return "", "", 0, fmt.Errorf("payload[3] device map") }
    seq := toInt64(pl[4]); if seq <= 0 { return "", "", 0, fmt.Errorf("payload[4] seq > 0") }
    feeMap, ok := asIntKeyedMap(pl[6]); if !ok { return "", "", 0, fmt.Errorf("payload[6] fee map") }
    amt := toInt64(feeMap[0]); denom, _ := feeMap[1].(string); if amt < 1 || denom != "uCR" { return "", "", 0, fmt.Errorf("fee invalid") }
    if _, ok := asIntKeyedMap(pl[8]); !ok { return "", "", 0, fmt.Errorf("payload[8] map") }

    devID, _ := devMap[0].(string); if devID == "" { return "", "", 0, fmt.Errorf("device id missing") }
    txid := sha256.Sum256(payload)
    return hex.EncodeToString(txid[:]), devID, seq, nil
}

// ExtractKid returns the key id (kid) from a COSE_Sign1 message without verifying it.
func ExtractKid(b []byte) ([]byte, error) {
    var tag cbor.Tag
    var arr []interface{}
    if err := decMode.Unmarshal(b, &tag); err == nil && tag.Number == 18 {
        var ok bool
        if arr, ok = tag.Content.([]interface{}); !ok { return nil, fmt.Errorf("cose: bad content") }
    } else {
        if err := decMode.Unmarshal(b, &arr); err != nil { return nil, err }
    }
    if len(arr) != 4 { return nil, fmt.Errorf("cose: array len %d", len(arr)) }
    var prot []byte
    switch v := arr[0].(type) {
    case []byte:
        prot = v
    case cbor.RawMessage:
        prot = []byte(v)
    case map[int]interface{}, map[uint64]interface{}, map[int64]interface{}, map[interface{}]interface{}:
        b2, err := encMode.Marshal(v); if err != nil { return nil, err }
        prot = b2
    default:
        return nil, fmt.Errorf("cose: protected not bstr")
    }
    var ph map[int]interface{}
    if err := decMode.Unmarshal(prot, &ph); err != nil { return nil, err }
    kidv, ok := ph[4]; if !ok { return nil, fmt.Errorf("cose: missing kid") }
    kid, ok := kidv.([]byte); if !ok { return nil, fmt.Errorf("cose: kid type") }
    return kid, nil
}

// BuildDevCOSE creates a synthetic payload and wraps it into COSE_Sign1 tag(18).
func BuildDevCOSE(priv ed25519.PrivateKey, kid []byte, h host.Host, seq uint64) ([]byte, string, error) {
    did := "did:iot:DEV-" + shortPeer(h.ID().String())
    payload := map[int]interface{}{
        0: int64(1),
        1: "iotnet-main",
        2: "data",
        3: map[int]interface{}{0: did, 1: "1.0.0", 2: "ed25519:DEV"},
        4: int64(seq),
        5: time.Now().UTC(),
        6: map[int]interface{}{0: int64(25), 1: "uCR"},
        7: []interface{}{randBytes(7), randBytes(7)},
        8: map[int]interface{}{
            0: "urn:example:sensor:v1",
            1: map[string]interface{}{"temp_c": 21.5, "humidity": 0.45},
            2: map[string]interface{}{"gps": []interface{}{52.520008, 13.404954, 8.0}, "site": "plant-berlin-a"},
            3: randBytes(6),
        },
        9: map[int]interface{}{0: "urn:cap:write:sensors/thermo", 1: time.Now().UTC().Add(24 * time.Hour)},
    }
    payloadCBOR, err := encMode.Marshal(payload)
    if err != nil { return nil, "", err }
    txid := sha256.Sum256(payloadCBOR)
    ph := map[int]interface{}{1: int64(-8), 4: kid}
    prot, err := encMode.Marshal(ph)
    if err != nil { return nil, "", err }
    toSign, err := encMode.Marshal([]interface{}{"Signature1", prot, []byte{}, payloadCBOR})
    if err != nil { return nil, "", err }
    sig := ed25519.Sign(priv, toSign)
    arr := []interface{}{cbor.RawMessage(prot), map[int]interface{}{}, payloadCBOR, []byte(sig)}
    tagged := cbor.Tag{Number: 18, Content: arr}
    out, err := encMode.Marshal(tagged)
    if err != nil { return nil, "", err }
    return out, hex.EncodeToString(txid[:]), nil
}

// Helpers
func triadFromArray(arr []interface{}) ([]byte, []byte, []byte, error) {
    var prot, payload, sig []byte
    // protected
    switch v := arr[0].(type) {
    case []byte:
        prot = v
    case cbor.RawMessage:
        prot = []byte(v)
    case map[int]interface{}, map[uint64]interface{}, map[int64]interface{}, map[interface{}]interface{}:
        b, err := encMode.Marshal(v)
        if err != nil { return nil, nil, nil, err }
        prot = b
    default:
        return nil, nil, nil, fmt.Errorf("cose: protected not bstr")
    }
    // payload
    switch v := arr[2].(type) {
    case []byte:
        payload = v
    case cbor.RawMessage:
        payload = []byte(v)
    default:
        return nil, nil, nil, fmt.Errorf("cose: payload not bstr")
    }
    // signature
    switch v := arr[3].(type) {
    case []byte:
        sig = v
    case cbor.RawMessage:
        sig = []byte(v)
    default:
        return nil, nil, nil, fmt.Errorf("cose: signature not bstr")
    }
    return prot, payload, sig, nil
}

func asIntKeyedMap(v interface{}) (map[int64]interface{}, bool) {
    out := make(map[int64]interface{})
    switch m := v.(type) {
    case map[int]interface{}:
        for k, val := range m { out[int64(k)] = val }
        return out, true
    case map[int64]interface{}:
        for k, val := range m { out[k] = val }
        return out, true
    case map[uint64]interface{}:
        for k, val := range m { out[int64(k)] = val }
        return out, true
    case map[interface{}]interface{}:
        for k, val := range m {
            switch kk := k.(type) {
            case int: out[int64(kk)] = val
            case int64: out[kk] = val
            case uint64: out[int64(kk)] = val
            case uint: out[int64(kk)] = val
            default: return nil, false
            }
        }
        return out, true
    default:
        return nil, false
    }
}

func toInt64(v interface{}) int64 {
    switch t := v.(type) {
    case int64: return t
    case uint64: return int64(t)
    case int: return int64(t)
    case uint: return int64(t)
    case uint32: return int64(t)
    case int32: return int64(t)
    default: return 0
    }
}

func isUint(v interface{}) bool {
    switch v.(type) {
    case uint, uint64, uint32, uint16, uint8:
        return true
    default:
        return false
    }
}

func shortPeer(id string) string {
    if len(id) <= 8 { return id }
    return id[len(id)-8:]
}

func randBytes(n int) []byte {
    b := make([]byte, n)
    if _, err := crand.Read(b); err != nil {
        for i := range b { b[i] = byte(time.Now().UnixNano()>>uint(i%8)) }
    }
    return b
}

// Optional no-op to satisfy linters when importing context
var _ = context.Background
