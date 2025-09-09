package main

import (
    "bytes"
    "bufio"
    "context"
    crand "crypto/rand"
    "crypto/sha256"
    "crypto/ed25519"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "sync"
    "sync/atomic"
    "time"
    mrand "math/rand"

    cbor "github.com/fxamacker/cbor/v2"
    libp2p "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    pb "github.com/libp2p/go-libp2p-pubsub/pb"
    mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
    ma "github.com/multiformats/go-multiaddr"
)

// protocolID identifies our very simple stream type.
const protocolID = "/pose/simple/1.0.0"

// mdnsServiceTag is used to discover peers on the local network.
const mdnsServiceTag = "pose-simple-mdns"

// default pubsub heartbeat topic
const heartbeatTopic = "pose/heartbeat/1.0.0"
// tx gossip topic
const txTopicDefault = "pose/tx/1.0.0"

// memberSet tracks peers seen via heartbeat, expiring them after a TTL.
type memberSet struct {
    mu   sync.Mutex
    last map[string]time.Time
    ttl  time.Duration
}

func newMemberSet(ttl time.Duration) *memberSet {
    return &memberSet{last: make(map[string]time.Time), ttl: ttl}
}

func (m *memberSet) touch(id string) {
    m.mu.Lock()
    m.last[id] = time.Now()
    m.mu.Unlock()
}

func (m *memberSet) countAndSweep() int {
    now := time.Now()
    m.mu.Lock()
    for id, t := range m.last {
        if now.Sub(t) > m.ttl {
            delete(m.last, id)
        }
    }
    n := len(m.last)
    m.mu.Unlock()
    return n
}

// mdnsNotifee reacts to newly discovered peers.
type mdnsNotifee struct {
    h    host.Host
    mu   sync.Mutex
    seen map[peer.ID]struct{}
}

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
    if pi.ID == m.h.ID() {
        return
    }

    m.mu.Lock()
    if _, ok := m.seen[pi.ID]; ok {
        m.mu.Unlock()
        return
    }
    m.seen[pi.ID] = struct{}{}
    m.mu.Unlock()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := m.h.Connect(ctx, pi); err != nil {
        log.Printf("mdns: connect to %s failed: %v", pi.ID, err)
        return
    }
    log.Printf("mdns: connected to %s", pi.ID)

    // Open a stream and send a hello
    s, err := m.h.NewStream(ctx, pi.ID, protocolID)
    if err != nil {
        log.Printf("mdns: open stream to %s failed: %v", pi.ID, err)
        return
    }
    defer s.Close()

    // Send our hello + addresses (for peer gossip)
    _ = sendHello(m.h, s)
    reply, _ := bufio.NewReader(s).ReadString('\n')
    if reply != "" {
        log.Printf("mdns: reply from %s: %s", pi.ID, strings.TrimSpace(reply))
    }
}

// handleStream handles inbound streams for our protocol.
func handleStream(h host.Host, s network.Stream) {
    defer s.Close()
    r := bufio.NewReader(s)
    line, _ := r.ReadString('\n')

    // Try to parse as JSON hello; fallback to raw log.
    var pm peerMsg
    if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &pm); err == nil && pm.Type == "hello" {
        log.Printf("recv: hello from=%s peers=%d", s.Conn().RemotePeer(), len(pm.Addrs))
        // Optional: register announced dev key
        if pm.Kid != "" && pm.Pub != "" {
            if kidBytes, err1 := hex.DecodeString(pm.Kid); err1 == nil {
                if pubBytes, err2 := hex.DecodeString(pm.Pub); err2 == nil && len(pubBytes) == ed25519.PublicKeySize {
                    registryRegister(kidBytes, ed25519.PublicKey(pubBytes))
                }
            }
        }
        // Try connecting to provided peers.
        connectToAddrs(h, pm.Addrs)
    } else {
        log.Printf("recv: from=%s msg=%q", s.Conn().RemotePeer(), strings.TrimSpace(line))
    }
    _, _ = io.WriteString(s, "ack\n")
}

// peerMsg is a minimal JSON message to gossip our node addresses.
type peerMsg struct {
    Type  string   `json:"type"`
    From  string   `json:"from"`
    Addrs []string `json:"addrs"`
    Kid   string   `json:"kid,omitempty"` // hex-encoded
    Pub   string   `json:"pub,omitempty"` // hex-encoded ed25519 pubkey
}

// localAddrs returns this host's dialable multiaddrs with /p2p/<peerID> suffix.
func localAddrs(h host.Host) []string {
    var out []string
    for _, a := range h.Addrs() {
        out = append(out, fmt.Sprintf("%s/p2p/%s", a, h.ID()))
    }
    return out
}

var devAnnounce struct { kid []byte; pub ed25519.PublicKey }

func sendHello(h host.Host, s network.Stream) error {
    pm := peerMsg{Type: "hello", From: h.ID().String(), Addrs: localAddrs(h)}
    if len(devAnnounce.kid) > 0 && len(devAnnounce.pub) == ed25519.PublicKeySize {
        pm.Kid = hex.EncodeToString(devAnnounce.kid)
        pm.Pub = hex.EncodeToString(devAnnounce.pub)
    }
    b, _ := json.Marshal(pm)
    _, err := io.WriteString(s, string(b)+"\n")
    return err
}

func sendHelloToAllPeers(ctx context.Context, h host.Host) {
    for _, pid := range h.Network().Peers() {
        s, err := h.NewStream(ctx, pid, protocolID)
        if err != nil { continue }
        _ = sendHello(h, s)
        _ = s.Close()
    }
}

// connectToAddrs attempts to connect to peers described by p2p multiaddrs.
func connectToAddrs(h host.Host, addrs []string) {
    for _, as := range addrs {
        maddr, err := ma.NewMultiaddr(as)
        if err != nil {
            continue
        }
        ai, err := peer.AddrInfoFromP2pAddr(maddr)
        if err != nil || ai.ID == h.ID() {
            continue
        }
        // Don't re-dial if already connected.
        if len(h.Network().ConnsToPeer(ai.ID)) > 0 {
            continue
        }
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        err = h.Connect(ctx, *ai)
        cancel()
        if err == nil {
            log.Printf("gossip: connected to %s", ai.ID)
        }
    }
}

func main() {
    // Flags for scaling to many nodes.
    listenPort := flag.Int("port", 0, "TCP listen port (0=random)")
    enableMDNS := flag.Bool("mdns", true, "enable mDNS discovery")
    mdnsTag := flag.String("mdns-tag", mdnsServiceTag, "mDNS service tag")
    hbTopic := flag.String("topic", heartbeatTopic, "pubsub heartbeat topic")
    hbInterval := flag.Duration("hb", 2*time.Second, "heartbeat publish interval")
    statsInterval := flag.Duration("stats", 5*time.Second, "stats log interval (0=off)")
    memberTTL := flag.Duration("ttl", 10*time.Second, "membership entry TTL")
    // Gossip for blockchain data
    txTopicName := flag.String("tx-topic", txTopicDefault, "pubsub topic for transactions")
    bridgeURL := flag.String("bridge-url", "", "optional HTTP URL to forward validated txs (e.g., http://localhost:1337/tx)")
    httpIn := flag.String("http", "", "optional HTTP listen addr to accept POST /tx and publish to gossip (e.g., :14000)")
    // Dev: synthetic tx generator
    devGen := flag.Bool("dev-gen-tx", false, "enable built-in synthetic tx generator")
    devInterval := flag.Duration("dev-interval", 500*time.Millisecond, "interval between dev tx publishes")
    devReuseKey := flag.Bool("dev-reuse-key", true, "reuse a single dev private key (device) per node")
    var bootstraps multiFlag
    flag.Var(&bootstraps, "bootstrap", "bootstrap peer multiaddr (repeatable)")
    flag.Parse()

    // Root context for services
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Create a node listening on a random TCP port.
    listen := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *listenPort)
    if *listenPort == 0 {
        listen = "/ip4/0.0.0.0/tcp/0"
    }
    h, err := libp2p.New(libp2p.ListenAddrStrings(listen))
    if err != nil {
        log.Fatalf("create host: %v", err)
    }
    defer func() { _ = h.Close() }()

    // Log listening addresses.
    log.Printf("Node ID: %s", h.ID())
    for _, a := range h.Addrs() {
        log.Printf("Listen: %s/p2p/%s", a, h.ID())
    }

    // Register protocol handler.
    h.SetStreamHandler(protocolID, func(s network.Stream) { handleStream(h, s) })

    // mDNS discovery (optional)
    if *enableMDNS {
        n := &mdnsNotifee{h: h, seen: make(map[peer.ID]struct{})}
        svc := mdns.NewMdnsService(h, *mdnsTag, n)
        if err := svc.Start(); err != nil {
            log.Fatalf("mdns start: %v", err)
        }
        defer svc.Close()
    }

    // Bootstrap dials (optional)
    if len(bootstraps) > 0 {
        var addrs []string
        for _, b := range bootstraps {
            addrs = append(addrs, b)
        }
        connectToAddrs(h, addrs)
    }

    // ----- PubSub heartbeat -----
    // GossipSub with message-id based on message bytes (COSE), reducing duplicate forwarding
    ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithMessageIdFn(func(m *pb.Message) string {
        sum := sha256.Sum256(m.GetData())
        return hex.EncodeToString(sum[:])
    }))
    if err != nil {
        log.Fatalf("pubsub init: %v", err)
    }
    topic, err := ps.Join(*hbTopic)
    if err != nil {
        log.Fatalf("pubsub join(%s): %v", *hbTopic, err)
    }
    sub, err := topic.Subscribe()
    if err != nil {
        log.Fatalf("pubsub subscribe: %v", err)
    }

    // Membership tracker
    members := newMemberSet(*memberTTL)
    members.touch(h.ID().String()) // include self

    // Reader: print heartbeats from others and refresh membership
    go func() {
        for {
            msg, err := sub.Next(ctx)
            if err != nil {
                return
            }
            if msg.ReceivedFrom == h.ID() {
                continue // skip self
            }
            payload := string(msg.Message.GetData())
            log.Printf("pubsub: from=%s msg=%s", msg.ReceivedFrom, strings.TrimSpace(payload))
            members.touch(msg.ReceivedFrom.String())
        }
    }()

    // Writer: periodic heartbeat
    go func() {
        t := time.NewTicker(*hbInterval)
        defer t.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-t.C:
                payload := fmt.Sprintf("heartbeat %s %s", h.ID(), time.Now().UTC().Format(time.RFC3339Nano))
                _ = topic.Publish(ctx, []byte(payload))
                // refresh our own membership timestamp
                members.touch(h.ID().String())
            }
        }
    }()

    // ----- Transaction gossip -----
    txTopic, err := ps.Join(*txTopicName)
    if err != nil {
        log.Fatalf("join tx topic: %v", err)
    }
    txSub, err := txTopic.Subscribe()
    if err != nil {
        log.Fatalf("subscribe tx: %v", err)
    }

    // Seen set for txids (basic dedup/metrics)
    seenTx := struct {
        mu sync.Mutex
        m  map[string]time.Time
    }{m: make(map[string]time.Time)}

    // Reader: handle inbound tx messages (COSE_Sign1 Ed25519)
    go func() {
        for {
            msg, err := txSub.Next(ctx)
            if err != nil {
                return
            }
            // Validate COSE Sign1 + basic payload checks and replay
            txid, devID, seq, err := validateCOSETx(msg.Message.GetData())
            if err != nil {
                log.Printf("tx: invalid: %v", err)
                continue
            }

            // Replay protection: seq must increase
            if !updateLastSeq(devID, seq) {
                // not strictly invalid, but ignore as replay
                continue
            }

            // Dedup by txid
            seenTx.mu.Lock()
            if _, ok := seenTx.m[txid]; ok {
                seenTx.mu.Unlock()
                continue
            }
            seenTx.m[txid] = time.Now()
            seenTx.mu.Unlock()

            log.Printf("tx: accepted txid=%s dev=%s seq=%d from %s", txid, devID, seq, msg.ReceivedFrom)
            // Optional forward to HTTP bridge (e.g., local block producer)
            if *bridgeURL != "" {
                go forwardCOSE(*bridgeURL, msg.Message.GetData())
            }
        }
    }()

    // Optional: HTTP ingress -> validate -> publish to gossip
    if *httpIn != "" {
        mux := http.NewServeMux()
        mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
            if r.Method != http.MethodPost {
                http.Error(w, "POST only", http.StatusMethodNotAllowed)
                return
            }
            defer r.Body.Close()
            body, err := io.ReadAll(r.Body)
            if err != nil {
                http.Error(w, "read error", http.StatusBadRequest)
                return
            }
            // Validate COSE tx before gossiping
            txid, devID, seq, err := validateCOSETx(body)
            if err != nil {
                http.Error(w, "invalid tx", http.StatusBadRequest)
                return
            }
            // Update replay window for HTTP-ingested txs
            if !updateLastSeq(devID, seq) {
                http.Error(w, "replay", http.StatusBadRequest)
                return
            }
            if err := txTopic.Publish(ctx, body); err != nil {
                http.Error(w, "publish failed", http.StatusInternalServerError)
                return
            }
            log.Printf("http: accepted txid=%s dev=%s seq=%d", txid, devID, seq)
            w.WriteHeader(http.StatusAccepted)
        })
        srv := &http.Server{Addr: *httpIn, Handler: mux}
        go func() {
            log.Printf("HTTP tx ingress listening on %s/tx", *httpIn)
            if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                log.Printf("http ingress error: %v", err)
            }
        }()
        defer srv.Shutdown(ctx)
    }

    // Dev synthetic tx generator (COSE Sign1 Ed25519)
    if *devGen {
        var devPriv ed25519.PrivateKey
        var devPub ed25519.PublicKey
        var err error
        if *devReuseKey {
            devPub, devPriv, err = ed25519.GenerateKey(crand.Reader)
            if err != nil { log.Fatalf("dev: keygen: %v", err) }
            devAnnounce.kid = kidFromPub(devPub)
            devAnnounce.pub = devPub
            registryRegister(devAnnounce.kid, devPub)
            // Proactively send hello with our dev key to current peers
            go sendHelloToAllPeers(ctx, h)
        }
        var devNonce uint64
        go func() {
            t := time.NewTicker(*devInterval)
            defer t.Stop()
            for {
                select {
                case <-ctx.Done():
                    return
                case <-t.C:
                    var pvt ed25519.PrivateKey
                    var pub ed25519.PublicKey
                    if *devReuseKey {
                        pvt, pub = devPriv, devPub
                    } else {
                        var err error
                        pub, pvt, err = ed25519.GenerateKey(crand.Reader)
                        if err != nil { log.Printf("dev: keygen: %v", err); continue }
                    }
                    // kid = first 8 bytes of sha256(pub)
                    kid := kidFromPub(pub)
                    // ensure registry has this device key
                    registryRegister(kid, pub)
                    // build payload and COSE_Sign1
                    seq := atomic.AddUint64(&devNonce, 1)
                    coseBytes, txid, err := buildDevCOSE(pvt, kid, h, seq)
                    if err != nil { log.Printf("dev: build: %v", err); continue }
                    if err := txTopic.Publish(ctx, coseBytes); err != nil { log.Printf("dev: publish failed: %v", err) } else { log.Printf("dev: published tx %s", txid) }
                }
            }
        }()
    }

    // Stats logger: all_nodes and connected_nodes_counter
    if statsInterval != nil && *statsInterval > 0 {
        go func() {
            t := time.NewTicker(*statsInterval)
            defer t.Stop()
            for {
                select {
                case <-ctx.Done():
                    return
                case <-t.C:
                    all := members.countAndSweep()
                    connected := len(h.Network().Peers())
                    log.Printf("stats: all_nodes=%d connected_nodes_counter=%d", all, connected)
                }
            }
        }()
    }

    // Wait for Ctrl+C.
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt)
    <-sig
    log.Println("Shutting down...")
}

// multiFlag allows repeating -bootstrap flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
    *m = append(*m, v)
    return nil
}

// -------- COSE Sign1 Ed25519 Utilities --------

var (
    encMode cbor.EncMode
    decMode cbor.DecMode
)

func init() {
    em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
    dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
    encMode, decMode = em, dm
}

// in-memory key registry: kid (hex) -> ed25519 public key
var keyRegistry = struct {
    mu sync.RWMutex
    m  map[string]ed25519.PublicKey
}{m: make(map[string]ed25519.PublicKey)}

func registryRegister(kid []byte, pub ed25519.PublicKey) {
    keyRegistry.mu.Lock()
    keyRegistry.m[hex.EncodeToString(kid)] = pub
    keyRegistry.mu.Unlock()
}

func registryGet(kid []byte) (ed25519.PublicKey, bool) {
    keyRegistry.mu.RLock()
    pk, ok := keyRegistry.m[hex.EncodeToString(kid)]
    keyRegistry.mu.RUnlock()
    return pk, ok
}

// last seen sequence per device id
var devSeq = struct {
    mu sync.Mutex
    m  map[string]int64
}{m: make(map[string]int64)}

func updateLastSeq(devID string, seq int64) bool {
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

func kidFromPub(pub ed25519.PublicKey) []byte {
    sum := sha256.Sum256(pub)
    return sum[:8]
}

// validateCOSETx parses a COSE_Sign1 (tag 18) Ed25519 message, verifies signature,
// validates the CBOR payload schema and replay, and returns txid/devID/seq.
func validateCOSETx(b []byte) (string, string, int64, error) {
    // Decode COSE_Sign1 with or without tag 18
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
    if len(arr) != 4 {
        return "", "", 0, fmt.Errorf("cose: array len %d", len(arr))
    }
    // protected header can arrive as []byte or cbor.RawMessage, sometimes even a map (non‑strict encoders)
    var prot []byte
    switch v := arr[0].(type) {
    case []byte:
        prot = v
    case cbor.RawMessage:
        prot = []byte(v)
    case map[int]interface{}:
        // tolerate map by re-encoding deterministically
        b, err := encMode.Marshal(v)
        if err != nil { return "", "", 0, fmt.Errorf("cose: protected marshal: %w", err) }
        prot = b
    default:
        return "", "", 0, fmt.Errorf("cose: protected not bstr")
    }
    // unprotected := arr[1] // ignored
    var payload []byte
    switch v := arr[2].(type) {
    case []byte:
        payload = v
    case cbor.RawMessage:
        payload = []byte(v)
    default:
        return "", "", 0, fmt.Errorf("cose: payload not bstr")
    }
    var sig []byte
    switch v := arr[3].(type) {
    case []byte:
        sig = v
    case cbor.RawMessage:
        sig = []byte(v)
    default:
        return "", "", 0, fmt.Errorf("cose: signature not bstr")
    }

    // Parse protected header
    var ph map[int]interface{}
    if err := decMode.Unmarshal(prot, &ph); err != nil {
        return "", "", 0, fmt.Errorf("cose: protected map: %w", err)
    }
    // alg (1) must be -8 (EdDSA)
    if alg, ok := ph[1]; !ok || toInt64(alg) != -8 {
        return "", "", 0, fmt.Errorf("cose: alg != -8")
    }
    // kid (4) must be bstr
    kidv, ok := ph[4]
    if !ok { return "", "", 0, fmt.Errorf("cose: missing kid") }
    kid, ok := kidv.([]byte)
    if !ok { return "", "", 0, fmt.Errorf("cose: kid type") }

    // signature base string: Sig_structure
    sigStruct := []interface{}{"Signature1", prot, []byte{}, payload}
    toSign, err := encMode.Marshal(sigStruct)
    if err != nil { return "", "", 0, fmt.Errorf("cose: sig-struct: %w", err) }

    // Verify signature
    pub, ok := registryGet(kid)
    if !ok { return "", "", 0, fmt.Errorf("registry: unknown kid %s", hex.EncodeToString(kid)) }
    if !ed25519.Verify(pub, toSign, sig) {
        return "", "", 0, fmt.Errorf("signature mismatch")
    }

    // Decode payload (canonical CBOR bytes) and validate minimal schema
    var pl map[int]interface{}
    if err := decMode.Unmarshal(payload, &pl); err != nil {
        return "", "", 0, fmt.Errorf("payload: decode: %w", err)
    }
    // types
    if _, ok := pl[0].(int64); !ok && !isUint(pl[0]) { return "", "", 0, fmt.Errorf("payload[0] version int") }
    if _, ok := pl[1].(string); !ok { return "", "", 0, fmt.Errorf("payload[1] network_id string") }
    if _, ok := pl[2].(string); !ok { return "", "", 0, fmt.Errorf("payload[2] tx_type string") }
    devMap, ok := pl[3].(map[int]interface{})
    if !ok { return "", "", 0, fmt.Errorf("payload[3] device map") }
    seq := toInt64(pl[4])
    if seq <= 0 { return "", "", 0, fmt.Errorf("payload[4] seq > 0") }
    // fee
    fee, ok := pl[6].(map[int]interface{})
    if !ok { return "", "", 0, fmt.Errorf("payload[6] fee map") }
    amt := toInt64(fee[0])
    denom, _ := fee[1].(string)
    if amt < 1 || denom != "uCR" { return "", "", 0, fmt.Errorf("fee invalid") }
    if _, ok := pl[8].(map[int]interface{}); !ok { return "", "", 0, fmt.Errorf("payload[8] map") }

    // device id
    devID, _ := devMap[0].(string)
    if devID == "" { return "", "", 0, fmt.Errorf("device id missing") }

    // txid is hash of payload canonical bytes
    txid := sha256.Sum256(payload)
    return hex.EncodeToString(txid[:]), devID, seq, nil
}

func toInt64(v interface{}) int64 {
    switch t := v.(type) {
    case int64:
        return t
    case uint64:
        if t > ^uint64(0)/2 { return int64(^uint64(0)/2) }
        return int64(t)
    case int:
        return int64(t)
    case uint:
        return int64(t)
    case uint32:
        return int64(t)
    case int32:
        return int64(t)
    default:
        return 0
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

// buildDevCOSE creates a sample payload and wraps it into a COSE_Sign1 (tag 18) with Ed25519.
func buildDevCOSE(priv ed25519.PrivateKey, kid []byte, h host.Host, seq uint64) ([]byte, string, error) {
    did := fmt.Sprintf("did:iot:DEV-%s", shortPeer(h.ID().String()))
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
            1: map[string]interface{}{"temp_c": 21.5 + mrand.Float64(), "humidity": 0.4 + 0.1*mrand.Float64()},
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

func randBytes(n int) []byte {
    b := make([]byte, n)
    if _, err := crand.Read(b); err != nil {
        for i := range b { b[i] = byte(mrand.Intn(256)) }
    }
    return b
}

func shortPeer(id string) string {
    if len(id) <= 8 { return id }
    return id[len(id)-8:]
}

func forwardCOSE(url string, cose []byte) {
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(cose))
    if err != nil { log.Printf("bridge: build request: %v", err); return }
    req.Header.Set("Content-Type", "application/cbor")
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
    if err != nil { log.Printf("bridge: send: %v", err); return }
    io.Copy(io.Discard, resp.Body)
    resp.Body.Close()
}
