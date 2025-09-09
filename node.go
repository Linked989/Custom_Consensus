package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    crand "crypto/rand"
    "crypto/sha256"
    "encoding/asn1"
    "encoding/base64"
    "bufio"
    "context"
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
    "math/big"

    libp2p "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
    ma "github.com/multiformats/go-multiaddr"
    mrand "math/rand"
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
}

// localAddrs returns this host's dialable multiaddrs with /p2p/<peerID> suffix.
func localAddrs(h host.Host) []string {
    var out []string
    for _, a := range h.Addrs() {
        out = append(out, fmt.Sprintf("%s/p2p/%s", a, h.ID()))
    }
    return out
}

func sendHello(h host.Host, s network.Stream) error {
    pm := peerMsg{Type: "hello", From: h.ID().String(), Addrs: localAddrs(h)}
    b, _ := json.Marshal(pm)
    _, err := io.WriteString(s, string(b)+"\n")
    return err
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
    ps, err := pubsub.NewGossipSub(ctx, h)
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

    // Reader: handle inbound tx messages
    go func() {
        for {
            msg, err := txSub.Next(ctx)
            if err != nil {
                return
            }
            // Accept from anyone (including self) for simplicity; we'll dedup by txid.
            var tx BlockchainTx
            if err := json.Unmarshal(msg.Message.GetData(), &tx); err != nil {
                log.Printf("tx: bad json: %v", err)
                continue
            }
            if tx.TxID == "" {
                log.Printf("tx: missing txid")
                continue
            }
            if computeTXID(tx) != tx.TxID {
                log.Printf("tx: txid mismatch %s", tx.TxID)
                continue
            }
            if err := validateTxSignature(tx); err != nil {
                log.Printf("tx: invalid sig %s: %v", tx.TxID, err)
                continue
            }

            // Dedup
            seenTx.mu.Lock()
            if _, ok := seenTx.m[tx.TxID]; ok {
                seenTx.mu.Unlock()
                continue
            }
            seenTx.m[tx.TxID] = time.Now()
            seenTx.mu.Unlock()

            log.Printf("tx: accepted %s from %s", tx.TxID, msg.ReceivedFrom)
            // Optional forward to HTTP bridge (e.g., local block producer)
            if *bridgeURL != "" {
                go forwardTx(*bridgeURL, tx)
            }
        }
    }()

    // Optional: HTTP ingress -> publish to gossip
    if *httpIn != "" {
        mux := http.NewServeMux()
        mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
            if r.Method != http.MethodPost {
                http.Error(w, "POST only", http.StatusMethodNotAllowed)
                return
            }
            var tx BlockchainTx
            if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
                http.Error(w, "bad json", http.StatusBadRequest)
                return
            }
            if tx.TxID == "" || computeTXID(tx) != tx.TxID {
                http.Error(w, "bad txid", http.StatusBadRequest)
                return
            }
            if err := validateTxSignature(tx); err != nil {
                http.Error(w, "bad signature", http.StatusBadRequest)
                return
            }
            b, _ := json.Marshal(tx)
            if err := txTopic.Publish(ctx, b); err != nil {
                http.Error(w, "publish failed", http.StatusInternalServerError)
                return
            }
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

    // Dev synthetic tx generator
    if *devGen {
        var devPriv *ecdsa.PrivateKey
        var err error
        if *devReuseKey {
            devPriv, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
            if err != nil {
                log.Fatalf("dev: keygen: %v", err)
            }
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
                    var priv *ecdsa.PrivateKey
                    if *devReuseKey {
                        priv = devPriv
                    } else {
                        var err error
                        priv, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
                        if err != nil {
                            log.Printf("dev: keygen: %v", err)
                            continue
                        }
                    }
                    tx := generateDevTx(priv, h, atomic.AddUint64(&devNonce, 1))
                    b, _ := json.Marshal(tx)
                    if err := txTopic.Publish(ctx, b); err != nil {
                        log.Printf("dev: publish failed: %v", err)
                    } else {
                        log.Printf("dev: published tx %s", tx.TxID)
                    }
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

// -------- BlockchainTx + Validation (compatible with groups_iot.go) --------

type BlockchainTx struct {
    TxID       string          `json:"txid"`
    DeviceID   string          `json:"device_id"`
    PublicKey  string          `json:"public_key"`
    Timestamp  string          `json:"timestamp"`
    Nonce      int             `json:"nonce"`
    SensorType string          `json:"sensor_type"`
    SensorData json.RawMessage `json:"sensor_data"`
    Signature  string          `json:"signature"`
}

// computeTXID replicates the producer’s TXID logic.
func computeTXID(tx BlockchainTx) string {
    tmp := tx
    tmp.TxID = ""
    tmp.Signature = ""
    b, _ := json.Marshal(tmp)
    sum := sha256.Sum256(b)
    return fmt.Sprintf("%x", sum[:])
}

func validateTxSignature(tx BlockchainTx) error {
    // rebuild signing hash (txid present, signature cleared)
    tmp := tx
    tmp.Signature = ""
    payload, _ := json.Marshal(tmp)
    hash := sha256.Sum256(payload)

    // decode public key
    pubBytes, err := base64.StdEncoding.DecodeString(tx.PublicKey)
    if err != nil {
        return err
    }
    x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
    if x == nil {
        return fmt.Errorf("invalid public key")
    }
    pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

    // decode signature
    sigBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
    if err != nil {
        return err
    }
    var r, s *big.Int
    switch len(sigBytes) {
    case 64:
        r = new(big.Int).SetBytes(sigBytes[:32])
        s = new(big.Int).SetBytes(sigBytes[32:])
    default:
        var esig struct{ R, S *big.Int }
        if _, err := asn1.Unmarshal(sigBytes, &esig); err != nil {
            return fmt.Errorf("bad signature format")
        }
        r, s = esig.R, esig.S
    }
    if !ecdsa.Verify(pub, hash[:], r, s) {
        return fmt.Errorf("signature mismatch")
    }
    return nil
}

// generateDevTx creates a synthetic valid transaction signed with priv.
func generateDevTx(priv *ecdsa.PrivateKey, h host.Host, nonce uint64) BlockchainTx {
    // Build fields
    pubB := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
    tx := BlockchainTx{
        DeviceID:   fmt.Sprintf("dev-%s", h.ID()),
        PublicKey:  base64.StdEncoding.EncodeToString(pubB),
        Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
        Nonce:      int(nonce),
        SensorType: "vital_signs",
        SensorData: mustJSON(map[string]interface{}{
            "heart_rate":  60 + mrand.Intn(40),
            "spo2":        94 + mrand.Intn(5),
            "temperature": 36.5 + mrand.Float64(),
            "status":      "stable",
        }),
    }

    // Compute TXID
    tx.TxID = computeTXID(tx)

    // Sign
    tmp := tx
    tmp.Signature = ""
    payload, _ := json.Marshal(tmp)
    sum := sha256.Sum256(payload)
    r, s, _ := ecdsa.Sign(crand.Reader, priv, sum[:])
    tx.Signature = base64.StdEncoding.EncodeToString(padBig32(r, s))
    return tx
}

func padBig32(r, s *big.Int) []byte {
    rb := r.Bytes()
    sb := s.Bytes()
    if len(rb) < 32 {
        rb = append(make([]byte, 32-len(rb)), rb...)
    }
    if len(sb) < 32 {
        sb = append(make([]byte, 32-len(sb)), sb...)
    }
    out := make([]byte, 64)
    copy(out[:32], rb[:32])
    copy(out[32:], sb[:32])
    return out
}

func mustJSON(v interface{}) json.RawMessage {
    b, _ := json.Marshal(v)
    return b
}

func forwardTx(url string, tx BlockchainTx) {
    b, _ := json.Marshal(tx)
    req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(b)))
    if err != nil {
        log.Printf("bridge: build request: %v", err)
        return
    }
    req.Header.Set("Content-Type", "application/json")
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("bridge: send: %v", err)
        return
    }
    io.Copy(io.Discard, resp.Body)
    resp.Body.Close()
}
