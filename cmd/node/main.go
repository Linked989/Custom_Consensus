package main

import (
    "context"
    crand "crypto/rand"
    "encoding/hex"
    "flag"
    "fmt"
    "log"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "os"
    "os/signal"
    "strings"
    "time"

    "pose/internal/blockchain"
    "pose/internal/dev"
    "pose/internal/gossip"
    "pose/internal/httpapi"
    "pose/internal/p2p"
)

const mdnsServiceTag = "pose-simple-mdns"
const heartbeatTopic = "pose/heartbeat/1.0.0"
const txTopicDefault = "pose/tx/1.0.0"

func main() {
    // Flags
    listenPort := flag.Int("port", 0, "TCP listen port (0=random)")
    enableMDNS := flag.Bool("mdns", true, "enable mDNS discovery")
    mdnsTag := flag.String("mdns-tag", mdnsServiceTag, "mDNS service tag")
    hbTopic := flag.String("topic", heartbeatTopic, "pubsub heartbeat topic")
    hbInterval := flag.Duration("hb", 2*time.Second, "heartbeat publish interval")
    statsInterval := flag.Duration("stats", 5*time.Second, "stats log interval (0=off)")
    memberTTL := flag.Duration("ttl", 10*time.Second, "membership entry TTL")
    // Gossip
    txTopicName := flag.String("tx-topic", txTopicDefault, "pubsub topic for transactions")
    blockTopicName := flag.String("block-topic", "pose/block/1.0.0", "pubsub topic for blocks")
    produceBlocks := flag.Bool("produce-blocks", false, "enable local block production")
    blockInterval := flag.Duration("block-interval", 2*time.Second, "block production interval")
    blockMax := flag.Int("block-max", 100, "max txs per block")
    bridgeURL := flag.String("bridge-url", "", "optional HTTP URL to forward validated txs (e.g., http://localhost:1337/tx)")
    httpIn := flag.String("http", "", "optional HTTP listen addr to accept POST /tx and publish to gossip (e.g., :14000)")
    // Dev generator
    devGen := flag.Bool("dev-gen-tx", false, "enable built-in synthetic tx generator")
    devInterval := flag.Duration("dev-interval", 500*time.Millisecond, "interval between dev tx publishes")
    devReuseKey := flag.Bool("dev-reuse-key", true, "reuse a single dev private key (device) per node")
    // LAN/private network
    bindIP := flag.String("bind", "", "IPv4 to bind (default all interfaces, e.g., 192.168.0.10)")
    swarmKeyPath := flag.String("pnet", "", "path to swarm.key for libp2p private network")
    genSwarmKey := flag.String("gen-swarm-key", "", "generate a new swarm.key at the given path and exit")
    var bootstraps multiFlag
    flag.Var(&bootstraps, "bootstrap", "bootstrap peer multiaddr (repeatable)")
    flag.Parse()

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    if *genSwarmKey != "" {
        if err := generateSwarmKey(*genSwarmKey); err != nil { log.Fatalf("gen-swarm-key: %v", err) }
        log.Printf("swarm.key written to %s", *genSwarmKey)
        return
    }

    ip := "0.0.0.0"
    if *bindIP != "" { ip = *bindIP }
    listen := fmt.Sprintf("/ip4/%s/tcp/%d", ip, *listenPort)
    if *listenPort == 0 { listen = fmt.Sprintf("/ip4/%s/tcp/0", ip) }

    var psk []byte
    if *swarmKeyPath != "" {
        var err error
        psk, err = loadSwarmKey(*swarmKeyPath)
        if err != nil { log.Fatalf("pnet: load swarm.key: %v", err) }
        log.Printf("pnet: private network enabled (swarm key)")
    }

    h, err := p2p.NewHost(listen, psk)
    if err != nil { log.Fatalf("create host: %v", err) }
    defer h.Close()

    log.Printf("Node ID: %s", h.ID())
    for _, a := range h.Addrs() {
        log.Printf("Listen: %s/p2p/%s", a, h.ID())
    }

    // Hello stream handler: register announced device keys and peer addrs
    p2p.RegisterHelloHandler(h)

    if *enableMDNS {
        n := &p2p.MDNSNotifee{H: h}
        svc, err := p2p.SetupMDNS(h, *mdnsTag, n)
        if err != nil { log.Fatalf("mdns start: %v", err) }
        defer svc.Close()
    }

    if len(bootstraps) > 0 {
        p2p.ConnectToAddrs(h, []string(bootstraps))
    }

    ps, err := gossip.InitPubSub(ctx, h)
    if err != nil { log.Fatalf("pubsub init: %v", err) }
    members, txTopic, err := func() (*gossip.MemberSet, *pubsub.Topic, error) {
        m, _, err := gossip.StartHeartbeat(ctx, h, ps, *hbTopic, *hbInterval, *memberTTL)
        if err != nil { return nil, nil, err }
        t, err := gossip.StartTxGossip(ctx, ps, *txTopicName, *bridgeURL)
        if err != nil { return nil, nil, err }
        return m, t, nil
    }()
    if err != nil { log.Fatalf("gossip start: %v", err) }

    if *httpIn != "" {
        srv := httpapi.StartHTTPIngress(ctx, *httpIn, txTopic)
        defer srv.Shutdown(ctx)
    }

    if *devGen {
        dev.StartDevGenerator(ctx, h, txTopic, *devReuseKey, *devInterval)
    }

    // Block gossip: subscribe always; optionally produce
    blkTopic, err := blockchain.StartBlockSubscriber(ctx, ps, *blockTopicName)
    if err != nil { log.Fatalf("block sub: %v", err) }
    if *produceBlocks {
        if err := blockchain.StartBlockBuilder(ctx, h, txTopic, blkTopic, "iotnet-main", *blockInterval, *blockMax); err != nil { log.Fatalf("block builder: %v", err) }
    }

    if statsInterval != nil && *statsInterval > 0 {
        go func() {
            t := time.NewTicker(*statsInterval); defer t.Stop()
            for {
                select { case <-ctx.Done(): return; case <-t.C:
                    all := members.CountAndSweep()
                    connected := len(h.Network().Peers())
                    log.Printf("stats: all_nodes=%d connected_nodes_counter=%d", all, connected)
                }
            }
        }()
    }

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt)
    <-sig
    log.Println("Shutting down...")
}

// multiFlag allows repeating -bootstrap flags.
type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// -------- Swarm key helpers (pnet) --------

func generateSwarmKey(path string) error {
    b := make([]byte, 32)
    if _, err := crand.Read(b); err != nil { return err }
    hexKey := strings.ToLower(hex.EncodeToString(b))
    content := []byte("/key/swarm/psk/1.0.0/\n/base16/\n" + hexKey + "\n")
    return os.WriteFile(path, content, 0o600)
}

func loadSwarmKey(path string) ([]byte, error) {
    data, err := os.ReadFile(path)
    if err != nil { return nil, err }
    s := strings.TrimSpace(string(data))
    lines := strings.Split(s, "\n")
    var keyHex string
    if len(lines) >= 3 && strings.HasPrefix(lines[0], "/key/swarm/psk/") {
        keyHex = strings.TrimSpace(lines[2])
    } else if len(lines) == 1 && len(lines[0]) >= 64 {
        keyHex = strings.TrimSpace(lines[0])
    }
    if keyHex != "" {
        b, err := hex.DecodeString(keyHex); if err != nil { return nil, err }
        return b, nil
    }
    if len(data) == 32 { return data, nil }
    return nil, fmt.Errorf("unsupported swarm.key format")
}
