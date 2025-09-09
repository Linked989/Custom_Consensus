package main

import (
    "bufio"
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "os"
    "os/signal"
    "strings"
    "sync"
    "time"

    libp2p "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
    ma "github.com/multiformats/go-multiaddr"
)

// protocolID identifies our very simple stream type.
const protocolID = "/pose/simple/1.0.0"

// mdnsServiceTag is used to discover peers on the local network.
const mdnsServiceTag = "pose-simple-mdns"

// default pubsub heartbeat topic
const heartbeatTopic = "pose/heartbeat/1.0.0"

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
