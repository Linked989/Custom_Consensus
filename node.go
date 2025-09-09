package main

import (
    "bufio"
    "context"
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
    mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

// protocolID identifies our very simple stream type.
const protocolID = "/pose/simple/1.0.0"

// mdnsServiceTag is used to discover peers on the local network.
const mdnsServiceTag = "pose-simple-mdns"

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

    _, _ = io.WriteString(s, fmt.Sprintf("hello from %s\n", m.h.ID()))
    reply, _ := bufio.NewReader(s).ReadString('\n')
    if reply != "" {
        log.Printf("mdns: reply from %s: %s", pi.ID, strings.TrimSpace(reply))
    }
}

// handleStream handles inbound streams for our protocol.
func handleStream(s network.Stream) {
    defer s.Close()
    r := bufio.NewReader(s)
    msg, _ := r.ReadString('\n')
    if msg == "" {
        msg = "(empty)"
    }
    log.Printf("recv: from=%s msg=%q", s.Conn().RemotePeer(), strings.TrimSpace(msg))
    _, _ = io.WriteString(s, "ack\n")
}

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Create a node listening on a random TCP port.
    h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
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
    h.SetStreamHandler(protocolID, handleStream)

    // Start mDNS discovery so that multiple instances on the same LAN find each other.
    n := &mdnsNotifee{h: h, seen: make(map[peer.ID]struct{})}
    svc := mdns.NewMdnsService(h, mdnsServiceTag, n)
    if err := svc.Start(); err != nil {
        log.Fatalf("mdns start: %v", err)
    }
    defer svc.Close()

    // Wait for Ctrl+C.
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt)
    <-sig
    log.Println("Shutting down...")
}

