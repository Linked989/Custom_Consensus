package p2p

import (
    "bufio"
    "context"
    "encoding/hex"
    "encoding/json"
    "io"
    "sync"
    "time"
    "strings"

    "crypto/ed25519"

    libp2p "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    pnet "github.com/libp2p/go-libp2p/core/pnet"
    mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"

    "pose/internal/coseutil"
    "pose/internal/logx"
)

// ProtocolID for hello streams.
const ProtocolID = "/pose/simple/1.0.0"

// PeerMsg is exchanged over the hello stream for peer gossip and device key announce.
type PeerMsg struct {
    Type  string   `json:"type"`
    From  string   `json:"from"`
    Addrs []string `json:"addrs"`
    Kid   string   `json:"kid,omitempty"` // hex ed25519 key id (prefix)
    Pub   string   `json:"pub,omitempty"` // hex ed25519 public key
    Chain string   `json:"chain,omitempty"` // chain/network id
}

// Global announce for dev key.
var devAnnounce struct{ kid []byte; pub ed25519.PublicKey }
var expectedChain string

// SetChainID configures the chain/network id to announce and accept.
func SetChainID(id string) { expectedChain = id }

func SetDevAnnouncement(kid []byte, pub ed25519.PublicKey) {
    devAnnounce.kid, devAnnounce.pub = kid, pub
}

// NewHost creates a libp2p host with optional private network PSK.
func NewHost(listenAddr string, psk []byte) (host.Host, error) {
    var opts []libp2p.Option
    opts = append(opts, libp2p.ListenAddrStrings(listenAddr))
    if len(psk) > 0 {
        opts = append(opts, libp2p.PrivateNetwork(pnet.PSK(psk)))
    }
    return libp2p.New(opts...)
}

// MDNSNotifee connects to discovered peers and sends hello.
type MDNSNotifee struct {
    H    host.Host
    Mu   sync.Mutex
    Seen map[peer.ID]struct{}
}

func (m *MDNSNotifee) HandlePeerFound(pi peer.AddrInfo) {
    if pi.ID == m.H.ID() {
        return
    }
    m.Mu.Lock()
    if m.Seen == nil {
        m.Seen = make(map[peer.ID]struct{})
    }
    if _, ok := m.Seen[pi.ID]; ok {
        m.Mu.Unlock()
        return
    }
    m.Seen[pi.ID] = struct{}{}
    m.Mu.Unlock()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if err := m.H.Connect(ctx, pi); err != nil {
        logx.Debug("mdns connect failed", "peer", pi.ID.String(), "err", err)
        return
    }
    s, err := m.H.NewStream(ctx, pi.ID, ProtocolID)
    if err != nil {
        logx.Debug("mdns stream failed", "peer", pi.ID.String(), "err", err)
        return
    }
    defer s.Close()
    _ = SendHello(m.H, s)
}

// SetupMDNS starts mDNS discovery service.
func SetupMDNS(h host.Host, tag string, n *MDNSNotifee) (io.Closer, error) {
    svc := mdns.NewMdnsService(h, tag, n)
    if err := svc.Start(); err != nil {
        return nil, err
    }
    return svc, nil
}

// SendHello writes a JSON hello message on the stream.
func SendHello(h host.Host, s network.Stream) error {
    pm := PeerMsg{Type: "hello", From: h.ID().String(), Addrs: LocalAddrs(h), Chain: expectedChain}
    if len(devAnnounce.kid) > 0 && len(devAnnounce.pub) == ed25519.PublicKeySize {
        pm.Kid = hex.EncodeToString(devAnnounce.kid)
        pm.Pub = hex.EncodeToString(devAnnounce.pub)
    }
    b, _ := json.Marshal(pm)
    _, err := s.Write(append(b, '\n'))
    return err
}

// SendHelloToAllPeers announces to all connected peers.
func SendHelloToAllPeers(ctx context.Context, h host.Host) {
    for _, pid := range h.Network().Peers() {
        s, err := h.NewStream(ctx, pid, ProtocolID)
        if err != nil {
            continue
        }
        _ = SendHello(h, s)
        _ = s.Close()
    }
}

// RegisterHelloHandler sets a stream handler that parses hello messages,
// registers announced device keys, and optionally dials additional addrs.
func RegisterHelloHandler(h host.Host) {
    h.SetStreamHandler(ProtocolID, func(s network.Stream) {
        defer s.Close()
        r := bufio.NewReader(s)
        line, _ := r.ReadString('\n')
        var pm PeerMsg
        if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &pm); err == nil && pm.Type == "hello" {
            // Drop peers on chain mismatch (if they supplied a chain id)
            if pm.Chain != "" && expectedChain != "" && pm.Chain != expectedChain {
                _ = s.Close()
                // best-effort: close peer connections
                _ = h.Network().ClosePeer(s.Conn().RemotePeer())
                return
            }
            if pm.Kid != "" && pm.Pub != "" {
                if kidBytes, err1 := hex.DecodeString(pm.Kid); err1 == nil {
                    if pubBytes, err2 := hex.DecodeString(pm.Pub); err2 == nil && len(pubBytes) == ed25519.PublicKeySize {
                        coseutil.RegistryRegister(kidBytes, ed25519.PublicKey(pubBytes))
                    }
                }
            }
            if len(pm.Addrs) > 0 {
                ConnectToAddrs(h, pm.Addrs)
            }
        }
        // best-effort ack
        _, _ = io.WriteString(s, "ack\n")
    })
}

// LocalAddrs returns this host's multiaddrs with /p2p suffix.
func LocalAddrs(h host.Host) []string {
    var out []string
    for _, a := range h.Addrs() {
        out = append(out, a.String()+"/p2p/"+h.ID().String())
    }
    return out
}

// ConnectToAddrs dials peers from multiaddr strings.
func ConnectToAddrs(h host.Host, addrs []string) {
    for _, as := range addrs {
        pi, err := peer.AddrInfoFromString(as)
        if err != nil || pi.ID == h.ID() {
            continue
        }
        if len(h.Network().ConnsToPeer(pi.ID)) > 0 {
            continue
        }
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        _ = h.Connect(ctx, *pi)
        cancel()
    }
}
