package main

import (
    "bufio"
    "context"
    "crypto/ed25519"
    crand "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "time"

    libp2p "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/peer"

    "pose/internal/iot"
)

func main() {
    peerAddr := flag.String("peer", "", "gateway peer multiaddr (e.g., /ip4/10.0.0.1/tcp/4001/p2p/<id>)")
    chain := flag.String("chain", "iotnet-main", "chain/network id")
    deviceID := flag.String("device-id", "", "device ID (default derived from key)")
    firmware := flag.String("firmware", "1.0.0", "firmware version")
    model := flag.String("model", "sim-p2p", "device model")
    sensors := flag.String("sensors", "temp,humidity", "comma-separated sensors")
    caps := flag.String("caps", "push", "comma-separated capabilities")
    flag.Parse()
    if *peerAddr == "" { log.Fatal("-peer is required") }

    // Keypair
    pub, priv, err := ed25519.GenerateKey(crand.Reader)
    if err != nil { log.Fatalf("keygen: %v", err) }
    kid := sha256.Sum256(pub)
    did := *deviceID
    if did == "" { did = fmt.Sprintf("did:iot:P2P-%x", kid[:8]) }

    // Host
    h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
    if err != nil { log.Fatalf("host: %v", err) }
    defer h.Close()

    // Dial
    ai, err := peer.AddrInfoFromString(*peerAddr)
    if err != nil { log.Fatalf("addr: %v", err) }
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := h.Connect(ctx, *ai); err != nil { log.Fatalf("connect: %v", err) }

    // Open stream and send hello
    s, err := h.NewStream(ctx, ai.ID, iot.IotProto)
    if err != nil { log.Fatalf("stream: %v", err) }
    defer s.Close()
    msg := iot.Hello{
        Type: "iot_hello",
        ChainID: *chain,
        DeviceID: did,
        Firmware: *firmware,
        Model: *model,
        Kid: hex.EncodeToString(kid[:8]),
        Pub: hex.EncodeToString(pub),
        Sensors: splitList(*sensors),
        Caps: splitList(*caps),
    }
    by, _ := json.Marshal(msg)
    by = append(by, '\n')
    if _, err := s.Write(by); err != nil { log.Fatalf("write: %v", err) }

    // Read ack
    r := bufio.NewReader(s)
    ack, _ := r.ReadString('\n')
    log.Printf("registered: ack=%s did=%s kid=%x", ack, did, kid[:8])

    // Keep process alive briefly to ensure stream flushes
    time.Sleep(500 * time.Millisecond)
}

func splitList(s string) []string {
    if s == "" { return nil }
    var out []string
    for _, x := range strings.Split(s, ",") {
        x = strings.TrimSpace(x)
        if x != "" { out = append(out, x) }
    }
    return out
}

