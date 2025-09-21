package main

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/gossip"
	"pose/internal/p2p"
)

var encMode cbor.EncMode

func init() {
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	encMode = em
	rand.Seed(time.Now().UnixNano())
}

const (
	joinRetry       = 45 * time.Second
	discoveryRetry  = 5 * time.Second
	txTopicDefault  = "pose/tx/1.0.0"
	defaultFirmware = "1.0.0"
	defaultModel    = "sim-sensor"
	mdnsServiceTag  = "pose-simple-mdns"
)

type device struct {
	id         string
	pub        ed25519.PublicKey
	priv       ed25519.PrivateKey
	kid        []byte
	seq        uint64
	assigned   peer.ID
	registered bool
	nextJoin   time.Time
	baseOffset int
}

type peerBook struct {
	mu    sync.RWMutex
	seeds map[string]struct{}
}

func newPeerBook() *peerBook { return &peerBook{seeds: make(map[string]struct{})} }

func (pb *peerBook) add(addrs []string) bool {
	pb.mu.Lock()
	added := false
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, ok := pb.seeds[addr]; ok {
			continue
		}
		pb.seeds[addr] = struct{}{}
		added = true
	}
	pb.mu.Unlock()
	return added
}

func (pb *peerBook) list(h host.Host) []peer.AddrInfo {
	seen := make(map[peer.ID]peer.AddrInfo)
	pb.mu.RLock()
	for addr := range pb.seeds {
		if pi, err := peer.AddrInfoFromString(addr); err == nil {
			seen[pi.ID] = *pi
		}
	}
	pb.mu.RUnlock()
	for _, pid := range h.Network().Peers() {
		seen[pid] = peer.AddrInfo{ID: pid, Addrs: h.Peerstore().Addrs(pid)}
	}
	out := make([]peer.AddrInfo, 0, len(seen))
	for _, info := range seen {
		out = append(out, info)
	}
	return out
}

func main() {
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/0", "libp2p listen multiaddr")
	var peers multiFlag
	flag.Var(&peers, "peer", "target node multiaddr (repeatable)")
	chain := flag.String("chain", "iotnet-main", "chain/network id")
	devices := flag.Int("devices", 5, "number of simulated devices")
	interval := flag.Duration("interval", 1500*time.Millisecond, "send interval per device")
	jitter := flag.Duration("jitter", 500*time.Millisecond, "random jitter added to interval")
	once := flag.Bool("once", false, "send just one reading per device then exit")
	list := flag.Bool("list", false, "list devices registered on first peer and exit")
	topicName := flag.String("topic", txTopicDefault, "pubsub topic for COSE telemetry")
	pnetPath := flag.String("pnet", "", "path to swarm.key for private network")
	enableMDNS := flag.Bool("mdns", true, "enable mDNS discovery")
	mdnsTag := flag.String("mdns-tag", mdnsServiceTag, "mDNS service tag")
	flag.Parse()

	if len(peers) == 0 {
		log.Printf("no -peer addresses provided; waiting for discovery")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var psk []byte
	if *pnetPath != "" {
		key, err := loadSwarmKey(*pnetPath)
		if err != nil {
			log.Fatalf("pnet: %v", err)
		}
		psk = key
	}

	book := newPeerBook()
	book.add([]string(peers))

	p2p.SetChainID(*chain)
	h, err := p2p.NewHost(*listen, psk)
	if err != nil {
		log.Fatalf("host: %v", err)
	}
	defer h.Close()

	log.Printf("host id=%s", h.ID())
	for _, a := range h.Addrs() {
		log.Printf("listen %s/p2p/%s", a.String(), h.ID())
	}

	p2p.RegisterHelloHandlerWithCallback(h, func(pm p2p.PeerMsg) {
		if len(pm.Addrs) > 0 {
			book.add(pm.Addrs)
		}
	})

	if *enableMDNS {
		n := &p2p.MDNSNotifee{H: h, OnPeer: func(pi peer.AddrInfo) {
			ma, _ := peer.AddrInfoToP2pAddrs(&pi)
			addrs := make([]string, 0, len(ma))
			for _, m := range ma {
				addrs = append(addrs, m.String())
			}
			book.add(addrs)
		}}
		svc, err := p2p.SetupMDNS(h, *mdnsTag, n)
		if err != nil {
			log.Fatalf("mdns: %v", err)
		}
		defer svc.Close()
	}

	if len(peers) > 0 {
		p2p.ConnectToAddrs(h, []string(peers))
	}

	ps, err := gossip.InitPubSub(ctx, h)
	if err != nil {
		log.Fatalf("pubsub: %v", err)
	}
	txTopic, err := ps.Join(*topicName)
	if err != nil {
		log.Fatalf("topic join: %v", err)
	}
	defer txTopic.Close()

	if *list {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			candidates := book.list(h)
			if len(candidates) == 0 {
				log.Printf("waiting for peers to list devices")
				time.Sleep(1 * time.Second)
				continue
			}
			if err := listDevices(ctx, h, candidates[0]); err != nil {
				log.Fatalf("list: %v", err)
			}
			return
		}
	}

	devs := make([]device, *devices)
	for i := 0; i < *devices; i++ {
		pub, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			log.Fatalf("keygen: %v", err)
		}
		kid := kidFromPub(pub)
		devs[i] = device{
			id:         fmt.Sprintf("did:iot:SIM-%x", kid),
			pub:        pub,
			priv:       priv,
			kid:        kid,
			seq:        0,
			nextJoin:   time.Now(),
			baseOffset: i,
		}
	}
	log.Printf("initialized %d devices", *devices)

	for i := range devs {
		if ok, retry := attemptJoinWithBackoff(ctx, h, book.list(h), *chain, &devs[i]); !ok {
			if retry <= 0 {
				retry = joinRetry
			}
			devs[i].nextJoin = time.Now().Add(retry)
		}
	}

	var wg sync.WaitGroup
	for i := range devs {
		wg.Add(1)
		go func(d *device) {
			defer wg.Done()
			runDevice(ctx, h, txTopic, book, *chain, interval, jitter, once, d)
		}(&devs[i])
	}

	wg.Wait()
}

func runDevice(ctx context.Context, h host.Host, topic *pubsub.Topic, book *peerBook, chain string, interval, jitter *time.Duration, once *bool, d *device) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		peers := book.list(h)
		if !d.registered {
			if len(peers) > 0 && time.Until(d.nextJoin) > 5*time.Second {
				d.nextJoin = time.Now()
			}
			if time.Now().After(d.nextJoin) {
				if ok, retry := attemptJoinWithBackoff(ctx, h, peers, chain, d); ok {
					log.Printf("device=%s joined peer=%s", short(d.id), d.assigned)
					d.nextJoin = time.Now().Add(joinRetry)
				} else {
					if retry <= 0 {
						retry = joinRetry
					}
					d.nextJoin = time.Now().Add(retry)
					log.Printf("device=%s retry join in %s", short(d.id), retry)
				}
			}
		}
		if !d.registered {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		d.seq++
		cose, txid, err := buildCOSE(d.priv, d.kid, chain, d.id, d.seq)
		if err != nil {
			log.Printf("build error (%s): %v", short(d.id), err)
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = topic.Publish(sendCtx, cose)
		cancel()
		if err != nil {
			log.Printf("publish failed (%s): %v", short(d.id), err)
			d.registered = false
			d.nextJoin = time.Now().Add(10 * time.Second)
			continue
		}
		log.Printf("sent device=%s txid=%s", short(d.id), txid[:12])
		if *once {
			return
		}
		delay := *interval
		if jitter != nil && *jitter > 0 {
			delay += time.Duration(rand.Int63n(int64(*jitter)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func attemptJoinWithBackoff(ctx context.Context, h host.Host, peers []peer.AddrInfo, chain string, d *device) (bool, time.Duration) {
	if len(peers) == 0 {
		log.Printf("no peers available for device=%s", short(d.id))
		return false, discoveryRetry
	}
	order := rotatePeers(peers, d.baseOffset)
	for _, pi := range order {
		if ctx.Err() != nil {
			return false, discoveryRetry
		}
		if err := ensureConnected(ctx, h, pi); err != nil {
			log.Printf("connect failed (%s -> %s): %v", short(d.id), pi.ID, err)
			continue
		}
		capCtx, cancelCap := context.WithTimeout(ctx, 5*time.Second)
		capResp, err := p2p.SendIoTRequest(capCtx, h, pi.ID, p2p.IoTRequest{Action: "capacity"})
		cancelCap()
		if err != nil {
			log.Printf("capacity failed (%s -> %s): %v", short(d.id), pi.ID, err)
			continue
		}
		if !capResp.Accepting {
			continue
		}
		regCtx, cancelReg := context.WithTimeout(ctx, 5*time.Second)
		regResp, err := p2p.SendIoTRequest(regCtx, h, pi.ID, p2p.IoTRequest{
			Action:   "register",
			DeviceID: d.id,
			Firmware: defaultFirmware,
			Model:    defaultModel,
			Kid:      hex.EncodeToString(d.kid),
			Pub:      hex.EncodeToString(d.pub),
			Sensors:  []string{"temp", "humidity"},
			Caps:     []string{"push"},
		})
		cancelReg()
		if err != nil {
			log.Printf("register failed (%s -> %s): %v", short(d.id), pi.ID, err)
			continue
		}
		if !regResp.OK {
			if regResp.Error == "iot_limit_reached" {
				continue
			}
			log.Printf("register rejected (%s -> %s): %s", short(d.id), pi.ID, regResp.Error)
			continue
		}
		if d.registered && d.assigned != pi.ID {
			removeCtx, cancelRemove := context.WithTimeout(ctx, 3*time.Second)
			_, _ = p2p.SendIoTRequest(removeCtx, h, d.assigned, p2p.IoTRequest{Action: "remove", DeviceID: d.id})
			cancelRemove()
		}
		d.registered = true
		d.assigned = pi.ID
		return true, joinRetry
	}
	return false, joinRetry
}

func listDevices(ctx context.Context, h host.Host, target peer.AddrInfo) error {
	if err := ensureConnected(ctx, h, target); err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := p2p.SendIoTRequest(reqCtx, h, target.ID, p2p.IoTRequest{Action: "list"})
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(resp.Devices, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func ensureConnected(ctx context.Context, h host.Host, pi peer.AddrInfo) error {
	if len(h.Network().ConnsToPeer(pi.ID)) > 0 {
		return nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return h.Connect(dialCtx, pi)
}

func rotatePeers(peers []peer.AddrInfo, offset int) []peer.AddrInfo {
	if len(peers) == 0 {
		return nil
	}
	out := make([]peer.AddrInfo, len(peers))
	for i := range peers {
		idx := (offset + i) % len(peers)
		out[i] = peers[idx]
	}
	return out
}

func buildCOSE(priv ed25519.PrivateKey, kid []byte, chain string, deviceID string, seq uint64) ([]byte, string, error) {
	payload := map[int]interface{}{
		0: int64(1),
		1: chain,
		2: "data",
		3: map[int]interface{}{0: deviceID, 1: defaultFirmware, 2: "ed25519:SIM"},
		4: int64(seq),
		5: time.Now().UTC(),
		6: map[int]interface{}{0: int64(25), 1: "uCR"},
		7: []interface{}{randBytes(7), randBytes(7)},
		8: map[int]interface{}{
			0: "urn:example:sensor:v1",
			1: map[string]interface{}{"temp_c": 18 + rand.Float64()*8, "humidity": 0.35 + rand.Float64()*0.25},
			2: map[string]interface{}{"gps": []interface{}{52.520008, 13.404954, 8.0}, "site": "plant-berlin-a"},
			3: randBytes(6),
		},
		9: map[int]interface{}{0: "urn:cap:write:sensors/thermo", 1: time.Now().UTC().Add(24 * time.Hour)},
	}
	payloadCBOR, err := encMode.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	txid := sha256.Sum256(payloadCBOR)
	ph := map[int]interface{}{1: int64(-8), 4: kid}
	prot, err := encMode.Marshal(ph)
	if err != nil {
		return nil, "", err
	}
	toSign, err := encMode.Marshal([]interface{}{"Signature1", prot, []byte{}, payloadCBOR})
	if err != nil {
		return nil, "", err
	}
	sig := ed25519.Sign(priv, toSign)
	arr := []interface{}{cbor.RawMessage(prot), map[int]interface{}{}, payloadCBOR, []byte(sig)}
	tagged := cbor.Tag{Number: 18, Content: arr}
	out, err := encMode.Marshal(tagged)
	if err != nil {
		return nil, "", err
	}
	return out, hex.EncodeToString(txid[:]), nil
}

func kidFromPub(pub ed25519.PublicKey) []byte { sum := sha256.Sum256(pub); return sum[:8] }

func randBytes(n int) []byte { b := make([]byte, n); io.ReadFull(crand.Reader, b); return b }

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func loadSwarmKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	lines := strings.Split(s, "\n")
	var keyHex string
	if len(lines) >= 3 && strings.HasPrefix(lines[0], "/key/swarm/psk/") {
		keyHex = strings.TrimSpace(lines[2])
	} else if len(lines) == 1 && len(lines[0]) >= 64 {
		keyHex = strings.TrimSpace(lines[0])
	}
	if keyHex != "" {
		b, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	if len(data) == 32 {
		return data, nil
	}
	return nil, fmt.Errorf("unsupported swarm.key format")
}
