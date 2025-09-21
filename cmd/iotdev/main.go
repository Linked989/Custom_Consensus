package main

import (
	"bytes"
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
	"net/http"
	"os"
	"os/signal"
	"sort"
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

type addrBook struct {
	mu    sync.RWMutex
	addrs map[string]struct{}
}

func newAddrBook() *addrBook { return &addrBook{addrs: make(map[string]struct{})} }

func (ab *addrBook) add(addrs []string) []string {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	var fresh []string
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, ok := ab.addrs[addr]; ok {
			continue
		}
		ab.addrs[addr] = struct{}{}
		fresh = append(fresh, addr)
	}
	return fresh
}

func (ab *addrBook) list() []string {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	out := make([]string, 0, len(ab.addrs))
	for addr := range ab.addrs {
		out = append(out, addr)
	}
	sort.Strings(out)
	return out
}

type httpRegisterRequest struct {
	DeviceID string   `json:"device_id"`
	Firmware string   `json:"firmware,omitempty"`
	Model    string   `json:"model,omitempty"`
	Kid      string   `json:"kid,omitempty"`
	Pub      string   `json:"pub"`
	Sensors  []string `json:"sensors,omitempty"`
	Caps     []string `json:"caps,omitempty"`
	ChainID  string   `json:"chain_id,omitempty"`
}

type httpRegisterResponse struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Message    string   `json:"message,omitempty"`
	NodeID     string   `json:"node_id,omitempty"`
	Connected  int      `json:"connected,omitempty"`
	MaxDevices int      `json:"max_devices,omitempty"`
	Accepting  bool     `json:"accepting,omitempty"`
	P2PAddrs   []string `json:"p2p_addrs,omitempty"`
}

func main() {
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/0", "libp2p listen multiaddr")
	var peers multiFlag
	flag.Var(&peers, "peer", "target node multiaddr (repeatable)")
	var nodes multiFlag
	flag.Var(&nodes, "node", "node HTTP base URL for registration (repeatable)")
	chain := flag.String("chain", "iotnet-main", "chain/network id")
	devices := flag.Int("devices", 5, "number of simulated devices")
	interval := flag.Duration("interval", 1500*time.Millisecond, "send interval per device")
	jitter := flag.Duration("jitter", 500*time.Millisecond, "random jitter added to interval")
	once := flag.Bool("once", false, "send just one reading per device then exit")
	list := flag.Bool("list", false, "list devices from first HTTP node and exit")
	topicName := flag.String("topic", txTopicDefault, "pubsub topic for COSE telemetry")
	pnetPath := flag.String("pnet", "", "path to swarm.key for private network")
	flag.Parse()

	if len(nodes) == 0 {
		log.Fatalf("at least one -node HTTP address is required")
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

	client := &http.Client{Timeout: 5 * time.Second}
	book := newAddrBook()
	if newAddrs := book.add([]string(peers)); len(newAddrs) > 0 {
		log.Printf("seeded %d libp2p peers from flags", len(newAddrs))
	}

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

	p2p.RegisterHelloHandler(h)
	if existing := book.list(); len(existing) > 0 {
		p2p.ConnectToAddrs(h, existing)
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
		if err := listDevicesHTTP(ctx, client, nodes[0]); err != nil {
			log.Fatalf("list: %v", err)
		}
		return
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
		if ok, retry := registerViaNodes(ctx, h, client, book, nodes, *chain, &devs[i]); !ok {
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
			runDevice(ctx, h, txTopic, book, client, nodes, *chain, interval, jitter, once, d)
		}(&devs[i])
	}

	wg.Wait()
}

func runDevice(ctx context.Context, h host.Host, topic *pubsub.Topic, book *addrBook, client *http.Client, nodes []string, chain string, interval, jitter *time.Duration, once *bool, d *device) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !d.registered && time.Now().After(d.nextJoin) {
			if ok, retry := registerViaNodes(ctx, h, client, book, nodes, chain, d); ok {
				log.Printf("device=%s registered via HTTP", short(d.id))
			} else {
				if retry <= 0 {
					retry = joinRetry
				}
				d.nextJoin = time.Now().Add(retry)
				log.Printf("device=%s retry register in %s", short(d.id), retry)
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
			d.nextJoin = time.Now().Add(discoveryRetry)
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

func registerViaNodes(ctx context.Context, h host.Host, client *http.Client, book *addrBook, nodes []string, chain string, d *device) (bool, time.Duration) {
	if len(nodes) == 0 {
		log.Printf("no HTTP nodes available for device=%s", short(d.id))
		return false, joinRetry
	}
	req := httpRegisterRequest{
		DeviceID: d.id,
		Firmware: defaultFirmware,
		Model:    defaultModel,
		Kid:      hex.EncodeToString(d.kid),
		Pub:      hex.EncodeToString(d.pub),
		Sensors:  []string{"temp", "humidity"},
		Caps:     []string{"push"},
		ChainID:  chain,
	}
	delay := discoveryRetry
	for _, base := range nodes {
		resp, err := httpRegisterDevice(ctx, client, base, req)
		if err != nil {
			log.Printf("register error (%s -> %s): %v", short(d.id), base, err)
			continue
		}
		if !resp.OK {
			if resp.Error == "iot_limit_reached" {
				delay = joinRetry
				continue
			}
			log.Printf("register rejected (%s -> %s): %s", short(d.id), base, firstNonEmpty(resp.Message, resp.Error))
			continue
		}
		if len(resp.P2PAddrs) > 0 {
			if newAddrs := book.add(resp.P2PAddrs); len(newAddrs) > 0 {
				p2p.ConnectToAddrs(h, newAddrs)
			}
		}
		if resp.NodeID != "" {
			if pid, err := peer.Decode(resp.NodeID); err == nil {
				d.assigned = pid
			}
		}
		d.registered = true
		d.nextJoin = time.Now().Add(joinRetry)
		return true, joinRetry
	}
	return false, delay
}

func httpRegisterDevice(ctx context.Context, client *http.Client, base string, req httpRegisterRequest) (httpRegisterResponse, error) {
	var resp httpRegisterResponse
	payload, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, requestURL(base, "/iot/register"), bytes.NewReader(payload))
	if err != nil {
		return resp, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, err
	}
	if !resp.OK && httpResp.StatusCode >= 400 && resp.Error == "" {
		resp.Error = httpResp.Status
	}
	return resp, nil
}

func listDevicesHTTP(ctx context.Context, client *http.Client, base string) error {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, requestURL(base, "/iot/devices"), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

func requestURL(base, path string) string {
	trim := strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return trim + path
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
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
	return nil, fmt.Errorf("invalid swarm.key format")
}
