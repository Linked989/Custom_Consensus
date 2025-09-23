package iotsim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/gossip"
	"pose/internal/iot"
	"pose/internal/p2p"
)

var encMode cbor.EncMode

func init() {
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	encMode = em
	rand.Seed(time.Now().UnixNano())
}

const (
	joinRetry       = 5 * time.Minute
	discoveryRetry  = 5 * time.Second
	txTopicDefault  = "pose/tx/1.0.0"
	defaultFirmware = "1.0.0"
	defaultModel    = "sim-sensor"
)

// Options controls the IoT simulator behavior.
type Options struct {
	Listen                   string
	Peers                    []string
	Nodes                    []string
	Chain                    string
	TelemetryDevices         int
	AttesterDevices          int
	Interval                 time.Duration
	AttesterInterval         time.Duration
	Jitter                   time.Duration
	Once                     bool
	ListOnly                 bool
	Topic                    string
	PNetPath                 string
	OrchestratorInterval     time.Duration
	OrchestratorMinNodes     int
	OrchestratorMinAccepting int
	OrchestratorRefresh      time.Duration
}

type device struct {
	id           string
	pub          ed25519.PublicKey
	priv         ed25519.PrivateKey
	kid          []byte
	seq          uint64
	attester     bool
	assigned     peer.ID
	assignedNode string
	assignedBase string
	fallback     bool
	registered   bool
	nextJoin     time.Time
	baseOffset   int
	lastAttested string
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

func Run(ctx context.Context, opts Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(opts.Nodes) == 0 {
		return fmt.Errorf("at least one node endpoint is required")
	}
	listen := strings.TrimSpace(opts.Listen)
	if listen == "" {
		listen = "/ip4/0.0.0.0/tcp/0"
	}
	chain := strings.TrimSpace(opts.Chain)
	if chain == "" {
		chain = "iotnet-main"
	}
	topic := strings.TrimSpace(opts.Topic)
	if topic == "" {
		topic = txTopicDefault
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = 1500 * time.Millisecond
	}
	attesterInterval := opts.AttesterInterval
	if attesterInterval <= 0 {
		attesterInterval = 150 * time.Millisecond
	}
	jitter := opts.Jitter
	orchInterval := opts.OrchestratorInterval
	if orchInterval <= 0 {
		orchInterval = 2 * time.Second
	}
	orchRefresh := opts.OrchestratorRefresh
	if orchRefresh <= 0 {
		orchRefresh = 15 * time.Second
	}
	minNodes := opts.OrchestratorMinNodes
	if minNodes <= 0 {
		minNodes = 2
	}
	minAccept := opts.OrchestratorMinAccepting
	if minAccept <= 0 {
		minAccept = 1
	}

	endpoints := make([]*nodeEndpoint, len(opts.Nodes))
	for i, base := range opts.Nodes {
		endpoints[i] = newNodeEndpoint(base)
	}

	var psk []byte
	if strings.TrimSpace(opts.PNetPath) != "" {
		key, err := loadSwarmKey(opts.PNetPath)
		if err != nil {
			return fmt.Errorf("pnet: %w", err)
		}
		psk = key
	}

	client := &http.Client{Timeout: 5 * time.Second}
	book := newAddrBook()
	if fresh := book.add(opts.Peers); len(fresh) > 0 {
		log.Printf("seeded %d libp2p peers from flags", len(fresh))
	}

	p2p.SetChainID(chain)
	h, err := p2p.NewHost(listen, psk)
	if err != nil {
		return fmt.Errorf("host: %w", err)
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
		return fmt.Errorf("pubsub: %w", err)
	}
	txTopic, err := ps.Join(topic)
	if err != nil {
		return fmt.Errorf("topic join: %w", err)
	}
	defer txTopic.Close()

	if opts.ListOnly {
		if err := listDevicesHTTP(ctx, client, endpoints[0].base); err != nil {
			return fmt.Errorf("list: %w", err)
		}
		return nil
	}

	totalDevices := opts.TelemetryDevices + opts.AttesterDevices
	if totalDevices <= 0 {
		log.Printf("no devices configured")
		return nil
	}
	devs := make([]device, 0, totalDevices)
	for i := 0; i < opts.TelemetryDevices; i++ {
		pub, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return fmt.Errorf("device keygen: %w", err)
		}
		kid := kidFromPub(pub)
		devs = append(devs, device{
			id:         fmt.Sprintf("did:iot:SIM-%x", kid),
			pub:        pub,
			priv:       priv,
			kid:        kid,
			seq:        0,
			nextJoin:   time.Now(),
			baseOffset: len(devs),
		})
	}
	for i := 0; i < opts.AttesterDevices; i++ {
		pub, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return fmt.Errorf("attester keygen: %w", err)
		}
		kid := kidFromPub(pub)
		devs = append(devs, device{
			id:         fmt.Sprintf("%s%03d-%x", iot.L3AttesterPrefix, i, kid),
			pub:        pub,
			priv:       priv,
			kid:        kid,
			seq:        0,
			nextJoin:   time.Now(),
			baseOffset: len(devs),
			attester:   true,
		})
	}
	log.Printf("initialized %d devices (%d telemetry, %d L3 attesters)", len(devs), opts.TelemetryDevices, opts.AttesterDevices)
	devPtrs := make([]*device, len(devs))
	for i := range devs {
		devs[i].baseOffset = i
		devPtrs[i] = &devs[i]
	}

	reg := newRegistrar(h, book, client, chain, endpoints)
	reg.start(ctx)
	orchPlan, err := runOrchestrator(orchestratorConfig{
		ctx:         ctx,
		client:      client,
		host:        h,
		book:        book,
		nodes:       endpoints,
		minNodes:    minNodes,
		minAccept:   minAccept,
		interval:    orchInterval,
		refresh:     orchRefresh,
		reg:         reg,
		deviceCount: len(devPtrs),
	})
	if err != nil {
		log.Printf("orchestrator warning: %v", err)
	}
	if len(orchPlan) > 0 {
		for i, d := range devPtrs {
			d.baseOffset = orchPlan[i%len(orchPlan)]
		}
	}

	var wg sync.WaitGroup
	for i := range devs {
		wg.Add(1)
		go func(d *device) {
			defer wg.Done()
			runDevice(ctx, txTopic, reg, client, chain, interval, jitter, attesterInterval, opts.Once, d)
		}(&devs[i])
	}

	wg.Wait()
	return nil
}

func runDevice(ctx context.Context, topic *pubsub.Topic, reg *registrar, client *http.Client, chain string, interval time.Duration, jitter time.Duration, attesterInterval time.Duration, once bool, d *device) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if (!d.registered || d.fallback) && time.Now().After(d.nextJoin) {
			res, ok := reg.Register(ctx, d)
			if !ok {
				return
			}
			retry := res.retry
			if retry <= 0 {
				retry = joinRetry
			}
			d.nextJoin = time.Now().Add(retry)
			if res.ok {
				if res.fallback {
					log.Printf("device=%s fallback mode active", short(d.id))
				} else {
					log.Printf("device=%s registered via node=%s", short(d.id), d.assignedNode)
				}
			} else {
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

		if !d.attester {
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
			if d.assignedNode != "" {
				log.Printf("sent device=%s node=%s txid=%s", short(d.id), d.assignedNode, txid[:12])
			} else if d.fallback {
				log.Printf("sent device=%s node=fallback txid=%s", short(d.id), txid[:12])
			} else {
				log.Printf("sent device=%s txid=%s", short(d.id), txid[:12])
			}
		}
		if client != nil && d.assignedBase != "" {
			loops := 1
			if d.attester {
				loops = 3
			}
			for i := 0; i < loops; i++ {
				next, votes, required, total, err := attestPending(ctx, client, d.assignedBase, d.id, d.lastAttested)
				if err != nil {
					if !d.attester {
						log.Printf("attest failed (device %s): %v", short(d.id), err)
					}
					break
				}
				if next == "" || next == d.lastAttested {
					break
				}
				if !d.attester {
					log.Printf("attested device=%s block=%s votes=%d/%d total_devices=%d", short(d.id), short(next), votes, required, total)
				}
				d.lastAttested = next
			}
		}
		if once && !d.attester {
			return
		}
		delay := interval
		if d.attester {
			delay = time.Second
			if attesterInterval > 0 {
				delay = attesterInterval
			}
		} else if jitter > 0 {
			delay += time.Duration(rand.Int63n(int64(jitter)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
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

func nodeHost(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		return host
	}
	parts := strings.Split(host, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}

func nodePort(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func rotateIndices(length, offset int) []int {
	if length == 0 {
		return nil
	}
	out := make([]int, length)
	for i := 0; i < length; i++ {
		out[i] = (offset + i) % length
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

type nodeEndpoint struct {
	base    string
	host    string
	port    string
	retryAt time.Time
}

func newNodeEndpoint(base string) *nodeEndpoint {
	host := nodeHost(base)
	port := nodePort(base)
	return &nodeEndpoint{base: base, host: host, port: port}
}

func (n *nodeEndpoint) label() string {
	if n == nil {
		return ""
	}
	if n.port != "" {
		return fmt.Sprintf("%s:%s", n.host, n.port)
	}
	return n.host
}

func attestPending(ctx context.Context, client *http.Client, base string, deviceID string, last string) (string, int, int, int, error) {
	target, _, votes, required, total, err := fetchPendingBlock(ctx, client, base)
	if err != nil {
		if errors.Is(err, errNoPending) {
			return last, votes, required, total, nil
		}
		return last, votes, required, total, err
	}
	if target == "" || target == last {
		return last, votes, required, total, nil
	}
	votes, required, total, err = postDeviceAttestation(ctx, client, base, deviceID, target)
	if err != nil {
		return last, votes, required, total, err
	}
	return target, votes, required, total, nil
}

var errNoPending = errors.New("no pending block")

func fetchPendingBlock(ctx context.Context, client *http.Client, base string) (string, int64, int, int, int, error) {
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, requestURL(base, "/helios/l3/pending"), nil)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, 0, 0, 0, errNoPending
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return "", 0, 0, 0, 0, fmt.Errorf("pending status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		Block    string `json:"block"`
		Height   int64  `json:"height"`
		Votes    int    `json:"votes"`
		Required int    `json:"required"`
		Total    int    `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, 0, 0, 0, err
	}
	return strings.ToLower(strings.TrimSpace(out.Block)), out.Height, out.Votes, out.Required, out.Total, nil
}

func postDeviceAttestation(ctx context.Context, client *http.Client, base, deviceID, block string) (int, int, int, error) {
	payload := map[string]string{"device_id": deviceID, "block": block}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, 0, 0, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, requestURL(base, "/iot/attest"), bytes.NewReader(body))
	if err != nil {
		return 0, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return 0, 0, 0, fmt.Errorf("attest status %s: %s", resp.Status, strings.TrimSpace(string(buf)))
	}
	var out struct {
		OK       bool `json:"ok"`
		Votes    int  `json:"votes"`
		Required int  `json:"required"`
		Total    int  `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, 0, 0, err
	}
	return out.Votes, out.Required, out.Total, nil
}

type regRequest struct {
	device *device
	resp   chan regResult
}

type regResult struct {
	ok       bool
	fallback bool
	retry    time.Duration
}

type orchestratorConfig struct {
	ctx         context.Context
	client      *http.Client
	host        host.Host
	book        *addrBook
	nodes       []*nodeEndpoint
	minNodes    int
	minAccept   int
	interval    time.Duration
	refresh     time.Duration
	reg         *registrar
	deviceCount int
}

type registrar struct {
	host      host.Host
	book      *addrBook
	client    *http.Client
	chain     string
	endpoints []*nodeEndpoint
	reqCh     chan regRequest
	prefMu    sync.RWMutex
	pref      []int
}

func newRegistrar(h host.Host, book *addrBook, client *http.Client, chain string, endpoints []*nodeEndpoint) *registrar {
	return &registrar{
		host:      h,
		book:      book,
		client:    client,
		chain:     chain,
		endpoints: endpoints,
		reqCh:     make(chan regRequest),
	}
}

func (r *registrar) start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-r.reqCh:
				res := r.handle(req.device)
				req.resp <- res
			}
		}
	}()
}

func (r *registrar) Register(ctx context.Context, d *device) (regResult, bool) {
	respCh := make(chan regResult, 1)
	select {
	case <-ctx.Done():
		return regResult{}, false
	case r.reqCh <- regRequest{device: d, resp: respCh}:
	}
	select {
	case <-ctx.Done():
		return regResult{}, false
	case res := <-respCh:
		return res, true
	}
}

func (r *registrar) setPreferred(order []int) {
	r.prefMu.Lock()
	r.pref = append([]int(nil), order...)
	r.prefMu.Unlock()
}

func (r *registrar) orderFor(base int) []int {
	max := len(r.endpoints)
	if max == 0 {
		return nil
	}
	r.prefMu.RLock()
	pref := append([]int(nil), r.pref...)
	r.prefMu.RUnlock()
	if len(pref) == 0 {
		return rotateIndices(max, base)
	}
	seen := make(map[int]struct{}, len(pref))
	ordered := make([]int, 0, max)
	start := 0
	if len(pref) > 0 && max > 0 {
		start = base % len(pref)
	}
	for i := 0; i < len(pref); i++ {
		idx := pref[(start+i)%len(pref)]
		if idx < 0 || idx >= max {
			continue
		}
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		ordered = append(ordered, idx)
	}
	for _, idx := range rotateIndices(max, base) {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		ordered = append(ordered, idx)
	}
	return ordered
}

func (r *registrar) handle(d *device) regResult {
	req := httpRegisterRequest{
		DeviceID: d.id,
		Firmware: defaultFirmware,
		Model:    defaultModel,
		Kid:      hex.EncodeToString(d.kid),
		Pub:      hex.EncodeToString(d.pub),
		Sensors:  []string{"temp", "humidity"},
		Caps:     []string{"push"},
		ChainID:  r.chain,
	}

	delay := discoveryRetry
	order := r.orderFor(d.baseOffset)
	limitHits := 0
	attempts := 0
	blocked := 0
	var earliest time.Time
	now := time.Now()
	var firstBase string
	for _, idx := range order {
		ep := r.endpoints[idx]
		if ep == nil {
			continue
		}
		if firstBase == "" {
			firstBase = ep.base
		}
		if now.Before(ep.retryAt) {
			blocked++
			if earliest.IsZero() || ep.retryAt.Before(earliest) {
				earliest = ep.retryAt
			}
			continue
		}
		resp, err := httpRegisterDevice(context.Background(), r.client, ep.base, req)
		if err != nil {
			log.Printf("register error (%s -> %s): %v", short(d.id), ep.label(), err)
			continue
		}
		attempts++
		if !resp.OK {
			if resp.Error == "iot_limit_reached" {
				delay = joinRetry
				limitHits++
				ep.retryAt = time.Now().Add(joinRetry)
				log.Printf("device=%s cell full for node=%s", short(d.id), ep.label())
				continue
			}
			log.Printf("register rejected (%s -> %s): %s", short(d.id), ep.label(), firstNonEmpty(resp.Message, resp.Error))
			continue
		}
		if len(resp.P2PAddrs) > 0 {
			if newAddrs := r.book.add(resp.P2PAddrs); len(newAddrs) > 0 {
				p2p.ConnectToAddrs(r.host, newAddrs)
			}
		}
		if resp.NodeID != "" {
			if pid, err := peer.Decode(resp.NodeID); err == nil {
				d.assigned = pid
			}
		}
		d.assignedNode = ep.label()
		d.assignedBase = ep.base
		d.registered = true
		d.fallback = false
		if resp.Accepting {
			ep.retryAt = time.Now().Add(discoveryRetry)
		} else {
			ep.retryAt = time.Now().Add(joinRetry)
		}
		d.nextJoin = time.Now().Add(joinRetry)
		return regResult{ok: true, fallback: false, retry: joinRetry}
	}

	if attempts > 0 && limitHits == attempts {
		d.assigned = ""
		d.assignedNode = ""
		if firstBase != "" {
			d.assignedBase = firstBase
		}
		d.registered = true
		d.fallback = true
		d.nextJoin = time.Now().Add(joinRetry)
		log.Printf("device=%s all nodes are full, start send only tx, try connection later", short(d.id))
		return regResult{ok: true, fallback: true, retry: joinRetry}
	}

	if blocked > 0 {
		wait := delay
		if !earliest.IsZero() {
			wait = time.Until(earliest)
			if wait < discoveryRetry {
				wait = discoveryRetry
			}
			if wait > joinRetry {
				wait = joinRetry
			}
		}
		return regResult{ok: false, fallback: false, retry: wait}
	}

	return regResult{ok: false, fallback: false, retry: delay}
}

type nodeCapacity struct {
	idx       int
	label     string
	nodeID    string
	connected int
	max       int
	accepting bool
	addrs     []string
	err       error
}

func runOrchestrator(cfg orchestratorConfig) ([]int, error) {
	ctx := cfg.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.interval <= 0 {
		cfg.interval = 2 * time.Second
	}
	if cfg.refresh <= 0 {
		cfg.refresh = cfg.interval
	}
	if cfg.minNodes <= 0 {
		cfg.minNodes = 1
	}
	if cfg.minAccept <= 0 {
		cfg.minAccept = 1
	}
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	var (
		lastFetch  time.Time
		states     []nodeCapacity
		lastNodes  int
		lastAccept int
	)
	for {
		if states == nil || time.Since(lastFetch) >= cfg.refresh {
			now := time.Now()
			states = fetchCapacities(ctx, cfg.client, cfg.nodes)
			lastFetch = now
			if cfg.book != nil && cfg.host != nil {
				for _, st := range states {
					if st.err != nil || len(st.addrs) == 0 {
						continue
					}
					if newAddrs := cfg.book.add(st.addrs); len(newAddrs) > 0 {
						p2p.ConnectToAddrs(cfg.host, newAddrs)
					}
				}
			}
		}
		success := make([]nodeCapacity, 0, len(states))
		for _, st := range states {
			if st.err == nil {
				success = append(success, st)
			}
		}
		totalNodes := len(success)
		accepting := make([]nodeCapacity, 0, len(success))
		for _, st := range success {
			if st.accepting {
				accepting = append(accepting, st)
			}
		}
		if totalNodes != lastNodes || len(accepting) != lastAccept {
			log.Printf("orchestrator check: nodes=%d accepting=%d devices=%d", totalNodes, len(accepting), cfg.deviceCount)
			lastNodes = totalNodes
			lastAccept = len(accepting)
		}
		if totalNodes >= cfg.minNodes && len(accepting) >= cfg.minAccept && len(accepting) > 0 {
			order := rankNodes(accepting)
			if cfg.reg != nil {
				cfg.reg.setPreferred(order)
			}
			log.Printf("orchestrator ready: using %d nodes", len(order))
			return order, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func rankNodes(nodes []nodeCapacity) []int {
	if len(nodes) == 0 {
		return nil
	}
	copyNodes := append([]nodeCapacity(nil), nodes...)
	sort.Slice(copyNodes, func(i, j int) bool {
		iSlots := slotsLeft(copyNodes[i].max, copyNodes[i].connected)
		jSlots := slotsLeft(copyNodes[j].max, copyNodes[j].connected)
		if iSlots == jSlots {
			return copyNodes[i].label < copyNodes[j].label
		}
		return iSlots > jSlots
	})
	order := make([]int, 0, len(copyNodes))
	for _, st := range copyNodes {
		order = append(order, st.idx)
	}
	return order
}

func slotsLeft(max, connected int) int {
	if max <= 0 {
		return 1 << 20
	}
	if connected >= max {
		return 0
	}
	return max - connected
}

func fetchCapacities(ctx context.Context, client *http.Client, nodes []*nodeEndpoint) []nodeCapacity {
	out := make([]nodeCapacity, len(nodes))
	for i, ep := range nodes {
		out[i] = pullCapacity(ctx, client, ep, i)
	}
	return out
}

func pullCapacity(ctx context.Context, client *http.Client, ep *nodeEndpoint, idx int) nodeCapacity {
	info := nodeCapacity{idx: idx}
	if ep == nil {
		info.err = fmt.Errorf("missing endpoint")
		return info
	}
	info.label = ep.label()
	reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, requestURL(ep.base, "/iot/capacity"), nil)
	if err != nil {
		info.err = err
		return info
	}
	cli := client
	if cli == nil {
		cli = http.DefaultClient
	}
	resp, err := cli.Do(req)
	if err != nil {
		info.err = err
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		info.err = fmt.Errorf("capacity status %s", resp.Status)
		return info
	}
	var payload struct {
		OK        bool     `json:"ok"`
		NodeID    string   `json:"node_id"`
		Connected int      `json:"connected"`
		Max       int      `json:"max_devices"`
		Accepting bool     `json:"accepting"`
		Addrs     []string `json:"p2p_addrs"`
		Error     string   `json:"error"`
		Message   string   `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		info.err = err
		return info
	}
	if !payload.OK {
		msg := firstNonEmpty(payload.Message, payload.Error, "node unavailable")
		info.err = fmt.Errorf(msg)
		return info
	}
	info.nodeID = payload.NodeID
	info.connected = payload.Connected
	info.max = payload.Max
	info.accepting = payload.Accepting
	info.addrs = payload.Addrs
	return info
}

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
