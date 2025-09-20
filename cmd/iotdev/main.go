package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

// Deterministic CBOR mode (matches server).
var encMode cbor.EncMode

func init() {
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	encMode = em
	rand.Seed(time.Now().UnixNano())
}

const joinRetry = 5 * time.Minute

var errCellFull = errors.New("cell full")

type device struct {
	id         string
	pub        ed25519.PublicKey
	priv       ed25519.PrivateKey
	kid        []byte
	seq        uint64
	assigned   string
	nextJoin   time.Time
	baseOffset int
}

func main() {
	// Flags
	base := flag.String("base", "http://localhost:14000", "default base URL (no trailing slash); used for TX unless -tx-base provided")
	txBase := flag.String("tx-base", "", "HTTP base URL to POST /tx and /keys/register (defaults to -base)")
	regBasesCSV := flag.String("reg-bases", "", "comma-separated HTTP base URLs for /iot/register assignment (defaults to -base)")
	regCapsCSV := flag.String("reg-caps", "", "comma-separated caps per -reg-bases (0=unlimited). Example: 3,0 means first base gets up to 3, rest unlimited on second")
	chain := flag.String("chain", "iotnet-main", "chain/network id")
	n := flag.Int("devices", 5, "number of simulated devices")
	interval := flag.Duration("interval", 1500*time.Millisecond, "send interval per device")
	jitter := flag.Duration("jitter", 500*time.Millisecond, "random jitter added to interval")
	once := flag.Bool("once", false, "send just one reading per device then exit")
	list := flag.Bool("list", false, "list devices connected to the node and exit")
	flag.Parse()

	// Context and signals
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *list {
		if err := listDevices(ctx, *base); err != nil {
			log.Fatalf("list: %v", err)
		}
		return
	}

	// Resolve TX and registration bases
	regBases := parseCSV(*regBasesCSV)
	if len(regBases) == 0 {
		regBases = []string{strings.TrimRight(*base, "/")}
	}
	if *txBase == "" {
		*txBase = strings.TrimRight(*base, "/")
	} else {
		*txBase = strings.TrimRight(*txBase, "/")
	}
	regCaps := parseCaps(*regCapsCSV, len(regBases))

	// Create devices and register
	devs := make([]device, *n)
	assign := planAssignments(*n, regBases, regCaps)
	baseIndex := make(map[string]int)
	for i, b := range regBases {
		baseIndex[b] = i
	}
	for i := 0; i < *n; i++ {
		pub, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			log.Fatalf("keygen: %v", err)
		}
		kid := kidFromPub(pub)
		id := fmt.Sprintf("did:iot:SIM-%x", kid)
		offset := baseIndex[assign[i]]
		devs[i] = device{id: id, pub: pub, priv: priv, kid: kid, seq: 0, nextJoin: time.Now(), baseOffset: offset}
		keyTarget := *txBase
		if keyTarget == "" && len(regBases) > 0 {
			keyTarget = regBases[offset%len(regBases)]
		}
		if keyTarget != "" {
			if err := registerKey(ctx, keyTarget, devs[i]); err != nil {
				log.Fatalf("register key %d at %s: %v", i+1, keyTarget, err)
			}
		}
	}
	log.Printf("initialized %d devices (preferred=%v)", *n, summarizeAssignments(assign))
	for i := range devs {
		if len(regBases) == 0 {
			continue
		}
		if attemptJoin(ctx, &devs[i], regBases) {
			log.Printf("device=%s joined %s", short(devs[i].id), devs[i].assigned)
		} else {
			devs[i].nextJoin = time.Now().Add(joinRetry)
			log.Printf("device=%s tx-only until %s", short(devs[i].id), devs[i].nextJoin.Format(time.RFC3339))
		}
	}

	// Start senders
	var wg sync.WaitGroup
	for i := range devs {
		wg.Add(1)
		go func(d *device) {
			defer wg.Done()
			cli := &http.Client{Timeout: 5 * time.Second}
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if len(regBases) > 0 && d.assigned == "" && time.Now().After(d.nextJoin) {
					if attemptJoin(ctx, d, regBases) {
						log.Printf("device=%s joined %s", short(d.id), d.assigned)
					} else {
						d.nextJoin = time.Now().Add(joinRetry)
						log.Printf("device=%s retry join at %s", short(d.id), d.nextJoin.Format(time.RFC3339))
					}
				}
				sendBase := d.assigned
				if sendBase == "" {
					sendBase = *txBase
				}
				if sendBase == "" && len(regBases) > 0 {
					sendBase = regBases[d.baseOffset%len(regBases)]
				}
				if sendBase == "" {
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				d.seq++
				cose, txid, err := buildCOSE(d.priv, d.kid, *chain, d.id, d.seq)
				if err != nil {
					log.Printf("build error (%s): %v", d.id, err)
					continue
				}
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, sendBase+"/tx", bytes.NewReader(cose))
				req.Header.Set("Content-Type", "application/cbor")

				resp, err := doHTTPWithRetry(ctx, cli, req)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return
					}
					log.Printf("send failed (%s -> %s): %v", short(d.id), sendBase, err)
					markForRejoin(d, sendBase)
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
					continue
				}
				io.Copy(io.Discard, resp.Body)
				status := resp.StatusCode
				resp.Body.Close()
				if status >= 500 {
					log.Printf("send failed (%s -> %s): status=%s", short(d.id), sendBase, http.StatusText(status))
					markForRejoin(d, sendBase)
					continue
				}
				if status >= 300 {
					log.Printf("send warning (%s -> %s): status=%s", short(d.id), sendBase, resp.Status)
				}
				log.Printf("sent device=%s txid=%s status=%s", short(d.id), txid[:12], resp.Status)

				if *once {
					return
				}
				delay := *interval + time.Duration(rand.Int63n(int64(*jitter)))
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
		}(&devs[i])
	}

	wg.Wait()
}

func registerDevice(ctx context.Context, base string, d device) error {
	base = strings.TrimRight(base, "/")
	// HTTP: POST /iot/register {device_id, firmware, model, kid, pub}
	body := fmt.Sprintf(`{"device_id":"%s","firmware":"1.0.0","model":"sim-sensor","kid":"%s","pub":"%s","sensors":["temp","humidity"],"caps":["push"]}`,
		d.id, hex.EncodeToString(d.kid), hex.EncodeToString(d.pub))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/iot/register", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 5 * time.Second}

	resp, err := doHTTPWithRetry(ctx, cli, req)
	if err != nil {
		return err
	}
	payload, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		var msg struct {
			Error      string `json:"error"`
			Message    string `json:"message"`
			MaxDevices int    `json:"max_devices"`
			Connected  int    `json:"connected"`
		}
		if len(payload) > 0 && json.Unmarshal(payload, &msg) == nil {
			log.Printf("node %s full (connected=%d max=%d)", base, msg.Connected, msg.MaxDevices)
		} else if len(payload) > 0 {
			log.Printf("node %s full: %s", base, strings.TrimSpace(string(payload)))
		}
		return errCellFull
	}
	if resp.StatusCode >= 300 {
		if len(payload) > 0 {
			return fmt.Errorf("status %s body=%s", resp.Status, strings.TrimSpace(string(payload)))
		}
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func registerKey(ctx context.Context, base string, d device) error {
	// HTTP: POST /keys/register {kid: hex, pub: hex}
	body := fmt.Sprintf(`{"kid":"%s","pub":"%s"}`, hex.EncodeToString(d.kid), hex.EncodeToString(d.pub))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/keys/register", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 5 * time.Second}

	resp, err := doHTTPWithRetry(ctx, cli, req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

type capacityInfo struct {
	NodeID     string    `json:"node_id"`
	Connected  int       `json:"connected"`
	MaxDevices int       `json:"max_devices"`
	Accepting  bool      `json:"accepting"`
	Timestamp  time.Time `json:"timestamp"`
}

func fetchCapacity(ctx context.Context, base string) (capacityInfo, error) {
	base = strings.TrimRight(base, "/")
	url := base + "/iot/capacity"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return capacityInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return capacityInfo{NodeID: base, Accepting: true}, nil
	}
	if resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return capacityInfo{}, fmt.Errorf("capacity status %s", resp.Status)
	}
	var info capacityInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return capacityInfo{}, err
	}
	if info.NodeID == "" {
		info.NodeID = base
	}
	if info.MaxDevices > 0 && info.Connected >= info.MaxDevices {
		info.Accepting = false
	} else if info.MaxDevices == 0 {
		info.Accepting = true
	}
	return info, nil
}

func rotateBases(bases []string, offset int) []string {
	l := len(bases)
	if l == 0 {
		return nil
	}
	out := make([]string, l)
	for i := 0; i < l; i++ {
		idx := (offset + i) % l
		out[i] = strings.TrimRight(bases[idx], "/")
	}
	return out
}

func attemptJoin(ctx context.Context, d *device, bases []string) bool {
	order := rotateBases(bases, d.baseOffset)
	for _, base := range order {
		info, err := fetchCapacity(ctx, base)
		if err != nil {
			log.Printf("capacity check failed (%s): %v", base, err)
			continue
		}
		if !info.Accepting {
			continue
		}
		if err := registerDevice(ctx, base, *d); err != nil {
			if errors.Is(err, errCellFull) {
				continue
			}
			log.Printf("register failed (%s -> %s): %v", short(d.id), base, err)
			continue
		}
		if err := registerKey(ctx, base, *d); err != nil {
			log.Printf("register key failed (%s -> %s): %v", short(d.id), base, err)
			continue
		}
		if d.assigned != "" && d.assigned != base {
			leaveNode(ctx, d.assigned, *d)
		}
		d.assigned = base
		d.nextJoin = time.Now().Add(joinRetry)
		return true
	}
	return false
}

func leaveNode(ctx context.Context, base string, d device) {
	base = strings.TrimRight(base, "/")
	endpoint := base + "/iot/session/" + neturl.PathEscape(d.id)
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	cli := &http.Client{Timeout: 3 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func markForRejoin(d *device, base string) {
	if d.assigned == base {
		d.assigned = ""
		d.nextJoin = time.Now()
	}
}

func listDevices(ctx context.Context, base string) error {
	cli := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/iot/devices", nil)
	resp, err := doHTTPWithRetry(ctx, cli, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %s", resp.Status)
	}
	io.Copy(os.Stdout, resp.Body)
	return nil
}

// --- Retry machinery ---

func retryable(resp *http.Response, err error) bool {
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) {
			return true // timeouts, temporary, etc.
		}
		msg := strings.ToLower(err.Error())
		// Canonical dial/transport failures worth retrying.
		if strings.Contains(msg, "connection refused") ||
			strings.Contains(msg, "dial tcp") ||
			strings.Contains(msg, "no such host") ||
			strings.Contains(msg, "connection reset") ||
			strings.Contains(msg, "tls handshake timeout") ||
			strings.Contains(msg, "server misbehaving") {
			return true
		}
		return false
	}
	// Retry on 425/429/5xx
	if resp.StatusCode == 425 || resp.StatusCode == 429 || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
		return true
	}
	return false
}

func doHTTPWithRetry(ctx context.Context, cli *http.Client, req *http.Request) (*http.Response, error) {
	const (
		base   = 500 * time.Millisecond
		max    = 30 * time.Second
		factor = 2.0
	)
	backoff := base

	for attempt := 0; ; attempt++ {
		// Ensure the request carries the latest context on each attempt.
		r := req.Clone(ctx)
		resp, err := cli.Do(r)
		if !retryable(resp, err) {
			return resp, err
		}
		// Drain/close on retry to free connection.
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		log.Printf("retrying %s %s (attempt=%d, next=%s): %s",
			req.Method, req.URL.String(), attempt+1, backoff, errOrStatus(err, resp))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff + time.Duration(rand.Int63n(int64(backoff/2)))):
		}

		// Exponential backoff with cap.
		next := time.Duration(float64(backoff) * factor)
		if next > max {
			next = max
		}
		backoff = next
	}
}

func errOrStatus(err error, resp *http.Response) string {
	if err != nil {
		return err.Error()
	}
	if resp != nil {
		return resp.Status
	}
	return "unknown"
}

// --- Payload/COSE ---

func buildCOSE(priv ed25519.PrivateKey, kid []byte, chain string, deviceID string, seq uint64) ([]byte, string, error) {
	payload := map[int]interface{}{
		0: int64(1),
		1: chain,
		2: "data",
		3: map[int]interface{}{0: deviceID, 1: "1.0.0", 2: "ed25519:SIM"},
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

// --- Misc helpers ---

func kidFromPub(pub ed25519.PublicKey) []byte { sum := sha256.Sum256(pub); return sum[:8] }

func randBytes(n int) []byte { b := make([]byte, n); io.ReadFull(crand.Reader, b); return b }

func short(s string) string {
	if len(s) > 12 {
		return s[len(s)-12:]
	}
	return s
}

// parseCSV splits a comma-separated list and trims empties/spaces.
func parseCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, strings.TrimRight(p, "/"))
	}
	return out
}

// parseCaps parses caps CSV into a slice of length n (or 0s if empty).
func parseCaps(s string, n int) []int {
	if strings.TrimSpace(s) == "" {
		return make([]int, n)
	}
	parts := strings.Split(s, ",")
	caps := make([]int, n)
	for i := 0; i < n; i++ {
		if i < len(parts) {
			v := strings.TrimSpace(parts[i])
			if v == "" {
				caps[i] = 0
				continue
			}
			var val int
			_, err := fmt.Sscanf(v, "%d", &val)
			if err != nil {
				val = 0
			}
			if val < 0 {
				val = 0
			}
			caps[i] = val
		} else {
			caps[i] = 0
		}
	}
	return caps
}

// planAssignments returns a per-device chosen registration base URL,
// honoring caps (0 = unlimited). Devices are assigned in order, filling
// the first base up to its cap, then the next, etc.
func planAssignments(n int, bases []string, caps []int) []string {
	assign := make([]string, n)
	counts := make([]int, len(bases))
	for i := 0; i < n; i++ {
		chosen := -1
		for j := 0; j < len(bases); j++ {
			if caps[j] == 0 || counts[j] < caps[j] {
				chosen = j
				break
			}
		}
		if chosen == -1 {
			chosen = len(bases) - 1
		}
		assign[i] = bases[chosen]
		counts[chosen]++
	}
	return assign
}

// summarizeAssignments prints counts per base for logging.
func summarizeAssignments(assign []string) map[string]int {
	counts := map[string]int{}
	for _, b := range assign {
		counts[b]++
	}
	return counts
}
