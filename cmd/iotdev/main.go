package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
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

type device struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	kid  []byte
	seq  uint64
}

func main() {
	// Flags
	base := flag.String("base", "http://localhost:14000", "gateway base URL (no trailing slash)")
	chain := flag.String("chain", "iotnet-main", "chain/network id")
	n := flag.Int("devices", 5, "number of simulated devices")
	interval := flag.Duration("interval", 1500*time.Millisecond, "send interval per device")
	jitter := flag.Duration("jitter", 500*time.Millisecond, "random jitter added to interval")
	once := flag.Bool("once", false, "send just one reading per device then exit")
	flag.Parse()

	// Context and signals
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Create devices and register
	devs := make([]device, *n)
	for i := 0; i < *n; i++ {
		pub, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			log.Fatalf("keygen: %v", err)
		}
		kid := kidFromPub(pub)
		id := fmt.Sprintf("did:iot:SIM-%x", kid)
		devs[i] = device{id: id, pub: pub, priv: priv, kid: kid, seq: 0}
		if err := registerDevice(*base, devs[i]); err != nil {
			log.Fatalf("register %d: %v", i+1, err)
		}
	}
	log.Printf("registered %d devices", *n)

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
				// Build COSE tx and POST /tx
				d.seq++
				cose, txid, err := buildCOSE(d.priv, d.kid, *chain, d.id, d.seq)
				if err != nil {
					log.Printf("build error (%s): %v", d.id, err)
					return
				}
				req, _ := http.NewRequest(http.MethodPost, *base+"/tx", bytes.NewReader(cose))
				req.Header.Set("Content-Type", "application/cbor")
				resp, err := cli.Do(req)
				if err != nil {
					log.Printf("post error (%s): %v", d.id, err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				log.Printf("sent device=%s txid=%s status=%s", short(d.id), txid[:12], resp.Status)
				if *once {
					return
				}
				// Sleep with jitter
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

func registerDevice(base string, d device) error {
	// HTTP: POST /iot/register {device_id, firmware, model, kid, pub}
	body := fmt.Sprintf(`{"device_id":"%s","firmware":"1.0.0","model":"sim-sensor","kid":"%s","pub":"%s","sensors":["temp","humidity"],"caps":["push"]}`,
		d.id, hex.EncodeToString(d.kid), hex.EncodeToString(d.pub))
	req, _ := http.NewRequest(http.MethodPost, base+"/iot/register", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
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

func kidFromPub(pub ed25519.PublicKey) []byte { sum := sha256.Sum256(pub); return sum[:8] }
func randBytes(n int) []byte                  { b := make([]byte, n); io.ReadFull(crand.Reader, b); return b }
func short(s string) string {
	if len(s) > 12 {
		return s[len(s)-12:]
	}
	return s
}
