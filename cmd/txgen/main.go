package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

// Deterministic CBOR modes
var encMode cbor.EncMode

func init() {
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	encMode = em
}

func main() {
	url := flag.String("url", "http://localhost:14000/tx", "HTTP /tx endpoint")
	count := flag.Int("count", 10, "number of txs to send")
	interval := flag.Duration("interval", 200*time.Millisecond, "delay between txs")
	register := flag.Bool("register", true, "register pubkey via /keys/register before sending")
	chain := flag.String("chain", "iotnet-main", "chain id label for device DID")
	flag.Parse()

	// Keypair and kid
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	kid := kidFromPub(pub)

	if *register {
		regURL := replacePath(*url, "/keys/register")
		body := fmt.Sprintf("{\"kid\":\"%s\",\"pub\":\"%s\"}", hex.EncodeToString(kid), hex.EncodeToString(pub))
		if err := doPostJSON(regURL, []byte(body)); err != nil {
			log.Fatalf("register: %v", err)
		}
		log.Printf("registered pubkey kid=%s", hex.EncodeToString(kid))
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < *count; i++ {
		cose, txid, err := buildCOSE(priv, kid, *chain, uint64(i+1))
		if err != nil {
			log.Fatalf("build: %v", err)
		}
		req, _ := http.NewRequest(http.MethodPost, *url, bytes.NewReader(cose))
		req.Header.Set("Content-Type", "application/cbor")
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("post: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		log.Printf("sent txid=%s status=%s", txid, resp.Status)
		time.Sleep(*interval)
	}
}

func kidFromPub(pub ed25519.PublicKey) []byte { sum := sha256.Sum256(pub); return sum[:8] }

func replacePath(url, path string) string {
	// naive: replace trailing /tx with the given path
	if len(url) >= 3 && url[len(url)-3:] == "/tx" {
		return url[:len(url)-3] + path
	}
	return url + path
}

func doPostJSON(url string, body []byte) error {
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
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

// buildCOSE builds a COSE_Sign1 (tag 18) with Ed25519 matching server validation.
func buildCOSE(priv ed25519.PrivateKey, kid []byte, chain string, seq uint64) ([]byte, string, error) {
	// payload map
	payload := map[int]interface{}{
		0: int64(1),
		1: chain,
		2: "data",
		3: map[int]interface{}{0: fmt.Sprintf("did:iot:EXT-%x", kid), 1: "1.0.0", 2: "ed25519:EXT"},
		4: int64(seq),
		5: time.Now().UTC(),
		6: map[int]interface{}{0: int64(25), 1: "uCR"},
		7: []interface{}{randBytes(7), randBytes(7)},
		8: map[int]interface{}{
			0: "urn:example:sensor:v1",
			1: map[string]interface{}{"temp_c": 21.5, "humidity": 0.45},
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

	// protected headers {1:-8, 4:kid}
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

func randBytes(n int) []byte { b := make([]byte, n); io.ReadFull(crand.Reader, b); return b }
