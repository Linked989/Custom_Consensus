package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// ──────────── Configuration ────────────

// If true, producers will run forever and ignore -count
const infiniteMode = true

// Number of concurrent producer goroutines generating & queuing transactions.
var parallelProducers = 8

// ──────────── Data types ────────────

type IoTTransaction struct {
	TXID       string                 `json:"txid"`
	DeviceID   string                 `json:"device_id"`
	PublicKey  string                 `json:"public_key"`
	Timestamp  string                 `json:"timestamp"`
	Nonce      uint64                 `json:"nonce"`
	SensorType string                 `json:"sensor_type"`
	SensorData map[string]interface{} `json:"sensor_data"`
	Signature  string                 `json:"signature"`
}

var globalNonce uint64

// ──────────── Helpers ────────────

func generateSensorData() map[string]interface{} {
	return map[string]interface{}{
		"heart_rate":  60 + randInt(0, 40),
		"spo2":        94 + randInt(0, 5),
		"temperature": 36.5 + randFloat(0, 1.0),
		"status":      "stable",
	}
}

func randInt(min, max int) int {
	return min + int(time.Now().UnixNano()%int64(max-min+1))
}

func randFloat(min, max float64) float64 {
	return min + (float64(time.Now().UnixNano()%1e9)/1e9)*(max-min)
}

func encodePublicKey(pub *ecdsa.PublicKey) string {
	return base64.StdEncoding.EncodeToString(
		elliptic.Marshal(pub.Curve, pub.X, pub.Y),
	)
}

func signHash(priv *ecdsa.PrivateKey, hash []byte) (string, error) {
	r, s, err := ecdsa.Sign(crand.Reader, priv, hash)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(r.Bytes(), s.Bytes()...)), nil
}

func computeTXID(tx IoTTransaction) string {
	tmp := tx
	tmp.TXID = ""
	tmp.Signature = ""
	b, _ := json.Marshal(tmp)
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

// ──────────── Producer & Consumer ────────────

// producer generates transactions and pushes them into txCh.
// If infiniteMode, loops forever; otherwise stops after batchCount.
func producer(batchCount int, txCh chan<- IoTTransaction, wg *sync.WaitGroup, workerID int) {
	defer wg.Done()
	if infiniteMode {
		for {
			enqueueTx(txCh, workerID)
		}
	} else {
		for i := 0; i < batchCount; i++ {
			enqueueTx(txCh, workerID)
		}
	}
}

// enqueueTx actually builds, signs, and sends one tx into txCh
func enqueueTx(txCh chan<- IoTTransaction, workerID int) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		log.Fatalf("[producer %d] key gen failed: %v", workerID, err)
	}

	tx := IoTTransaction{
		DeviceID:   "device-" + uuid.NewString(),
		PublicKey:  encodePublicKey(&priv.PublicKey),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Nonce:      atomic.AddUint64(&globalNonce, 1),
		SensorType: "vital_signs",
		SensorData: generateSensorData(),
	}

	tx.TXID = computeTXID(tx)

	tmp := tx
	tmp.Signature = ""
	payload, _ := json.Marshal(tmp)
	sum := sha256.Sum256(payload)
	sig, err := signHash(priv, sum[:])
	if err != nil {
		log.Fatalf("[producer %d] signing failed: %v", workerID, err)
	}
	tx.Signature = sig

	txCh <- tx
}

// consumer drains txCh and posts each tx to the HTTP endpoint, pausing `interval` between sends.
func consumer(txCh <-chan IoTTransaction, client *http.Client, interval time.Duration, done chan<- struct{}) {
	for tx := range txCh {
		if tx.TXID == "" || tx.Signature == "" {
			log.Printf("[consumer] skipping invalid tx")
			continue
		}
		out, _ := json.Marshal(tx)
		req, err := http.NewRequest("POST", "http://localhost:1337/tx", bytes.NewBuffer(out))
		if err != nil {
			log.Fatalf("[consumer] create request failed: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("[consumer] send failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		log.Printf("[consumer] sent txid=%s status=%s", tx.TXID, resp.Status)
		time.Sleep(interval)
	}
	close(done)
}

// ──────────── main ────────────

func main() {
	countPtr := flag.Int("count", 1, "total number of transactions to generate (ignored in infinite mode)")
	intervalPtr := flag.Int("interval", 1000, "delay between sends in milliseconds")
	flag.Parse()

	total := *countPtr
	client := &http.Client{Timeout: 5 * time.Second}

	var prodWg sync.WaitGroup
	txCh := make(chan IoTTransaction, 1000) // buffered channel

	// Launch producers
	prodWg.Add(parallelProducers)
	for i := 0; i < parallelProducers; i++ {
		var batchSize int
		if infiniteMode {
			batchSize = 0 // ignored in infiniteMode
		} else {
			// divide work evenly
			base := total / parallelProducers
			rem := total % parallelProducers
			batchSize = base
			if i < rem {
				batchSize++
			}
		}
		go producer(batchSize, txCh, &prodWg, i+1)
	}

	// Launch consumer
	done := make(chan struct{})
	go consumer(txCh, client, time.Duration(*intervalPtr)*time.Millisecond, done)

	// Wait for producers if not infinite, then close channel
	if !infiniteMode {
		prodWg.Wait()
		close(txCh)
		<-done
		log.Println("All transactions sent.")
	} else {
		// In infinite mode, block forever (Ctrl+C to exit)
		select {}
	}
}
