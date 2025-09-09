package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	bls "github.com/kilic/bls12-381"
)

/*────────────  Data types  ────────────*/

type IoTDevice struct {
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name"`
	SensorType  string    `json:"sensor_type"`
	SensorValue []float64 `json:"sensor_value"`
	Timestamp   string    `json:"timestamp"`

	PrivKey *bls.Fr      // secret scalar
	PubKey  *bls.PointG1 // public point
}

type BlockchainTx struct {
	TxID       string          `json:"txid"`
	DeviceID   string          `json:"device_id"`
	PublicKey  string          `json:"public_key"` // base64 uncompressed ECDSA key
	Timestamp  string          `json:"timestamp"`
	Nonce      int             `json:"nonce"`
	SensorType string          `json:"sensor_type"`
	SensorData json.RawMessage `json:"sensor_data"`
	Signature  string          `json:"signature"` // base64(r||s)
}

type Block struct {
	Index            int            `json:"index"`
	ProposerDeviceID string         `json:"proposer_device_id"`
	Timestamp        string         `json:"timestamp"`
	Transactions     []BlockchainTx `json:"transactions"`
	PreviousHash     string         `json:"previous_hash"`
	Nonce            int            `json:"nonce"`
	Hash             string         `json:"hash"`

	GroupSignature  string   `json:"group_signature"`
	SignerMemberIDs []string `json:"signer_member_ids"`
}

/*────────────  Parameters  ────────────*/

const (
	maxGroupSize        = 15
	mempoolBufSize      = 1000000
	listenAddr          = ":1337"
	slotDuration        = 400 * time.Millisecond
	fullGroupValidation = false
)

/*────────────  main  ────────────*/

func main() {
	devs, err := loadAndKeygenDevices("iot_devices.json")
	if err != nil {
		log.Fatalf("load devices: %v", err)
	}
	log.Printf("Loaded %d devices (with BLS keys)", len(devs))

	groups := chunkDevices(devs, maxGroupSize)
	leaderGrp := pickEntropyLeader(groups)
	log.Printf("Entropy-leader is Group %02d", leaderGrp+1)

	g1 := bls.NewG1()
	groupPub := g1.Zero()
	for _, d := range groups[leaderGrp] {
		g1.Add(groupPub, groupPub, d.PubKey)
	}

	mempools := make([]chan BlockchainTx, len(groups))
	for i := range groups {
		mempools[i] = make(chan BlockchainTx, mempoolBufSize)
		if i == leaderGrp {
			go leaderWorker(i, groups[i], mempools[i], groupPub)
		}
	}

	http.HandleFunc("/tx", handleTxFanout(mempools))
	log.Printf("Listening on %s/tx …", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

/*────────────  Load + BLS keygen  ────────────*/

func loadAndKeygenDevices(path string) ([]IoTDevice, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []IoTDevice
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	g1 := bls.NewG1()
	for i := range out {
		sk := bls.NewFr()
		sk.Rand(crand.Reader)
		pk := g1.New()
		g1.MulScalar(pk, g1.One(), sk)
		out[i].PrivKey, out[i].PubKey = sk, pk
	}
	return out, nil
}

/*────────────  HTTP fan-out  ────────────*/

func handleTxFanout(pools []chan BlockchainTx) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var tx BlockchainTx
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}
		for _, ch := range pools {
			select {
			case ch <- tx:
			default:
				log.Printf("⚠️ mempool full, dropped %s", tx.TxID)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

/*────────────  Leader Worker ────────────*/

func leaderWorker(
	grpIdx int,
	grp []IoTDevice,
	pool <-chan BlockchainTx,
	grpPub *bls.PointG1,
) {
	prevHash := "0"
	blockIdx := 1
	proposer := 0
	log.Printf("[Group %02d] initial proposer %s", grpIdx+1, grp[proposer].DeviceID)

	pending := make([]BlockchainTx, 0, mempoolBufSize)
	go func() {
		for tx := range pool {
			pending = append(pending, tx)
		}
	}()

	g2 := bls.NewG2()
	g1 := bls.NewG1()
	engine := bls.NewEngine()
	ticker := time.NewTicker(slotDuration)
	defer ticker.Stop()

	for range ticker.C {
		proposer = (proposer + 1) % len(grp)
		inbound := pending
		pending = make([]BlockchainTx, 0, mempoolBufSize)

		var validTxs []BlockchainTx
		dropped := 0
		for _, tx := range inbound {
			// 1) TXID match
			if computeTXID(tx) != tx.TxID {
				dropped++
				continue
			}
			// 2) ECDSA signature validation
			if fullGroupValidation {
				ok := true
				for _, d := range grp {
					if d.DeviceID == grp[proposer].DeviceID {
						continue
					}
					if err := validateTxSignature(tx); err != nil {
						ok = false
						break
					}
				}
				if !ok {
					dropped++
					continue
				}
			} else {
				if err := validateTxSignature(tx); err != nil {
					dropped++
					continue
				}
			}
			validTxs = append(validTxs, tx)
		}

		blk := Block{
			Index:            blockIdx,
			ProposerDeviceID: grp[proposer].DeviceID,
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			Transactions:     validTxs,
			PreviousHash:     prevHash,
			Nonce:            mrand.Int(),
		}
		blk.Hash = hashBlock(blk)

		msg, _ := g2.HashToCurve([]byte(blk.Hash), []byte("BLS_SIG"))
		agg := g2.New()
		for i, d := range grp {
			sig := g2.New()
			g2.MulScalar(sig, msg, d.PrivKey)
			if i == 0 {
				agg = sig
			} else {
				tmp := g2.New()
				g2.Add(tmp, agg, sig)
				agg = tmp
			}
			blk.SignerMemberIDs = append(blk.SignerMemberIDs, d.DeviceID)
		}
		blk.GroupSignature = hex.EncodeToString(g2.ToCompressed(agg))

		engine.Reset()
		engine.AddPair(grpPub, msg)
		engine.AddPairInv(g1.One(), agg)
		verified := engine.Check()

		txCount := len(validTxs)
		tps := float64(txCount) / slotDuration.Seconds()
		log.Printf(
			"[SUMMARY] Group=%02d Proposer=%s Block=%d Accepted=%d Dropped=%d Sigs=%d TPS=%.2f Valid=%v",
			grpIdx+1,
			grp[proposer].DeviceID,
			blockIdx,
			txCount,
			dropped,
			len(grp),
			tps,
			verified,
		)

		prevHash = blk.Hash
		blockIdx++
	}
}

/*────────────  Helpers ────────────*/

// computeTXID replicates the sender’s TXID logic
func computeTXID(tx BlockchainTx) string {
	tmp := tx
	tmp.TxID = "" // correct field name
	tmp.Signature = ""
	b, _ := json.Marshal(tmp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validateTxSignature(tx BlockchainTx) error {
	// 1) rebuild signing hash (txid present, signature cleared)
	tmp := tx
	tmp.Signature = ""
	payload, _ := json.Marshal(tmp)
	hash := sha256.Sum256(payload)

	// 2) decode public key
	pubBytes, err := base64.StdEncoding.DecodeString(tx.PublicKey)
	if err != nil {
		return err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if x == nil {
		return errors.New("invalid public key")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// 3) decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
	if err != nil {
		return err
	}

	var r, s *big.Int
	switch len(sigBytes) {
	case 64: // fast-path: raw 32 + 32 concat
		r = new(big.Int).SetBytes(sigBytes[:32])
		s = new(big.Int).SetBytes(sigBytes[32:])
	default: // fallback: treat as ASN.1 DER
		var esig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sigBytes, &esig); err != nil {
			return errors.New("bad signature format")
		}
		r, s = esig.R, esig.S
	}

	// 4) verify
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("signature mismatch")
	}
	return nil
}

func chunkDevices(devs []IoTDevice, sz int) [][]IoTDevice {
	mrand.Shuffle(len(devs), func(i, j int) { devs[i], devs[j] = devs[j], devs[i] })
	var out [][]IoTDevice
	for len(devs) > 0 {
		end := sz
		if len(devs) < end {
			end = len(devs)
		}
		out, devs = append(out, devs[:end]), devs[end:]
	}
	return out
}

func pickEntropyLeader(grps [][]IoTDevice) int {
	best, idx := -math.MaxFloat64, 0
	for i, g := range grps {
		if e := entropy(g); e > best {
			best, idx = e, i
		}
	}
	return idx
}

func entropy(g []IoTDevice) float64 {
	var flat []float64
	for _, d := range g {
		flat = append(flat, d.SensorValue...)
	}
	if len(flat) < 2 {
		return 0
	}
	n := float64(len(flat))
	var sum float64
	for _, v := range flat {
		sum += v
	}
	mean := sum / n
	var sq float64
	for _, v := range flat {
		d := v - mean
		sq += d * d
	}
	variance := sq / (n - 1)
	return 0.5 * math.Log(2*math.Pi*math.E*variance)
}

func hashBlock(b Block) string {
	var ids []string
	for _, t := range b.Transactions {
		ids = append(ids, t.TxID)
	}
	pre := b.PreviousHash + b.Timestamp + strings.Join(ids, "") + strconv.Itoa(b.Nonce)
	sum := sha256.Sum256([]byte(pre))
	return hex.EncodeToString(sum[:])
}
