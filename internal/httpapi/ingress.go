package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"

	"pose/internal/aion"
	"pose/internal/blockchain"
	"pose/internal/cell"
	"pose/internal/coseutil"
	"pose/internal/entropy"
	"pose/internal/helios"
	"pose/internal/iot"
	"pose/internal/logx"
	"pose/internal/mempool"
	// AION status endpoint disabled here; use blockchain and gossip for status
)

// StartHTTPIngress runs a simple HTTP server that validates COSE txs and publishes them to gossip.
// StartHTTPAPI starts the HTTP server. getAION/getHELIOS/getL2/getL3 may be nil; if provided, they should return the current services.
func StartHTTPAPI(ctx context.Context, addr string, txTopic *pubsub.Topic, h host.Host, pool *mempool.Pool, chainID string, devReg *iot.Registry, cellMgr *cell.Manager, getAION func() *aion.Service, getHELIOS func() *helios.L1Service, getL2 func() *helios.L2Service, getL3 func() *helios.L3Service) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		txid, devID, seq, err := coseutil.ValidateCOSETx(body)
		if err != nil {
			http.Error(w, "invalid tx", http.StatusBadRequest)
			return
		}
		// Do NOT update the replay window here; let mempool admission own it to avoid
		// marking this seq as used before local pubsub delivers to our subscriber.
		if err := txTopic.Publish(ctx, body); err != nil {
			http.Error(w, "publish failed", http.StatusInternalServerError)
			return
		}
		// Best-effort: insert locally as well (duplicate will be ignored by mempool)
		if pool != nil {
			_, _ = pool.AddValidatedCOSE(body)
		}
		logx.Info("http accepted", "txid", txid, "dev", devID, "seq", seq)
		w.WriteHeader(http.StatusAccepted)
	})
	// GET /status
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		th, thash := blockchain.GetTip(chainID)
		peers := h.Network().Peers()
		out := map[string]any{"chain_id": chainID, "tip_height": th, "tip_hash": thash, "peers": len(peers), "mempool": pool.Len()}
		if getL2 != nil {
			if svc := getL2(); svc != nil {
				st := svc.Status()
				out["l2_status"] = st
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	// GET /blocks?n=20 — list recent block hashes
	mux.HandleFunc("/blocks", func(w http.ResponseWriter, r *http.Request) {
		n := 20
		if qs := r.URL.Query().Get("n"); qs != "" {
			if v, err := strconv.Atoi(qs); err == nil && v > 0 {
				n = v
			}
		}
		lst := blockchain.ListRecentHashes(chainID, n)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"blocks": lst})
	})
	// POST /keys/register {kid: hex, pub: hex}
	mux.HandleFunc("/keys/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Kid string `json:"kid"`
			Pub string `json:"pub"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		kid, err1 := hex.DecodeString(req.Kid)
		pub, err2 := hex.DecodeString(req.Pub)
		if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || len(kid) == 0 {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		coseutil.RegistryRegister(kid, ed25519.PublicKey(pub))
		w.WriteHeader(http.StatusNoContent)
	})
	// GET /block/{hash}
	mux.HandleFunc("/block/", func(w http.ResponseWriter, r *http.Request) {
		hash := strings.TrimPrefix(r.URL.Path, "/block/")
		if hash == "" {
			http.NotFound(w, r)
			return
		}
		if blk, ok := blockchain.LoadBlockByHash(chainID, hash); ok {
			out := map[string]any{
				"version":     blk.Version,
				"chain_id":    blk.ChainID,
				"height":      blk.Height,
				"prev_hash":   strings.ToLower(hex.EncodeToString(blk.PrevHash)),
				"timestamp":   blk.Timestamp,
				"producer_id": blk.ProducerID,
				"tx_root":     blk.TxRoot,
				"hash":        strings.ToLower(hash),
				"txids":       blk.TxIDs,
				"l1_attestations": func() []string {
					if len(blk.L1Attestations) == 0 {
						return nil
					}
					out := make([]string, len(blk.L1Attestations))
					for i := range blk.L1Attestations {
						out[i] = hex.EncodeToString(blk.L1Attestations[i])
					}
					return out
				}(),
			}
			// Augment with live HELIOS attestations if service available
			if getHELIOS != nil {
				svc := getHELIOS()
				if svc != nil {
					if hh, err := hex.DecodeString(hash); err == nil {
						infos := svc.GetAttestationInfos(hh, 0)
						out["l1_attestations_live_count"] = len(infos)
						out["l1_attestations_live"] = infos
						// If none live and block did not embed attestations for its parent,
						// try to surface attestations embedded by the child block (height+1)
						if len(infos) == 0 && len(blk.L1Attestations) == 0 {
							if h2, ok := blockchain.GetHashByHeight(chainID, blk.Height+1); ok {
								if child, ok := blockchain.LoadBlockByHash(chainID, h2); ok {
									// Ensure this block is indeed the parent
									if bytes.Equal(child.PrevHash, blk.Hash) && len(child.L1Attestations) > 0 {
										// Decode using HELIOS' decoder for consistency
										emb := svc.DecodeRawAttestations(child.L1Attestations, 0)
										if len(emb) > 0 {
											out["l1_attestations_embedded_from_child"] = emb
										}
									}
								}
							}
						}
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
			return
		}
		http.NotFound(w, r)
	})
	// GET /block/height/{h}
	mux.HandleFunc("/block/height/", func(w http.ResponseWriter, r *http.Request) {
		hs := strings.TrimPrefix(r.URL.Path, "/block/height/")
		hgt, err := strconv.ParseInt(hs, 10, 64)
		if err != nil {
			http.Error(w, "bad height", http.StatusBadRequest)
			return
		}
		if hash, ok := blockchain.GetHashByHeight(chainID, hgt); ok {
			http.Redirect(w, r, "/block/"+hash, http.StatusTemporaryRedirect)
			return
		}
		http.NotFound(w, r)
	})
	// GET /tx/{txid}
	mux.HandleFunc("/tx/", func(w http.ResponseWriter, r *http.Request) {
		txid := strings.TrimPrefix(r.URL.Path, "/tx/")
		if txid == "" {
			http.NotFound(w, r)
			return
		}
		if hash, height, ok := blockchain.GetBlockByTxID(chainID, txid); ok {
			out := map[string]any{"txid": txid, "block_hash": hash, "height": height}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
			return
		}
		http.NotFound(w, r)
	})
	// GET /cell/status
	mux.HandleFunc("/cell/status", func(w http.ResponseWriter, r *http.Request) {
		st := cellMgr.Status()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st)
	})
	// GET /cell/entropy: recompute entropy now and return summary + per-device breakdown
	mux.HandleFunc("/cell/entropy", func(w http.ResponseWriter, r *http.Request) {
		st := cellMgr.Status()
		resp := map[string]any{
			"cell_active": st.Active,
			"cell_id":     st.ID,
			"devices":     len(st.Devices),
		}
		entries := pool.Snapshot()
		score, used := entropy.ComputeCellEntropy(st, entries)
		per := entropy.ComputePerDeviceEntropy(st, entries)
		resp["entropy_bits_per_byte"] = score
		resp["tx_samples"] = used
		resp["per_device"] = per
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	// GET /aion/status: network election status snapshot
	mux.HandleFunc("/aion/status", func(w http.ResponseWriter, r *http.Request) {
		if getAION == nil {
			http.Error(w, "aion not available", http.StatusServiceUnavailable)
			return
		}
		svc := getAION()
		if svc == nil {
			http.Error(w, "aion not initialized", http.StatusServiceUnavailable)
			return
		}
		st := svc.GetNetStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st)
	})
	// GET /helios/status: recent notarization info
	mux.HandleFunc("/helios/status", func(w http.ResponseWriter, r *http.Request) {
		if getHELIOS == nil {
			http.Error(w, "helios not available", http.StatusServiceUnavailable)
			return
		}
		svc := getHELIOS()
		if svc == nil {
			http.Error(w, "helios not initialized", http.StatusServiceUnavailable)
			return
		}
		recs := svc.RecentStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"recent": recs})
	})
	// GET /helios/l2/status: checkpoint/quorum diagnostics
	mux.HandleFunc("/helios/l2/status", func(w http.ResponseWriter, r *http.Request) {
		if getL2 == nil {
			http.Error(w, "helios l2 not available", http.StatusServiceUnavailable)
			return
		}
		svc := getL2()
		if svc == nil {
			http.Error(w, "helios l2 not initialized", http.StatusServiceUnavailable)
			return
		}
		st := svc.Status()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st)
	})
	// GET /helios/l3/status?block=<hex>
	mux.HandleFunc("/helios/l3/status", func(w http.ResponseWriter, r *http.Request) {
		if getL3 == nil {
			http.Error(w, "helios l3 not available", http.StatusServiceUnavailable)
			return
		}
		svc := getL3()
		if svc == nil {
			http.Error(w, "helios l3 not initialized", http.StatusServiceUnavailable)
			return
		}
		blockHex := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("block")))
		if blockHex == "" {
			http.Error(w, "missing block", http.StatusBadRequest)
			return
		}
		blockID, err := hex.DecodeString(blockHex)
		if err != nil {
			http.Error(w, "bad block", http.StatusBadRequest)
			return
		}
		status := svc.QueryL3Status(blockID)
		ready := svc.IsL3Ready(blockID)
		cells, regions, auditsPassed, auditsFailed := svc.MetricsForBlock(blockID)
		resp := map[string]any{
			"block":         blockHex,
			"status":        status.String(),
			"ready":         ready,
			"cells":         cells,
			"regions":       regions,
			"audits_passed": auditsPassed,
			"audits_failed": auditsFailed,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	// GET /helios/l3/envelope?block=<hex>
	mux.HandleFunc("/helios/l3/envelope", func(w http.ResponseWriter, r *http.Request) {
		if getL3 == nil {
			http.Error(w, "helios l3 not available", http.StatusServiceUnavailable)
			return
		}
		svc := getL3()
		if svc == nil {
			http.Error(w, "helios l3 not initialized", http.StatusServiceUnavailable)
			return
		}
		blockHex := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("block")))
		if blockHex == "" {
			http.Error(w, "missing block", http.StatusBadRequest)
			return
		}
		blockID, err := hex.DecodeString(blockHex)
		if err != nil {
			http.Error(w, "bad block", http.StatusBadRequest)
			return
		}
		env, err := svc.GetFinalityEnvelope(blockID)
		if err != nil {
			http.Error(w, "envelope not found", http.StatusNotFound)
			return
		}
		desc := make([]map[string]any, 0, len(env.DescendantQCs))
		for _, qc := range env.DescendantQCs {
			signers := make([]string, 0, len(qc.Signers))
			for _, sgn := range qc.Signers {
				signers = append(signers, strings.ToLower(hex.EncodeToString(sgn)))
			}
			desc = append(desc, map[string]any{
				"block":      strings.ToLower(hex.EncodeToString(qc.BlockID)),
				"height":     qc.Height,
				"epoch":      qc.Epoch,
				"weight":     qc.Weight,
				"signers":    signers,
				"created_at": qc.CreatedAt,
			})
		}
		resp := map[string]any{
			"block":          blockHex,
			"height":         env.Height,
			"horizon":        env.Horizon,
			"cells":          env.CellBitmap,
			"regions":        env.RegionBitmap,
			"finalized_at":   env.FinalizedAt,
			"descendant_qcs": desc,
		}
		if len(env.CellAggSig) > 0 {
			resp["cell_agg_sig"] = strings.ToLower(hex.EncodeToString(env.CellAggSig))
		}
		if len(env.ValidatorAggSig) > 0 {
			resp["validator_agg_sig"] = strings.ToLower(hex.EncodeToString(env.ValidatorAggSig))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	// GET /helios/l3/overview?limit=10
	mux.HandleFunc("/helios/l3/overview", func(w http.ResponseWriter, r *http.Request) {
		if getL3 == nil {
			http.Error(w, "helios l3 not available", http.StatusServiceUnavailable)
			return
		}
		svc := getL3()
		if svc == nil {
			http.Error(w, "helios l3 not initialized", http.StatusServiceUnavailable)
			return
		}
		limit := 0
		if qs := r.URL.Query().Get("limit"); qs != "" {
			if v, err := strconv.Atoi(qs); err == nil && v > 0 {
				limit = v
			}
		}
		blocks := svc.Snapshot(limit)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"blocks": blocks})
	})
	// GET /iot/devices
	mux.HandleFunc("/iot/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(devReg.List())
	})
	// POST /iot/register: {device_id, firmware, model, kid, pub, sensors[], caps[]}
	mux.HandleFunc("/iot/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			DeviceID string   `json:"device_id"`
			Firmware string   `json:"firmware"`
			Model    string   `json:"model"`
			Kid      string   `json:"kid"`
			Pub      string   `json:"pub"`
			Sensors  []string `json:"sensors"`
			Caps     []string `json:"caps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		// basic checks
		if req.DeviceID == "" || req.Kid == "" || req.Pub == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}
		pub, err := hex.DecodeString(req.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			http.Error(w, "bad pub", http.StatusBadRequest)
			return
		}
		if _, err := hex.DecodeString(req.Kid); err != nil {
			http.Error(w, "bad kid", http.StatusBadRequest)
			return
		}
		// save in device registry and key registry for tx validation
		// Derive kid from pub (sha256(pub)[:8]) if none, and register for COSE validation
		kid := sha256.Sum256(pub)
		devReg.Upsert(iot.Device{DeviceID: req.DeviceID, Firmware: req.Firmware, Model: req.Model, KidHex: strings.ToLower(hex.EncodeToString(kid[:8])), PubHex: strings.ToLower(req.Pub), Sensors: req.Sensors, Caps: req.Caps, FirstSeen: time.Now(), LastSeen: time.Now()})
		coseutil.RegistryRegister(kid[:8], ed25519.PublicKey(pub))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logx.Error("http ingress", "err", err)
		}
	}()
	return srv
}
