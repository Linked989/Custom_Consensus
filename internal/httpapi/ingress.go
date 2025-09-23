package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
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
	"pose/internal/gossip"
	"pose/internal/helios"
	"pose/internal/iot"
	"pose/internal/logx"
	"pose/internal/mempool"
	"pose/internal/p2p"
	// AION status endpoint disabled here; use blockchain and gossip for status
)

type layerBlockView struct {
	Block  string                  `json:"block"`
	Height int64                   `json:"height"`
	L1     *helios.L1Record        `json:"l1,omitempty"`
	L2     *helios.L2BlockDebug    `json:"l2,omitempty"`
	L3     *helios.L3BlockProgress `json:"l3,omitempty"`
}

// StartHTTPIngress runs a simple HTTP server that validates COSE txs and publishes them to gossip.
// StartHTTPAPI starts the HTTP server. getAION/getHELIOS/getL2/getL3 may be nil; if provided, they should return the current services.
func StartHTTPAPI(ctx context.Context, addr string, txTopic *pubsub.Topic, h host.Host, pool *mempool.Pool, chainID string, dir *gossip.NodeDirectory, reg *iot.Registry, cellMgr *cell.Manager, getAION func() *aion.Service, getHELIOS func() *helios.L1Service, getL2 func() *helios.L2Service, getL3 func() *helios.L3Service) *http.Server {
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
		if dir != nil {
			nodes := dir.List()
			online := 0
			for _, node := range nodes {
				if node.Status == "online" {
					online++
				}
			}
			out["nodes_online"] = online
			out["nodes_known"] = len(nodes)
		}
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
	// GET /network/members: directory of nodes and statuses.
	mux.HandleFunc("/network/members", func(w http.ResponseWriter, r *http.Request) {
		if dir == nil {
			http.Error(w, "directory not available", http.StatusServiceUnavailable)
			return
		}
		resp := map[string]any{
			"nodes":        dir.List(),
			"generated_at": time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	// GET /helios/debug/layers?limit=10
	mux.HandleFunc("/helios/debug/layers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		limit := 10
		if qs := r.URL.Query().Get("limit"); qs != "" {
			if v, err := strconv.Atoi(qs); err == nil && v >= 0 {
				limit = v
			}
		}
		resp := map[string]any{"limit": limit}
		var l1Records []helios.L1Record
		if getHELIOS == nil {
			resp["l1"] = map[string]any{"available": false, "reason": "helios l1 not available"}
		} else if svc := getHELIOS(); svc == nil {
			resp["l1"] = map[string]any{"available": false, "reason": "helios l1 not initialized"}
		} else {
			recs := svc.RecentStatus()
			if limit > 0 && len(recs) > limit {
				recs = recs[:limit]
			}
			l1Records = recs
			resp["l1"] = map[string]any{"available": true, "recent": recs}
		}
		var l2Debug helios.L2DebugState
		var l2Status helios.L2Status
		if getL2 == nil {
			resp["l2"] = map[string]any{"available": false, "reason": "helios l2 not available"}
		} else if svc := getL2(); svc == nil {
			resp["l2"] = map[string]any{"available": false, "reason": "helios l2 not initialized"}
		} else {
			l2Status = svc.Status()
			l2Debug = svc.DebugState(limit)
			resp["l2"] = map[string]any{"available": true, "status": l2Status, "debug": l2Debug}
		}
		var l3Blocks []helios.L3BlockProgress
		if getL3 == nil {
			resp["l3"] = map[string]any{"available": false, "reason": "helios l3 not available"}
		} else if svc := getL3(); svc == nil {
			resp["l3"] = map[string]any{"available": false, "reason": "helios l3 not initialized"}
		} else {
			blocks := svc.Snapshot(limit)
			l3Blocks = blocks
			resp["l3"] = map[string]any{"available": true, "blocks": blocks}
		}
		blockMap := make(map[string]*layerBlockView)
		ensure := func(hash string) *layerBlockView {
			h := strings.ToLower(strings.TrimSpace(hash))
			if h == "" {
				return nil
			}
			if entry, ok := blockMap[h]; ok {
				return entry
			}
			entry := &layerBlockView{Block: h}
			blockMap[h] = entry
			return entry
		}
		for i := range l1Records {
			rec := l1Records[i]
			entry := ensure(rec.Hash)
			if entry == nil {
				continue
			}
			recCopy := rec
			entry.L1 = &recCopy
			if recCopy.Height > entry.Height {
				entry.Height = recCopy.Height
			}
		}
		if l2Debug.Blocks != nil {
			for i := range l2Debug.Blocks {
				blk := l2Debug.Blocks[i]
				entry := ensure(blk.Block)
				if entry == nil {
					continue
				}
				blkCopy := blk
				entry.L2 = &blkCopy
				if blkCopy.Height > entry.Height {
					entry.Height = blkCopy.Height
				}
			}
		}
		for i := range l3Blocks {
			blk := l3Blocks[i]
			entry := ensure(blk.Block)
			if entry == nil {
				continue
			}
			blkCopy := blk
			entry.L3 = &blkCopy
			if blkCopy.Height > entry.Height {
				entry.Height = blkCopy.Height
			}
		}
		combined := make([]layerBlockView, 0, len(blockMap))
		for _, entry := range blockMap {
			combined = append(combined, *entry)
		}
		sort.Slice(combined, func(i, j int) bool {
			if combined[i].Height == combined[j].Height {
				return combined[i].Block < combined[j].Block
			}
			return combined[i].Height > combined[j].Height
		})
		resp["blocks"] = combined
		resp["generated_at"] = time.Now().UTC()
		json.NewEncoder(w).Encode(resp)
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
		cells, deviceVotes, deviceNeeded, deviceTotal, auditsPassed, auditsFailed := svc.MetricsForBlock(blockID)
		resp := map[string]any{
			"block":           blockHex,
			"status":          status.String(),
			"ready":           ready,
			"cells":           cells,
			"device_votes":    deviceVotes,
			"device_required": deviceNeeded,
			"device_total":    deviceTotal,
			"audits_passed":   auditsPassed,
			"audits_failed":   auditsFailed,
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
	// GET /helios/l3/pending
	mux.HandleFunc("/helios/l3/pending", func(w http.ResponseWriter, r *http.Request) {
		if getL3 == nil {
			http.Error(w, "helios l3 not available", http.StatusServiceUnavailable)
			return
		}
		svc := getL3()
		if svc == nil {
			http.Error(w, "helios l3 not initialized", http.StatusServiceUnavailable)
			return
		}
		block, height, votes, required, total, ok := svc.NextPending()
		if !ok {
			http.Error(w, "no pending block", http.StatusNotFound)
			return
		}
		resp := map[string]any{
			"block":    block,
			"height":   height,
			"votes":    votes,
			"required": required,
			"total":    total,
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

	mux.HandleFunc("/iot/capacity", func(w http.ResponseWriter, r *http.Request) {
		if reg == nil {
			http.Error(w, "iot registry disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		count := reg.Count()
		max := reg.Max()
		accepting := max == 0 || count < max
		resp := map[string]any{
			"ok":          true,
			"node_id":     h.ID().String(),
			"connected":   count,
			"max_devices": max,
			"accepting":   accepting,
			"p2p_addrs":   p2p.LocalAddrs(h),
			"timestamp":   time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/iot/register", func(w http.ResponseWriter, r *http.Request) {
		if reg == nil {
			http.Error(w, "iot registry disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			DeviceID string   `json:"device_id"`
			Firmware string   `json:"firmware,omitempty"`
			Model    string   `json:"model,omitempty"`
			Kid      string   `json:"kid,omitempty"`
			Pub      string   `json:"pub"`
			Sensors  []string `json:"sensors,omitempty"`
			Caps     []string `json:"caps,omitempty"`
			ChainID  string   `json:"chain_id,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.DeviceID == "" || req.Pub == "" {
			http.Error(w, "device_id and pub required", http.StatusBadRequest)
			return
		}
		pubBytes, err := hex.DecodeString(req.Pub)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			http.Error(w, "pub must be ed25519 hex", http.StatusBadRequest)
			return
		}
		kidBytes := sha256.Sum256(pubBytes)
		kidHex := strings.ToLower(hex.EncodeToString(kidBytes[:8]))
		if req.Kid != "" && !strings.EqualFold(req.Kid, kidHex) {
			http.Error(w, "kid mismatch", http.StatusBadRequest)
			return
		}
		limit := reg.Max()
		device := iot.Device{
			DeviceID:  req.DeviceID,
			Firmware:  req.Firmware,
			Model:     req.Model,
			KidHex:    kidHex,
			PubHex:    strings.ToLower(req.Pub),
			Sensors:   req.Sensors,
			Caps:      req.Caps,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		if err := reg.UpsertWithLimit(device, limit); err != nil {
			if errors.Is(err, iot.ErrRegistryFull) {
				resp := map[string]any{
					"ok":          false,
					"error":       "iot_limit_reached",
					"message":     "node at capacity",
					"node_id":     h.ID().String(),
					"connected":   reg.Count(),
					"max_devices": limit,
					"accepting":   false,
					"timestamp":   time.Now().UTC(),
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(resp)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		coseutil.RegistryRegister(kidBytes[:8], ed25519.PublicKey(pubBytes))
		count := reg.Count()
		accepting := limit == 0 || count < limit
		resp := map[string]any{
			"ok":          true,
			"node_id":     h.ID().String(),
			"connected":   count,
			"max_devices": limit,
			"accepting":   accepting,
			"p2p_addrs":   p2p.LocalAddrs(h),
			"timestamp":   time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/iot/attest", func(w http.ResponseWriter, r *http.Request) {
		if reg == nil {
			http.Error(w, "iot registry disabled", http.StatusServiceUnavailable)
			return
		}
		if getL3 == nil {
			http.Error(w, "helios l3 not available", http.StatusServiceUnavailable)
			return
		}
		svc := getL3()
		if svc == nil {
			http.Error(w, "helios l3 not initialized", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			DeviceID string `json:"device_id"`
			Block    string `json:"block"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.DeviceID == "" || req.Block == "" {
			http.Error(w, "device_id and block required", http.StatusBadRequest)
			return
		}
		if dev, ok := reg.Get(req.DeviceID); !ok {
			if iot.IsL3Attester(req.DeviceID) {
				now := time.Now()
				dev := iot.Device{
					DeviceID:  req.DeviceID,
					Firmware:  "attester",
					Model:     "l3-attester",
					Caps:      []string{"attest"},
					FirstSeen: now,
					LastSeen:  now,
				}
				if err := reg.UpsertWithLimit(dev, 0); err != nil {
					logx.Warn("auto-register attester failed", "device", req.DeviceID, "err", err)
					http.Error(w, "device registration failed", http.StatusInternalServerError)
					return
				}
				if svc != nil {
					svc.UpdateDeviceTotal(iot.CountAttesters(reg))
				}
			} else {
				http.Error(w, "device not registered", http.StatusNotFound)
				return
			}
		} else if iot.IsL3Attester(req.DeviceID) {
			dev.LastSeen = time.Now()
			if err := reg.UpsertWithLimit(dev, 0); err != nil {
				logx.Warn("attester heartbeat update failed", "device", req.DeviceID, "err", err)
			}
		}
		blockID, err := hex.DecodeString(strings.ToLower(req.Block))
		if err != nil {
			http.Error(w, "bad block", http.StatusBadRequest)
			return
		}
		votes, required, total, recorded := svc.RecordDeviceAttestation(blockID, req.DeviceID)
		resp := map[string]any{
			"ok":       recorded,
			"votes":    votes,
			"required": required,
			"total":    total,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/iot/devices", func(w http.ResponseWriter, r *http.Request) {
		if reg == nil {
			http.Error(w, "iot registry disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		list := reg.List()
		sort.Slice(list, func(i, j int) bool { return list[i].DeviceID < list[j].DeviceID })
		resp := map[string]any{
			"ok":          true,
			"node_id":     h.ID().String(),
			"devices":     list,
			"connected":   len(list),
			"max_devices": reg.Max(),
			"timestamp":   time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logx.Error("http ingress", "err", err)
		}
	}()
	return srv
}
