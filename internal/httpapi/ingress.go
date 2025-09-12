package httpapi

import (
    "context"
    "io"
    "net/http"
    "encoding/json"
    "strconv"
    "strings"
    "crypto/ed25519"
    "encoding/hex"
    "crypto/sha256"
    "time"

    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "github.com/libp2p/go-libp2p/core/host"

    "pose/internal/coseutil"
    "pose/internal/logx"
    "pose/internal/blockchain"
    "pose/internal/mempool"
    "pose/internal/iot"
)

// StartHTTPIngress runs a simple HTTP server that validates COSE txs and publishes them to gossip.
func StartHTTPAPI(ctx context.Context, addr string, txTopic *pubsub.Topic, h host.Host, pool *mempool.Pool, chainID string, devReg *iot.Registry) *http.Server {
    mux := http.NewServeMux()
    mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
        defer r.Body.Close()
        body, err := io.ReadAll(r.Body); if err != nil { http.Error(w, "read error", http.StatusBadRequest); return }
        txid, devID, seq, err := coseutil.ValidateCOSETx(body)
        if err != nil { http.Error(w, "invalid tx", http.StatusBadRequest); return }
        // Do NOT update the replay window here; let mempool admission own it to avoid
        // marking this seq as used before local pubsub delivers to our subscriber.
        if err := txTopic.Publish(ctx, body); err != nil { http.Error(w, "publish failed", http.StatusInternalServerError); return }
        // Best-effort: insert locally as well (duplicate will be ignored by mempool)
        if pool != nil { _, _ = pool.AddValidatedCOSE(body) }
        logx.Info("http accepted", "txid", txid, "dev", devID, "seq", seq)
        w.WriteHeader(http.StatusAccepted)
    })
    // GET /status
    mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
        th, thash := blockchain.GetTip(chainID)
        peers := h.Network().Peers()
        out := map[string]any{"chain_id": chainID, "tip_height": th, "tip_hash": thash, "peers": len(peers), "mempool": pool.Len()}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(out)
    })
    // POST /keys/register {kid: hex, pub: hex}
    mux.HandleFunc("/keys/register", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
        var req struct{ Kid string `json:"kid"`; Pub string `json:"pub"` }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
        kid, err1 := hex.DecodeString(req.Kid)
        pub, err2 := hex.DecodeString(req.Pub)
        if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || len(kid) == 0 { http.Error(w, "bad key", http.StatusBadRequest); return }
        coseutil.RegistryRegister(kid, ed25519.PublicKey(pub))
        w.WriteHeader(http.StatusNoContent)
    })
    // GET /block/{hash}
    mux.HandleFunc("/block/", func(w http.ResponseWriter, r *http.Request) {
        hash := strings.TrimPrefix(r.URL.Path, "/block/")
        if hash == "" { http.NotFound(w, r); return }
        if blk, ok := blockchain.LoadBlockByHash(chainID, hash); ok {
            out := map[string]any{
                "version": blk.Version,
                "chain_id": blk.ChainID,
                "height": blk.Height,
                "prev_hash": hash,
                "timestamp": blk.Timestamp,
                "producer_id": blk.ProducerID,
                "tx_root": blk.TxRoot,
                "hash": hash,
                "txids": blk.TxIDs,
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
        if err != nil { http.Error(w, "bad height", http.StatusBadRequest); return }
        if hash, ok := blockchain.GetHashByHeight(chainID, hgt); ok {
            http.Redirect(w, r, "/block/"+hash, http.StatusTemporaryRedirect)
            return
        }
        http.NotFound(w, r)
    })
    // GET /tx/{txid}
    mux.HandleFunc("/tx/", func(w http.ResponseWriter, r *http.Request) {
        txid := strings.TrimPrefix(r.URL.Path, "/tx/")
        if txid == "" { http.NotFound(w, r); return }
        if hash, height, ok := blockchain.GetBlockByTxID(chainID, txid); ok {
            out := map[string]any{"txid": txid, "block_hash": hash, "height": height}
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(out)
            return
        }
        http.NotFound(w, r)
    })
    // GET /iot/devices
    mux.HandleFunc("/iot/devices", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(devReg.List())
    })
    // POST /iot/register: {device_id, firmware, model, kid, pub, sensors[], caps[]}
    mux.HandleFunc("/iot/register", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
        var req struct{
            DeviceID string `json:"device_id"`
            Firmware string `json:"firmware"`
            Model    string `json:"model"`
            Kid      string `json:"kid"`
            Pub      string `json:"pub"`
            Sensors  []string `json:"sensors"`
            Caps     []string `json:"caps"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
        // basic checks
        if req.DeviceID == "" || req.Kid == "" || req.Pub == "" { http.Error(w, "missing fields", http.StatusBadRequest); return }
        pub, err := hex.DecodeString(req.Pub); if err != nil || len(pub) != ed25519.PublicKeySize { http.Error(w, "bad pub", http.StatusBadRequest); return }
        if _, err := hex.DecodeString(req.Kid); err != nil { http.Error(w, "bad kid", http.StatusBadRequest); return }
        // save in device registry and key registry for tx validation
        // Derive kid from pub (sha256(pub)[:8]) if none, and register for COSE validation
        kid := sha256.Sum256(pub)
        devReg.Upsert(iot.Device{DeviceID: req.DeviceID, Firmware: req.Firmware, Model: req.Model, KidHex: strings.ToLower(hex.EncodeToString(kid[:8])), PubHex: strings.ToLower(req.Pub), Sensors: req.Sensors, Caps: req.Caps, FirstSeen: time.Now(), LastSeen: time.Now()})
        coseutil.RegistryRegister(kid[:8], ed25519.PublicKey(pub))
        w.WriteHeader(http.StatusNoContent)
    })
    srv := &http.Server{Addr: addr, Handler: mux}
    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { logx.Error("http ingress", "err", err) }
    }()
    return srv
}
