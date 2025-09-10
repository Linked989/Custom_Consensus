package httpapi

import (
    "context"
    "io"
    "net/http"

    pubsub "github.com/libp2p/go-libp2p-pubsub"

    "pose/internal/coseutil"
    "pose/internal/logx"
)

// StartHTTPIngress runs a simple HTTP server that validates COSE txs and publishes them to gossip.
func StartHTTPIngress(ctx context.Context, addr string, txTopic *pubsub.Topic) *http.Server {
    mux := http.NewServeMux()
    mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
        defer r.Body.Close()
        body, err := io.ReadAll(r.Body); if err != nil { http.Error(w, "read error", http.StatusBadRequest); return }
        txid, devID, seq, err := coseutil.ValidateCOSETx(body)
        if err != nil { http.Error(w, "invalid tx", http.StatusBadRequest); return }
        if !coseutil.UpdateLastSeq(devID, seq) { http.Error(w, "replay", http.StatusBadRequest); return }
        if err := txTopic.Publish(ctx, body); err != nil { http.Error(w, "publish failed", http.StatusInternalServerError); return }
        logx.Info("http accepted", "txid", txid, "dev", devID, "seq", seq)
        w.WriteHeader(http.StatusAccepted)
    })
    srv := &http.Server{Addr: addr, Handler: mux}
    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { logx.Error("http ingress", "err", err) }
    }()
    return srv
}
