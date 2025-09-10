package dev

import (
    "context"
    "crypto/ed25519"
    crand "crypto/rand"
    "log"
    "sync/atomic"
    "time"

    "github.com/libp2p/go-libp2p/core/host"
    pubsub "github.com/libp2p/go-libp2p-pubsub"

    "pose/internal/coseutil"
    "pose/internal/p2p"
)

// StartDevGenerator publishes synthetic COSE txs periodically.
func StartDevGenerator(ctx context.Context, h host.Host, topic *pubsub.Topic, reuseKey bool, interval time.Duration) {
    var devPriv ed25519.PrivateKey
    var devPub ed25519.PublicKey
    var err error
    if reuseKey {
        devPub, devPriv, err = ed25519.GenerateKey(crand.Reader)
        if err != nil { log.Printf("dev: keygen: %v", err); return }
        kid := coseutil.KidFromPub(devPub)
        coseutil.RegistryRegister(kid, devPub)
        p2p.SetDevAnnouncement(kid, devPub)
        go p2p.SendHelloToAllPeers(ctx, h)
    }
    var nonce uint64
    go func() {
        t := time.NewTicker(interval); defer t.Stop()
        for {
            select { case <-ctx.Done(): return; case <-t.C:
                var p ed25519.PrivateKey; var pub ed25519.PublicKey
                if reuseKey { p, pub = devPriv, devPub } else {
                    pub, p, err = ed25519.GenerateKey(crand.Reader); if err != nil { continue }
                }
                kid := coseutil.KidFromPub(pub)
                coseutil.RegistryRegister(kid, pub)
                b, txid, err := coseutil.BuildDevCOSE(p, kid, h, atomic.AddUint64(&nonce, 1))
                if err != nil { continue }
                if err := topic.Publish(ctx, b); err == nil {
                    log.Printf("dev: published tx %s", txid)
                }
            }
        }
    }()
}

