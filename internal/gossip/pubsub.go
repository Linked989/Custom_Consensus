package gossip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"

	"pose/internal/blockchain"
	"pose/internal/coseutil"
	"pose/internal/logx"
	"pose/internal/mempool"
)

// InitPubSub sets up GossipSub with a content-based message ID.
func InitPubSub(ctx context.Context, h host.Host) (*pubsub.PubSub, error) {
	return pubsub.NewGossipSub(ctx, h, pubsub.WithMessageIdFn(func(m *pb.Message) string {
		sum := sha256.Sum256(m.GetData())
		return hex.EncodeToString(sum[:])
	}))
}

// MemberSet tracks heartbeat membership with TTL.
type MemberSet struct {
	Mu   sync.Mutex
	Last map[string]time.Time
	TTL  time.Duration
}

func NewMemberSet(ttl time.Duration) *MemberSet {
	return &MemberSet{Last: make(map[string]time.Time), TTL: ttl}
}
func (m *MemberSet) Touch(id string) {
	m.Mu.Lock()
	m.Last[id] = time.Now()
	m.Mu.Unlock()
}
func (m *MemberSet) CountAndSweep() int {
	now := time.Now()
	m.Mu.Lock()
	for id, t := range m.Last {
		if now.Sub(t) > m.TTL {
			delete(m.Last, id)
		}
	}
	n := len(m.Last)
	m.Mu.Unlock()
	return n
}

// StartHeartbeat joins a topic, subscribes, logs, and publishes periodic heartbeats.
func StartHeartbeat(ctx context.Context, h host.Host, ps *pubsub.PubSub, topicName string, interval, ttl time.Duration, logHeartbeats bool) (*MemberSet, *pubsub.Topic, error) {
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, nil, err
	}
	members := NewMemberSet(ttl)
	members.Touch(h.ID().String())
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			if msg.ReceivedFrom == h.ID() {
				continue
			}
			if logHeartbeats {
				logx.Debug("heartbeat", "from", msg.ReceivedFrom.String(), "msg", strings.TrimSpace(string(msg.Message.GetData())))
			}
			members.Touch(msg.ReceivedFrom.String())
		}
	}()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				payload := "heartbeat " + h.ID().String() + " " + time.Now().UTC().Format(time.RFC3339Nano)
				_ = topic.Publish(ctx, []byte(payload))
				members.Touch(h.ID().String())
			}
		}
	}()
	return members, topic, nil
}

// StartTxGossip subscribes to tx topic, validates and optionally forwards.
func StartTxGossip(ctx context.Context, ps *pubsub.PubSub, topicName string, bridgeURL string) (*pubsub.Topic, error) {
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	seen := struct {
		Mu sync.Mutex
		M  map[string]time.Time
	}{M: make(map[string]time.Time)}
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			txid, devID, kid, seq, err := coseutil.ValidateCOSETx(msg.Message.GetData())
			if err != nil {
				logx.Debug("tx invalid", "err", err)
				continue
			}
			if !coseutil.UpdateLastSeq(devID, kid, seq) {
				continue
			}
			seen.Mu.Lock()
			if _, ok := seen.M[txid]; ok {
				seen.Mu.Unlock()
				continue
			}
			seen.M[txid] = time.Now()
			seen.Mu.Unlock()
			logx.Info("tx accepted", "txid", txid, "dev", devID, "seq", seq, "from", msg.ReceivedFrom.String())
			if bridgeURL != "" {
				go forwardCOSE(bridgeURL, msg.Message.GetData())
			}
		}
	}()
	return topic, nil
}

// StartTxGossipToPool is like StartTxGossip but inserts validated txs into the provided mempool.
func StartTxGossipToPool(ctx context.Context, h host.Host, ps *pubsub.PubSub, topicName string, bridgeURL string, pool *mempool.Pool, logTx bool) (*pubsub.Topic, error) {
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	// seen is still used to avoid re-processing duplicates excessively
	seen := struct {
		Mu sync.Mutex
		M  map[string]time.Time
	}{M: make(map[string]time.Time)}
	type retryTx struct {
		Data     []byte
		Attempts int
	}
	const maxRetry = 5
	retries := make(chan retryTx, 256)
	process := func(data []byte, sender string, viaRetry bool) (bool, bool) {
		e, err := pool.AddValidatedCOSE(data)
		if err != nil {
			reason := err.Error()
			unknown := strings.Contains(reason, "unknown kid")
			if unknown {
				// try to fetch the missing key via libp2p block sync
				if kid, kerr := coseutil.ExtractKid(data); kerr == nil {
					fetchCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
					_ = blockchain.FetchAndRegisterKey(fetchCtx, h, kid)
					cancel()
					// re-attempt admission after fetch
					if _, err2 := pool.AddValidatedCOSE(data); err2 == nil {
						unknown = false
						if logTx {
							logx.Info("tx accepted after key fetch", "from", sender)
						}
						return true, false
					}
				}
			}
			if logTx {
				if reason == "replay" || reason == "duplicate" {
					logx.Debug("tx skipped", "reason", reason, "from", sender)
				} else {
					logx.Warn("tx rejected", "reason", reason, "from", sender, "retrying", unknown && !viaRetry)
				}
			}
			if unknown && !viaRetry {
				copyData := append([]byte(nil), data...)
				select {
				case retries <- retryTx{Data: copyData, Attempts: 1}:
				default:
				}
			}
			return false, unknown
		}
		seen.Mu.Lock()
		if _, ok := seen.M[e.TxID]; ok {
			seen.Mu.Unlock()
			return true, false
		}
		seen.M[e.TxID] = time.Now()
		seen.Mu.Unlock()
		if logTx {
			logx.Info("tx accepted", "txid", e.TxID, "dev", e.DevID, "seq", e.Seq, "from", sender)
		}
		// if devID, dataPart, ok := entropy.ExtractDevIDAndData(data); ok {
		// 	var decoded interface{}
		// 	if err := cbor.Unmarshal(dataPart, &decoded); err == nil {
		// 		jsReady := normalizeForJSON(decoded)
		// 		if js, err2 := json.Marshal(jsReady); err2 == nil {
		// 			logx.Info("\x1b[1mIOT DATA RECEIVED\x1b[0m", "device", devID, "payload", string(js))
		// 		} else {
		// 			logx.Info("\x1b[1mIOT DATA RECEIVED\x1b[0m", "device", devID, "payload_err", err2.Error())
		// 		}
		// 	} else {
		// 		logx.Info("\x1b[1mIOT DATA RECEIVED\x1b[0m", "device", devID, "payload_hex", hex.EncodeToString(dataPart))
		// 	}
		// }
		if bridgeURL != "" {
			go forwardCOSE(bridgeURL, data)
		}
		return true, false
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rt := <-retries:
				if len(rt.Data) == 0 {
					continue
				}
				sleep := time.Duration(rt.Attempts) * 150 * time.Millisecond
				if sleep > 750*time.Millisecond {
					sleep = 750 * time.Millisecond
				}
				timer := time.NewTimer(sleep)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				success, unknown := process(rt.Data, "retry", true)
				if !success && unknown && rt.Attempts < maxRetry {
					rt.Attempts++
					select {
					case retries <- rt:
					default:
					}
				}
			}
		}
	}()
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			process(msg.Message.GetData(), msg.ReceivedFrom.String(), false)
		}
	}()
	return topic, nil
}

func forwardCOSE(url string, cose []byte) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(cose)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/cbor")
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func normalizeForJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[k] = normalizeForJSON(vv)
		}
		return out
	case map[int]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[fmt.Sprintf("%d", k)] = normalizeForJSON(vv)
		}
		return out
	case map[int64]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[fmt.Sprintf("%d", k)] = normalizeForJSON(vv)
		}
		return out
	case map[uint64]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[fmt.Sprintf("%d", k)] = normalizeForJSON(vv)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[fmt.Sprint(k)] = normalizeForJSON(vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i := range val {
			out[i] = normalizeForJSON(val[i])
		}
		return out
	default:
		return v
	}
}
