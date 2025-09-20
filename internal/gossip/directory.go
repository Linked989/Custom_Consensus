package gossip

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"

	"pose/internal/logx"
)

type NodeInfo struct {
	NodeID   string    `json:"node_id"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
}

type NodeDirectory struct {
	mu    sync.Mutex
	ttl   time.Duration
	nodes map[string]NodeInfo
}

func NewNodeDirectory(ttl time.Duration) *NodeDirectory {
	return &NodeDirectory{ttl: ttl, nodes: make(map[string]NodeInfo)}
}

func (d *NodeDirectory) Mark(nodeID, status string) {
	d.mu.Lock()
	d.nodes[nodeID] = NodeInfo{NodeID: nodeID, Status: status, LastSeen: time.Now().UTC()}
	d.mu.Unlock()
}

func (d *NodeDirectory) Sweep() {
	if d.ttl <= 0 {
		return
	}
	cutoff := time.Now().UTC().Add(-d.ttl)
	d.mu.Lock()
	for id, info := range d.nodes {
		if info.LastSeen.Before(cutoff) && info.Status != "offline" {
			info.Status = "offline"
			info.LastSeen = time.Now().UTC()
			d.nodes[id] = info
		}
	}
	d.mu.Unlock()
}

func (d *NodeDirectory) List() []NodeInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]NodeInfo, 0, len(d.nodes))
	for _, info := range d.nodes {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Status == out[j].Status {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].Status < out[j].Status
	})
	return out
}

type nodeStatusMsg struct {
	NodeID    string `json:"node_id"`
	Status    string `json:"status"`
	Timestamp int64  `json:"ts_unix_ms"`
}

func StartNodeDirectory(ctx context.Context, h host.Host, ps *pubsub.PubSub, topic string, ttl time.Duration) (*NodeDirectory, *pubsub.Topic, error) {
	t, err := ps.Join(topic)
	if err != nil {
		return nil, nil, err
	}
	sub, err := t.Subscribe()
	if err != nil {
		return nil, nil, err
	}
	dir := NewNodeDirectory(ttl)
	dir.Mark(h.ID().String(), "online")
	go func() {
		interval := ttl / 2
		if interval <= 0 {
			interval = 5 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dir.Sweep()
			}
		}
	}()
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			var payload nodeStatusMsg
			if err := json.Unmarshal(msg.Message.GetData(), &payload); err != nil {
				logx.Debug("node directory message decode failed", "err", err)
				continue
			}
			if payload.NodeID == "" || payload.Status == "" {
				continue
			}
			dir.Mark(payload.NodeID, payload.Status)
		}
	}()
	return dir, t, nil
}

func PublishNodeStatus(ctx context.Context, topic *pubsub.Topic, nodeID, status string) error {
	if topic == nil || nodeID == "" || status == "" {
		return nil
	}
	msg := nodeStatusMsg{NodeID: nodeID, Status: status, Timestamp: time.Now().UTC().UnixMilli()}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return topic.Publish(ctx, payload)
}
