package iot

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// IotProto is the libp2p stream protocol for device→gateway registration.
const IotProto = "/pose/iot/1.0.0"

// Hello is the device registration message.
// Sent as one JSON line on a new stream to IotProto.
type Hello struct {
	Type     string   `json:"type"` // "iot_hello"
	ChainID  string   `json:"chain_id"`
	DeviceID string   `json:"device_id"`
	Firmware string   `json:"firmware"`
	Model    string   `json:"model"`
	Kid      string   `json:"kid"` // hex of key id (e.g., sha256(pub)[:8])
	Pub      string   `json:"pub"` // hex ed25519 public key
	Sensors  []string `json:"sensors,omitempty"`
	Caps     []string `json:"caps,omitempty"`
}

type Device struct {
	DeviceID  string    `json:"device_id"`
	Firmware  string    `json:"firmware"`
	Model     string    `json:"model"`
	KidHex    string    `json:"kid"`
	PubHex    string    `json:"pub"`
	Sensors   []string  `json:"sensors,omitempty"`
	Caps      []string  `json:"caps,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	PeerID    string    `json:"peer_id"`
}

type Registry struct {
	mu      sync.Mutex
	chainID string
	byID    map[string]Device
}

func NewRegistry(chainID string) *Registry {
	r := &Registry{chainID: chainID, byID: make(map[string]Device)}
	_ = r.load()
	return r
}

// List returns a snapshot of registered devices.
func (r *Registry) List() []Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Device, 0, len(r.byID))
	for _, d := range r.byID {
		out = append(out, d)
	}
	return out
}

// Count returns the number of active device records.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

// Get returns the stored device if present.
func (r *Registry) Get(deviceID string) (Device, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.byID[deviceID]
	return d, ok
}

// Remove deletes the device entry if present.
func (r *Registry) Remove(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, deviceID)
	_ = r.saveLocked()
}

// Upsert adds or updates a device entry.
func (r *Registry) Upsert(d Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, ok := r.byID[d.DeviceID]
	if ok {
		d.FirstSeen = prev.FirstSeen
		if d.PeerID == "" {
			d.PeerID = prev.PeerID
		}
	} else if d.FirstSeen.IsZero() {
		d.FirstSeen = time.Now()
	}
	if d.LastSeen.IsZero() {
		d.LastSeen = time.Now()
	}
	r.byID[d.DeviceID] = d
	_ = r.saveLocked()
}

// RegisterIotHandler installs a libp2p handler that accepts IoT hello messages.
func RegisterIotHandler(h host.Host, reg *Registry) {
	h.SetStreamHandler(IotProto, func(s network.Stream) {
		defer s.Close()
		rd := bufio.NewReader(s)
		line, _ := rd.ReadString('\n')
		var msg Hello
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &msg) != nil || msg.Type != "iot_hello" {
			return
		}
		if reg.chainID != "" && msg.ChainID != "" && msg.ChainID != reg.chainID {
			_ = s.Close()
			return
		}
		// Basic sanity on key material.
		if _, err := hex.DecodeString(msg.Kid); err != nil {
			return
		}
		if _, err := hex.DecodeString(msg.Pub); err != nil {
			return
		}
		reg.Upsert(Device{
			DeviceID:  msg.DeviceID,
			Firmware:  msg.Firmware,
			Model:     msg.Model,
			KidHex:    strings.ToLower(msg.Kid),
			PubHex:    strings.ToLower(msg.Pub),
			Sensors:   msg.Sensors,
			Caps:      msg.Caps,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			PeerID:    peer.ID(s.Conn().RemotePeer()).String(),
		})
		// ack
		_, _ = s.Write([]byte("ok\n"))
	})
}

// ---- persistence ----
var dataDir string

// SetDataDir configures the root directory where devices.json will be stored.
func SetDataDir(dir string) error {
	dataDir = dir
	return os.MkdirAll(dir, 0o755)
}

func (r *Registry) path() string { return filepath.Join(dataDir, r.chainID, "devices.json") }

func (r *Registry) saveLocked() error {
	if dataDir == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path()), 0o755); err != nil {
		return err
	}
	by, _ := json.MarshalIndent(r.byID, "", "  ")
	return os.WriteFile(r.path(), by, 0o644)
}

func (r *Registry) load() error {
	if dataDir == "" {
		return nil
	}
	by, err := os.ReadFile(r.path())
	if err != nil {
		return err
	}
	var m map[string]Device
	if err := json.Unmarshal(by, &m); err != nil {
		return err
	}
	r.byID = m
	return nil
}
