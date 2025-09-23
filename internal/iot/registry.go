package iot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IotProto is retained for compatibility with tooling that still references the
// legacy libp2p registration flow. Servers no longer listen on this protocol.
const IotProto = "/pose/iot/1.0.0"

// L3AttesterPrefix identifies dedicated L3 attester device IDs.
const L3AttesterPrefix = "did:iot:l3_attester_"

// IsL3Attester reports whether the provided device ID belongs to an L3 attester.
func IsL3Attester(id string) bool {
	trim := strings.TrimSpace(id)
	if trim == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(trim), L3AttesterPrefix)
}

// CountAttesters returns the number of L3 attesters in the registry.
func CountAttesters(reg *Registry) int {
	if reg == nil {
		return 0
	}
	count := 0
	for _, dev := range reg.List() {
		if IsL3Attester(dev.DeviceID) {
			count++
		}
	}
	return count
}

// Hello mirrors the historical libp2p registration payload so existing clients
// can reuse the struct when calling HTTP registration.
type Hello struct {
	Type     string   `json:"type"`
	ChainID  string   `json:"chain_id"`
	DeviceID string   `json:"device_id"`
	Firmware string   `json:"firmware"`
	Model    string   `json:"model"`
	Kid      string   `json:"kid"`
	Pub      string   `json:"pub"`
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
}

type Registry struct {
	mu      sync.Mutex
	chainID string
	byID    map[string]Device
	max     int
}

// ErrRegistryFull indicates the node cannot accept more device registrations.
var ErrRegistryFull = errors.New("iot registry full")

func NewRegistry(chainID string) *Registry {
	r := &Registry{chainID: chainID, byID: make(map[string]Device)}
	_ = r.load()
	return r
}

// SetMax updates the maximum allowed devices (0 = unlimited).
func (r *Registry) SetMax(max int) {
	r.mu.Lock()
	r.max = max
	r.mu.Unlock()
}

// Max returns the configured device limit.
func (r *Registry) Max() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
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

// UpsertWithLimit inserts or updates a device entry while enforcing the
// provided maximum count. Use -1 to inherit registry default; 0 skips limits.
func (r *Registry) UpsertWithLimit(d Device, max int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Use registry default only when explicitly requested with -1
	if max < 0 {
		max = r.max
	}

	if prev, ok := r.byID[d.DeviceID]; ok {
		// Existing device - always allow updates
		if d.FirstSeen.IsZero() {
			d.FirstSeen = prev.FirstSeen
		}
	} else {
		// New device - check capacity if limit is set
		if max > 0 && len(r.byID) >= max {
			return ErrRegistryFull
		}
		if d.FirstSeen.IsZero() {
			d.FirstSeen = time.Now()
		}
	}

	if d.LastSeen.IsZero() {
		d.LastSeen = time.Now()
	}
	r.byID[d.DeviceID] = d
	return r.saveLocked()
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
