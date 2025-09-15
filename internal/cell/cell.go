package cell

import (
    "sort"
    "sync"
    "time"

    "pose/internal/iot"
)

// Cell represents a node-local group of IoT devices.
type Cell struct {
    ID         string        `json:"id"`
    NodeID     string        `json:"node_id"`
    ChainID    string        `json:"chain_id"`
    Devices    []iot.Device  `json:"devices"`
    FormedAt   time.Time     `json:"formed_at"`
    Threshold  int           `json:"threshold"`
    MaxDevices int           `json:"max_devices"`
    Active     bool          `json:"active"`
}

type Manager struct {
    mu         sync.Mutex
    chainID    string
    nodeID     string
    threshold  int
    maxDevices int
    cell       *Cell
}

func NewManager(chainID, nodeID string, threshold int, maxDevices int) *Manager {
    return &Manager{chainID: chainID, nodeID: nodeID, threshold: threshold, maxDevices: maxDevices}
}

func (m *Manager) Status() *Cell {
    m.mu.Lock(); defer m.mu.Unlock()
    if m.cell == nil { return &Cell{ID:"", NodeID: m.nodeID, ChainID: m.chainID, Devices: nil, Threshold: m.threshold, MaxDevices: m.maxDevices, Active: false} }
    cpy := *m.cell
    return &cpy
}

// TryForm tries to form a cell from the registry if not active and threshold met.
func (m *Manager) TryForm(reg *iot.Registry) *Cell {
    m.mu.Lock(); defer m.mu.Unlock()
    if m.cell != nil && m.cell.Active { return nil }
    devs := reg.List()
    if len(devs) < m.threshold { return nil }
    // Select devices by FirstSeen up to maxDevices (or threshold if maxDevices==0)
    sort.Slice(devs, func(i, j int) bool { return devs[i].FirstSeen.Before(devs[j].FirstSeen) })
    n := m.threshold
    if m.maxDevices > 0 && m.maxDevices < n { n = m.maxDevices }
    if m.maxDevices > 0 && len(devs) < m.maxDevices && len(devs) >= m.threshold {
        n = len(devs)
    }
    pick := devs[:n]
    c := &Cell{
        ID:       m.nodeID + "-cell-" + time.Now().UTC().Format("20060102T150405Z"),
        NodeID:   m.nodeID,
        ChainID:  m.chainID,
        Devices:  pick,
        FormedAt: time.Now().UTC(),
        Threshold: m.threshold,
        MaxDevices: m.maxDevices,
        Active:   true,
    }
    m.cell = c
    return m.cell
}
