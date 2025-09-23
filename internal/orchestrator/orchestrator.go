package orchestrator

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"

	"pose/internal/cell"
	"pose/internal/gossip"
	"pose/internal/iot"
	"pose/internal/logx"
)

// Config holds orchestrator wiring inputs.
type Config struct {
	Context       context.Context
	Host          host.Host
	Members       *gossip.MemberSet
	Directory     *gossip.NodeDirectory
	Registry      *iot.Registry
	Cells         *cell.Manager
	CellThreshold int
	MinNodes      int
	MinPeers      int
	Interval      time.Duration
	RegisterCell  func(*cell.Cell)
}

// Orchestrator monitors network/device state and triggers cell formation when viable.
type Orchestrator struct {
	ctx         context.Context
	cancel      context.CancelFunc
	conf        Config
	readyOnce   sync.Once
	readyCh     chan struct{}
	lastNodes   int
	lastPeers   int
	lastDevices int
	lastReady   bool
}

// Start launches the orchestrator loop.
func Start(conf Config) *Orchestrator {
	ctx := conf.Context
	if ctx == nil {
		ctx = context.Background()
	}
	loopCtx, cancel := context.WithCancel(ctx)
	if conf.Interval <= 0 {
		conf.Interval = 2 * time.Second
	}
	if conf.MinNodes <= 0 {
		conf.MinNodes = 3
	}
	if conf.MinPeers < 0 {
		conf.MinPeers = 0
	}
	orch := &Orchestrator{
		ctx:     loopCtx,
		cancel:  cancel,
		conf:    conf,
		readyCh: make(chan struct{}),
	}
	go orch.run()
	return orch
}

// Stop terminates the orchestrator loop.
func (o *Orchestrator) Stop() {
	o.cancel()
}

// Ready returns when min nodes/devices thresholds are satisfied.
func (o *Orchestrator) Ready() <-chan struct{} {
	return o.readyCh
}

func (o *Orchestrator) run() {
	ticker := time.NewTicker(o.conf.Interval)
	defer ticker.Stop()
	for {
		snap := o.snapshot()
		o.process(snap)
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type snapshot struct {
	nodes   int
	dir     int
	peers   int
	devices int
	max     int
	ready   bool
}

func (o *Orchestrator) snapshot() snapshot {
	peers := 0
	if o.conf.Host != nil {
		peers = len(o.conf.Host.Network().Peers())
	}
	nodes := 0
	if o.conf.Members != nil {
		nodes = o.conf.Members.CountAndSweep()
	}
	directoryNodes := 0
	if o.conf.Directory != nil {
		infos := o.conf.Directory.List()
		for _, info := range infos {
			if strings.EqualFold(info.Status, "offline") {
				continue
			}
			directoryNodes++
		}
		if directoryNodes > nodes {
			nodes = directoryNodes
		}
	}
	devices := 0
	max := 0
	if o.conf.Registry != nil {
		devices = o.conf.Registry.Count()
		max = o.conf.Registry.Max()
	}
	nodeReady := nodes >= o.conf.MinNodes || peers >= o.conf.MinPeers
	ready := nodeReady && devices >= o.conf.CellThreshold
	return snapshot{nodes: nodes, dir: directoryNodes, peers: peers, devices: devices, max: max, ready: ready}
}

func (o *Orchestrator) process(s snapshot) {
	if s.devices >= o.conf.CellThreshold && o.conf.Cells != nil && o.conf.Registry != nil {
		if cell := o.conf.Cells.TryForm(o.conf.Registry); cell != nil && cell.Active {
			if o.conf.RegisterCell != nil {
				o.conf.RegisterCell(cell)
			}
			logx.Info("orchestrator cell formed", "id", cell.ID, "devices", len(cell.Devices))
		}
	}
	if s.ready {
		o.readyOnce.Do(func() {
			logx.Info("orchestrator ready", "nodes_seen", s.nodes, "peers_connected", s.peers, "devices", s.devices, "cell_threshold", o.conf.CellThreshold)
			close(o.readyCh)
		})
	}
	if s.nodes != o.lastNodes || s.peers != o.lastPeers || s.devices != o.lastDevices || s.ready != o.lastReady {
		status := "waiting"
		if s.ready {
			status = "ready"
		}
		logx.Info("orchestrator status", "status", status, "nodes_seen", s.nodes, "directory_nodes", s.dir, "peers_connected", s.peers, "devices", s.devices, "cell_threshold", o.conf.CellThreshold, "iot_max", s.max)
		o.lastNodes = s.nodes
		o.lastPeers = s.peers
		o.lastDevices = s.devices
		o.lastReady = s.ready
	}
}
