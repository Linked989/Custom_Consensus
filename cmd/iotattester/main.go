package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"pose/internal/iotsim"
)

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/0", "libp2p listen multiaddr")
	var peers multiFlag
	flag.Var(&peers, "peer", "target node multiaddr (repeatable)")
	var nodes multiFlag
	flag.Var(&nodes, "node", "node HTTP base URL for registration (repeatable)")
	chain := flag.String("chain", "iotnet-main", "chain/network id")
	attesters := flag.Int("attesters", 2, "number of dedicated L3 attester devices")
	attesterInterval := flag.Duration("attester-interval", 150*time.Millisecond, "send interval per L3 attester")
	list := flag.Bool("list", false, "list devices from first HTTP node and exit")
	topicName := flag.String("topic", "", "pubsub topic for COSE telemetry")
	pnetPath := flag.String("pnet", "", "path to swarm.key for private network")
	orchInterval := flag.Duration("orchestrator-interval", 2*time.Second, "interval between orchestrator coordination passes")
	orchMinNodes := flag.Int("orchestrator-min-nodes", 2, "minimum nodes before devices attempt registration")
	orchMinAccept := flag.Int("orchestrator-min-accepting", 1, "minimum accepting nodes to distribute devices")
	orchRefresh := flag.Duration("orchestrator-refresh", 15*time.Second, "how often to refresh node capacity snapshots")
	flag.Parse()

	if len(nodes) == 0 {
		log.Fatalf("at least one -node HTTP address is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := iotsim.Options{
		Listen:                   *listen,
		Peers:                    peers,
		Nodes:                    nodes,
		Chain:                    *chain,
		TelemetryDevices:         0,
		AttesterDevices:          *attesters,
		Interval:                 0,
		AttesterInterval:         *attesterInterval,
		Jitter:                   0,
		Once:                     false,
		ListOnly:                 *list,
		Topic:                    *topicName,
		PNetPath:                 *pnetPath,
		OrchestratorInterval:     *orchInterval,
		OrchestratorMinNodes:     *orchMinNodes,
		OrchestratorMinAccepting: *orchMinAccept,
		OrchestratorRefresh:      *orchRefresh,
	}

	if err := iotsim.Run(ctx, opts); err != nil {
		log.Fatal(err)
	}
}
