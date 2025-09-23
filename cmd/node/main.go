package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"

	"pose/internal/aion"
	"pose/internal/blockchain"
	"pose/internal/cell"
	"pose/internal/dev"
	"pose/internal/gossip"
	"pose/internal/helios"
	"pose/internal/httpapi"
	"pose/internal/iot"
	"pose/internal/logx"
	"pose/internal/mempool"
	"pose/internal/p2p"
)

const mdnsServiceTag = "pose-simple-mdns"
const heartbeatTopic = "pose/heartbeat/1.0.0"
const txTopicDefault = "pose/tx/1.0.0"
const networkTopic = "pose/network/status/1.0.0"

func main() {
	// Flags
	listenPort := flag.Int("port", 0, "TCP listen port (0=random)")
	enableMDNS := flag.Bool("mdns", true, "enable mDNS discovery")
	mdnsTag := flag.String("mdns-tag", mdnsServiceTag, "mDNS service tag")
	hbTopic := flag.String("topic", heartbeatTopic, "pubsub heartbeat topic")
	hbInterval := flag.Duration("hb", 2*time.Second, "heartbeat publish interval")
	statsInterval := flag.Duration("stats", 5*time.Second, "stats log interval (0=off)")
	memberTTL := flag.Duration("ttl", 10*time.Second, "membership entry TTL")
	// Gossip
	chainID := flag.String("chain-id", "iotnet-main", "chain/network id")
	txTopicName := flag.String("tx-topic", txTopicDefault, "pubsub topic for transactions")
	blockTopicName := flag.String("block-topic", "pose/block/1.0.0", "pubsub topic for blocks")
	// blockInterval := flag.Duration("block-interval", 2*time.Second, "block production interval")
	blockMax := flag.Int("block-max", 100, "max txs per block")
	blockBytesMax := flag.Int("block-bytes-max", 0, "max total tx bytes per block (0 = unlimited)")
	memCapacity := flag.Int("mempool-cap", 8192, "mempool max entries")
	memTTL := flag.Duration("mempool-ttl", 60*time.Second, "mempool entry TTL")
	memBytesCap := flag.Int("mempool-bytes-cap", 0, "mempool max total bytes (0 = unlimited)")
	// Logging toggles
	logHeartbeats := flag.Bool("log-heartbeats", false, "log every heartbeat message")
	logTx := flag.Bool("log-tx", false, "log every accepted tx from gossip")
	logDev := flag.Bool("log-dev", false, "log dev tx publishes")
	logBlockQueue := flag.Bool("log-block-queue", false, "log when blocks are queued waiting for parent")
	logPrune := flag.Bool("log-mempool-prune", true, "log mempool pruning due to accepted blocks")
	logMempool := flag.Bool("log-mempool", false, "log mempool length in stats ticker")
	bridgeURL := flag.String("bridge-url", "", "optional HTTP URL to forward validated txs (e.g., http://localhost:1337/tx)")
	httpIn := flag.String("http", "", "optional HTTP listen addr to accept POST /tx and publish to gossip (e.g., :14000)")
	// Dev generator
	devGen := flag.Bool("dev-gen-tx", false, "enable built-in synthetic tx generator")
	devInterval := flag.Duration("dev-interval", 500*time.Millisecond, "interval between dev tx publishes")
	devReuseKey := flag.Bool("dev-reuse-key", true, "reuse a single dev private key (device) per node")
	// LAN/private network
	bindIP := flag.String("bind", "", "IPv4 to bind (default all interfaces, e.g., 192.168.0.10)")
	swarmKeyPath := flag.String("pnet", "", "path to swarm.key for libp2p private network")
	genSwarmKey := flag.String("gen-swarm-key", "", "generate a new swarm.key at the given path and exit")
	dataDir := flag.String("data-dir", ".data", "directory for block/index storage")
	// Logging
	logLevel := flag.String("log-level", "info", "log level: debug|info|warn|error")
	logFormat := flag.String("log-format", "text", "log format: text|json")
	verboseLogs := flag.Bool("verbose", false, "enable verbose logs (default: startup line only)")
	// Slots
	slotDuration := flag.Duration("slot-duration", 500*time.Millisecond, "AION slot duration (e.g., 500ms)")
	// AION: enabled by default (no dev flags)
	listIot := flag.Bool("list-iot", false, "periodically log IoT devices registered")
	listIotInterval := flag.Duration("list-iot-interval", 10*time.Second, "interval to log IoT devices when -list-iot is set")
	iotMax := flag.Int("iot-max-devices", 0, "maximum IoT devices this node accepts (0 = unlimited)")
	legacyCellMin := flag.Int("cell-min-devices", -1, "deprecated; ignored (use -iot-max-devices)")
	legacyCellMax := flag.Int("cell-max-devices", -1, "deprecated; use -iot-max-devices")
	// HELIOS L1
	l1Min := flag.Int("l1-min-attesters", 2, "minimum distinct attesters required to notarize")
	var bootstraps multiFlag
	flag.Var(&bootstraps, "bootstrap", "bootstrap peer multiaddr (repeatable)")
	boolFlags := map[string]struct{}{
		"mdns":              {},
		"log-heartbeats":    {},
		"log-tx":            {},
		"log-dev":           {},
		"log-block-queue":   {},
		"log-mempool-prune": {},
		"log-mempool":       {},
		"dev-gen-tx":        {},
		"dev-reuse-key":     {},
		"verbose":           {},
		"list-iot":          {},
	}
	if err := flag.CommandLine.Parse(normalizeBoolFlags(os.Args[1:], boolFlags)); err != nil {
		if err == flag.ErrHelp {
			return
		}
		logx.Error("parse flags", "err", err)
		os.Exit(2)
	}

	// Configure logging first
	logx.Configure(*logLevel, *logFormat)
	logx.SetVerbose(*verboseLogs)
	// Configure P2P chain handshake
	p2p.SetChainID(*chainID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	maxDevices := *iotMax
	if maxDevices <= 0 && *legacyCellMax >= 0 {
		maxDevices = *legacyCellMax
		logx.Warn("-cell-max-devices is deprecated; use -iot-max-devices instead", "value", maxDevices)
	}
	logx.Info("Device limit configuration", "maxDevices", maxDevices, "iotMax", *iotMax, "legacyCellMax", *legacyCellMax)

	if *legacyCellMin >= 0 {
		logx.Warn("-cell-min-devices is deprecated; minimum derives from -iot-max-devices", "value", *legacyCellMin)
	}

	if *genSwarmKey != "" {
		if err := generateSwarmKey(*genSwarmKey); err != nil {
			logx.Error("gen-swarm-key", "err", err)
			os.Exit(1)
		}
		logx.Info("swarm.key written", "path", *genSwarmKey)
		return
	}

	ip := "0.0.0.0"
	if *bindIP != "" {
		ip = *bindIP
	}
	listen := fmt.Sprintf("/ip4/%s/tcp/%d", ip, *listenPort)
	if *listenPort == 0 {
		listen = fmt.Sprintf("/ip4/%s/tcp/0", ip)
	}

	var psk []byte
	if *swarmKeyPath != "" {
		var err error
		psk, err = loadSwarmKey(*swarmKeyPath)
		if err != nil {
			logx.Error("pnet load", "err", err)
			os.Exit(1)
		}
		logx.Info("pnet enabled")
	}

	// set data dir before services start
	if err := blockchain.SetDataDir(*dataDir); err != nil {
		logx.Error("data dir", "err", err)
		os.Exit(1)
	}
	// also use same dir for IoT registry
	if err := iot.SetDataDir(*dataDir); err != nil {
		logx.Error("iot data dir", "err", err)
		os.Exit(1)
	}

	h, err := p2p.NewHost(listen, psk)
	if err != nil {
		logx.Error("create host", "err", err)
		os.Exit(1)
	}
	defer h.Close()

	// Always show startup line with node id; other logs follow verbosity
	logx.Startup("node started", "id", h.ID().String())
	for _, a := range h.Addrs() {
		logx.Info("listen", "addr", a.String()+"/p2p/"+h.ID().String())
	}

	// Hello stream handler: register announced device keys and peer addrs
	p2p.RegisterHelloHandler(h)
	// IoT registry served via libp2p control channel
	devReg := iot.NewRegistry(*chainID)
	devReg.SetMax(maxDevices)
	logx.Info("iot capacity", "max_devices", maxDevices)
	p2p.RegisterIoTHandler(h, devReg)
	// Cell manager (uses registry)
	cellThreshold := maxDevices
	if cellThreshold <= 0 && *iotMax > 0 {
		cellThreshold = *iotMax
	}
	if cellThreshold <= 0 && *legacyCellMax > 0 {
		cellThreshold = *legacyCellMax
	}
	if cellThreshold <= 0 {
		cellThreshold = 2
	}
	logx.Info("cell threshold", "min_devices", cellThreshold)
	cellMgr := cell.NewManager(*chainID, h.ID().String(), cellThreshold, maxDevices)

	if *enableMDNS {
		n := &p2p.MDNSNotifee{H: h}
		svc, err := p2p.SetupMDNS(h, *mdnsTag, n)
		if err != nil {
			logx.Error("mdns start", "err", err)
			os.Exit(1)
		}
		defer svc.Close()
	}

	if len(bootstraps) > 0 {
		p2p.ConnectToAddrs(h, []string(bootstraps))
	}

	ps, err := gossip.InitPubSub(ctx, h)
	if err != nil {
		logx.Error("pubsub init", "err", err)
		os.Exit(1)
	}
	directory, dirTopic, err := gossip.StartNodeDirectory(ctx, h, ps, networkTopic, *memberTTL)
	if err != nil {
		logx.Error("directory start", "err", err)
		os.Exit(1)
	}
	if err := gossip.PublishNodeStatus(ctx, dirTopic, h.ID().String(), "online"); err != nil {
		logx.Debug("directory announce failed", "err", err)
	}
	defer func() {
		offCtx, cancelOff := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelOff()
		_ = gossip.PublishNodeStatus(offCtx, dirTopic, h.ID().String(), "offline")
	}()
	// Local mempool
	pool := mempool.New(*memCapacity, *memTTL, *memBytesCap)

	members, txTopic, err := func() (*gossip.MemberSet, *pubsub.Topic, error) {
		m, _, err := gossip.StartHeartbeat(ctx, h, ps, *hbTopic, *hbInterval, *memberTTL, *logHeartbeats)
		if err != nil {
			return nil, nil, err
		}
		t, err := gossip.StartTxGossipToPool(ctx, ps, *txTopicName, *bridgeURL, pool, *logTx)
		if err != nil {
			return nil, nil, err
		}
		return m, t, nil
	}()
	if err != nil {
		logx.Error("gossip start", "err", err)
		os.Exit(1)
	}

	// Prepare AION/HELIOS service pointers and getter closures for HTTP.
	var aionSvc *aion.Service
	getAION := func() *aion.Service { return aionSvc }
	var l1svc *helios.L1Service
	getHELIOS := func() *helios.L1Service { return l1svc }
	var l2svc *helios.L2Service
	getL2 := func() *helios.L2Service { return l2svc }
	var l3svc *helios.L3Service
	getL3 := func() *helios.L3Service { return l3svc }
	// registerCell forwards the active cell profile into L3 service if available.
	registerCell := func(c *cell.Cell) {
		if c == nil || !c.Active {
			return
		}
		if l3 := l3svc; l3 != nil {
			var pub []byte
			if len(c.Devices) > 0 {
				if key, err := hex.DecodeString(strings.ToLower(c.Devices[0].PubHex)); err == nil {
					pub = key
				}
			}
			l3.RegisterCell(helios.CellRecord{ID: c.ID, PubKey: pub})
		}
	}
	// Start HTTP API early so devices can register while we wait for orchestration.
	if *httpIn != "" {
		srv := httpapi.StartHTTPAPI(ctx, *httpIn, txTopic, h, pool, *chainID, directory, devReg, cellMgr, getAION, getHELIOS, getL2, getL3)
		defer srv.Shutdown(ctx)
		logx.Info("http api", "listen", *httpIn)
	}

	// Preflight: ensure at least 2 nodes present and minimum devices are connected locally
	// before starting blockchain services. Log progress while waiting.
	for {
		if ctx.Err() != nil {
			return
		}
		total := members.CountAndSweep()
		peers := len(h.Network().Peers())
		devs := devReg.List()
		haveNodes := total >= 3 || peers >= 1 // at least 2 nodes total implies >=1 peer besides self
		haveDevices := len(devs) >= cellThreshold
		if haveDevices {
			if c := cellMgr.TryForm(devReg); c != nil && c.Active {
				// formed; proceed to node start after both conditions satisfied
				registerCell(c)
			}
		}
		if haveNodes && haveDevices {
			logx.Info("preflight Ok: starting blockchain services", "nodes_seen", total, "peers_connected", peers, "devices", len(devs), "cell_threshold", cellThreshold)
			break
		}
		logx.Info("preflight waiting", "nodes_seen", total, "peers_connected", peers, "devices", len(devs), "min_devices", cellThreshold)
		time.Sleep(1 * time.Second)
	}

	// AION network service (commit/reveal/VRF + selection); enabled by default
	aionParams := aion.DefaultParams()
	// Override slot duration from CLI for visibility/testing
	if slotDuration != nil && *slotDuration > 0 {
		aionParams.SlotDuration = *slotDuration
	}
	aionSvc = aion.StartAIONService(ctx, h, ps, *chainID, aionParams, cellMgr)
	logx.Info("aion params", "slot_duration_ms", int64(aionParams.SlotDuration/time.Millisecond), "epoch_length", aionParams.EpochLength)

	if *devGen {
		dev.StartDevGenerator(ctx, h, txTopic, *devReuseKey, *devInterval, *logDev)
	}

	// Block gossip: subscribe always; optionally produce
	// enable block sync protocol
	blockchain.RegisterBlockSync(h)
	// Leader enforcement predicate from AION
	leaderOK := func(epoch uint64, producerPub []byte) bool { return aionSvc.AcceptProducer(epoch, producerPub) }
	blkTopic, err := blockchain.StartBlockSubscriberWithMempool(ctx, h, ps, *blockTopicName, *chainID, pool, *logPrune, *logBlockQueue, *blockMax, *blockBytesMax, leaderOK, func(b *blockchain.Block) {
		if svc := getL2(); svc != nil {
			svc.UpdateBlockInfo(append([]byte(nil), b.Hash...), append([]byte(nil), b.PrevHash...), b.Height, append([]byte(nil), b.TxRoot...))
		}
		if l3 := l3svc; l3 != nil {
			l3.RecordBlockMeta(append([]byte(nil), b.Hash...), append([]byte(nil), b.PrevHash...), b.Height, 0, append([]byte(nil), b.TxRoot...), false)
		}
	})
	if err != nil {
		logx.Error("block sub", "err", err)
		os.Exit(1)
	}

	// HELIOS L1 notarization: start and observe the same block topic handle used by subscriber
	l1svc = helios.StartL1FromTopic(ctx, h, ps, aionSvc, helios.L1Params{MinAttesters: *l1Min}, blkTopic)
	// HELIOS L2 checkpointing: aggregate quorum votes for deterministic commits
	totalNodes := members.CountAndSweep()
	l2Quorum := helios.HotstuffQuorumSize(totalNodes)
	l2Params := helios.L2Params{QuorumSize: l2Quorum}
	l2svc = helios.StartL2FromTopic(ctx, h, ps, l2Params, blkTopic)
	logx.Info("helios l2 params", "validators", totalNodes, "quorum", l2Params.QuorumSize)
	l3Params := helios.L3Params{MinCells: cellThreshold, TotalStake: float64(totalNodes)}
	if l3Params.MinCells < 1 {
		l3Params.MinCells = 1
	}
	if l3Params.TotalStake <= 0 {
		l3Params.TotalStake = 1
	}
	l3svc = helios.StartL3Finality(ctx, h, ps, l3Params, nil, nil)
	if l2svc != nil && l3svc != nil {
		l2svc.AttachL3(l3svc)
	}
	if c := cellMgr.Status(); c != nil {
		registerCell(c)
	}
	if l3svc != nil {
		logx.Info("helios l3 params", "min_cells", l3Params.MinCells, "total_stake", l3Params.TotalStake)
	}
	if members != nil {
		go func() {
			interval := 5 * time.Second
			if memberTTL != nil && *memberTTL > 0 && *memberTTL/2 > interval {
				interval = *memberTTL / 2
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			lastCount := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					total := members.CountAndSweep()
					if total <= 0 {
						total = 1
					}
					if total == lastCount {
						continue
					}
					lastCount = total
					quorum := helios.HotstuffQuorumSize(total)
					if svc := getL2(); svc != nil {
						svc.UpdateQuorumSize(quorum)
					}
					if svc := getL3(); svc != nil {
						svc.UpdateTotalStake(float64(total))
					}
				}
			}
		}()
	}
	// Always start builder; AllowProduceSlot gates production to elected leader.
	{
		allow := func() bool { return aionSvc.AllowProduceSlot() }
		blkInterval := aionParams.SlotDuration
		// Inject attestation fetcher so builder can embed attestations for parent block
		ctxAtt := blockchain.WithAttestationFetcher(ctx, func(parent []byte) [][]byte {
			if l1svc == nil {
				return nil
			}
			return l1svc.GetAttestationsFor(parent, 0)
		})
		if err := blockchain.StartBlockBuilderFromPool(ctxAtt, h, pool, blkTopic, *chainID, blkInterval, *blockMax, *blockBytesMax, allow); err != nil {
			logx.Error("block builder", "err", err)
			os.Exit(1)
		}
	}

	if statsInterval != nil && *statsInterval > 0 {
		go func() {
			t := time.NewTicker(*statsInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					all := members.CountAndSweep()
					connected := len(h.Network().Peers())
					tipH, _ := blockchain.GetTip(*chainID)
					ns := aionSvc.GetNetStatus()
					var l2Commit int64
					if l2svc != nil {
						l2Commit = l2svc.LatestCommitHeight()
					}
					const magenta = "\x1b[35m"
					const reset = "\x1b[0m"
					if logMempool != nil && *logMempool {
						logx.Info(magenta+"STATS"+reset, "all_nodes", all, "connected_nodes_counter", connected, "tip_height", tipH, "epoch", ns.Epoch, "slot", ns.Slot, "slot_epoch", ns.SlotEpoch, "l2_commit_height", l2Commit, "mempool_len", pool.Len())
					} else {
						logx.Info(magenta+"STATS"+reset, "all_nodes", all, "connected_nodes_counter", connected, "tip_height", tipH, "epoch", ns.Epoch, "slot", ns.Slot, "slot_epoch", ns.SlotEpoch, "l2_commit_height", l2Commit)
					}
					// Try to form a cell when threshold is met
					if c := cellMgr.TryForm(devReg); c != nil {
						logx.Info("cell formed", "id", c.ID, "devices", len(c.Devices))
						registerCell(c)
					}
				}
			}
		}()
	}

	// Periodically list IoT devices if requested
	if *listIot && listIotInterval != nil && *listIotInterval > 0 {
		logDevices := func() {
			devs := devReg.List()
			logx.Info("iot devices", "count", len(devs), "devices", devs)
		}
		logDevices()
		go func() {
			t := time.NewTicker(*listIotInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					logDevices()
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	logx.Info("shutting down")
}

// multiFlag allows repeating -bootstrap flags.
type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// -------- Swarm key helpers (pnet) --------

func generateSwarmKey(path string) error {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return err
	}
	hexKey := strings.ToLower(hex.EncodeToString(b))
	content := []byte("/key/swarm/psk/1.0.0/\n/base16/\n" + hexKey + "\n")
	return os.WriteFile(path, content, 0o600)
}

// normalizeBoolFlags converts "-flag true" into "-flag=true" so parsing keeps going.
func normalizeBoolFlags(args []string, boolFlags map[string]struct{}) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) > 0 && arg[0] == '-' {
			name := strings.TrimLeft(arg, "-")
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			if _, ok := boolFlags[name]; ok {
				if !strings.Contains(arg, "=") && i+1 < len(args) {
					next := strings.ToLower(args[i+1])
					if next == "true" || next == "false" {
						out = append(out, fmt.Sprintf("%s=%s", arg, next))
						i++
						continue
					}
				}
			}
		}
		out = append(out, arg)
	}
	return out
}

func loadSwarmKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	lines := strings.Split(s, "\n")
	var keyHex string
	if len(lines) >= 3 && strings.HasPrefix(lines[0], "/key/swarm/psk/") {
		keyHex = strings.TrimSpace(lines[2])
	} else if len(lines) == 1 && len(lines[0]) >= 64 {
		keyHex = strings.TrimSpace(lines[0])
	}
	if keyHex != "" {
		b, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	if len(data) == 32 {
		return data, nil
	}
	return nil, fmt.Errorf("unsupported swarm.key format")
}
