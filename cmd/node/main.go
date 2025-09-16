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
	"pose/internal/httpapi"
	"pose/internal/helios"
	"pose/internal/iot"
	"pose/internal/logx"
	"pose/internal/mempool"
	"pose/internal/p2p"
)

const mdnsServiceTag = "pose-simple-mdns"
const heartbeatTopic = "pose/heartbeat/1.0.0"
const txTopicDefault = "pose/tx/1.0.0"

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
	cellMin := flag.Int("cell-min-devices", 3, "minimum devices to form a Cell")
	cellMax := flag.Int("cell-max-devices", 0, "maximum devices to include in a Cell (0 = unlimited)")
	var bootstraps multiFlag
	flag.Var(&bootstraps, "bootstrap", "bootstrap peer multiaddr (repeatable)")
	flag.Parse()

    // Configure logging first
    logx.Configure(*logLevel, *logFormat)
    logx.SetVerbose(*verboseLogs)
	// Configure P2P chain handshake
	p2p.SetChainID(*chainID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	// IoT registry and libp2p device registration protocol
	devReg := iot.NewRegistry(*chainID)
	iot.RegisterIotHandler(h, devReg)
	// Cell manager (uses registry)
	cellMgr := cell.NewManager(*chainID, h.ID().String(), *cellMin, *cellMax)

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
    // Start HTTP API early so devices can register while we wait for preflight.
    if *httpIn != "" {
        srv := httpapi.StartHTTPAPI(ctx, *httpIn, txTopic, h, pool, *chainID, devReg, cellMgr, getAION, getHELIOS)
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
		haveNodes := total >= 2 || peers >= 1 // at least 2 nodes total implies >=1 peer besides self
		haveDevices := len(devs) >= *cellMin
		if haveDevices {
			if c := cellMgr.TryForm(devReg); c != nil && c.Active {
				// formed; proceed to node start after both conditions satisfied
			}
		}
		if haveNodes && haveDevices {
			logx.Info("preflight ok: starting blockchain services", "nodes_seen", total, "peers_connected", peers, "devices", len(devs))
			break
		}
		logx.Info("preflight waiting", "nodes_seen", total, "peers_connected", peers, "devices", len(devs), "min_devices", *cellMin)
		time.Sleep(1 * time.Second)
	}

    // AION network service (commit/reveal/VRF + selection); enabled by default
    aionParams := aion.DefaultParams()
    // Override slot duration from CLI for visibility/testing
    if slotDuration != nil && *slotDuration > 0 { aionParams.SlotDuration = *slotDuration }
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
	blkTopic, err := blockchain.StartBlockSubscriberWithMempool(ctx, h, ps, *blockTopicName, *chainID, pool, *logPrune, *logBlockQueue, *blockMax, *blockBytesMax, leaderOK)
	if err != nil {
		logx.Error("block sub", "err", err)
		os.Exit(1)
	}

    // HELIOS L1 notarization: start and observe the same block topic handle used by subscriber
    l1svc = helios.StartL1FromTopic(ctx, h, ps, aionSvc, helios.L1Params{}, blkTopic)
    // Always start builder; AllowProduceSlot gates production to elected leader.
    {
        allow := func() bool { return aionSvc.AllowProduceSlot() }
        blkInterval := aionParams.SlotDuration
        // Inject attestation fetcher so builder can embed attestations for parent block
        ctxAtt := blockchain.WithAttestationFetcher(ctx, func(parent []byte) [][]byte {
            if l1svc == nil { return nil }
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
                    const magenta = "\x1b[35m"; const reset = "\x1b[0m"
                    if logMempool != nil && *logMempool {
                        logx.Info(magenta+"STATS"+reset, "all_nodes", all, "connected_nodes_counter", connected, "tip_height", tipH, "epoch", ns.Epoch, "slot", ns.Slot, "slot_epoch", ns.SlotEpoch, "mempool_len", pool.Len())
                    } else {
                        logx.Info(magenta+"STATS"+reset, "all_nodes", all, "connected_nodes_counter", connected, "tip_height", tipH, "epoch", ns.Epoch, "slot", ns.Slot, "slot_epoch", ns.SlotEpoch)
                    }
                // Try to form a cell when threshold is met
                if c := cellMgr.TryForm(devReg); c != nil {
                    logx.Info("cell formed", "id", c.ID, "devices", len(c.Devices))
                }
				}
			}
		}()
	}

	// Periodically list IoT devices if requested
	if *listIot && listIotInterval != nil && *listIotInterval > 0 {
		go func() {
			t := time.NewTicker(*listIotInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					devs := devReg.List()
					logx.Info("iot devices", "count", len(devs), "devices", devs)
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
