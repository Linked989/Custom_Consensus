package p2p

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/coseutil"
	"pose/internal/iot"
	"pose/internal/logx"
)

// IoTRequest drives the IoT control stream.
type IoTRequest struct {
	Action   string   `json:"action"`
	DeviceID string   `json:"device_id,omitempty"`
	Firmware string   `json:"firmware,omitempty"`
	Model    string   `json:"model,omitempty"`
	Kid      string   `json:"kid,omitempty"`
	Pub      string   `json:"pub,omitempty"`
	Sensors  []string `json:"sensors,omitempty"`
	Caps     []string `json:"caps,omitempty"`
}

// IoTResponse mirrors HTTP responses used historically.
type IoTResponse struct {
	OK         bool         `json:"ok"`
	Error      string       `json:"error,omitempty"`
	Message    string       `json:"message,omitempty"`
	NodeID     string       `json:"node_id,omitempty"`
	Connected  int          `json:"connected,omitempty"`
	MaxDevices int          `json:"max_devices,omitempty"`
	Accepting  bool         `json:"accepting,omitempty"`
	Timestamp  time.Time    `json:"timestamp,omitempty"`
	Total      int          `json:"total_devices,omitempty"`
	Devices    []iot.Device `json:"devices,omitempty"`
}

const maxIoTRequestBytes = 64 * 1024

// RegisterIoTHandler installs the IoT control stream handler on the node.
func RegisterIoTHandler(h host.Host, reg *iot.Registry) {
	h.SetStreamHandler(iot.IotProto, func(s network.Stream) {
		defer s.Close()
		if err := s.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			logx.Debug("iot stream deadline", "err", err)
		}
		data, err := io.ReadAll(io.LimitReader(s, maxIoTRequestBytes))
		if err != nil {
			writeIoTResponse(s, IoTResponse{OK: false, Error: "read_error", Message: err.Error()})
			return
		}
		var req IoTRequest
		if err := json.Unmarshal(data, &req); err != nil {
			writeIoTResponse(s, IoTResponse{OK: false, Error: "bad_json", Message: err.Error()})
			return
		}
		switch req.Action {
		case "register":
			handleIoTRegister(s, h, reg, req)
		case "capacity":
			handleIoTCapacity(s, h, reg)
		case "list":
			handleIoTList(s, h, reg)
		case "remove":
			handleIoTRemove(s, reg, req)
		default:
			writeIoTResponse(s, IoTResponse{OK: false, Error: "unknown_action", Message: req.Action})
		}
	})
}

func handleIoTRegister(s network.Stream, h host.Host, reg *iot.Registry, req IoTRequest) {
	if req.DeviceID == "" || req.Pub == "" {
		writeIoTResponse(s, IoTResponse{OK: false, Error: "missing_fields", Message: "device_id and pub required"})
		return
	}
	pubBytes, err := hex.DecodeString(req.Pub)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		writeIoTResponse(s, IoTResponse{OK: false, Error: "bad_pub", Message: "pub must be ed25519 hex"})
		return
	}
	kidBytes := sha256.Sum256(pubBytes)
	kidHex := hex.EncodeToString(kidBytes[:8])
	if req.Kid != "" && !stringsEqualFold(req.Kid, kidHex) {
		writeIoTResponse(s, IoTResponse{OK: false, Error: "kid_mismatch", Message: "kid must match pub"})
		return
	}
	limit := reg.Max()
	device := iot.Device{
		DeviceID:  req.DeviceID,
		Firmware:  req.Firmware,
		Model:     req.Model,
		KidHex:    kidHex,
		PubHex:    strings.ToLower(req.Pub),
		Sensors:   req.Sensors,
		Caps:      req.Caps,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	if err := reg.UpsertWithLimit(device, limit); err != nil {
		if errors.Is(err, iot.ErrRegistryFull) {
			nonAtt := reg.NonAttesterCount()
			total := reg.Count()
			writeIoTResponse(s, IoTResponse{OK: false, Error: "iot_limit_reached", Message: "node at capacity", NodeID: h.ID().String(), Connected: nonAtt, Total: total, MaxDevices: limit, Accepting: false, Timestamp: time.Now().UTC()})
			return
		}
		writeIoTResponse(s, IoTResponse{OK: false, Error: "registry_error", Message: err.Error()})
		return
	}
	coseutil.RegistryRegister(kidBytes[:8], ed25519.PublicKey(pubBytes))
	p2p.AnnounceDeviceKey(s.Context(), h, kidBytes[:8], ed25519.PublicKey(pubBytes))
	nonAtt := reg.NonAttesterCount()
	writeIoTResponse(s, IoTResponse{OK: true, NodeID: h.ID().String(), Connected: nonAtt, Total: reg.Count(), MaxDevices: limit, Accepting: limit == 0 || nonAtt < limit, Timestamp: time.Now().UTC()})
}

func handleIoTCapacity(s network.Stream, h host.Host, reg *iot.Registry) {
	count := reg.Count()
	max := reg.Max()
	nonAtt := reg.NonAttesterCount()
	accepting := max == 0 || nonAtt < max
	writeIoTResponse(s, IoTResponse{OK: true, NodeID: h.ID().String(), Connected: nonAtt, Total: count, MaxDevices: max, Accepting: accepting, Timestamp: time.Now().UTC()})
}

func handleIoTList(s network.Stream, h host.Host, reg *iot.Registry) {
	writeIoTResponse(s, IoTResponse{OK: true, NodeID: h.ID().String(), Devices: reg.List(), Connected: reg.Count(), MaxDevices: reg.Max(), Timestamp: time.Now().UTC()})
}

func handleIoTRemove(s network.Stream, reg *iot.Registry, req IoTRequest) {
	if req.DeviceID == "" {
		writeIoTResponse(s, IoTResponse{OK: false, Error: "missing_device_id"})
		return
	}
	reg.Remove(req.DeviceID)
	writeIoTResponse(s, IoTResponse{OK: true})
}

// SendIoTRequest opens a control stream to the target peer.
func SendIoTRequest(ctx context.Context, h host.Host, pid peer.ID, req IoTRequest) (IoTResponse, error) {
	var resp IoTResponse
	s, err := h.NewStream(ctx, pid, iot.IotProto)
	if err != nil {
		return resp, err
	}
	defer s.Close()
	if err := s.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logx.Debug("iot stream set write deadline", "err", err)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if _, err := s.Write(append(payload, '\n')); err != nil {
		return resp, err
	}
	if err := s.CloseWrite(); err != nil {
		logx.Debug("iot close write", "err", err)
	}
	if err := s.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logx.Debug("iot stream set read deadline", "err", err)
	}
	reader := bufio.NewReader(s)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

func writeIoTResponse(s network.Stream, resp IoTResponse) {
	payload, err := json.Marshal(resp)
	if err != nil {
		logx.Debug("iot marshal", "err", err)
		return
	}
	payload = append(payload, '\n')
	if err := s.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logx.Debug("iot set write deadline", "err", err)
	}
	if _, err := s.Write(payload); err != nil {
		logx.Debug("iot write resp", "err", err)
	}
}

func stringsEqualFold(a, b string) bool { return strings.EqualFold(a, b) }
