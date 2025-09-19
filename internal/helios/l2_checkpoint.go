package helios

import (
	"context"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"pose/internal/logx"
)

const (
	topicL2Vote   = "helios/l2/vote/1.0.0"
	topicL2QC     = "helios/l2/qc/1.0.0"
	topicL2Commit = "helios/l2/commit/1.0.0"

	stepPrepare = 1
)

// L2Params configures checkpoint quorum thresholds.
type L2Params struct {
	QuorumSize int
	VoteExpiry time.Duration
}

func defaultL2Params() L2Params { return L2Params{QuorumSize: 3, VoteExpiry: 15 * time.Second} }

// HotstuffQuorumSize returns ceil(2n/3) for n validators with a minimum quorum of three.
func HotstuffQuorumSize(validators int) int {
	if validators < 3 {
		return 3
	}
	quorum := (2*validators + 2) / 3
	if quorum < 3 {
		quorum = 3
	}
	return quorum
}

type votePayload struct {
	Block  []byte `cbor:"0,keyasint"`
	Parent []byte `cbor:"1,keyasint"`
	Height int64  `cbor:"2,keyasint"`
	Step   uint8  `cbor:"3,keyasint"`
	Pub    []byte `cbor:"4,keyasint"`
	Peer   string `cbor:"5,keyasint"`
}

type voteMsg struct {
	Payload votePayload `cbor:"0,keyasint"`
	Sig     []byte      `cbor:"1,keyasint"`
}

type qcMsg struct {
	Block     []byte    `cbor:"0,keyasint"`
	Parent    []byte    `cbor:"1,keyasint"`
	Height    int64     `cbor:"2,keyasint"`
	Step      uint8     `cbor:"3,keyasint"`
	Votes     []voteMsg `cbor:"4,keyasint"`
	CreatedBy string    `cbor:"5,keyasint"`
	CreatedAt time.Time `cbor:"6,keyasint"`
}

type commitMsg struct {
	Block       []byte    `cbor:"0,keyasint"`
	Height      int64     `cbor:"1,keyasint"`
	CommittedAt time.Time `cbor:"2,keyasint"`
}

type voteRecord struct {
	Msg      voteMsg
	Received time.Time
}

type blockMeta struct {
	height    int64
	parentHex string
	firstSeen time.Time
}

type commitInfo struct {
	height int64
	when   time.Time
}

// L2Service aggregates validator votes into quorum certificates and announces commits.
type L2Service struct {
	ctx    context.Context
	h      host.Host
	ps     *pubsub.PubSub
	em     cbor.EncMode
	dm     cbor.DecMode
	params L2Params

	tVote   *pubsub.Topic
	tQC     *pubsub.Topic
	tCommit *pubsub.Topic

	mu        sync.Mutex
	votes     map[string]map[string]voteRecord // blockHex -> peer -> vote
	qcs       map[string]qcMsg                 // blockHex -> qc
	blocks    map[string]blockMeta             // blockHex -> meta
	childQCs  map[string]map[string]struct{}   // parentHex -> childHex (with QC)
	committed map[string]commitInfo            // blockHex -> commit info
	commitMsg map[string]commitMsg             // blockHex -> commit payload
	sentVote  map[string]bool                  // local vote tracking
	lockedBlk string                           // highest locked block hex
	lockedH   int64                            // height of locked block
	pending   map[string]struct{}              // blocks awaiting safe vote conditions
}

// StartL2FromTopic launches the L2 checkpoint service using an existing block topic handle.
func StartL2FromTopic(ctx context.Context, h host.Host, ps *pubsub.PubSub, params L2Params, blockTopic *pubsub.Topic) *L2Service {
	if params.QuorumSize <= 0 {
		params.QuorumSize = defaultL2Params().QuorumSize
	}
	if params.VoteExpiry <= 0 {
		params.VoteExpiry = defaultL2Params().VoteExpiry
	}
	em, _ := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, TimeTag: cbor.EncTagRequired}.EncMode()
	dm, _ := cbor.DecOptions{TimeTag: cbor.DecTagRequired}.DecMode()
	s := &L2Service{
		ctx:       ctx,
		h:         h,
		ps:        ps,
		em:        em,
		dm:        dm,
		params:    params,
		votes:     make(map[string]map[string]voteRecord),
		qcs:       make(map[string]qcMsg),
		blocks:    make(map[string]blockMeta),
		childQCs:  make(map[string]map[string]struct{}),
		committed: make(map[string]commitInfo),
		commitMsg: make(map[string]commitMsg),
		sentVote:  make(map[string]bool),
		lockedH:   -1,
		pending:   make(map[string]struct{}),
	}

	tV, _ := ps.Join(topicL2Vote)
	tQ, _ := ps.Join(topicL2QC)
	tC, _ := ps.Join(topicL2Commit)
	s.tVote, s.tQC, s.tCommit = tV, tQ, tC

	if subV, err := tV.Subscribe(); err == nil {
		go func() {
			for {
				msg, err := subV.Next(ctx)
				if err != nil {
					return
				}
				s.onVote(msg.Message.GetData())
			}
		}()
	}
	if subQ, err := tQ.Subscribe(); err == nil {
		go func() {
			for {
				msg, err := subQ.Next(ctx)
				if err != nil {
					return
				}
				s.onQC(msg.Message.GetData())
			}
		}()
	}
	if subC, err := tC.Subscribe(); err == nil {
		go func() {
			for {
				msg, err := subC.Next(ctx)
				if err != nil {
					return
				}
				s.onCommit(msg.Message.GetData())
			}
		}()
	}
	if blockTopic != nil {
		if subB, err := blockTopic.Subscribe(); err == nil {
			go func() {
				for {
					msg, err := subB.Next(ctx)
					if err != nil {
						return
					}
					s.onBlock(msg.Message.GetData())
				}
			}()
		}
	}
	go s.cleanupLoop()
	return s
}

func (s *L2Service) onBlock(data []byte) {
	var blk struct {
		Height   int64     `cbor:"2,keyasint"`
		PrevHash []byte    `cbor:"3,keyasint"`
		Hash     []byte    `cbor:"9,keyasint"`
		Txs      [][]byte  `cbor:"8,keyasint"`
		Time     time.Time `cbor:"4,keyasint"`
	}
	if s.dm.Unmarshal(data, &blk) != nil {
		return
	}
	if len(blk.Hash) == 0 {
		return
	}
	hashHex := hex.EncodeToString(blk.Hash)
	parentHex := hex.EncodeToString(blk.PrevHash)
	s.mu.Lock()
	if _, ok := s.blocks[hashHex]; !ok {
		s.blocks[hashHex] = blockMeta{height: blk.Height, parentHex: parentHex, firstSeen: time.Now()}
	}
	s.mu.Unlock()
	s.voteForBlock(hashHex, blk.Height, parentHex)
}

func (s *L2Service) voteForBlock(hashHex string, height int64, parentHex string) {
	if !s.markVoteIfSafe(hashHex, parentHex, height) {
		return
	}
	s.publishVote(hashHex, height, parentHex)
}

func (s *L2Service) publishVote(hashHex string, height int64, parentHex string) {
	priv := s.h.Peerstore().PrivKey(s.h.ID())
	if priv == nil {
		return
	}
	pub := priv.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		return
	}
	blockBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return
	}
	parentBytes, _ := hex.DecodeString(parentHex)
	payload := votePayload{Block: cloneBytes(blockBytes), Parent: cloneBytes(parentBytes), Height: height, Step: stepPrepare, Pub: cloneBytes(pubBytes), Peer: s.h.ID().String()}
	toSign, err := s.em.Marshal(payload)
	if err != nil {
		return
	}
	sig, err := priv.Sign(toSign)
	if err != nil {
		return
	}
	msg := voteMsg{Payload: payload, Sig: cloneBytes(sig)}
	s.consumeVote(msg)
	by, err := s.em.Marshal(msg)
	if err != nil {
		return
	}
	if s.tVote != nil {
		_ = s.tVote.Publish(s.ctx, by)
	} else {
		_ = s.publish(topicL2Vote, by)
	}
}

func (s *L2Service) markVoteIfSafe(blockHex, parentHex string, height int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sentVote[blockHex] {
		return false
	}
	if !s.safeToVoteLocked(blockHex, parentHex, height) {
		s.pending[blockHex] = struct{}{}
		return false
	}
	delete(s.pending, blockHex)
	s.sentVote[blockHex] = true
	return true
}

func (s *L2Service) safeToVoteLocked(blockHex, parentHex string, height int64) bool {
	if parentHex == "" {
		return true
	}
	if s.lockedBlk == "" {
		return true
	}
	if parentHex == s.lockedBlk {
		return true
	}
	if !s.extendsLockedLocked(parentHex) {
		return false
	}
	if meta, ok := s.blocks[parentHex]; ok {
		return meta.height >= s.lockedH
	}
	if qc, ok := s.qcs[parentHex]; ok {
		return qc.Height >= s.lockedH
	}
	return false
}

func (s *L2Service) extendsLockedLocked(blockHex string) bool {
	if blockHex == "" {
		return true
	}
	if s.lockedBlk == "" || blockHex == s.lockedBlk {
		return true
	}
	cur := blockHex
	for steps := 0; steps < 1024 && cur != ""; steps++ {
		if cur == s.lockedBlk {
			return true
		}
		meta, ok := s.blocks[cur]
		if !ok {
			break
		}
		cur = meta.parentHex
	}
	return false
}

func (s *L2Service) retryPendingVotes() {
	type pendingInfo struct {
		blockHex string
		height   int64
		parent   string
	}
	for {
		var info pendingInfo
		s.mu.Lock()
		for blk := range s.pending {
			if s.sentVote[blk] {
				delete(s.pending, blk)
				continue
			}
			meta, ok := s.blocks[blk]
			if !ok {
				delete(s.pending, blk)
				continue
			}
			if s.safeToVoteLocked(blk, meta.parentHex, meta.height) {
				delete(s.pending, blk)
				s.sentVote[blk] = true
				info = pendingInfo{blockHex: blk, height: meta.height, parent: meta.parentHex}
				break
			}
		}
		s.mu.Unlock()
		if info.blockHex == "" {
			return
		}
		s.publishVote(info.blockHex, info.height, info.parent)
	}
}

func (s *L2Service) updateLockForQCLocked(blockHex string, qcHeight int64) {
	height := qcHeight
	if meta, ok := s.blocks[blockHex]; ok && meta.height > height {
		height = meta.height
	}
	if s.lockedBlk == "" {
		s.lockedBlk = blockHex
		s.lockedH = height
		return
	}
	if height > s.lockedH && s.extendsLockedLocked(blockHex) {
		s.lockedBlk = blockHex
		s.lockedH = height
	}
}

func (s *L2Service) onVote(data []byte) {
	var msg voteMsg
	if s.dm.Unmarshal(data, &msg) != nil {
		return
	}
	s.consumeVote(msg)
}

func (s *L2Service) consumeVote(msg voteMsg) {
	if !s.verifyVote(msg) {
		return
	}
	blockHex := hex.EncodeToString(msg.Payload.Block)
	peerID := msg.Payload.Peer

	var shouldBuild bool
	s.mu.Lock()
	if s.votes[blockHex] == nil {
		s.votes[blockHex] = make(map[string]voteRecord)
	}
	if _, exists := s.votes[blockHex][peerID]; !exists {
		s.votes[blockHex][peerID] = voteRecord{Msg: msg, Received: time.Now()}
		if _, ok := s.blocks[blockHex]; !ok {
			s.blocks[blockHex] = blockMeta{height: msg.Payload.Height, parentHex: hex.EncodeToString(msg.Payload.Parent), firstSeen: time.Now()}
		}
		if _, haveQC := s.qcs[blockHex]; !haveQC && len(s.votes[blockHex]) >= s.params.QuorumSize {
			shouldBuild = true
		}
	}
	s.mu.Unlock()

	if shouldBuild {
		s.buildAndBroadcastQC(blockHex)
	}
}

func (s *L2Service) buildAndBroadcastQC(blockHex string) {
	s.mu.Lock()
	if _, ok := s.qcs[blockHex]; ok {
		s.mu.Unlock()
		return
	}
	votes := s.votes[blockHex]
	meta := s.blocks[blockHex]
	if len(votes) < s.params.QuorumSize {
		s.mu.Unlock()
		return
	}
	list := make([]voteMsg, 0, len(votes))
	for _, vr := range votes {
		list = append(list, vr.Msg)
	}
	s.mu.Unlock()

	sort.Slice(list, func(i, j int) bool { return list[i].Payload.Peer < list[j].Payload.Peer })
	blockBytes, err := hex.DecodeString(blockHex)
	if err != nil {
		return
	}
	parentBytes, _ := hex.DecodeString(meta.parentHex)
	qc := qcMsg{Block: cloneBytes(blockBytes), Parent: cloneBytes(parentBytes), Height: meta.height, Step: stepPrepare, Votes: list, CreatedBy: s.h.ID().String(), CreatedAt: time.Now().UTC()}
	if !s.storeQC(blockHex, qc, meta.parentHex) {
		return
	}
	by, err := s.em.Marshal(qc)
	if err == nil {
		if s.tQC != nil {
			_ = s.tQC.Publish(s.ctx, by)
		} else {
			_ = s.publish(topicL2QC, by)
		}
	}
	logx.Info("HELIOS L2 QC", "height", meta.height, "hash", short(blockHex), "votes", len(list))
}

func (s *L2Service) onQC(data []byte) {
	var msg qcMsg
	if s.dm.Unmarshal(data, &msg) != nil {
		return
	}
	if !s.verifyQC(msg) {
		return
	}
	blockHex := hex.EncodeToString(msg.Block)
	parentHex := hex.EncodeToString(msg.Parent)
	s.mu.Lock()
	if _, ok := s.blocks[blockHex]; !ok {
		s.blocks[blockHex] = blockMeta{height: msg.Height, parentHex: parentHex, firstSeen: time.Now()}
	}
	s.mu.Unlock()
	if !s.storeQC(blockHex, msg, parentHex) {
		return
	}
	logx.Info("HELIOS L2 QC", "height", msg.Height, "hash", short(blockHex), "votes", len(msg.Votes), "from", msg.CreatedBy)
}

func (s *L2Service) storeQC(blockHex string, qc qcMsg, parentHex string) bool {
	stored := false
	grandParent := ""
	s.mu.Lock()
	if _, ok := s.qcs[blockHex]; !ok {
		s.qcs[blockHex] = qc
		if parentHex != "" {
			if s.childQCs[parentHex] == nil {
				s.childQCs[parentHex] = make(map[string]struct{})
			}
			s.childQCs[parentHex][blockHex] = struct{}{}
			if meta, ok := s.blocks[parentHex]; ok {
				grandParent = meta.parentHex
			}
		}
		s.updateLockForQCLocked(blockHex, qc.Height)
		stored = true
	}
	s.mu.Unlock()
	if stored {
		s.retryPendingVotes()
		s.checkCommitFor(parentHex)
		s.checkCommitFor(blockHex)
		if grandParent != "" {
			s.checkCommitFor(grandParent)
		}
	}
	return stored
}

func (s *L2Service) checkCommitFor(blockHex string) {
	if blockHex == "" {
		return
	}
	var commit commitMsg
	shouldBroadcast := false

	s.mu.Lock()
	if _, ok := s.committed[blockHex]; ok {
		s.mu.Unlock()
		return
	}
	if _, ok := s.qcs[blockHex]; !ok {
		s.mu.Unlock()
		return
	}
	kids := s.childQCs[blockHex]
	grandChain := false
	for childHex := range kids {
		if _, ok := s.qcs[childHex]; !ok {
			continue
		}
		grandkids := s.childQCs[childHex]
		for grandHex := range grandkids {
			if _, ok := s.qcs[grandHex]; ok {
				grandChain = true
				break
			}
		}
		if grandChain {
			break
		}
	}
	if !grandChain {
		s.mu.Unlock()
		return
	}
	meta, ok := s.blocks[blockHex]
	if !ok {
		s.mu.Unlock()
		return
	}
	blockBytes, err := hex.DecodeString(blockHex)
	if err != nil {
		s.mu.Unlock()
		return
	}
	commit = commitMsg{Block: cloneBytes(blockBytes), Height: meta.height, CommittedAt: time.Now().UTC()}
	s.committed[blockHex] = commitInfo{height: meta.height, when: commit.CommittedAt}
	s.commitMsg[blockHex] = commit
	s.mu.Unlock()
	shouldBroadcast = true

	if shouldBroadcast {
		logx.Info("HELIOS L2 COMMIT", "height", commit.Height, "hash", short(blockHex))
		by, err := s.em.Marshal(commit)
		if err == nil {
			if s.tCommit != nil {
				_ = s.tCommit.Publish(s.ctx, by)
			} else {
				_ = s.publish(topicL2Commit, by)
			}
		}
	}
}

func (s *L2Service) onCommit(data []byte) {
	var msg commitMsg
	if s.dm.Unmarshal(data, &msg) != nil {
		return
	}
	blockHex := hex.EncodeToString(msg.Block)
	s.mu.Lock()
	if _, ok := s.committed[blockHex]; ok {
		s.mu.Unlock()
		return
	}
	s.committed[blockHex] = commitInfo{height: msg.Height, when: msg.CommittedAt}
	s.commitMsg[blockHex] = msg
	s.mu.Unlock()
	logx.Info("HELIOS L2 COMMIT", "height", msg.Height, "hash", short(blockHex), "from", "network")
}

func (s *L2Service) verifyVote(msg voteMsg) bool {
	if msg.Payload.Step != stepPrepare {
		return false
	}
	if len(msg.Payload.Block) == 0 {
		return false
	}
	pub, err := crypto.UnmarshalPublicKey(msg.Payload.Pub)
	if err != nil {
		return false
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil || pid.String() != msg.Payload.Peer {
		return false
	}
	toSign, err := s.em.Marshal(msg.Payload)
	if err != nil {
		return false
	}
	ok, err := pub.Verify(toSign, msg.Sig)
	if err != nil || !ok {
		return false
	}
	return true
}

func (s *L2Service) verifyQC(qc qcMsg) bool {
	if qc.Step != stepPrepare {
		return false
	}
	if len(qc.Votes) < s.params.QuorumSize {
		return false
	}
	blockHex := hex.EncodeToString(qc.Block)
	parentHex := hex.EncodeToString(qc.Parent)
	seen := make(map[string]struct{}, len(qc.Votes))
	for _, v := range qc.Votes {
		if hex.EncodeToString(v.Payload.Block) != blockHex {
			return false
		}
		if hex.EncodeToString(v.Payload.Parent) != parentHex {
			return false
		}
		if !s.verifyVote(v) {
			return false
		}
		if _, dup := seen[v.Payload.Peer]; dup {
			return false
		}
		seen[v.Payload.Peer] = struct{}{}
	}
	return true
}

func (s *L2Service) publish(topic string, msg []byte) error {
	t, err := s.ps.Join(topic)
	if err != nil {
		return err
	}
	return t.Publish(s.ctx, msg)
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// LatestCommitHeight returns the height of the highest committed block known locally.
func (s *L2Service) LatestCommitHeight() int64 {
	s.mu.Lock()
	best := s.highestCommitLocked()
	s.mu.Unlock()
	return best
}

// HasQC reports whether a quorum certificate is available for the given block hash.
func (s *L2Service) HasQC(block []byte) bool {
	blockHex := hex.EncodeToString(block)
	s.mu.Lock()
	_, ok := s.qcs[blockHex]
	s.mu.Unlock()
	return ok
}

// GetQC returns the stored quorum certificate for block if present.
func (s *L2Service) GetQC(block []byte) (qcMsg, bool) {
	blockHex := hex.EncodeToString(block)
	s.mu.Lock()
	qc, ok := s.qcs[blockHex]
	s.mu.Unlock()
	return qc, ok
}

// GetCommit returns the commit record for block if known.
func (s *L2Service) GetCommit(block []byte) (commitMsg, bool) {
	blockHex := hex.EncodeToString(block)
	s.mu.Lock()
	cm, ok := s.commitMsg[blockHex]
	s.mu.Unlock()
	return cm, ok
}

// L2Status captures a snapshot of checkpoint state for diagnostics.
type L2Status struct {
	TrackedBlocks   int   `json:"tracked_blocks"`
	QuorumCerts     int   `json:"quorum_certs"`
	CommittedBlocks int   `json:"committed_blocks"`
	LatestCommit    int64 `json:"latest_commit_height"`
}

// Status returns a diagnostic snapshot of tracked L2 state.
func (s *L2Service) Status() L2Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return L2Status{
		TrackedBlocks:   len(s.blocks),
		QuorumCerts:     len(s.qcs),
		CommittedBlocks: len(s.committed),
		LatestCommit:    s.highestCommitLocked(),
	}
}

func (s *L2Service) highestCommitLocked() int64 {
	var best int64
	for _, info := range s.committed {
		if info.height > best {
			best = info.height
		}
	}
	return best
}

func (s *L2Service) cleanupLoop() {
	if s.params.VoteExpiry <= 0 {
		return
	}
	ticker := time.NewTicker(s.params.VoteExpiry / 2)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.pruneExpired()
		}
	}
}

func (s *L2Service) pruneExpired() {
	expiry := s.params.VoteExpiry
	now := time.Now()
	s.mu.Lock()
	for blockHex, peers := range s.votes {
		for peerID, rec := range peers {
			if expiry > 0 && now.Sub(rec.Received) > expiry {
				delete(peers, peerID)
			}
		}
		if len(peers) == 0 {
			delete(s.votes, blockHex)
		}
	}
	for blockHex := range s.sentVote {
		if _, committed := s.committed[blockHex]; committed {
			delete(s.sentVote, blockHex)
		}
	}
	for blockHex := range s.blocks {
		if _, committed := s.committed[blockHex]; committed {
			delete(s.blocks, blockHex)
		}
	}
	for blockHex := range s.pending {
		if _, committed := s.committed[blockHex]; committed {
			delete(s.pending, blockHex)
		}
	}
	for parentHex, kids := range s.childQCs {
		if _, committed := s.committed[parentHex]; committed {
			delete(s.childQCs, parentHex)
			continue
		}
		for childHex := range kids {
			if _, ok := s.qcs[childHex]; !ok {
				delete(kids, childHex)
			}
		}
		if len(kids) == 0 {
			delete(s.childQCs, parentHex)
		}
	}
	s.mu.Unlock()
}
