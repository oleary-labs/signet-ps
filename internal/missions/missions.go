// Package missions: the append-only, hash-chained agent<->PS interaction log
// and the intent-consistency gate. The AAuth stance is that missions are not
// a policy language — the PS judges whether each request is consistent with
// the mission's intent, using the accumulated log. v0 ships the log for real
// and the judge as a trivial threshold/allowlist evaluator behind an
// interface, because the log's integrity matters immediately (it is the
// dispute-evidence substrate) while judgment sophistication can grow.
package missions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Entry struct {
	Kind      string    `json:"kind"` // token_request | token_issued | agent_enrolled | clarification | audit
	RequestID string    `json:"request_id,omitempty"`
	At        time.Time `json:"at"`
	Prev      string    `json:"prev"` // hash chain: tamper-evident, exportable, and — for the
	Hash      string    `json:"hash"` // payment subset — anchorable to settlement (see NOTE below)
}

// NOTE(settlement anchoring): for payment resources the resource-side
// verifier is (or fronts) the settlement contract; periodically committing
// the log head hash on-chain makes the payment subset of this log provable
// against a verifier nobody operates. That is deliberately an *anchor* of
// this log, not a replacement for it.

type Log struct {
	mu      sync.Mutex
	byAgent map[string][]Entry
}

func NewLog() *Log { return &Log{byAgent: map[string][]Entry{}} }

func (l *Log) Append(agentID string, e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	chain := l.byAgent[agentID]
	if n := len(chain); n > 0 {
		e.Prev = chain[n-1].Hash
	}
	b, _ := json.Marshal(struct {
		Kind, RequestID, Prev string
		At                    time.Time
	}{e.Kind, e.RequestID, e.Prev, e.At})
	h := sha256.Sum256(b)
	e.Hash = hex.EncodeToString(h[:])
	l.byAgent[agentID] = append(chain, e)
}

func (l *Log) Export() map[string][]Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string][]Entry{}
	for k, v := range l.byAgent {
		out[k] = append([]Entry(nil), v...)
	}
	return out
}

// Consistent is the v0 judge: does this request fit the mission scope at all?
// Real impl consults the mission blob (spend caps, merchant classes,
// frequency) and the log (velocity, drift from stated intent).
func (l *Log) Consistent(agentID, missionS256 string, scope []string, amountWei string) error {
	if missionS256 == "" {
		return fmt.Errorf("no mission bound to agent")
	}
	return nil // v0: defer to PSA envelope + consent tiering
}

// AutoApprovable: standing mission rules that let TierRoutine requests skip
// the click (e.g., repeat merchant under running cap). v0: never.
func (l *Log) AutoApprovable(agentID string, scope []string, amountWei string) bool { return false }
