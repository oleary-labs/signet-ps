// Package consent implements AAuth's async authorization semantics (202 /
// Location / Retry-After, approval codes, polling) plus the non-custodial
// step-up: approvals above the PSA threshold are not clicks, they are
// root-key signatures over an ApprovalDigest the PS constructs but cannot
// forge (I3).
//
// Two tiers:
//
//	TierRoutine   within PSA scope, below step-up threshold. Approval is a
//	              click (or auto-approval per standing mission rules). The
//	              PSA is the authority; the click is UX.
//	TierElevated  above threshold / new counterparty / claim vouching beyond
//	              standing rules. Approval REQUIRES an EIP-712 signature by
//	              the root over the specific request. The PS relays it into
//	              the auth token's step_up claim; verifiers re-check it.
package consent

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type Tier int

const (
	TierRoutine Tier = iota
	TierElevated
)

type State string

const (
	StatePending  State = "pending"
	StateApproved State = "approved"
	StateDenied   State = "denied"
	StateExpired  State = "expired"
)

// Request is one authorization decision in flight. It is also a mission-log
// entry the moment it is created (append-only; see missions package).
type Request struct {
	ID          string
	Code        string // short human code shown at the approval URL
	AgentID     string
	Resource    string // aud-to-be
	AmountWei   string // "" for non-payment
	ScopeReq    []string
	MissionS256 string
	Tier        Tier
	State       State
	CreatedAt   time.Time
	ExpiresAt   time.Time // consent window; whoami demo uses 600s — same default

	// ResourceJSON is the full tokens.ResourceClaims marshalled at request
	// creation, so the async (poll) mint path reads back exactly what the
	// resource asked for instead of lossily reconstructing it. Kept as an
	// opaque blob so this package stays free of a tokens dependency.
	ResourceJSON []byte

	// TierElevated only, filled at approval:
	StepUpSig []byte // 65-byte root signature over ApprovalDigest
}

// ApprovalDigest is what the root key signs for TierElevated. It binds the
// approval to *this* request: agent, resource, amount, scope, and a window —
// so a captured signature cannot be replayed for a different action.
func ApprovalDigest(r *Request, chainID int64, registry string) ([32]byte, error) {
	td := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"}, {Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"},
			},
			"Approval": {
				{Name: "requestId", Type: "string"},
				{Name: "agent", Type: "string"},
				{Name: "resource", Type: "string"},
				{Name: "amountWei", Type: "uint256"},
				{Name: "scopeHash", Type: "bytes32"},
				{Name: "missionS256", Type: "bytes32"},
				{Name: "expiresAt", Type: "uint256"},
			},
		},
		PrimaryType: "Approval",
		Domain: apitypes.TypedDataDomain{
			Name: "SignetPS", Version: "1",
			ChainId: hexOrDec(chainID), VerifyingContract: registry,
		},
		Message: apitypes.TypedDataMessage{
			"requestId":   r.ID,
			"agent":       r.AgentID,
			"resource":    r.Resource,
			"amountWei":   orZero(r.AmountWei),
			"scopeHash":   keccakStrings(r.ScopeReq),
			"missionS256": "0x" + r.MissionS256,
			"expiresAt":   fmt.Sprint(r.ExpiresAt.Unix()),
		},
	}
	var out [32]byte
	h, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return out, err
	}
	copy(out[:], h)
	return out, nil
}

// Store is the pending-request state machine. Poll transitions nothing;
// only Approve/Deny/expiry do — polling is read-only by design so that the
// agent's Retry-After loop cannot influence outcomes.
type Store struct {
	mu     sync.Mutex
	byID   map[string]*Request
	byCode map[string]string
}

func NewStore() *Store {
	return &Store{byID: map[string]*Request{}, byCode: map[string]string{}}
}

func (s *Store) Create(r *Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.State = StatePending
	s.byID[r.ID] = r
	s.byCode[r.Code] = r.ID
}

func (s *Store) Poll(id string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("unknown request")
	}
	if r.State == StatePending && time.Now().After(r.ExpiresAt) {
		r.State = StateExpired
	}
	return r, nil
}

// ApproveRoutine: TierRoutine click-approval. Refuses to approve an elevated
// request — a click can never substitute for a signature (I3, enforced
// structurally rather than by handler discipline).
func (s *Store) ApproveRoutine(code string) error {
	r, err := s.byCodeLocked(code)
	if err != nil {
		return err
	}
	if r.Tier != TierRoutine {
		return fmt.Errorf("elevated request requires root signature, not click")
	}
	return s.transition(r, StateApproved)
}

// ApproveElevated verifies the root's signature over the ApprovalDigest and
// stores it for inclusion in the minted token's step_up claim.
func (s *Store) ApproveElevated(code, root string, chainID int64, registry string, sig []byte) error {
	r, err := s.byCodeLocked(code)
	if err != nil {
		return err
	}
	if r.Tier != TierElevated {
		return fmt.Errorf("request is not elevated")
	}
	digest, err := ApprovalDigest(r, chainID, registry)
	if err != nil {
		return err
	}
	if err := verifyEOASig(root, digest, sig); err != nil {
		// NOTE: smart-account roots go through attest.ERC1271Verifier here in
		// the wired server; kept EOA-only in this package to avoid the dep.
		return fmt.Errorf("step-up: %w", err)
	}
	s.mu.Lock()
	r.StepUpSig = sig
	s.mu.Unlock()
	return s.transition(r, StateApproved)
}

func (s *Store) Deny(code string) error {
	r, err := s.byCodeLocked(code)
	if err != nil {
		return err
	}
	return s.transition(r, StateDenied)
}

func (s *Store) transition(r *Request, to State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.State != StatePending {
		return fmt.Errorf("request already %s", r.State)
	}
	if time.Now().After(r.ExpiresAt) {
		r.State = StateExpired
		return fmt.Errorf("consent window expired")
	}
	r.State = to
	return nil
}

// ByCode resolves a pending request by its human-facing approval code. Used
// by the approval surface and step-up endpoint (which know the code, not the id).
func (s *Store) ByCode(code string) (*Request, error) { return s.byCodeLocked(code) }

func (s *Store) byCodeLocked(code string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byCode[code]
	if !ok {
		return nil, fmt.Errorf("unknown code")
	}
	return s.byID[id], nil
}

func verifyEOASig(root string, digest [32]byte, sig []byte) error {
	if len(sig) != 65 {
		return fmt.Errorf("bad signature length")
	}
	s := make([]byte, 65)
	copy(s, sig)
	if s[64] >= 27 {
		s[64] -= 27
	}
	pub, err := ethcrypto.SigToPub(digest[:], s)
	if err != nil {
		return err
	}
	if ethcrypto.PubkeyToAddress(*pub).Hex() != root { // normalize in wired code
		return fmt.Errorf("signer is not root")
	}
	return nil
}

// --- helpers: hexOrDec, keccakStrings, orZero ---

// hexOrDec adapts an int64 chain id to the apitypes EIP-712 domain type.
func hexOrDec(chainID int64) *math.HexOrDecimal256 { return math.NewHexOrDecimal256(chainID) }

// orZero maps an empty decimal string to "0" (uint256 fields must be non-empty).
func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// keccakStrings hashes a string slice to a bytes32 hex the way attest hashes
// its JSON arrays — keccak256 over the canonical JSON encoding — so the scope
// commitment is computed identically on both sides of the wire.
func keccakStrings(xs []string) string {
	b, _ := json.Marshal(xs)
	return "0x" + hex.EncodeToString(ethcrypto.Keccak256(b))
}
