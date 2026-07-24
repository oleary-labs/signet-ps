// Package attest implements the non-custodial extension: root-key-signed
// attestations that bound what the person server and agents may do.
//
// Two typed structures, both EIP-712 so wallets render them legibly and
// contracts can verify them:
//
//	PersonServerAuthorization (PSA): root -> PS issuer keys
//	AgentGrant (AG):                 root -> agent key
//
// Design rule: the PS *stores and serves* these; it can never *create* them.
// Everything in this package is verification-side except digest construction
// (which the PS builds so the wallet has the right thing to sign).
package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	// v0 dependency choices, pinned in go.mod:
	//   github.com/ethereum/go-ethereum/crypto        secp256k1 recover, keccak256
	//   github.com/ethereum/go-ethereum/signer/core   EIP-712 TypedData hashing
	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Scope bounds what a PSA-covered issuer key may mint. Kept deliberately
// flat and enumerable in v0 — this is a constraint envelope, not a policy
// language (same design stance the AAuth draft takes for missions).
type Scope struct {
	MaxTokenTTLSeconds int64    `json:"maxTokenTTLSeconds"` // cap on auth_token exp-iat
	AllowedClaims      []string `json:"allowedClaims"`      // claims PS may vouch: "name","email","kyc.relayed",...
	PaymentCapWei      string   `json:"paymentCapWei"`      // "0" = no payment vouching; decimal string
	StepUpAboveWei     string   `json:"stepUpAboveWei"`     // I3 threshold: above this, step_up REQUIRED
}

// PersonServerAuthorization: the root key's grant to a PS. The unsigned
// struct is what gets EIP-712-hashed; Signature is kept alongside.
type PersonServerAuthorization struct {
	Root           string   `json:"root"`           // 0x… EOA or ERC-1271 account
	Issuer         string   `json:"issuer"`         // PS `iss` URL this grant covers
	KeyThumbprints []string `json:"keyThumbprints"` // RFC 7638 thumbprints of authorized PS issuer keys
	Scope          Scope    `json:"scope"`
	NotBefore      int64    `json:"notBefore"` // unix seconds
	NotAfter       int64    `json:"notAfter"`
	RegistryChain  int64    `json:"registryChain"` // e.g. 8453 (Base)
	Registry       string   `json:"registry"`      // revocation registry contract address
	Nonce          uint64   `json:"nonce"`         // revocation handle: registry tracks (root, nonce) liveness

	Signature []byte `json:"signature"` // 65-byte [R||S||V] over the EIP-712 digest
}

// AgentGrant: the root key's grant to a specific agent instance. The PS
// witnesses (stores, serves, indexes) but does not author these.
type AgentGrant struct {
	Root            string `json:"root"`
	AgentIdentifier string `json:"agentIdentifier"` // aauth:local@domain
	AgentThumbprint string `json:"agentThumbprint"` // RFC 7638 of the agent's Ed25519 key
	// AgentPubKey is the base64url Ed25519 public key (JWK `x`). Transport-only:
	// NOT covered by the EIP-712 digest (AgentThumbprint commits to it), but the
	// PS needs the full key to build the token's `cnf`. Verifiers re-derive the
	// thumbprint from it and check it equals AgentThumbprint.
	AgentPubKey      string `json:"agentPubKey,omitempty"`
	MissionScopeS256 string `json:"missionScopeS256"` // hash of the mission-scope blob PS+agent hold
	NotBefore        int64  `json:"notBefore"`
	NotAfter         int64  `json:"notAfter"`
	RegistryChain    int64  `json:"registryChain"`
	Registry         string `json:"registry"`
	Nonce            uint64 `json:"nonce"`

	Signature []byte `json:"signature"`
}

// SuccessorStatement is reserved for rotation/recovery design (see DESIGN.md
// v0 cuts): oldRoot signs succession to newRoot; guardians handle loss.
type SuccessorStatement struct {
	OldRoot     string `json:"oldRoot"`
	NewRoot     string `json:"newRoot"`
	EffectiveAt int64  `json:"effectiveAt"`
	Signature   []byte `json:"signature"`
}

// ---------------------------------------------------------------------------
// EIP-712 digests
// ---------------------------------------------------------------------------

const eip712Name, eip712Version = "SignetPS", "1"

func domain(chainID int64, registry string) apitypes.TypedDataDomain {
	return apitypes.TypedDataDomain{
		Name:              eip712Name,
		Version:           eip712Version,
		ChainId:           mustBig(chainID),
		VerifyingContract: registry,
	}
}

var psaTypes = apitypes.Types{
	"EIP712Domain": {
		{Name: "name", Type: "string"}, {Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"},
	},
	"Scope": {
		{Name: "maxTokenTTLSeconds", Type: "uint256"},
		{Name: "allowedClaimsHash", Type: "bytes32"}, // keccak256 of canonical JSON array
		{Name: "paymentCapWei", Type: "uint256"},
		{Name: "stepUpAboveWei", Type: "uint256"},
	},
	"PersonServerAuthorization": {
		{Name: "root", Type: "address"},
		{Name: "issuer", Type: "string"},
		{Name: "keyThumbprintsHash", Type: "bytes32"}, // keccak256 of canonical JSON array
		{Name: "scope", Type: "Scope"},
		{Name: "notBefore", Type: "uint256"},
		{Name: "notAfter", Type: "uint256"},
		{Name: "nonce", Type: "uint256"},
	},
	"AgentGrant": {
		{Name: "root", Type: "address"},
		{Name: "agentIdentifier", Type: "string"},
		{Name: "agentThumbprint", Type: "string"},
		{Name: "missionScopeS256", Type: "bytes32"},
		{Name: "notBefore", Type: "uint256"},
		{Name: "notAfter", Type: "uint256"},
		{Name: "nonce", Type: "uint256"},
	},
}

// PSADigest returns the EIP-712 digest the root must sign. The PS calls this
// to hand the wallet a signable payload; verifiers call it to recover.
func PSADigest(p *PersonServerAuthorization) ([32]byte, error) {
	td := apitypes.TypedData{
		Types:       psaTypes,
		PrimaryType: "PersonServerAuthorization",
		Domain:      domain(p.RegistryChain, p.Registry),
		Message: apitypes.TypedDataMessage{
			"root":               p.Root,
			"issuer":             p.Issuer,
			"keyThumbprintsHash": keccakJSON(p.KeyThumbprints),
			"scope": apitypes.TypedDataMessage{
				"maxTokenTTLSeconds": fmt.Sprint(p.Scope.MaxTokenTTLSeconds),
				"allowedClaimsHash":  keccakJSON(p.Scope.AllowedClaims),
				"paymentCapWei":      orZero(p.Scope.PaymentCapWei),
				"stepUpAboveWei":     orZero(p.Scope.StepUpAboveWei),
			},
			"notBefore": fmt.Sprint(p.NotBefore),
			"notAfter":  fmt.Sprint(p.NotAfter),
			"nonce":     fmt.Sprint(p.Nonce),
		},
	}
	return typedDataDigest(td)
}

// AgentGrantDigest mirrors PSADigest for AgentGrant.
func AgentGrantDigest(g *AgentGrant) ([32]byte, error) {
	td := apitypes.TypedData{
		Types:       psaTypes,
		PrimaryType: "AgentGrant",
		Domain:      domain(g.RegistryChain, g.Registry),
		Message: apitypes.TypedDataMessage{
			"root":             g.Root,
			"agentIdentifier":  g.AgentIdentifier,
			"agentThumbprint":  g.AgentThumbprint,
			"missionScopeS256": "0x" + g.MissionScopeS256,
			"notBefore":        fmt.Sprint(g.NotBefore),
			"notAfter":         fmt.Sprint(g.NotAfter),
			"nonce":            fmt.Sprint(g.Nonce),
		},
	}
	return typedDataDigest(td)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// RevocationRegistry answers "is grant (root, nonce) still live?" from a
// source the PS does not control (I4). Implementations: contract read on
// Base; cached/indexed variants MUST fail closed on staleness > TTL.
type RevocationRegistry interface {
	IsRevoked(ctx context.Context, chainID int64, registry, root string, nonce uint64) (bool, error)
}

// ERC1271Verifier lets the root be a smart account (passkey-controlled,
// social recovery) instead of a raw EOA — the "key-rooted without being
// seed-phrase-rooted" requirement.
type ERC1271Verifier interface {
	IsValidSignature(ctx context.Context, chainID int64, account string, digest [32]byte, sig []byte) (bool, error)
}

type Verifier struct {
	Registry RevocationRegistry
	ERC1271  ERC1271Verifier // nil => EOA-only mode
	Now      func() time.Time
}

// VerifyPSA enforces invariant I1's precondition: a live, in-window,
// root-signed grant covering this issuer. issuerKeyThumb is the RFC 7638
// thumbprint of the key that signed the auth token under inspection.
func (v *Verifier) VerifyPSA(ctx context.Context, p *PersonServerAuthorization, issuer, issuerKeyThumb string) error {
	now := v.Now().Unix()
	if p.Issuer != issuer {
		return fmt.Errorf("psa: issuer mismatch: grant covers %q, token iss %q", p.Issuer, issuer)
	}
	if now < p.NotBefore || now > p.NotAfter {
		return fmt.Errorf("psa: outside validity window")
	}
	if !contains(p.KeyThumbprints, issuerKeyThumb) {
		return fmt.Errorf("psa: signing key %s not in authorized set", issuerKeyThumb)
	}

	digest, err := PSADigest(p)
	if err != nil {
		return fmt.Errorf("psa: digest: %w", err)
	}
	if err := v.verifyRootSig(ctx, p.RegistryChain, p.Root, digest, p.Signature); err != nil {
		return fmt.Errorf("psa: %w", err)
	}

	revoked, err := v.Registry.IsRevoked(ctx, p.RegistryChain, p.Registry, p.Root, p.Nonce)
	if err != nil {
		return fmt.Errorf("psa: registry unavailable (failing closed): %w", err)
	}
	if revoked {
		return fmt.Errorf("psa: revoked (root=%s nonce=%d)", p.Root, p.Nonce)
	}
	return nil
}

// VerifyAgentGrant is the AG twin; agentThumb comes from the auth token's
// cnf key (which the resource has already matched against the RFC 9421
// request signature — so this closes root -> agent).
func (v *Verifier) VerifyAgentGrant(ctx context.Context, g *AgentGrant, root, agentID, agentThumb string) error {
	now := v.Now().Unix()
	if g.Root != root {
		return fmt.Errorf("agentgrant: root mismatch")
	}
	if g.AgentIdentifier != agentID {
		return fmt.Errorf("agentgrant: agent identifier mismatch")
	}
	if g.AgentThumbprint != agentThumb {
		return fmt.Errorf("agentgrant: agent key mismatch")
	}
	if now < g.NotBefore || now > g.NotAfter {
		return fmt.Errorf("agentgrant: outside validity window")
	}
	digest, err := AgentGrantDigest(g)
	if err != nil {
		return err
	}
	if err := v.verifyRootSig(ctx, g.RegistryChain, g.Root, digest, g.Signature); err != nil {
		return fmt.Errorf("agentgrant: %w", err)
	}
	revoked, err := v.Registry.IsRevoked(ctx, g.RegistryChain, g.Registry, g.Root, g.Nonce)
	if err != nil {
		return fmt.Errorf("agentgrant: registry unavailable (failing closed): %w", err)
	}
	if revoked {
		return fmt.Errorf("agentgrant: revoked")
	}
	return nil
}

// verifyRootSig: EOA path = ecrecover and compare; smart-account path =
// ERC-1271 isValidSignature call. Try EOA first (cheap, offline), fall back
// to 1271 when recovery doesn't match AND a verifier is configured.
func (v *Verifier) verifyRootSig(ctx context.Context, chainID int64, root string, digest [32]byte, sig []byte) error {
	if len(sig) == 65 {
		s := make([]byte, 65)
		copy(s, sig)
		if s[64] >= 27 {
			s[64] -= 27
		}
		if pub, err := ethcrypto.SigToPub(digest[:], s); err == nil {
			if addrEq(ethcrypto.PubkeyToAddress(*pub).Hex(), root) {
				return nil
			}
		}
	}
	if v.ERC1271 != nil {
		ok, err := v.ERC1271.IsValidSignature(ctx, chainID, root, digest, sig)
		if err != nil {
			return fmt.Errorf("erc1271: %w", err)
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("root signature invalid for %s", root)
}

// ---------------------------------------------------------------------------
// Content hashing (by-reference resolution: `psa` claim carries #s256=…)
// ---------------------------------------------------------------------------

// S256 of the canonical (signed) attestation JSON, so tokens can carry a
// tamper-evident reference instead of the full blob.
func ContentHash(v any) (string, error) {
	b, err := json.Marshal(v) // v0: rely on Go's deterministic struct-order marshal; v1: JCS (RFC 8785)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// --- small helpers -------------------------------------------------------

func keccakJSON(v any) string {
	b, _ := json.Marshal(v)
	return "0x" + hex.EncodeToString(ethcrypto.Keccak256(b))
}

func typedDataDigest(td apitypes.TypedData) ([32]byte, error) {
	var out [32]byte
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return out, err
	}
	copy(out[:], hash)
	return out, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func addrEq(a, b string) bool { return normalizeHex(a) == normalizeHex(b) }

func normalizeHex(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'F' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func mustBig(i int64) *math.HexOrDecimal256 { // small adapter for the apitypes domain
	return math.NewHexOrDecimal256(i)
}
