package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/consent"
	"signet.dev/ps/internal/tokens"
)

// --- JSON responses -------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr renders an OAuth-style error body. `oerr` is the machine code
// (invalid_request, …); err carries the human description.
func writeErr(w http.ResponseWriter, code int, oerr string, err error) {
	writeJSON(w, code, map[string]any{
		"error":             oerr,
		"error_description": err.Error(),
	})
}

// --- consent tiering ------------------------------------------------------

// tierFor decides whether a request can ride the PSA envelope (routine click)
// or demands a fresh root signature (elevated). v0 rule: payment strictly
// above the PSA step-up threshold is elevated; everything else is routine.
func tierFor(scope attest.Scope, res tokens.ResourceClaims) consent.Tier {
	if res.AmountWei == "" {
		return consent.TierRoutine
	}
	amt := bigOrZero(res.AmountWei)
	th := bigOrZero(scope.StepUpAboveWei)
	if th.Sign() > 0 && amt.Cmp(th) > 0 {
		return consent.TierElevated
	}
	return consent.TierRoutine
}

func tierName(t consent.Tier) string {
	if t == consent.TierElevated {
		return "elevated"
	}
	return "routine"
}

// --- resource token -------------------------------------------------------

// parseResourceToken reads the claims out of an aa-resource+jwt. The PS is the
// audience here, not a verifier of the resource's key, so v0 decodes the
// payload without checking the resource's signature (the resource's own auth
// story is orthogonal to the non-custodial chain).
func parseResourceToken(raw string) (tokens.ResourceClaims, error) {
	var rc tokens.ResourceClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return rc, fmt.Errorf("resource_token: want compact jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return rc, fmt.Errorf("resource_token payload: %w", err)
	}
	if err := json.Unmarshal(payload, &rc); err != nil {
		return rc, fmt.Errorf("resource_token claims: %w", err)
	}
	if rc.Iss == "" {
		return rc, fmt.Errorf("resource_token: missing iss")
	}
	return rc, nil
}

// resourceOf reads back the ResourceClaims persisted on the request at
// creation — the whole-fidelity replacement for the old lossy reconstruction.
func resourceOf(req *consent.Request) tokens.ResourceClaims {
	var rc tokens.ResourceClaims
	_ = json.Unmarshal(req.ResourceJSON, &rc)
	return rc
}

func marshalResource(rc tokens.ResourceClaims) []byte {
	b, _ := json.Marshal(rc)
	return b
}

// agentKeyFromGrant reconstructs the agent's JWK from the grant's transport
// pubkey field, for the token's cnf (proof-of-possession) claim.
func agentKeyFromGrant(g *attest.AgentGrant) tokens.JWK {
	return tokens.JWK{Kty: "OKP", Crv: "Ed25519", X: g.AgentPubKey}
}

// --- ids, hex -------------------------------------------------------------

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// newCode is the short human-facing approval code shown at the approval URL.
func newCode() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func hexStr(b []byte) string { return "0x" + hex.EncodeToString(b) }

func hexBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, _ := hex.DecodeString(s)
	return b
}

// bigOrZero parses a decimal wei string; empty/invalid yields 0 (never nil).
func bigOrZero(s string) *big.Int {
	if s == "" {
		return big.NewInt(0)
	}
	if n, ok := new(big.Int).SetString(s, 10); ok {
		return n
	}
	return big.NewInt(0)
}
