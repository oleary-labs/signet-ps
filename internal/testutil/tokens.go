package testutil

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/tokens"
)

// IssuerKid is the `kid` the fixture issuer key publishes.
const IssuerKid = "ps-test-01"

// IssuerSigningKey is the PS issuer key in the form Mint wants.
func IssuerSigningKey(tb testing.TB) tokens.IssuerKey {
	tb.Helper()
	return tokens.IssuerKey{Kid: IssuerKid, Priv: IssuerKey(tb), Pub: IssuerJWK(tb)}
}

// LiveWindow returns a validity window around the real clock.
//
// Mint stamps iat/exp from time.Now() and takes no injectable clock, so tokens
// minted in tests are always "now". Attestations they ride on therefore need a
// window covering now — the frozen fixture window (which the golden digests
// depend on) is deliberately in the past and cannot be reused here.
func LiveWindow() (int64, int64) {
	n := time.Now().Unix()
	return n - 60, n + 3600
}

// --- resolver fakes -------------------------------------------------------

// FakeJWKS resolves issuer keys without a network. Kid is ignored unless
// ByKid is populated: most tests have exactly one issuer key.
type FakeJWKS struct {
	Key_  tokens.JWK
	ByKid map[string]tokens.JWK
	Err   error
}

func NewFakeJWKS(tb testing.TB) *FakeJWKS {
	tb.Helper()
	return &FakeJWKS{Key_: IssuerJWK(tb)}
}

func (f *FakeJWKS) Key(_ context.Context, _ string, kid string) (tokens.JWK, error) {
	if f.Err != nil {
		return tokens.JWK{}, f.Err
	}
	if f.ByKid != nil {
		k, ok := f.ByKid[kid]
		if !ok {
			return tokens.JWK{}, fmt.Errorf("no key for kid %q", kid)
		}
		return k, nil
	}
	return f.Key_, nil
}

// FakeAttest serves the PSA and AgentGrant a token references. It does NOT
// re-check content hashes: that is the real resolver's job (and is covered by
// the attest ContentHash golden test). Here the point is to control exactly
// which documents the verifier sees — including the case where they are
// documents the token never legitimately committed to.
type FakeAttest struct {
	PSAVal   *attest.PersonServerAuthorization
	GrantVal *attest.AgentGrant
	PSAErr   error
	GrantErr error
}

func (f *FakeAttest) PSA(_ context.Context, _ string) (*attest.PersonServerAuthorization, error) {
	if f.PSAErr != nil {
		return nil, f.PSAErr
	}
	return f.PSAVal, nil
}

func (f *FakeAttest) AgentGrant(_ context.Context, _, _ string) (*attest.AgentGrant, error) {
	if f.GrantErr != nil {
		return nil, f.GrantErr
	}
	return f.GrantVal, nil
}

// FakeReplay is an in-memory jti set. Seen exposes what was recorded, so tests
// can assert *whether a failed verification consumed the jti* — the difference
// between a rejected token and a burned one.
type FakeReplay struct {
	Seen map[string]bool
}

func NewFakeReplay() *FakeReplay { return &FakeReplay{Seen: map[string]bool{}} }

func (f *FakeReplay) SeenJTI(jti string, _ int64) bool {
	if f.Seen[jti] {
		return true
	}
	f.Seen[jti] = true
	return false
}

// --- hand-rolled JWTs -----------------------------------------------------

// SignJWTRaw builds a compact JWS from an arbitrary header and payload.
//
// Mint deliberately cannot produce malformed tokens — no `alg: none`, no
// over-long TTL, no missing extension claims. Those are exactly the inputs a
// verifier must reject, so the suite forges them directly rather than asking
// the minter to misbehave.
func SignJWTRaw(tb testing.TB, priv ed25519.PrivateKey, hdr map[string]any, claims any) string {
	tb.Helper()
	h, err := json.Marshal(hdr)
	if err != nil {
		tb.Fatalf("testutil: marshal header: %v", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		tb.Fatalf("testutil: marshal claims: %v", err)
	}
	signing := b64(h) + "." + b64(c)
	return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
}

// DefaultJWTHeader is the header Mint produces, for tests that vary only claims.
func DefaultJWTHeader() map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": "auth+jwt", "kid": IssuerKid}
}

// DecodeClaims parses a compact JWT's payload without verifying anything.
func DecodeClaims(tb testing.TB, raw string) tokens.AuthClaims {
	tb.Helper()
	parts := splitDot(raw)
	if len(parts) != 3 {
		tb.Fatalf("testutil: not a compact JWT: %q", raw)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("testutil: decode payload: %v", err)
	}
	var c tokens.AuthClaims
	if err := json.Unmarshal(body, &c); err != nil {
		tb.Fatalf("testutil: unmarshal claims: %v", err)
	}
	return c
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func splitDot(s string) []string {
	out, cur := []string{}, ""
	for _, r := range s {
		if r == '.' {
			out, cur = append(out, cur), ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}
