// Package testutil provides the deterministic keys, fixtures, and fakes the
// invariant suites share.
//
// Determinism is the whole point: golden digests must not move between runs,
// machines, or Go versions. Every key here is derived from a hardcoded seed,
// every timestamp from a constant, and nothing reads the clock or /dev/urandom.
//
// None of these keys are secret and none may be used outside tests.
package testutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"signet.dev/ps/internal/tokens"
)

// Root keys (secp256k1) — "the person". Two of them, so tests can express
// "signed by someone who is not this root" without inventing addresses.
const (
	RootPrivHex      = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	OtherRootPrivHex = "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
)

// Ed25519 seeds — the PS issuer key and two agent keys.
var (
	issuerSeed     = seed(0x11)
	agentSeed      = seed(0x22)
	otherAgentSeed = seed(0x33)
)

func seed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

// --- root (person) keys ---------------------------------------------------

func RootKey(tb testing.TB) *ecdsa.PrivateKey      { return ecdsaKey(tb, RootPrivHex) }
func OtherRootKey(tb testing.TB) *ecdsa.PrivateKey { return ecdsaKey(tb, OtherRootPrivHex) }

// RootAddr returns the EIP-55 checksummed address of the primary test root.
func RootAddr(tb testing.TB) string      { return addrOf(tb, RootKey(tb)) }
func OtherRootAddr(tb testing.TB) string { return addrOf(tb, OtherRootKey(tb)) }

func ecdsaKey(tb testing.TB, hexPriv string) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ethcrypto.HexToECDSA(hexPriv)
	if err != nil {
		tb.Fatalf("testutil: bad test private key: %v", err)
	}
	return k
}

func addrOf(tb testing.TB, k *ecdsa.PrivateKey) string {
	tb.Helper()
	return ethcrypto.PubkeyToAddress(k.PublicKey).Hex()
}

// --- PS issuer key (Ed25519) ---------------------------------------------

func IssuerKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	return ed25519.NewKeyFromSeed(issuerSeed)
}

func IssuerJWK(tb testing.TB) tokens.JWK { return jwkOf(tb, IssuerKey(tb)) }

// IssuerThumb is the RFC 7638 thumbprint a PSA pins in KeyThumbprints.
func IssuerThumb(tb testing.TB) string { return IssuerJWK(tb).Thumbprint() }

// --- agent keys (Ed25519) -------------------------------------------------

func AgentKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	return ed25519.NewKeyFromSeed(agentSeed)
}

func OtherAgentKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	return ed25519.NewKeyFromSeed(otherAgentSeed)
}

func AgentJWK(tb testing.TB) tokens.JWK      { return jwkOf(tb, AgentKey(tb)) }
func OtherAgentJWK(tb testing.TB) tokens.JWK { return jwkOf(tb, OtherAgentKey(tb)) }

func AgentThumb(tb testing.TB) string      { return AgentJWK(tb).Thumbprint() }
func OtherAgentThumb(tb testing.TB) string { return OtherAgentJWK(tb).Thumbprint() }

func jwkOf(tb testing.TB, priv ed25519.PrivateKey) tokens.JWK {
	tb.Helper()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		tb.Fatal("testutil: not an ed25519 key")
	}
	return tokens.JWK{
		Kty: "OKP", Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(pub),
	}
}

// --- clock ----------------------------------------------------------------

// The fixture validity window, and a "now" that sits inside it. Tests that
// exercise window edges move the clock, never the fixture.
const (
	NotBefore = int64(1700000000)
	NotAfter  = int64(1700003600)
	NowUnix   = int64(1700001000) // comfortably inside [NotBefore, NotAfter]
)

// Clock returns a Now func pinned to unix second u, for injection into the
// verifiers (all of which take a Now func precisely so this is possible).
func Clock(u int64) func() time.Time {
	return func() time.Time { return time.Unix(u, 0).UTC() }
}

// Now is the default in-window clock.
func Now() time.Time { return time.Unix(NowUnix, 0).UTC() }
