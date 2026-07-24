package testutil

import (
	"crypto/ecdsa"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"signet.dev/ps/internal/attest"
)

// Fixture constants. These are frozen: the golden digest tests hash them, so
// changing any value here changes those digests — which is exactly the alarm
// we want if someone edits a fixture without meaning to.
const (
	Issuer       = "https://ps.example.test"
	AgentID      = "aauth:fixture@agents.example.test"
	RegistryAddr = "0x00000000000000000000000000000000000000a1"
	ChainID      = int64(8453)

	// Separate revocation handles: revoking the PSA must not touch the grant.
	PSANonce   = uint64(7)
	GrantNonce = uint64(9)

	// 32 bytes of hex — MissionScopeS256 is an EIP-712 bytes32.
	MissionS256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// --- PersonServerAuthorization -------------------------------------------

// PSAOpt mutates the PSA *before* it is signed, so the result is always a
// validly-signed document. That distinction matters: "expired" and "wrong
// issuer" are legitimately signed grants that fail on their own terms, whereas
// tampering (flipping a byte after signing) is a different failure mode
// entirely. Tests express the latter by mutating the returned struct.
type PSAOpt func(*attest.PersonServerAuthorization)

// ValidPSA returns a root-signed PSA that passes VerifyPSA under the default
// clock, issuer, issuer-key thumbprint, and a live registry.
func ValidPSA(tb testing.TB, opts ...PSAOpt) *attest.PersonServerAuthorization {
	tb.Helper()
	p := &attest.PersonServerAuthorization{
		Root:           RootAddr(tb),
		Issuer:         Issuer,
		KeyThumbprints: []string{IssuerThumb(tb)},
		Scope: attest.Scope{
			MaxTokenTTLSeconds: 3600,
			AllowedClaims:      []string{"email"},
			PaymentCapWei:      "1000000000000000000", // 1e18
			StepUpAboveWei:     "100000000000000000",  // 1e17
		},
		NotBefore:     NotBefore,
		NotAfter:      NotAfter,
		RegistryChain: ChainID,
		Registry:      RegistryAddr,
		Nonce:         PSANonce,
	}
	for _, o := range opts {
		o(p)
	}
	SignPSA(tb, p, RootKey(tb))
	return p
}

// SignPSA (re)signs a PSA with the given key. Exported so tests can sign with
// OtherRootKey to build the "signed by the wrong person" case.
func SignPSA(tb testing.TB, p *attest.PersonServerAuthorization, key *ecdsa.PrivateKey) {
	tb.Helper()
	digest, err := attest.PSADigest(p)
	if err != nil {
		tb.Fatalf("testutil: PSADigest: %v", err)
	}
	sig, err := ethcrypto.Sign(digest[:], key)
	if err != nil {
		tb.Fatalf("testutil: sign PSA: %v", err)
	}
	p.Signature = sig
}

func WithPSAIssuer(iss string) PSAOpt {
	return func(p *attest.PersonServerAuthorization) { p.Issuer = iss }
}

func WithPSAWindow(nbf, naf int64) PSAOpt {
	return func(p *attest.PersonServerAuthorization) { p.NotBefore, p.NotAfter = nbf, naf }
}

func WithPSAKeyThumbs(thumbs ...string) PSAOpt {
	return func(p *attest.PersonServerAuthorization) { p.KeyThumbprints = thumbs }
}

func WithPSARoot(root string) PSAOpt {
	return func(p *attest.PersonServerAuthorization) { p.Root = root }
}

func WithPSANonce(n uint64) PSAOpt {
	return func(p *attest.PersonServerAuthorization) { p.Nonce = n }
}

func WithPSAScope(s attest.Scope) PSAOpt {
	return func(p *attest.PersonServerAuthorization) { p.Scope = s }
}

// --- AgentGrant -----------------------------------------------------------

type GrantOpt func(*attest.AgentGrant)

// ValidGrant returns a root-signed AgentGrant for the fixture agent key.
func ValidGrant(tb testing.TB, opts ...GrantOpt) *attest.AgentGrant {
	tb.Helper()
	g := &attest.AgentGrant{
		Root:             RootAddr(tb),
		AgentIdentifier:  AgentID,
		AgentThumbprint:  AgentThumb(tb),
		AgentPubKey:      AgentJWK(tb).X,
		MissionScopeS256: MissionS256,
		NotBefore:        NotBefore,
		NotAfter:         NotAfter,
		RegistryChain:    ChainID,
		Registry:         RegistryAddr,
		Nonce:            GrantNonce,
	}
	for _, o := range opts {
		o(g)
	}
	SignGrant(tb, g, RootKey(tb))
	return g
}

func SignGrant(tb testing.TB, g *attest.AgentGrant, key *ecdsa.PrivateKey) {
	tb.Helper()
	digest, err := attest.AgentGrantDigest(g)
	if err != nil {
		tb.Fatalf("testutil: AgentGrantDigest: %v", err)
	}
	sig, err := ethcrypto.Sign(digest[:], key)
	if err != nil {
		tb.Fatalf("testutil: sign grant: %v", err)
	}
	g.Signature = sig
}

func WithGrantRoot(root string) GrantOpt {
	return func(g *attest.AgentGrant) { g.Root = root }
}

func WithGrantAgentID(id string) GrantOpt {
	return func(g *attest.AgentGrant) { g.AgentIdentifier = id }
}

func WithGrantAgentThumb(thumb string) GrantOpt {
	return func(g *attest.AgentGrant) { g.AgentThumbprint = thumb }
}

func WithGrantWindow(nbf, naf int64) GrantOpt {
	return func(g *attest.AgentGrant) { g.NotBefore, g.NotAfter = nbf, naf }
}

func WithGrantNonce(n uint64) GrantOpt {
	return func(g *attest.AgentGrant) { g.Nonce = n }
}

// --- shared helpers -------------------------------------------------------

// FlipSigByte corrupts one byte of a signature in place, for "the signature
// does not verify" cases. It targets a byte inside R so the result stays a
// structurally valid 65-byte signature — the failure must come from recovery,
// not from a length check.
func FlipSigByte(tb testing.TB, sig []byte) {
	tb.Helper()
	if len(sig) != 65 {
		tb.Fatalf("testutil: expected 65-byte signature, got %d", len(sig))
	}
	sig[5] ^= 0xff
}
