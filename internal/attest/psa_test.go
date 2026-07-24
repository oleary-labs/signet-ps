package attest_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/testutil"
)

// ---------------------------------------------------------------------------
// Golden digests
// ---------------------------------------------------------------------------

// These constants are load-bearing in a way the round-trip tests are not.
//
// Sign-then-verify stays self-consistent even if the EIP-712 type list or the
// domain drifts — both sides move together and every test still passes. But a
// drifted digest strands every PSA already signed in the wild: those documents
// were signed over the OLD digest and can never be re-derived. So we pin the
// digest itself. If one of these fails, the question is not "update the
// constant" — it is "did we just break every attestation ever issued?"
const (
	goldenPSADigest   = "e7b38fdcd80c37c0532d7bb77ab1940cb3994411338d224594a294a075480c2b"
	goldenGrantDigest = "8a53e6d595577199fe861ac979570a13db70c7b55625a3ed47b7e2eab0d67414"
	goldenPSAHash     = "9d6b16c4fd06aa69e337f6dd1f91758de01df2584a153efffa3d7a4ea3694fe4"
)

func TestPSADigest_Golden(t *testing.T) {
	psa := testutil.ValidPSA(t)
	got, err := attest.PSADigest(psa)
	if err != nil {
		t.Fatalf("PSADigest: %v", err)
	}
	if h := hex.EncodeToString(got[:]); h != goldenPSADigest {
		t.Fatalf("PSA EIP-712 digest drifted.\n got: %s\nwant: %s\n"+
			"If this is intentional, understand that every PSA signed under the old "+
			"type/domain becomes unverifiable.", h, goldenPSADigest)
	}
}

func TestAgentGrantDigest_Golden(t *testing.T) {
	g := testutil.ValidGrant(t)
	got, err := attest.AgentGrantDigest(g)
	if err != nil {
		t.Fatalf("AgentGrantDigest: %v", err)
	}
	if h := hex.EncodeToString(got[:]); h != goldenGrantDigest {
		t.Fatalf("AgentGrant EIP-712 digest drifted.\n got: %s\nwant: %s", h, goldenGrantDigest)
	}
}

// TestContentHash_Golden pins by-reference resolution. ContentHash currently
// hashes Go's json.Marshal output, so it depends on struct field order and Go's
// encoder — meaning a verifier written in another language will compute a
// DIFFERENT hash for the same document. That is a known v0 limitation (the fix
// is JCS / RFC 8785). This test freezes today's behaviour so the eventual
// migration is a deliberate, visible break rather than a silent interop bug.
func TestContentHash_Golden(t *testing.T) {
	psa := testutil.ValidPSA(t)
	got, err := attest.ContentHash(psa)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if got != goldenPSAHash {
		t.Fatalf("PSA content hash drifted.\n got: %s\nwant: %s\n"+
			"Tokens pin this value in their `psa` claim as #s256=...", got, goldenPSAHash)
	}
}

// ---------------------------------------------------------------------------
// PSA verification
// ---------------------------------------------------------------------------

func TestVerifyPSA_RoundTrip(t *testing.T) {
	psa := testutil.ValidPSA(t)
	reg := testutil.LiveRegistry()
	v := &attest.Verifier{Registry: reg, Now: testutil.Clock(testutil.NowUnix)}

	if err := v.VerifyPSA(context.Background(), psa, testutil.Issuer, testutil.IssuerThumb(t)); err != nil {
		t.Fatalf("valid PSA rejected: %v", err)
	}
	if reg.Calls == 0 {
		t.Error("registry was never consulted: revocation is not being checked (I4)")
	}
}

func TestVerifyPSA_TamperMatrix(t *testing.T) {
	errUnreachable := errors.New("dial tcp: connection refused")

	cases := []struct {
		name string
		// build produces a validly-SIGNED document (opts apply pre-signing).
		build func(tb testing.TB) *attest.PersonServerAuthorization
		// mutate corrupts it AFTER signing, for tamper cases.
		mutate   func(tb testing.TB, p *attest.PersonServerAuthorization)
		issuer   string // defaults to testutil.Issuer
		thumb    func(tb testing.TB) string
		now      int64 // defaults to testutil.NowUnix
		registry func(tb testing.TB) *testutil.FakeRegistry
		wantErr  string
	}{
		{
			name: "issuer_mismatch",
			build: func(tb testing.TB) *attest.PersonServerAuthorization {
				return testutil.ValidPSA(tb, testutil.WithPSAIssuer("https://other-ps.example.test"))
			},
			wantErr: "issuer mismatch",
		},
		{
			name:    "expired",
			now:     testutil.NotAfter + 1,
			wantErr: "outside validity window",
		},
		{
			name:    "not_yet_valid",
			now:     testutil.NotBefore - 1,
			wantErr: "outside validity window",
		},
		{
			name:    "signing_key_not_in_authorized_set",
			thumb:   func(tb testing.TB) string { return testutil.OtherAgentThumb(tb) },
			wantErr: "not in authorized set",
		},
		{
			name: "signature_byte_flipped",
			mutate: func(tb testing.TB, p *attest.PersonServerAuthorization) {
				testutil.FlipSigByte(tb, p.Signature)
			},
			wantErr: "root signature invalid",
		},
		{
			name: "signed_by_a_different_key",
			build: func(tb testing.TB) *attest.PersonServerAuthorization {
				p := testutil.ValidPSA(tb)
				testutil.SignPSA(tb, p, testutil.OtherRootKey(tb)) // valid sig, wrong signer
				return p
			},
			wantErr: "root signature invalid",
		},
		{
			// The fabrication attempt: rewrite `root` to point at someone else
			// while keeping a real signature. Recovery returns the original
			// signer, which no longer equals the claimed root. (I1)
			name: "root_rewritten_to_another_person",
			build: func(tb testing.TB) *attest.PersonServerAuthorization {
				p := testutil.ValidPSA(tb)
				p.Root = testutil.OtherRootAddr(tb)
				return p
			},
			wantErr: "root signature invalid",
		},
		{
			name: "revoked",
			registry: func(tb testing.TB) *testutil.FakeRegistry {
				return testutil.RevokedRegistry(testutil.RootAddr(tb), testutil.PSANonce)
			},
			wantErr: "revoked",
		},
		{
			// Availability must never override revocation.
			name: "registry_unavailable_fails_closed",
			registry: func(tb testing.TB) *testutil.FakeRegistry {
				return testutil.ErrRegistry(errUnreachable)
			},
			wantErr: "registry unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			build := tc.build
			if build == nil {
				build = func(tb testing.TB) *attest.PersonServerAuthorization { return testutil.ValidPSA(tb) }
			}
			psa := build(t)
			if tc.mutate != nil {
				tc.mutate(t, psa)
			}

			issuer := tc.issuer
			if issuer == "" {
				issuer = testutil.Issuer
			}
			thumb := testutil.IssuerThumb(t)
			if tc.thumb != nil {
				thumb = tc.thumb(t)
			}
			now := tc.now
			if now == 0 {
				now = testutil.NowUnix
			}
			var reg attest.RevocationRegistry = testutil.LiveRegistry()
			if tc.registry != nil {
				reg = tc.registry(t)
			}

			v := &attest.Verifier{Registry: reg, Now: testutil.Clock(now)}
			err := v.VerifyPSA(context.Background(), psa, issuer, thumb)
			requireErr(t, err, tc.wantErr)
		})
	}
}

// ---------------------------------------------------------------------------
// AgentGrant verification
// ---------------------------------------------------------------------------

func TestVerifyAgentGrant_RoundTrip(t *testing.T) {
	g := testutil.ValidGrant(t)
	reg := testutil.LiveRegistry()
	v := &attest.Verifier{Registry: reg, Now: testutil.Clock(testutil.NowUnix)}

	err := v.VerifyAgentGrant(context.Background(), g, testutil.RootAddr(t), testutil.AgentID, testutil.AgentThumb(t))
	if err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
	if reg.Calls == 0 {
		t.Error("registry was never consulted for the grant")
	}
}

func TestVerifyAgentGrant_TamperMatrix(t *testing.T) {
	errUnreachable := errors.New("dial tcp: connection refused")

	cases := []struct {
		name       string
		build      func(tb testing.TB) *attest.AgentGrant
		mutate     func(tb testing.TB, g *attest.AgentGrant)
		root       func(tb testing.TB) string // defaults to RootAddr
		agentID    string                     // defaults to testutil.AgentID
		agentThumb func(tb testing.TB) string // defaults to AgentThumb
		now        int64
		registry   func(tb testing.TB) *testutil.FakeRegistry
		wantErr    string
	}{
		{
			// The grant names a different person than the PSA we resolved.
			name:    "root_mismatch",
			root:    func(tb testing.TB) string { return testutil.OtherRootAddr(tb) },
			wantErr: "root mismatch",
		},
		{
			name:    "agent_identifier_mismatch",
			agentID: "aauth:someone-else@agents.example.test",
			wantErr: "agent identifier mismatch",
		},
		{
			// The "stolen grant" case: presented by a key the grant does not name.
			name:       "agent_key_mismatch",
			agentThumb: func(tb testing.TB) string { return testutil.OtherAgentThumb(tb) },
			wantErr:    "agent key mismatch",
		},
		{
			name:    "expired",
			now:     testutil.NotAfter + 1,
			wantErr: "outside validity window",
		},
		{
			name:    "not_yet_valid",
			now:     testutil.NotBefore - 1,
			wantErr: "outside validity window",
		},
		{
			name: "signature_byte_flipped",
			mutate: func(tb testing.TB, g *attest.AgentGrant) {
				testutil.FlipSigByte(tb, g.Signature)
			},
			wantErr: "root signature invalid",
		},
		{
			name: "signed_by_a_different_key",
			build: func(tb testing.TB) *attest.AgentGrant {
				g := testutil.ValidGrant(tb)
				testutil.SignGrant(tb, g, testutil.OtherRootKey(tb))
				return g
			},
			wantErr: "root signature invalid",
		},
		{
			// Rewriting the agent key after signing — the grant-theft attempt.
			name: "agent_thumbprint_rewritten",
			build: func(tb testing.TB) *attest.AgentGrant {
				g := testutil.ValidGrant(tb)
				g.AgentThumbprint = testutil.OtherAgentThumb(tb)
				return g
			},
			agentThumb: func(tb testing.TB) string { return testutil.OtherAgentThumb(tb) },
			wantErr:    "root signature invalid",
		},
		{
			name: "revoked",
			registry: func(tb testing.TB) *testutil.FakeRegistry {
				return testutil.RevokedRegistry(testutil.RootAddr(tb), testutil.GrantNonce)
			},
			wantErr: "revoked",
		},
		{
			name: "registry_unavailable_fails_closed",
			registry: func(tb testing.TB) *testutil.FakeRegistry {
				return testutil.ErrRegistry(errUnreachable)
			},
			wantErr: "registry unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			build := tc.build
			if build == nil {
				build = func(tb testing.TB) *attest.AgentGrant { return testutil.ValidGrant(tb) }
			}
			g := build(t)
			if tc.mutate != nil {
				tc.mutate(t, g)
			}

			root := testutil.RootAddr(t)
			if tc.root != nil {
				root = tc.root(t)
			}
			agentID := tc.agentID
			if agentID == "" {
				agentID = testutil.AgentID
			}
			thumb := testutil.AgentThumb(t)
			if tc.agentThumb != nil {
				thumb = tc.agentThumb(t)
			}
			now := tc.now
			if now == 0 {
				now = testutil.NowUnix
			}
			var reg attest.RevocationRegistry = testutil.LiveRegistry()
			if tc.registry != nil {
				reg = tc.registry(t)
			}

			v := &attest.Verifier{Registry: reg, Now: testutil.Clock(now)}
			err := v.VerifyAgentGrant(context.Background(), g, root, agentID, thumb)
			requireErr(t, err, tc.wantErr)
		})
	}
}

// TestRevocation_IsPerNonce pins the separation that makes selective revocation
// possible: a PSA and an AgentGrant from the same root carry different nonces,
// so killing one must leave the other alive. Without this, "revoke this agent"
// would mean "log out of everything".
func TestRevocation_IsPerNonce(t *testing.T) {
	psa := testutil.ValidPSA(t)
	grant := testutil.ValidGrant(t)

	// Revoke ONLY the agent grant's handle.
	reg := testutil.RevokedRegistry(testutil.RootAddr(t), testutil.GrantNonce)
	v := &attest.Verifier{Registry: reg, Now: testutil.Clock(testutil.NowUnix)}
	ctx := context.Background()

	if err := v.VerifyPSA(ctx, psa, testutil.Issuer, testutil.IssuerThumb(t)); err != nil {
		t.Errorf("revoking the agent grant must not kill the PSA: %v", err)
	}
	err := v.VerifyAgentGrant(ctx, grant, testutil.RootAddr(t), testutil.AgentID, testutil.AgentThumb(t))
	requireErr(t, err, "revoked")
}

// ---------------------------------------------------------------------------

func requireErr(tb testing.TB, err error, want string) {
	tb.Helper()
	if err == nil {
		tb.Fatalf("expected error containing %q, got nil (this case was ACCEPTED)", want)
	}
	if !strings.Contains(err.Error(), want) {
		tb.Fatalf("wrong failure mode.\n got: %v\nwant substring: %q", err, want)
	}
}
