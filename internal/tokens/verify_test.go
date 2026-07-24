package tokens_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/testutil"
	"signet.dev/ps/internal/tokens"
)

// harness wires a verifier over in-memory resolvers and mints one valid token.
// Tests mutate the pieces they care about before calling Verify.
type harness struct {
	V      *tokens.Verifier
	Replay *testutil.FakeReplay
	Att    *testutil.FakeAttest
	JWKS   *testutil.FakeJWKS
	PSA    *attest.PersonServerAuthorization
	Grant  *attest.AgentGrant
	Token  string
	Aud    string
	Ctx    context.Context
}

func newHarness(tb testing.TB) *harness {
	tb.Helper()
	nbf, naf := testutil.LiveWindow()
	psa := testutil.ValidPSA(tb, testutil.WithPSAWindow(nbf, naf))
	grant := testutil.ValidGrant(tb, testutil.WithGrantWindow(nbf, naf))

	raw, err := tokens.Mint(testutil.IssuerSigningKey(tb), tokens.MintInput{
		PSA:        psa,
		PSABlobURL: "https://ps.example.test/psa/" + psa.Root,
		Grant:      grant,
		Resource:   tokens.ResourceClaims{Iss: resourceURL, Scope: []string{"read:orders"}},
		AgentID:    testutil.AgentID,
		AgentKey:   testutil.AgentJWK(tb),
		TTL:        time.Hour,
	})
	if err != nil {
		tb.Fatalf("harness mint: %v", err)
	}

	replay := testutil.NewFakeReplay()
	att := &testutil.FakeAttest{PSAVal: psa, GrantVal: grant}
	jwks := testutil.NewFakeJWKS(tb)
	return &harness{
		V: &tokens.Verifier{
			Keys:   jwks,
			Attest: att,
			Chain:  &attest.Verifier{Registry: testutil.LiveRegistry(), Now: time.Now},
			Replay: replay,
			Now:    time.Now,
		},
		Replay: replay, Att: att, JWKS: jwks,
		PSA: psa, Grant: grant, Token: raw, Aud: resourceURL,
		Ctx: context.Background(),
	}
}

func TestVerify_HappyPath(t *testing.T) {
	h := newHarness(t)
	c, err := h.V.Verify(h.Ctx, h.Token, h.Aud, testutil.AgentThumb(t))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	wantSub := "eip155:8453:" + testutil.RootAddr(t)
	if c.Sub != wantSub {
		t.Errorf("sub = %q, want %q", c.Sub, wantSub)
	}
	if c.PSA == "" {
		t.Error("expected the extension chain to be present on a key-rooted token")
	}
}

// TestVerify_SubIsNotPSARoot is THE fabrication check.
//
// A custodial PS can always mint a syntactically perfect token naming anyone —
// Layer 1 has no way to tell. Layer 2 resolves the PSA that actually exists and
// asks: does this person's own key say this PS may speak for them? Here the PS
// mints `sub` = our root, but the PSA it can produce belongs to someone else.
func TestVerify_SubIsNotPSARoot(t *testing.T) {
	h := newHarness(t)

	// A perfectly valid PSA — signed by a DIFFERENT person, covering the same
	// PS and the same issuer key. Everything about it verifies on its own terms.
	nbf, naf := testutil.LiveWindow()
	other := testutil.ValidPSA(t,
		testutil.WithPSAWindow(nbf, naf),
		testutil.WithPSARoot(testutil.OtherRootAddr(t)))
	testutil.SignPSA(t, other, testutil.OtherRootKey(t))
	h.Att.PSAVal = other

	_, err := h.V.Verify(h.Ctx, h.Token, h.Aud, testutil.AgentThumb(t))
	requireErr(t, err, "sub is not the PSA root")
}

func TestVerify_Table(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(tb testing.TB, h *harness)
		thumb   func(tb testing.TB) string // defaults to the agent's
		aud     string                     // defaults to the token's aud
		wantErr string
	}{
		{
			name:    "aud_mismatch",
			aud:     "https://someone-elses-api.example.test",
			wantErr: "aud mismatch",
		},
		{
			// A token presented by anyone other than the agent named in cnf.
			name:    "cnf_mismatch_stolen_token",
			thumb:   func(tb testing.TB) string { return testutil.OtherAgentThumb(tb) },
			wantErr: "cnf/request-signature mismatch",
		},
		{
			name: "jti_replay",
			setup: func(tb testing.TB, h *harness) {
				if _, err := h.V.Verify(h.Ctx, h.Token, h.Aud, testutil.AgentThumb(tb)); err != nil {
					tb.Fatalf("first use should succeed: %v", err)
				}
			},
			wantErr: "jti replay",
		},
		{
			name: "expired",
			setup: func(tb testing.TB, h *harness) {
				h.V.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
			},
			wantErr: "expired",
		},
		{
			name: "psa_resolve_failure",
			setup: func(tb testing.TB, h *harness) {
				h.Att.PSAErr = errors.New("404 not found")
			},
			wantErr: "psa resolve",
		},
		{
			name: "agentgrant_resolve_failure",
			setup: func(tb testing.TB, h *harness) {
				h.Att.GrantErr = errors.New("404 not found")
			},
			wantErr: "agentgrant resolve",
		},
		{
			// Layer 2 must reject a revoked PSA even though the JWT is pristine.
			name: "psa_revoked",
			setup: func(tb testing.TB, h *harness) {
				h.V.Chain = &attest.Verifier{
					Registry: testutil.RevokedRegistry(testutil.RootAddr(tb), testutil.PSANonce),
					Now:      time.Now,
				}
			},
			wantErr: "revoked",
		},
		{
			// The grant resolved does not describe the agent the token names.
			name: "grant_is_for_a_different_agent",
			setup: func(tb testing.TB, h *harness) {
				nbf, naf := testutil.LiveWindow()
				h.Att.GrantVal = testutil.ValidGrant(tb,
					testutil.WithGrantWindow(nbf, naf),
					testutil.WithGrantAgentID("aauth:impostor@agents.example.test"))
			},
			wantErr: "agent identifier mismatch",
		},
		{
			name: "issuer_key_unresolvable",
			setup: func(tb testing.TB, h *harness) {
				h.JWKS.Err = errors.New("jwks unreachable")
			},
			wantErr: "jwks unreachable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			if tc.setup != nil {
				tc.setup(t, h)
			}
			thumb := testutil.AgentThumb(t)
			if tc.thumb != nil {
				thumb = tc.thumb(t)
			}
			aud := h.Aud
			if tc.aud != "" {
				aud = tc.aud
			}
			_, err := h.V.Verify(h.Ctx, h.Token, aud, thumb)
			requireErr(t, err, tc.wantErr)
		})
	}
}

// TestVerify_MalformedTokens forges tokens Mint would never emit. `alg: none`
// and typ confusion are the classic JWT breaks; the over-long TTL is the one a
// compromised minter would reach for.
func TestVerify_MalformedTokens(t *testing.T) {
	baseClaims := func(tb testing.TB) tokens.AuthClaims {
		now := time.Now()
		return tokens.AuthClaims{
			Iss: testutil.Issuer, Aud: resourceURL, Jti: "forged-jti",
			Agent: testutil.AgentID, Cnf: tokens.CNF{JWK: testutil.AgentJWK(tb)},
			Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(),
			Sub: "eip155:8453:" + testutil.RootAddr(tb),
		}
	}

	cases := []struct {
		name    string
		build   func(tb testing.TB) string
		wantErr string
	}{
		{
			name: "alg_none",
			build: func(tb testing.TB) string {
				h := testutil.DefaultJWTHeader()
				h["alg"] = "none"
				return testutil.SignJWTRaw(tb, testutil.IssuerKey(tb), h, baseClaims(tb))
			},
			wantErr: "unacceptable alg/typ",
		},
		{
			// A resource token must never be accepted where an auth token is due.
			name: "typ_confusion",
			build: func(tb testing.TB) string {
				h := testutil.DefaultJWTHeader()
				h["typ"] = "aa-resource+jwt"
				return testutil.SignJWTRaw(tb, testutil.IssuerKey(tb), h, baseClaims(tb))
			},
			wantErr: "unacceptable alg/typ",
		},
		{
			name: "over_long_lifetime",
			build: func(tb testing.TB) string {
				c := baseClaims(tb)
				c.Exp = time.Now().Add(48 * time.Hour).Unix()
				return testutil.SignJWTRaw(tb, testutil.IssuerKey(tb), testutil.DefaultJWTHeader(), c)
			},
			wantErr: "over-long token",
		},
		{
			name: "signed_by_a_key_that_is_not_the_issuer",
			build: func(tb testing.TB) string {
				return testutil.SignJWTRaw(tb, testutil.OtherAgentKey(tb), testutil.DefaultJWTHeader(), baseClaims(tb))
			},
			wantErr: "jwt signature invalid",
		},
		{
			name:    "not_a_jwt",
			build:   func(tb testing.TB) string { return "obviously-not-a-token" },
			wantErr: "malformed jwt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.V.Verify(h.Ctx, tc.build(t), h.Aud, testutil.AgentThumb(t))
			requireErr(t, err, tc.wantErr)
		})
	}
}

// TestVerify_VanillaTokenPassesLayer1 pins the interop claim: a token with no
// extension claims is still a valid AAuth token. Verify returns it rather than
// rejecting it, and the CALLER decides whether key-rooting is required. This is
// what makes the extension a strict superset instead of a fork.
func TestVerify_VanillaTokenPassesLayer1(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	vanilla := testutil.SignJWTRaw(t, testutil.IssuerKey(t), testutil.DefaultJWTHeader(), tokens.AuthClaims{
		Iss: testutil.Issuer, Aud: resourceURL, Jti: "vanilla-jti",
		Agent: testutil.AgentID, Cnf: tokens.CNF{JWK: testutil.AgentJWK(t)},
		Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(),
		Sub: "some-opaque-ps-assigned-subject", // no psa claim at all
	})

	// Resolvers are broken on purpose: Layer 2 must never be reached.
	h.Att.PSAErr = errors.New("should not be called")

	c, err := h.V.Verify(h.Ctx, vanilla, h.Aud, testutil.AgentThumb(t))
	if err != nil {
		t.Fatalf("vanilla AAuth token rejected: %v", err)
	}
	if c.PSA != "" {
		t.Errorf("expected no extension chain, got psa=%q", c.PSA)
	}
}

// TestVerifyVanilla_IgnoresExtensionEntirely is Demo B in unit form.
//
// The same key-rooted token, run through the surface a resource WITHOUT the
// key-rooting requirement uses. Layer 2 never runs — proven by breaking every
// resolver it would need. A vanilla deployment cannot distinguish a genuine
// token from a fabricated one, which is precisely why the extension exists.
func TestVerifyVanilla_IgnoresExtensionEntirely(t *testing.T) {
	h := newHarness(t)
	h.Att.PSAErr = errors.New("resolver is down")
	h.Att.GrantErr = errors.New("resolver is down")
	h.V.Chain = &attest.Verifier{
		Registry: testutil.ErrRegistry(errors.New("registry is down")),
		Now:      time.Now,
	}

	c, err := h.V.VerifyVanilla(h.Ctx, h.Token, h.Aud, testutil.AgentThumb(t))
	if err != nil {
		t.Fatalf("VerifyVanilla must not touch Layer 2: %v", err)
	}
	if c.Sub == "" {
		t.Error("expected Layer 1 claims to be returned")
	}
}

// TestVerify_FailedCnfDoesNotBurnJTI pins the ordering of Layer 1 checks.
//
// SeenJTI both tests AND records, so any check that runs before it lets a
// failing request consume the token's single-use id. An attacker who obtains a
// token but not the agent key could then burn every jti on sight and deny the
// rightful agent its own tokens — a pure availability attack requiring no
// secrets. Replay must therefore be the LAST Layer 1 check.
func TestVerify_FailedCnfDoesNotBurnJTI(t *testing.T) {
	h := newHarness(t)

	// An attacker holding the token but not the key.
	_, err := h.V.Verify(h.Ctx, h.Token, h.Aud, testutil.OtherAgentThumb(t))
	requireErr(t, err, "cnf/request-signature mismatch")

	// The rightful agent must still be able to use its own token.
	if _, err := h.V.Verify(h.Ctx, h.Token, h.Aud, testutil.AgentThumb(t)); err != nil {
		t.Fatalf("a failed verification burned the jti: the rightful agent is now "+
			"denied its own token (%v)", err)
	}
}

// A token that fails on aud must likewise not be consumed.
func TestVerify_FailedAudDoesNotBurnJTI(t *testing.T) {
	h := newHarness(t)
	_, err := h.V.Verify(h.Ctx, h.Token, "https://wrong.example.test", testutil.AgentThumb(t))
	requireErr(t, err, "aud mismatch")

	if _, err := h.V.Verify(h.Ctx, h.Token, h.Aud, testutil.AgentThumb(t)); err != nil {
		t.Fatalf("a failed aud check burned the jti: %v", err)
	}
}
