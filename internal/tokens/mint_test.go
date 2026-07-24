package tokens_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/testutil"
	"signet.dev/ps/internal/tokens"
)

// Every refusal in this file is a case where a custodial PS could have quietly
// proceeded. Mint is where invariant I1 is enforced structurally: the PS is
// unable to exceed its grant, rather than merely policy-bound not to.

const resourceURL = "https://api.example.test/orders"

func mintInput(tb testing.TB, opts ...func(*tokens.MintInput)) tokens.MintInput {
	tb.Helper()
	nbf, naf := testutil.LiveWindow()
	psa := testutil.ValidPSA(tb, testutil.WithPSAWindow(nbf, naf))
	grant := testutil.ValidGrant(tb, testutil.WithGrantWindow(nbf, naf))

	in := tokens.MintInput{
		PSA:        psa,
		PSABlobURL: "https://ps.example.test/psa/" + psa.Root,
		Grant:      grant,
		Resource:   tokens.ResourceClaims{Iss: resourceURL, Scope: []string{"read:orders"}},
		AgentID:    testutil.AgentID,
		AgentKey:   testutil.AgentJWK(tb),
		Mission:    &tokens.MissionRef{Approver: testutil.Issuer, S256: testutil.MissionS256},
		TTL:        time.Hour,
	}
	for _, o := range opts {
		o(&in)
	}
	return in
}

func TestMint_HappyPath(t *testing.T) {
	in := mintInput(t)
	raw, err := tokens.Mint(testutil.IssuerSigningKey(t), in)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c := testutil.DecodeClaims(t, raw)

	// `sub` is the person's own address, not a PS-assigned identifier. This is
	// the claim an enhanced verifier checks against the PSA's root.
	wantSub := fmt.Sprintf("eip155:%d:%s", in.PSA.RegistryChain, in.PSA.Root)
	if c.Sub != wantSub {
		t.Errorf("sub = %q, want %q", c.Sub, wantSub)
	}
	if c.Iss != in.PSA.Issuer {
		t.Errorf("iss = %q, want %q", c.Iss, in.PSA.Issuer)
	}
	if c.Aud != resourceURL {
		t.Errorf("aud = %q, want %q", c.Aud, resourceURL)
	}
	// cnf carries the agent's key: this is what makes the token non-bearer.
	if c.Cnf.JWK.X != testutil.AgentJWK(t).X {
		t.Errorf("cnf key = %q, want the agent's key", c.Cnf.JWK.X)
	}
	// The extension claims: by-reference PSA with a content hash, plus the grant hash.
	if !strings.Contains(c.PSA, "#s256=") {
		t.Errorf("psa claim %q lacks a content hash", c.PSA)
	}
	psaHash, err := attest.ContentHash(in.PSA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(c.PSA, psaHash) {
		t.Errorf("psa claim pins %q, want hash %q", c.PSA, psaHash)
	}
	agHash, err := attest.ContentHash(in.Grant)
	if err != nil {
		t.Fatal(err)
	}
	if c.AgS256 != agHash {
		t.Errorf("ag_s256 = %q, want %q", c.AgS256, agHash)
	}
	if c.Jti == "" {
		t.Error("jti is empty: replay protection needs a unique id")
	}
}

// TestMint_JTIIsUnique guards against a constant or low-entropy jti, which
// would make every token look like a replay of the last one.
func TestMint_JTIIsUnique(t *testing.T) {
	key := testutil.IssuerSigningKey(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		raw, err := tokens.Mint(key, mintInput(t))
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		jti := testutil.DecodeClaims(t, raw).Jti
		if seen[jti] {
			t.Fatalf("duplicate jti %q on iteration %d", jti, i)
		}
		seen[jti] = true
	}
}

func TestMint_RefusalTable(t *testing.T) {
	cases := []struct {
		name    string
		opt     func(*tokens.MintInput)
		wantErr string
	}{
		{
			// The PS holds a key the person never authorized. Without this check
			// a PS could rotate to a new key and keep minting under an old PSA.
			name: "issuer_key_not_covered_by_psa",
			opt: func(in *tokens.MintInput) {
				nbf, naf := testutil.LiveWindow()
				in.PSA = testutil.ValidPSA(t,
					testutil.WithPSAWindow(nbf, naf),
					testutil.WithPSAKeyThumbs("some-other-key-thumbprint"))
			},
			wantErr: "issuer key not covered by PSA",
		},
		{
			// Vouching an identity claim the person did not authorize.
			name: "claim_outside_allowed_claims",
			opt: func(in *tokens.MintInput) {
				in.Claims = map[string]tokens.Vouched{"name": {Value: "Ada", Provenance: "verified"}}
			},
			wantErr: "does not allow vouching",
		},
		{
			name:    "unparseable_amount",
			opt:     func(in *tokens.MintInput) { in.Resource.AmountWei = "not-a-number" },
			wantErr: "bad amount",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tokens.Mint(testutil.IssuerSigningKey(t), mintInput(t, tc.opt))
			requireErr(t, err, tc.wantErr)
		})
	}
}

// TestMint_TTLClamping pins that the PSA is a CEILING, not a request to honour.
// Mint clamps rather than erroring — asking for too much gets you less, not a
// failure — and clamps twice: to the PSA's max, then to the spec's 1h.
func TestMint_TTLClamping(t *testing.T) {
	cases := []struct {
		name       string
		psaMaxTTL  int64
		request    time.Duration
		wantExpIat int64
	}{
		{"under_both_ceilings_is_untouched", 3600, 10 * time.Minute, 600},
		{"clamped_to_psa_max", 1800, 4 * time.Hour, 1800},
		{"clamped_to_spec_1h_when_psa_allows_more", 86400, 4 * time.Hour, 3600},
		{"psa_max_above_1h_still_capped_at_1h", 7200, 2 * time.Hour, 3600},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := mintInput(t, func(in *tokens.MintInput) {
				nbf, naf := testutil.LiveWindow()
				scope := in.PSA.Scope
				scope.MaxTokenTTLSeconds = tc.psaMaxTTL
				in.PSA = testutil.ValidPSA(t, testutil.WithPSAWindow(nbf, naf), testutil.WithPSAScope(scope))
				in.TTL = tc.request
			})
			raw, err := tokens.Mint(testutil.IssuerSigningKey(t), in)
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			c := testutil.DecodeClaims(t, raw)
			if got := c.Exp - c.Iat; got != tc.wantExpIat {
				t.Errorf("token lifetime = %ds, want %ds", got, tc.wantExpIat)
			}
		})
	}
}

// TestMint_PaymentEnvelope covers the cap (I1) and the step-up threshold (I3),
// including the boundaries. Off-by-one on a spending limit is a real bug class,
// so "exactly at the cap" and "exactly at the threshold" are explicit rows.
func TestMint_PaymentEnvelope(t *testing.T) {
	const (
		cap       = "1000"
		threshold = "100"
	)
	stepUp := &tokens.StepUp{Digest: "0xdead", Sig: "0xbeef"}

	cases := []struct {
		name    string
		amount  string
		cap     string
		thresh  string
		stepUp  *tokens.StepUp
		wantErr string // "" means the mint must succeed
	}{
		{name: "no_amount_skips_payment_checks", amount: "", cap: cap, thresh: threshold},
		{name: "below_threshold_needs_no_stepup", amount: "50", cap: cap, thresh: threshold},
		{name: "exactly_at_threshold_needs_no_stepup", amount: "100", cap: cap, thresh: threshold},
		{
			name:   "above_threshold_without_stepup_refused",
			amount: "101", cap: cap, thresh: threshold,
			wantErr: "step-up signature required above threshold",
		},
		{name: "above_threshold_with_stepup_allowed", amount: "101", cap: cap, thresh: threshold, stepUp: stepUp},
		{name: "exactly_at_cap_allowed", amount: "1000", cap: cap, thresh: threshold, stepUp: stepUp},
		{
			name:   "above_cap_refused_even_with_stepup",
			amount: "1001", cap: cap, thresh: threshold, stepUp: stepUp,
			wantErr: "exceeds PSA payment cap",
		},
		{
			// A zero cap is not "unlimited" — it means this PSA authorizes no
			// payments at all. Reading it as unlimited would be catastrophic.
			name:   "zero_cap_refuses_any_amount",
			amount: "1", cap: "0", thresh: threshold, stepUp: stepUp,
			wantErr: "exceeds PSA payment cap",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := mintInput(t, func(in *tokens.MintInput) {
				nbf, naf := testutil.LiveWindow()
				in.PSA = testutil.ValidPSA(t, testutil.WithPSAWindow(nbf, naf),
					testutil.WithPSAScope(attest.Scope{
						MaxTokenTTLSeconds: 3600,
						AllowedClaims:      []string{"email"},
						PaymentCapWei:      tc.cap,
						StepUpAboveWei:     tc.thresh,
					}))
				in.Resource.AmountWei = tc.amount
				in.StepUp = tc.stepUp
			})
			_, err := tokens.Mint(testutil.IssuerSigningKey(t), in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("mint refused a within-envelope request: %v", err)
				}
				return
			}
			requireErr(t, err, tc.wantErr)
		})
	}
}

// TestMint_VouchedClaimIsCarried confirms the allow-list is a gate, not a filter:
// permitted claims must actually reach the token.
func TestMint_VouchedClaimIsCarried(t *testing.T) {
	in := mintInput(t, func(in *tokens.MintInput) {
		in.Claims = map[string]tokens.Vouched{"email": {Value: "ada@example.test", Provenance: "verified"}}
	})
	raw, err := tokens.Mint(testutil.IssuerSigningKey(t), in)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c := testutil.DecodeClaims(t, raw)
	if c.Email == nil || c.Email.Value != "ada@example.test" {
		t.Fatalf("email claim not carried: %+v", c.Email)
	}
	if c.Email.Provenance != "verified" {
		t.Errorf("provenance = %q, want %q", c.Email.Provenance, "verified")
	}
}

func requireErr(tb testing.TB, err error, want string) {
	tb.Helper()
	if err == nil {
		tb.Fatalf("expected error containing %q, got nil (this case was ACCEPTED)", want)
	}
	if !strings.Contains(err.Error(), want) {
		tb.Fatalf("wrong failure mode.\n got: %v\nwant substring: %q", err, want)
	}
}
