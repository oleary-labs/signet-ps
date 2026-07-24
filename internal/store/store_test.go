package store_test

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/missions"
	"signet.dev/ps/internal/store"
	"signet.dev/ps/internal/testutil"
)

// Tenancy here is derived entirely from signed objects: there is no account
// row to get wrong. These tests pin the two properties that follow from that —
// an agent acts for exactly one person, and a person's history survives
// everything that happens to their PSA.

func verifier() *attest.Verifier {
	return &attest.Verifier{Registry: testutil.LiveRegistry(), Now: testutil.Clock(testutil.NowUnix)}
}

func onboard(tb testing.TB, ts *store.Tenants, psa *attest.PersonServerAuthorization) *store.Tenant {
	tb.Helper()
	t, err := ts.VerifyAndOnboard(context.Background(), verifier(), psa,
		testutil.Issuer, []string{testutil.IssuerThumb(tb)})
	if err != nil {
		tb.Fatalf("onboard: %v", err)
	}
	return t
}

// psaFor builds a PSA for an arbitrary root, signed by that root's key.
func psaFor(tb testing.TB, root string, key *ecdsa.PrivateKey, opts ...testutil.PSAOpt) *attest.PersonServerAuthorization {
	tb.Helper()
	p := testutil.ValidPSA(tb, append([]testutil.PSAOpt{testutil.WithPSARoot(root)}, opts...)...)
	testutil.SignPSA(tb, p, key)
	return p
}

func grantFor(tb testing.TB, root string, key *ecdsa.PrivateKey, opts ...testutil.GrantOpt) *attest.AgentGrant {
	tb.Helper()
	g := testutil.ValidGrant(tb, append([]testutil.GrantOpt{testutil.WithGrantRoot(root)}, opts...)...)
	testutil.SignGrant(tb, g, key)
	return g
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

func TestVerifyAndOnboard_HappyPath(t *testing.T) {
	ts := store.NewTenants()
	psa := testutil.ValidPSA(t)
	tenant := onboard(t, ts, psa)

	if tenant.Root != testutil.RootAddr(t) {
		t.Errorf("tenant root = %q, want %q", tenant.Root, testutil.RootAddr(t))
	}
	got, ok := ts.ByRoot(testutil.RootAddr(t))
	if !ok {
		t.Fatal("tenant not retrievable by root after onboarding")
	}
	if got.PSA != psa {
		t.Error("stored PSA is not the one submitted")
	}
}

func TestVerifyAndOnboard_Rejections(t *testing.T) {
	cases := []struct {
		name      string
		psa       func(tb testing.TB) *attest.PersonServerAuthorization
		keyThumbs []string
		wantErr   string
	}{
		{
			// A PSA authorizing keys this PS does not hold could never yield a
			// usable token, so it is refused rather than stored and failed later.
			name:      "psa_covers_none_of_our_issuer_keys",
			keyThumbs: []string{"a-key-this-ps-does-not-have"},
			wantErr:   "covers none of this PS's issuer keys",
		},
		{
			name: "tampered_signature",
			psa: func(tb testing.TB) *attest.PersonServerAuthorization {
				p := testutil.ValidPSA(tb)
				testutil.FlipSigByte(tb, p.Signature)
				return p
			},
			wantErr: "root signature invalid",
		},
		{
			name: "issuer_is_a_different_ps",
			psa: func(tb testing.TB) *attest.PersonServerAuthorization {
				return testutil.ValidPSA(tb, testutil.WithPSAIssuer("https://not-us.example.test"))
			},
			wantErr: "issuer mismatch",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := store.NewTenants()
			build := tc.psa
			if build == nil {
				build = func(tb testing.TB) *attest.PersonServerAuthorization { return testutil.ValidPSA(tb) }
			}
			thumbs := tc.keyThumbs
			if thumbs == nil {
				thumbs = []string{testutil.IssuerThumb(t)}
			}
			_, err := ts.VerifyAndOnboard(context.Background(), verifier(), build(t), testutil.Issuer, thumbs)
			requireErr(t, err, tc.wantErr)

			if _, ok := ts.ByRoot(testutil.RootAddr(t)); ok {
				t.Error("a rejected PSA still created a tenant")
			}
		})
	}
}

// TestReOnboard_PreservesGrantsAndLog is portability in the data model: the PSA
// is replaceable (rotation, scope change, provider move) but it is not the
// tenant. Grants and the mission log hang off the ROOT, so replacing a PSA must
// never look like starting a new account.
func TestReOnboard_PreservesGrantsAndLog(t *testing.T) {
	ts := store.NewTenants()
	root := testutil.RootAddr(t)

	tenant := onboard(t, ts, testutil.ValidPSA(t))
	grant := testutil.ValidGrant(t)
	if err := ts.Enroll(testutil.AgentID, tenant, grant); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	tenant.Log().Append(testutil.AgentID, missions.Entry{Kind: "token_request", RequestID: "r1", At: time.Now()})

	// A second PSA for the same person: new nonce, tighter scope.
	psa2 := testutil.ValidPSA(t, testutil.WithPSANonce(testutil.PSANonce+1))
	returned := onboard(t, ts, psa2)

	live, ok := ts.ByRoot(root)
	if !ok {
		t.Fatal("tenant vanished after re-onboarding")
	}
	if live.PSA.Nonce != testutil.PSANonce+1 {
		t.Errorf("PSA was not replaced: nonce = %d", live.PSA.Nonce)
	}
	if _, ok := live.Grant(testutil.AgentID); !ok {
		t.Error("agent grant did not survive PSA replacement")
	}
	if n := len(live.Log().Export()[testutil.AgentID]); n != 1 {
		t.Errorf("mission log entries after re-onboard = %d, want 1", n)
	}

	// The tenant handed back must BE the live tenant, not a detached copy —
	// otherwise a caller reading grants or the log off it silently sees nothing.
	if _, ok := returned.Grant(testutil.AgentID); !ok {
		t.Error("VerifyAndOnboard returned a detached tenant: its grants are empty " +
			"while the registered tenant still has them")
	}
}

// ---------------------------------------------------------------------------
// Enrollment: an agent acts for exactly one person
// ---------------------------------------------------------------------------

func TestEnroll_RebindToDifferentRootRefused(t *testing.T) {
	ts := store.NewTenants()
	alice := onboard(t, ts, testutil.ValidPSA(t))
	bob := onboard(t, ts, psaFor(t, testutil.OtherRootAddr(t), testutil.OtherRootKey(t)))

	if err := ts.Enroll(testutil.AgentID, alice, testutil.ValidGrant(t)); err != nil {
		t.Fatalf("first enrollment: %v", err)
	}

	// Bob signs a perfectly valid grant for the same agent identifier. The
	// agent still cannot serve two people: rebinding requires revoking first.
	bobGrant := grantFor(t, testutil.OtherRootAddr(t), testutil.OtherRootKey(t))
	err := ts.Enroll(testutil.AgentID, bob, bobGrant)
	requireErr(t, err, "already bound to a different root")

	// And the original binding is intact.
	got, ok := ts.ByAgent(testutil.AgentID)
	if !ok || got.Root != testutil.RootAddr(t) {
		t.Error("the failed rebind disturbed the original tenancy")
	}
}

func TestEnroll_SameRootIsIdempotent(t *testing.T) {
	ts := store.NewTenants()
	alice := onboard(t, ts, testutil.ValidPSA(t))

	if err := ts.Enroll(testutil.AgentID, alice, testutil.ValidGrant(t)); err != nil {
		t.Fatalf("first enrollment: %v", err)
	}
	// Re-enrolling under a fresh grant from the same root is normal (grant
	// renewal) and must succeed.
	renewed := testutil.ValidGrant(t, testutil.WithGrantNonce(testutil.GrantNonce+1))
	if err := ts.Enroll(testutil.AgentID, alice, renewed); err != nil {
		t.Fatalf("grant renewal refused: %v", err)
	}
	g, ok := alice.Grant(testutil.AgentID)
	if !ok || g.Nonce != testutil.GrantNonce+1 {
		t.Error("renewed grant did not replace the old one")
	}
}

func TestByAgent_UnknownAgentHasNoTenant(t *testing.T) {
	ts := store.NewTenants()
	onboard(t, ts, testutil.ValidPSA(t))
	if _, ok := ts.ByAgent("aauth:never-enrolled@agents.example.test"); ok {
		t.Error("an unenrolled agent resolved to a tenant")
	}
}

// TestTenantIsolation: two people on one PS. Neither's agent can resolve to the
// other's tenancy, and this falls out of the grant chain — there is no
// row-level security to configure or forget.
func TestTenantIsolation(t *testing.T) {
	ts := store.NewTenants()
	alice := onboard(t, ts, testutil.ValidPSA(t))
	bob := onboard(t, ts, psaFor(t, testutil.OtherRootAddr(t), testutil.OtherRootKey(t)))

	const bobAgent = "aauth:bob-agent@agents.example.test"
	if err := ts.Enroll(testutil.AgentID, alice, testutil.ValidGrant(t)); err != nil {
		t.Fatal(err)
	}
	bobGrant := grantFor(t, testutil.OtherRootAddr(t), testutil.OtherRootKey(t),
		testutil.WithGrantAgentID(bobAgent))
	if err := ts.Enroll(bobAgent, bob, bobGrant); err != nil {
		t.Fatal(err)
	}

	aliceTenant, _ := ts.ByAgent(testutil.AgentID)
	bobTenant, _ := ts.ByAgent(bobAgent)
	if aliceTenant.Root == bobTenant.Root {
		t.Fatal("two agents under different roots resolved to the same tenant")
	}
	if _, ok := aliceTenant.Grant(bobAgent); ok {
		t.Error("Bob's grant is visible inside Alice's tenant")
	}
	if _, ok := bobTenant.Grant(testutil.AgentID); ok {
		t.Error("Alice's grant is visible inside Bob's tenant")
	}
}

// GrantByS256 is how a verifier resolves the ag_s256 a token pins.
func TestGrantByS256(t *testing.T) {
	ts := store.NewTenants()
	alice := onboard(t, ts, testutil.ValidPSA(t))
	grant := testutil.ValidGrant(t)
	if err := ts.Enroll(testutil.AgentID, alice, grant); err != nil {
		t.Fatal(err)
	}

	hash, err := attest.ContentHash(grant)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ts.GrantByS256(hash)
	if !ok {
		t.Fatal("enrolled grant is not resolvable by its content hash")
	}
	if got.AgentIdentifier != testutil.AgentID {
		t.Errorf("resolved the wrong grant: %q", got.AgentIdentifier)
	}
	if _, ok := ts.GrantByS256("0000000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Error("an unknown content hash resolved to a grant")
	}
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Revocation is per (root, nonce). This is what lets a person kill one agent,
// or leave one PS, without detonating everything else they have signed.
func TestMemoryRegistry_IsPerRootAndNonce(t *testing.T) {
	reg := store.NewMemoryRegistry()
	ctx := context.Background()
	alice, bob := testutil.RootAddr(t), testutil.OtherRootAddr(t)

	reg.Revoke(alice, 1)

	check := func(root string, nonce uint64, want bool) {
		t.Helper()
		got, err := reg.IsRevoked(ctx, testutil.ChainID, testutil.RegistryAddr, root, nonce)
		if err != nil {
			t.Fatalf("IsRevoked: %v", err)
		}
		if got != want {
			t.Errorf("IsRevoked(%s, %d) = %v, want %v", root, nonce, got, want)
		}
	}
	check(alice, 1, true)  // the revoked handle
	check(alice, 0, false) // same person, different grant
	check(alice, 2, false)
	check(bob, 1, false) // different person, same nonce
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
