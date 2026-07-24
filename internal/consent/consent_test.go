package consent_test

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"signet.dev/ps/internal/consent"
	"signet.dev/ps/internal/testutil"
)

// The tier model is invariant I3 made structural: below the PSA's step-up
// threshold a click is sufficient (the PSA is the authority, the click is UX);
// above it, nothing but a fresh root signature over THIS action will do. These
// tests exist so that distinction can never be softened by handler discipline.

// farFuture keeps fixtures inside their consent window without reading the clock.
var farFuture = time.Unix(4102444800, 0) // 2100-01-01T00:00:00Z

func req(tb testing.TB, tier consent.Tier, mut ...func(*consent.Request)) *consent.Request {
	tb.Helper()
	r := &consent.Request{
		ID:          "req-1",
		Code:        "CODE1",
		AgentID:     testutil.AgentID,
		Resource:    "https://api.example.test/orders",
		AmountWei:   "500",
		ScopeReq:    []string{"payment:create"},
		MissionS256: testutil.MissionS256,
		Tier:        tier,
		CreatedAt:   time.Now(),
		// A fixed far-future instant, not now+10m: ExpiresAt feeds the approval
		// digest, so a moving value would give every run a different signature —
		// and signature-corruption cases would flake between failure modes.
		// Expiry tests override this with an explicit past time.
		ExpiresAt: farFuture,
	}
	for _, m := range mut {
		m(r)
	}
	return r
}

func signApproval(tb testing.TB, r *consent.Request, key *ecdsa.PrivateKey) []byte {
	tb.Helper()
	d, err := consent.ApprovalDigest(r, testutil.ChainID, testutil.RegistryAddr)
	if err != nil {
		tb.Fatalf("ApprovalDigest: %v", err)
	}
	sig, err := ethcrypto.Sign(d[:], key)
	if err != nil {
		tb.Fatalf("sign approval: %v", err)
	}
	return sig
}

func approveElevated(tb testing.TB, s *consent.Store, r *consent.Request, root string, sig []byte) error {
	tb.Helper()
	return s.ApproveElevated(r.Code, root, testutil.ChainID, testutil.RegistryAddr, sig)
}

// ---------------------------------------------------------------------------
// Tiers: a click can never become a signature
// ---------------------------------------------------------------------------

// TestApproveRoutine_RefusesElevated is the structural heart of I3. If this
// ever passes, a click has been allowed to authorize an action that the PSA
// says requires the person's key.
func TestApproveRoutine_RefusesElevated(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierElevated)
	s.Create(r)

	err := s.ApproveRoutine(r.Code)
	requireErr(t, err, "requires root signature")

	got, err := s.Poll(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != consent.StatePending {
		t.Errorf("state = %q, want still pending after a refused click", got.State)
	}
}

func TestApproveRoutine_HappyPath(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierRoutine)
	s.Create(r)

	if err := s.ApproveRoutine(r.Code); err != nil {
		t.Fatalf("routine approval rejected: %v", err)
	}
	got, _ := s.Poll(r.ID)
	if got.State != consent.StateApproved {
		t.Errorf("state = %q, want approved", got.State)
	}
}

func TestApproveElevated_RefusesRoutineRequest(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierRoutine)
	s.Create(r)

	err := approveElevated(t, s, r, testutil.RootAddr(t), signApproval(t, r, testutil.RootKey(t)))
	requireErr(t, err, "not elevated")
}

func TestApproveElevated_HappyPath(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierElevated)
	s.Create(r)

	sig := signApproval(t, r, testutil.RootKey(t))
	if err := approveElevated(t, s, r, testutil.RootAddr(t), sig); err != nil {
		t.Fatalf("valid step-up rejected: %v", err)
	}
	got, _ := s.Poll(r.ID)
	if got.State != consent.StateApproved {
		t.Fatalf("state = %q, want approved", got.State)
	}
	// The signature must be retained: it becomes the token's step_up claim,
	// which verifiers re-check against the root.
	if len(got.StepUpSig) != 65 {
		t.Errorf("StepUpSig len = %d, want the 65-byte root signature", len(got.StepUpSig))
	}
}

func TestApproveElevated_RejectionTable(t *testing.T) {
	cases := []struct {
		name    string
		sig     func(tb testing.TB, r *consent.Request) []byte
		root    func(tb testing.TB) string
		wantErr string
	}{
		{
			name:    "signed_by_someone_who_is_not_the_root",
			sig:     func(tb testing.TB, r *consent.Request) []byte { return signApproval(tb, r, testutil.OtherRootKey(tb)) },
			wantErr: "signer is not root",
		},
		{
			name:    "truncated_signature",
			sig:     func(tb testing.TB, r *consent.Request) []byte { return []byte{1, 2, 3} },
			wantErr: "bad signature length",
		},
		{
			// Corrupting R has two legitimate outcomes: recovery yields some
			// other address ("signer is not root"), or it fails outright
			// ("recovery failed"). Which one depends on the corrupted bytes, so
			// asserting either specifically would be asserting a coin flip. What
			// must hold is that it is rejected on the step-up path.
			name: "corrupted_signature",
			sig: func(tb testing.TB, r *consent.Request) []byte {
				s := signApproval(tb, r, testutil.RootKey(tb))
				testutil.FlipSigByte(tb, s)
				return s
			},
			wantErr: "step-up:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := consent.NewStore()
			r := req(t, consent.TierElevated)
			s.Create(r)

			root := testutil.RootAddr(t)
			if tc.root != nil {
				root = tc.root(t)
			}
			err := approveElevated(t, s, r, root, tc.sig(t, r))
			requireErr(t, err, tc.wantErr)

			got, _ := s.Poll(r.ID)
			if got.State != consent.StatePending {
				t.Errorf("state = %q, want still pending after a failed step-up", got.State)
			}
		})
	}
}

// TestApproveElevated_AcceptsLowercaseRoot pins address normalization.
//
// Ethereum addresses are case-insensitive; EIP-55 checksum casing is
// presentational. A PSA submitted with a lowercase root onboards fine (attest
// compares normalized), so if the step-up path compares raw strings, that
// tenant can never approve an elevated request — their money is stuck.
func TestApproveElevated_AcceptsLowercaseRoot(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierElevated)
	s.Create(r)

	lower := strings.ToLower(testutil.RootAddr(t))
	sig := signApproval(t, r, testutil.RootKey(t))
	if err := approveElevated(t, s, r, lower, sig); err != nil {
		t.Fatalf("step-up rejected for a lowercase root address: %v\n"+
			"EIP-55 casing is presentational; the same key signed it.", err)
	}
}

// ---------------------------------------------------------------------------
// The approval digest binds to the specific action
// ---------------------------------------------------------------------------

// TestApprovalDigest_BindsEveryField is what makes step-up an approval of an
// ACTION rather than of a session. If any field could change without moving the
// digest, a signature captured for a small payment could be replayed against a
// large one.
func TestApprovalDigest_BindsEveryField(t *testing.T) {
	base := req(t, consent.TierElevated)
	baseDigest, err := consent.ApprovalDigest(base, testutil.ChainID, testutil.RegistryAddr)
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*consent.Request){
		"requestId":  func(r *consent.Request) { r.ID = "req-2" },
		"agent":      func(r *consent.Request) { r.AgentID = "aauth:other@agents.example.test" },
		"resource":   func(r *consent.Request) { r.Resource = "https://evil.example.test/drain" },
		"amountWei":  func(r *consent.Request) { r.AmountWei = "500000" },
		"scope":      func(r *consent.Request) { r.ScopeReq = []string{"payment:create", "payment:recurring"} },
		"mission":    func(r *consent.Request) { r.MissionS256 = strings.Repeat("ab", 32) },
		"expiration": func(r *consent.Request) { r.ExpiresAt = r.ExpiresAt.Add(time.Hour) },
	}

	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			r := req(t, consent.TierElevated)
			mut(r)
			d, err := consent.ApprovalDigest(r, testutil.ChainID, testutil.RegistryAddr)
			if err != nil {
				t.Fatal(err)
			}
			if d == baseDigest {
				t.Errorf("changing %s did not change the approval digest: a signature "+
					"for one action would be valid for another", name)
			}
		})
	}
}

// The digest is also bound to the chain and registry through the EIP-712 domain
// separator, so an approval cannot be replayed against a different deployment.
func TestApprovalDigest_BindsDomain(t *testing.T) {
	r := req(t, consent.TierElevated)
	base, _ := consent.ApprovalDigest(r, testutil.ChainID, testutil.RegistryAddr)

	otherChain, _ := consent.ApprovalDigest(r, 1, testutil.RegistryAddr)
	if otherChain == base {
		t.Error("digest does not bind the chain id")
	}
	otherRegistry, _ := consent.ApprovalDigest(r, testutil.ChainID, "0x00000000000000000000000000000000000000ff")
	if otherRegistry == base {
		t.Error("digest does not bind the registry address")
	}
}

// TestApproveElevated_StaleSignatureRejected is the replay attempt in full: the
// person approves 500 wei, then the amount is altered to 500000 and the old
// signature re-presented.
func TestApproveElevated_StaleSignatureRejected(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierElevated)
	s.Create(r)

	sig := signApproval(t, r, testutil.RootKey(t)) // signed while amount == "500"
	r.AmountWei = "500000"                         // ...then the action is changed

	err := approveElevated(t, s, r, testutil.RootAddr(t), sig)
	requireErr(t, err, "signer is not root")
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

func TestPollDoesNotTransition(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierRoutine)
	s.Create(r)

	// Polling is read-only by design: an agent's Retry-After loop must not be
	// able to influence the outcome.
	for i := 0; i < 5; i++ {
		got, err := s.Poll(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != consent.StatePending {
			t.Fatalf("poll %d moved the state to %q", i, got.State)
		}
	}
}

func TestExpiry(t *testing.T) {
	t.Run("poll_marks_expired", func(t *testing.T) {
		s := consent.NewStore()
		r := req(t, consent.TierRoutine, func(r *consent.Request) {
			r.ExpiresAt = time.Now().Add(-time.Second)
		})
		s.Create(r)

		got, err := s.Poll(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != consent.StateExpired {
			t.Errorf("state = %q, want expired", got.State)
		}
	})

	t.Run("cannot_approve_after_window_closes", func(t *testing.T) {
		s := consent.NewStore()
		r := req(t, consent.TierRoutine, func(r *consent.Request) {
			r.ExpiresAt = time.Now().Add(-time.Second)
		})
		s.Create(r)
		requireErr(t, s.ApproveRoutine(r.Code), "expired")
	})

	t.Run("elevated_cannot_be_approved_after_window_closes", func(t *testing.T) {
		s := consent.NewStore()
		r := req(t, consent.TierElevated, func(r *consent.Request) {
			r.ExpiresAt = time.Now().Add(-time.Second)
		})
		s.Create(r)
		// A perfectly valid signature must still not revive a closed window.
		err := approveElevated(t, s, r, testutil.RootAddr(t), signApproval(t, r, testutil.RootKey(t)))
		requireErr(t, err, "expired")
	})
}

// TestTerminalStatesAreImmutable: once a request resolves, it stays resolved.
// Re-approval would otherwise let a single consent be spent twice.
func TestTerminalStatesAreImmutable(t *testing.T) {
	t.Run("approved_cannot_be_reapproved", func(t *testing.T) {
		s := consent.NewStore()
		r := req(t, consent.TierRoutine)
		s.Create(r)
		if err := s.ApproveRoutine(r.Code); err != nil {
			t.Fatal(err)
		}
		requireErr(t, s.ApproveRoutine(r.Code), "already approved")
	})

	t.Run("denied_cannot_be_approved", func(t *testing.T) {
		s := consent.NewStore()
		r := req(t, consent.TierRoutine)
		s.Create(r)
		if err := s.Deny(r.Code); err != nil {
			t.Fatal(err)
		}
		requireErr(t, s.ApproveRoutine(r.Code), "already denied")
	})

	t.Run("approved_cannot_be_denied", func(t *testing.T) {
		s := consent.NewStore()
		r := req(t, consent.TierRoutine)
		s.Create(r)
		if err := s.ApproveRoutine(r.Code); err != nil {
			t.Fatal(err)
		}
		requireErr(t, s.Deny(r.Code), "already approved")
	})
}

func TestUnknownLookups(t *testing.T) {
	s := consent.NewStore()
	if _, err := s.Poll("no-such-id"); err == nil {
		t.Error("expected an error polling an unknown request id")
	}
	if _, err := s.ByCode("NOPE"); err == nil {
		t.Error("expected an error resolving an unknown code")
	}
	requireErr(t, s.ApproveRoutine("NOPE"), "unknown code")
}

// ByCode is how the approval surface and the step-up endpoint find a request:
// they know the human-facing code, not the internal id.
func TestByCode_ResolvesTheSameRequest(t *testing.T) {
	s := consent.NewStore()
	r := req(t, consent.TierElevated)
	s.Create(r)

	got, err := s.ByCode(r.Code)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != r.ID {
		t.Errorf("ByCode returned id %q, want %q", got.ID, r.ID)
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
