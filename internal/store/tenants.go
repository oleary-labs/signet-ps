// Package store — tenants.go: multi-tenant state.
//
// A "tenant" is a root that has onboarded by signing a PSA covering this
// PS's issuer keys. There is no account object: the PSA IS the tenancy.
// Everything the PS holds for a tenant is either root-signed (PSA, AgentGrants)
// or hash-chained and exportable (mission logs) — so hosting many tenants
// never means custodying any of them (the invariants are per-root, and
// migration/export/revocation of one tenant is invisible to the others).
//
// Resolution rule (the multi-tenant core): tenancy is derived from the
// grant chain, never from a session. An inbound signed request identifies
// an agent key; the AgentGrant for that agent names its root; the root's
// PSA is the envelope for everything that follows. If any link is missing,
// there is no tenant — and structurally, nothing the PS can do about it.
package store

import (
	"context"
	"fmt"
	"sync"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/missions"
)

type Tenant struct {
	Root string // 0x… — the tenant identifier IS the root address
	PSA  *attest.PersonServerAuthorization

	mu     sync.Mutex
	grants map[string]*attest.AgentGrant // agentID -> grant (each grant is root-signed)
	log    *missions.Log                 // per-tenant mission log (per-agent chains inside)
}

func NewTenant(psa *attest.PersonServerAuthorization) *Tenant {
	return &Tenant{Root: psa.Root, PSA: psa, grants: map[string]*attest.AgentGrant{}, log: missions.NewLog()}
}

func (t *Tenant) Grant(agentID string) (*attest.AgentGrant, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	g, ok := t.grants[agentID]
	return g, ok
}

func (t *Tenant) PutGrant(agentID string, g *attest.AgentGrant) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.grants[agentID] = g
}

func (t *Tenant) Log() *missions.Log { return t.log }

// Tenants is the multi-tenant registry with the two lookups the server
// needs: by root (onboarding, governance, export) and by agent (the hot
// path: every /token and /pending call resolves tenancy through the agent).
type Tenants struct {
	mu          sync.Mutex
	byRoot      map[string]*Tenant
	byAgent     map[string]string             // agentID -> root (maintained on enrollment)
	byGrantS256 map[string]*attest.AgentGrant // content hash -> grant (verifiers resolve ag_s256 by-ref)
}

func NewTenants() *Tenants {
	return &Tenants{
		byRoot:      map[string]*Tenant{},
		byAgent:     map[string]string{},
		byGrantS256: map[string]*attest.AgentGrant{},
	}
}

// Onboard admits a tenant. The PSA MUST already be verified (signature,
// window, key coverage, registry liveness) by the caller — this store is
// deliberately dumb: it never judges, it only holds judged objects.
func (s *Tenants) Onboard(t *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byRoot[t.Root]; ok {
		// Re-onboarding = PSA replacement (rotation, scope change). Allowed;
		// grants and logs survive because they hang off the root, not the PSA.
		existing.PSA = t.PSA
		return nil
	}
	s.byRoot[t.Root] = t
	return nil
}

func (s *Tenants) ByRoot(root string) (*Tenant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byRoot[root]
	return t, ok
}

// ByAgent: the hot path. agent -> root -> tenant.
func (s *Tenants) ByAgent(agentID string) (*Tenant, bool) {
	s.mu.Lock()
	root, ok := s.byAgent[agentID]
	if !ok {
		s.mu.Unlock()
		return nil, false
	}
	t := s.byRoot[root]
	s.mu.Unlock()
	return t, t != nil
}

// Enroll links agent -> tenant after the server has verified the root-signed
// AgentGrant. Enforces the AAuth invariant that an agent instance acts for
// exactly one legal person: re-binding an agent to a different root requires
// the old grant to be revoked first (checked by the caller via registry).
func (s *Tenants) Enroll(agentID string, t *Tenant, g *attest.AgentGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byAgent[agentID]; ok && prev != t.Root {
		return fmt.Errorf("agent already bound to a different root (revoke first)")
	}
	s.byAgent[agentID] = t.Root
	t.PutGrant(agentID, g)
	if h, err := attest.ContentHash(g); err == nil {
		s.byGrantS256[h] = g
	}
	return nil
}

// GrantByS256 resolves a stored AgentGrant by its content hash — the by-ref
// handle a token carries in `ag_s256`, which an enhanced verifier resolves.
func (s *Tenants) GrantByS256(s256 string) (*attest.AgentGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byGrantS256[s256]
	return g, ok
}

// VerifyAndOnboard is the onboarding ceremony in one place: verify the PSA
// end-to-end (root signature, issuer match, key coverage, window, registry),
// then admit. issuerURL/keyThumbs describe THIS PS; the PSA must cover at
// least one live issuer key or the tenant could never be served.
func (s *Tenants) VerifyAndOnboard(ctx context.Context, v *attest.Verifier, psa *attest.PersonServerAuthorization, issuerURL string, keyThumbs []string) (*Tenant, error) {
	var covered string
	for _, kt := range keyThumbs {
		if containsStr(psa.KeyThumbprints, kt) {
			covered = kt
			break
		}
	}
	if covered == "" {
		return nil, fmt.Errorf("psa covers none of this PS's issuer keys")
	}
	if err := v.VerifyPSA(ctx, psa, issuerURL, covered); err != nil {
		return nil, err
	}
	if err := s.Onboard(NewTenant(psa)); err != nil {
		return nil, err
	}
	// Return the CANONICAL registered tenant, not the candidate just built.
	// Re-onboarding (rotation, scope change) updates the existing tenant's PSA
	// in place and discards the candidate — so returning the candidate would
	// hand back a detached object whose grants and mission log are empty, and
	// any caller reading them would silently see a brand-new account.
	live, ok := s.ByRoot(psa.Root)
	if !ok {
		return nil, fmt.Errorf("tenant not registered after onboarding")
	}
	return live, nil
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
