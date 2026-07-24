// Package server wires the PS's HTTP surface — multi-tenant edition.
//
// The tenancy rule, stated once: every request's tenant is resolved through
// the grant chain (agent key -> AgentGrant -> root -> PSA), never through a
// session, cookie, or account. Governance endpoints (/export, /psa) are
// authenticated the same non-custodial way: a root-key signature over a
// challenge (SIWE-style), because a tenant with no password to check is
// also a tenant with no password to phish.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/consent"
	"signet.dev/ps/internal/missions"
	"signet.dev/ps/internal/store"
	"signet.dev/ps/internal/tokens"
)

type SigVerifier interface {
	Verify(r *http.Request) (agentKeyThumb string, agentID string, err error)
}

// RootAuth authenticates a PERSON (not an agent) for governance calls:
// verifies a root-key signature over a server-issued challenge. EOA or
// ERC-1271. Implementation TODO(v0) — SIWE is the obvious profile.
type RootAuth interface {
	VerifyChallenge(r *http.Request) (root string, err error)
}

type Config struct {
	IssuerURL    string
	IssuerKeys   []tokens.IssuerKey
	Registry     attest.RevocationRegistry
	ChainID      int64
	RegistryAddr string
}

type Server struct {
	cfg      Config
	sig      SigVerifier
	rootAuth RootAuth
	tenants  *store.Tenants
	pending  *consent.Store
	chain    *attest.Verifier
}

func New(cfg Config, sig SigVerifier, ra RootAuth) *Server {
	return &Server{
		cfg: cfg, sig: sig, rootAuth: ra,
		tenants: store.NewTenants(),
		pending: consent.NewStore(),
		chain:   &attest.Verifier{Registry: cfg.Registry, Now: time.Now},
	}
}

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/aauth-issuer.json", s.metadata)
	mux.HandleFunc("GET /jwks.json", s.jwks)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /pending/{id}", s.poll)
	mux.HandleFunc("GET /approve/{code}", s.approvePage)
	mux.HandleFunc("POST /approve/{code}/signature", s.approveElevated)

	// Tenant lifecycle — all root-authenticated or root-signed:
	mux.HandleFunc("POST /psa", s.onboard)             // body: signed PSA -> tenancy
	mux.HandleFunc("POST /agents", s.enrollAgent)      // agent-signed req carrying root-signed AG
	mux.HandleFunc("GET /psa/{root}", s.servePSA)      // public: verifiers resolve by-ref
	mux.HandleFunc("GET /grants/{s256}", s.serveGrant) // public: verifiers resolve ag_s256 by-ref
	mux.HandleFunc("GET /export", s.export)            // RootAuth: I5 per tenant
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":         s.cfg.IssuerURL,
		"jwks_uri":       s.cfg.IssuerURL + "/jwks.json",
		"token_endpoint": s.cfg.IssuerURL + "/token",
		"signet_non_custodial": map[string]any{
			// Per-tenant PSAs resolve at /psa/{root}; tokens carry the exact ref.
			"psa_endpoint_template":  s.cfg.IssuerURL + "/psa/{root}",
			"onboarding_endpoint":    s.cfg.IssuerURL + "/psa",
			"revocation_registry":    map[string]any{"chain": s.cfg.ChainID, "address": s.cfg.RegistryAddr},
			"root_signature_schemes": []string{"eoa-secp256k1", "erc1271"},
		},
	})
}

// onboard: a new tenant arrives as nothing but a signed PSA. Verify
// end-to-end, admit, done. No email, no password, no KYC (KYC is an
// attestation a tenant may later attach — not a gate to existence).
func (s *Server) onboard(w http.ResponseWriter, r *http.Request) {
	var psa attest.PersonServerAuthorization
	if err := json.NewDecoder(r.Body).Decode(&psa); err != nil {
		writeErr(w, 400, "invalid_request", err)
		return
	}
	t, err := s.tenants.VerifyAndOnboard(r.Context(), s.chain, &psa, s.cfg.IssuerURL, s.keyThumbs())
	if err != nil {
		writeErr(w, 403, "invalid_psa", err)
		return
	}
	writeJSON(w, 201, map[string]any{"root": t.Root, "psa_url": s.cfg.IssuerURL + "/psa/" + t.Root})
}

// token: hot path. Note the tenancy resolution — three lines, no session.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	agentKeyThumb, agentID, err := s.sig.Verify(r)
	if err != nil {
		writeErr(w, 401, "invalid_signature", err)
		return
	}
	tenant, ok := s.tenants.ByAgent(agentID)
	if !ok {
		writeErr(w, 403, "no_agent_grant", fmt.Errorf("agent not enrolled by any root"))
		return
	}
	grant, ok := tenant.Grant(agentID)
	if !ok || grant.AgentThumbprint != agentKeyThumb {
		writeErr(w, 403, "no_agent_grant", fmt.Errorf("agent key does not match grant"))
		return
	}

	var body struct {
		ResourceToken string             `json:"resource_token"`
		Mission       *tokens.MissionRef `json:"mission,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid_request", err)
		return
	}
	res, err := parseResourceToken(body.ResourceToken)
	if err != nil {
		writeErr(w, 400, "invalid_request", err)
		return
	}
	if err := tenant.Log().Consistent(agentID, grant.MissionScopeS256, res.Scope, res.AmountWei); err != nil {
		writeErr(w, 403, "mission_inconsistent", err)
		return
	}

	tier := tierFor(tenant.PSA.Scope, res)
	req := &consent.Request{
		ID: newID(), Code: newCode(), AgentID: agentID,
		Resource: res.Iss, AmountWei: res.AmountWei, ScopeReq: res.Scope,
		MissionS256: grant.MissionScopeS256, Tier: tier,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
		ResourceJSON: marshalResource(res), // full-fidelity claims for the async mint path
	}
	s.pending.Create(req)
	tenant.Log().Append(agentID, missions.Entry{Kind: "token_request", RequestID: req.ID, At: time.Now()})

	if tier == consent.TierRoutine && tenant.Log().AutoApprovable(agentID, res.Scope, res.AmountWei) {
		_ = s.pending.ApproveRoutine(req.Code)
		s.finish(w, req, tenant, grant, res, agentID)
		return
	}
	w.Header().Set("Location", s.cfg.IssuerURL+"/pending/"+req.ID)
	w.Header().Set("Retry-After", "5")
	writeJSON(w, 202, map[string]any{"interaction": map[string]any{
		"approval_url": s.cfg.IssuerURL + "/approve/" + req.Code,
		"code":         req.Code,
		"tier":         tierName(tier),
	}})
}

func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	_, agentID, err := s.sig.Verify(r)
	if err != nil {
		writeErr(w, 401, "invalid_signature", err)
		return
	}
	req, err := s.pending.Poll(r.PathValue("id"))
	if err != nil || req.AgentID != agentID {
		writeErr(w, 404, "unknown_request", fmt.Errorf("no such pending request for this agent"))
		return
	}
	switch req.State {
	case consent.StatePending:
		w.Header().Set("Retry-After", "5")
		writeJSON(w, 202, map[string]any{"status": "pending"})
	case consent.StateApproved:
		tenant, _ := s.tenants.ByAgent(agentID)
		grant, _ := tenant.Grant(agentID)
		s.finish(w, req, tenant, grant, resourceOf(req), agentID)
	case consent.StateDenied:
		writeErr(w, 403, "denied", fmt.Errorf("person denied the request"))
	default:
		writeErr(w, 410, "expired", fmt.Errorf("consent window closed"))
	}
}

func (s *Server) finish(w http.ResponseWriter, req *consent.Request, tenant *store.Tenant, grant *attest.AgentGrant, res tokens.ResourceClaims, agentID string) {
	var su *tokens.StepUp
	if len(req.StepUpSig) > 0 {
		d, _ := consent.ApprovalDigest(req, s.cfg.ChainID, s.cfg.RegistryAddr)
		su = &tokens.StepUp{Digest: hexStr(d[:]), Sig: hexStr(req.StepUpSig)}
	}
	tok, err := tokens.Mint(s.cfg.IssuerKeys[0], tokens.MintInput{
		PSA:        tenant.PSA,
		PSABlobURL: s.cfg.IssuerURL + "/psa/" + tenant.Root, // per-tenant by-ref
		Grant:      grant, Resource: res, AgentID: agentID,
		AgentKey: agentKeyFromGrant(grant),
		Mission:  &tokens.MissionRef{Approver: s.cfg.IssuerURL, S256: grant.MissionScopeS256},
		StepUp:   su, TTL: time.Hour,
	})
	if err != nil {
		writeErr(w, 403, "outside_grant", err)
		return
	}
	tenant.Log().Append(agentID, missions.Entry{Kind: "token_issued", RequestID: req.ID, At: time.Now()})
	writeJSON(w, 200, map[string]any{"auth_token": tok})
}

// approveElevated: the root for THIS request comes from the grant chain of
// the requesting agent — not from server config (the single-tenant bug this
// rewrite exists to fix).
func (s *Server) approveElevated(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid_request", err)
		return
	}
	code := r.PathValue("code")
	req, err := s.pending.ByCode(code)
	if err != nil {
		writeErr(w, 404, "unknown_code", err)
		return
	}
	tenant, ok := s.tenants.ByAgent(req.AgentID)
	if !ok {
		writeErr(w, 404, "unknown_tenant", fmt.Errorf("request's agent has no tenant"))
		return
	}
	if err := s.pending.ApproveElevated(code, tenant.Root, s.cfg.ChainID, s.cfg.RegistryAddr, hexBytes(body.Signature)); err != nil {
		writeErr(w, 403, "step_up_failed", err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "approved"})
}

// enrollAgent: the AgentGrant names its root; the root must be an onboarded
// tenant (live PSA), and the grant must verify against that root.
func (s *Server) enrollAgent(w http.ResponseWriter, r *http.Request) {
	agentKeyThumb, agentID, err := s.sig.Verify(r)
	if err != nil {
		writeErr(w, 401, "invalid_signature", err)
		return
	}
	var g attest.AgentGrant
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeErr(w, 400, "invalid_request", err)
		return
	}
	tenant, ok := s.tenants.ByRoot(g.Root)
	if !ok {
		writeErr(w, 403, "unknown_root", fmt.Errorf("root has not onboarded (no PSA)"))
		return
	}
	if err := s.chain.VerifyAgentGrant(r.Context(), &g, tenant.Root, agentID, agentKeyThumb); err != nil {
		writeErr(w, 403, "invalid_grant", err)
		return
	}
	if err := s.tenants.Enroll(agentID, tenant, &g); err != nil {
		writeErr(w, 409, "conflict", err)
		return
	}
	tenant.Log().Append(agentID, missions.Entry{Kind: "agent_enrolled", At: time.Now()})
	writeJSON(w, 201, map[string]any{"status": "enrolled", "root": tenant.Root})
}

func (s *Server) servePSA(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenants.ByRoot(r.PathValue("root"))
	if !ok {
		writeErr(w, 404, "unknown_root", fmt.Errorf("no such tenant"))
		return
	}
	writeJSON(w, 200, t.PSA)
}

// serveGrant resolves an AgentGrant by content hash so an enhanced verifier
// can fetch what a token's ag_s256 points at. Public and tamper-evident: the
// caller re-hashes the response and checks it equals the s256 it asked for.
func (s *Server) serveGrant(w http.ResponseWriter, r *http.Request) {
	g, ok := s.tenants.GrantByS256(r.PathValue("s256"))
	if !ok {
		writeErr(w, 404, "unknown_grant", fmt.Errorf("no grant with that content hash"))
		return
	}
	writeJSON(w, 200, g)
}

// export: RootAuth (root-signed challenge), then only that tenant's bundle.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootAuth.VerifyChallenge(r)
	if err != nil {
		writeErr(w, 401, "root_auth_failed", err)
		return
	}
	t, ok := s.tenants.ByRoot(root)
	if !ok {
		writeErr(w, 404, "unknown_root", fmt.Errorf("no such tenant"))
		return
	}
	writeJSON(w, 200, map[string]any{
		"psa": t.PSA, "mission_log": t.Log().Export(),
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	keys := []tokens.JWK{}
	for _, k := range s.cfg.IssuerKeys {
		keys = append(keys, k.Pub)
	}
	writeJSON(w, 200, map[string]any{"keys": keys})
}

func (s *Server) keyThumbs() []string {
	out := []string{}
	for _, k := range s.cfg.IssuerKeys {
		out = append(out, k.Pub.Thumbprint())
	}
	return out
}

// Mechanical helpers live in helpers.go; the approval surface in approve.go.
// (resourceFromRequest is gone: the request now carries ResourceJSON, so the
// async mint path reads the exact claims instead of reconstructing a subset.)
