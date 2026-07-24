// Package tokens defines the AAuth token shapes this PS consumes and mints,
// plus the two-layer verification an enhanced (non-custodial-aware) resource
// runs. Layer 1 is standard AAuth; Layer 2 is the signet extension.
//
// Minting discipline (invariant I1 lives here): Mint refuses to produce a
// token that the live PSA would not cover — the PS is structurally unable
// to exceed its grant, rather than merely policy-bound not to.
package tokens

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"signet.dev/ps/internal/attest"
)

// ---------------------------------------------------------------------------
// Claim shapes
// ---------------------------------------------------------------------------

// CNF is the proof-of-possession confirmation claim: the agent's public key.
// The resource matches this against the RFC 9421 signature on the request,
// which is what makes a stolen auth token useless (no bearer semantics).
type CNF struct {
	JWK JWK `json:"jwk"`
}

type JWK struct {
	Kty string `json:"kty"` // "OKP"
	Crv string `json:"crv"` // "Ed25519"
	X   string `json:"x"`   // base64url public key
}

// Thumbprint implements RFC 7638 for the OKP/Ed25519 case: SHA-256 over the
// canonical JSON {"crv","kty","x"} in lexicographic member order.
func (k JWK) Thumbprint() string {
	c := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, k.Crv, k.Kty, k.X)
	h := sha256.Sum256([]byte(c))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type MissionRef struct {
	Approver string `json:"approver"` // this PS's URL
	S256     string `json:"s256"`     // hash of the mission blob (agent+PS hold the blob)
}

// StepUp carries a fresh root signature over the specific approval (I3).
// Digest construction is in package consent; verifiers recompute it.
type StepUp struct {
	Digest string `json:"digest"` // hex, 32 bytes
	Sig    string `json:"sig"`    // hex, 65 bytes (or 1271 blob)
}

// AuthClaims is the auth+jwt payload. Standard AAuth fields first; signet
// extension fields (ignored by vanilla verifiers) after.
type AuthClaims struct {
	Iss     string      `json:"iss"`
	Dwk     string      `json:"dwk"` // "aauth-issuer.json"
	Aud     string      `json:"aud"`
	Jti     string      `json:"jti"`
	Agent   string      `json:"agent"`
	Cnf     CNF         `json:"cnf"`
	Iat     int64       `json:"iat"`
	Exp     int64       `json:"exp"`
	Sub     string      `json:"sub"` // CAIP-10 root: "eip155:8453:0x…"
	Mission *MissionRef `json:"mission,omitempty"`

	// --- signet non-custodial extension ---
	PSA    string  `json:"psa,omitempty"`     // by-ref: URL#s256=<hash of signed PSA>
	AgS256 string  `json:"ag_s256,omitempty"` // content hash of the AgentGrant
	StepUp *StepUp `json:"step_up,omitempty"`

	// Vouched identity claims (OIDC vocabulary), each gated by PSA.Scope.AllowedClaims.
	// Provenance is explicit: "verified" (PS checked) vs "relayed:<attester>".
	Name  *Vouched `json:"name,omitempty"`
	Email *Vouched `json:"email,omitempty"`
	KYC   *Vouched `json:"kyc,omitempty"`
}

type Vouched struct {
	Value      string `json:"value"`
	Provenance string `json:"provenance"` // "verified" | "relayed:<attester-id>"
}

// ResourceClaims is the subset of aa-resource+jwt we need: what the resource
// says it requires before it will serve the agent.
type ResourceClaims struct {
	Iss       string   `json:"iss"` // resource URL (also the future aud)
	Jti       string   `json:"jti"`
	Iat       int64    `json:"iat"`
	Exp       int64    `json:"exp"`
	Scope     []string `json:"scope"`            // requested claims/permissions
	AmountWei string   `json:"amount,omitempty"` // payment resources: requested authorization amount
}

// ---------------------------------------------------------------------------
// Minting (PS side)
// ---------------------------------------------------------------------------

type IssuerKey struct {
	Kid  string
	Priv ed25519.PrivateKey
	Pub  JWK
}

type MintInput struct {
	PSA        *attest.PersonServerAuthorization
	PSABlobURL string // where /psa/current serves it
	Grant      *attest.AgentGrant
	Resource   ResourceClaims
	AgentID    string
	AgentKey   JWK
	Mission    *MissionRef
	StepUp     *StepUp // nil unless consent tier required it
	Claims     map[string]Vouched
	TTL        time.Duration
}

// Mint enforces the PSA envelope *at mint time*. Every rejection here is a
// case where a custodial PS could have quietly proceeded.
func Mint(key IssuerKey, in MintInput) (string, error) {
	if !containsStr(in.PSA.KeyThumbprints, key.Pub.Thumbprint()) {
		return "", fmt.Errorf("mint: issuer key not covered by PSA (I1)")
	}
	ttl := in.TTL
	if max := time.Duration(in.PSA.Scope.MaxTokenTTLSeconds) * time.Second; ttl > max {
		ttl = max // clamp, don't error: the grant is the ceiling
	}
	if ttl > time.Hour {
		ttl = time.Hour // spec SHOULD; we treat as MUST
	}
	for name := range in.Claims {
		if !containsStr(in.PSA.Scope.AllowedClaims, name) {
			return "", fmt.Errorf("mint: PSA scope does not allow vouching %q (I1)", name)
		}
	}
	if err := checkPaymentEnvelope(in.PSA.Scope, in.Resource.AmountWei, in.StepUp); err != nil {
		return "", err // I3: step-up required above threshold; cap is absolute
	}

	now := time.Now()
	psaHash, err := attest.ContentHash(in.PSA)
	if err != nil {
		return "", err
	}
	agHash, err := attest.ContentHash(in.Grant)
	if err != nil {
		return "", err
	}

	claims := AuthClaims{
		Iss: in.PSA.Issuer, Dwk: "aauth-issuer.json",
		Aud: in.Resource.Iss, Jti: newJTI(), Agent: in.AgentID,
		Cnf: CNF{JWK: in.AgentKey},
		Iat: now.Unix(), Exp: now.Add(ttl).Unix(),
		Sub:     fmt.Sprintf("eip155:%d:%s", in.PSA.RegistryChain, in.PSA.Root),
		Mission: in.Mission,
		PSA:     fmt.Sprintf("%s#s256=%s", in.PSABlobURL, psaHash),
		AgS256:  agHash,
		StepUp:  in.StepUp,
	}
	applyVouched(&claims, in.Claims)

	return signJWT(key, "auth+jwt", claims)
}

func checkPaymentEnvelope(s attest.Scope, amountWei string, su *StepUp) error {
	if amountWei == "" {
		return nil
	}
	amt, ok := new(big.Int).SetString(amountWei, 10)
	if !ok {
		return fmt.Errorf("mint: bad amount")
	}
	cap := bigOrZero(s.PaymentCapWei)
	if cap.Sign() == 0 || amt.Cmp(cap) > 0 {
		return fmt.Errorf("mint: amount exceeds PSA payment cap (I1)")
	}
	if th := bigOrZero(s.StepUpAboveWei); th.Sign() > 0 && amt.Cmp(th) > 0 && su == nil {
		return fmt.Errorf("mint: step-up signature required above threshold (I3)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verification (resource side) — Layer 1 + Layer 2
// ---------------------------------------------------------------------------

type JWKSResolver interface {
	Key(ctx context.Context, iss, kid string) (JWK, error) // fetch via iss + dwk metadata
}
type AttestationResolver interface {
	PSA(ctx context.Context, ref string) (*attest.PersonServerAuthorization, error) // fetch + s256 check
	AgentGrant(ctx context.Context, iss, agS256 string) (*attest.AgentGrant, error)
}
type ReplayCache interface {
	SeenJTI(jti string, exp int64) bool
}

type Verifier struct {
	Keys   JWKSResolver
	Attest AttestationResolver
	Chain  *attest.Verifier
	Replay ReplayCache
	Now    func() time.Time
}

// Verify runs the full enhanced chain. `requestSigKeyThumb` is the thumbprint
// of the key that produced the RFC 9421 signature on the HTTP request (the
// httpsig layer extracts it); aud is the resource's own URL.
//
// Layer 2 is run iff the token carries a `psa` claim. A resource that REQUIRES
// key-rooting should additionally reject a returned claim set whose PSA is
// empty (see AuthClaims.PSA); a resource that does not care can call
// VerifyVanilla, which stops after Layer 1 and never touches the extension.
func (v *Verifier) Verify(ctx context.Context, rawJWT, aud, requestSigKeyThumb string) (*AuthClaims, error) {
	hdr, claims, err := v.verifyLayer1(ctx, rawJWT, aud, requestSigKeyThumb)
	if err != nil {
		return nil, err
	}

	// ---- Layer 2: non-custodial extension (skip iff absent -> vanilla PS) ----
	if claims.PSA == "" {
		return claims, nil // valid vanilla AAuth; caller decides if key-rooted is REQUIRED
	}
	psa, err := v.Attest.PSA(ctx, claims.PSA)
	if err != nil {
		return nil, fmt.Errorf("psa resolve: %w", err)
	}
	issuerKeyThumb, err := issuerThumbFromHeader(ctx, v.Keys, claims.Iss, hdr.Kid)
	if err != nil {
		return nil, err
	}
	if err := v.Chain.VerifyPSA(ctx, psa, claims.Iss, issuerKeyThumb); err != nil {
		return nil, err
	}
	if got := fmt.Sprintf("eip155:%d:%s", psa.RegistryChain, psa.Root); !caipEq(got, claims.Sub) {
		return nil, fmt.Errorf("sub is not the PSA root: PS asserting an identity it was not granted")
	}
	grant, err := v.Attest.AgentGrant(ctx, claims.Iss, claims.AgS256)
	if err != nil {
		return nil, fmt.Errorf("agentgrant resolve: %w", err)
	}
	if err := v.Chain.VerifyAgentGrant(ctx, grant, psa.Root, claims.Agent, claims.Cnf.JWK.Thumbprint()); err != nil {
		return nil, err
	}
	// Chain closed: root -> PS key -> token -> agent key -> this very request.
	return claims, nil
}

// VerifyVanilla runs Layer 1 only (standard AAuth), ignoring any non-custodial
// extension claims entirely. This is what a resource deployed WITHOUT the
// key-rooting requirement runs — and it is exactly the surface against which a
// forged (custodially-minted) token still passes: the whole point of the
// extension is that Layer 1 alone cannot tell a fabricated `sub` from a real one.
func (v *Verifier) VerifyVanilla(ctx context.Context, rawJWT, aud, requestSigKeyThumb string) (*AuthClaims, error) {
	_, claims, err := v.verifyLayer1(ctx, rawJWT, aud, requestSigKeyThumb)
	return claims, err
}

// verifyLayer1 is standard AAuth: JWT signature against the issuer JWKS, typ,
// aud, expiry, jti replay, and cnf/request-signature binding.
func (v *Verifier) verifyLayer1(ctx context.Context, rawJWT, aud, requestSigKeyThumb string) (*jwtHeader, *AuthClaims, error) {
	hdr, claims, err := parseAndCheckSig[AuthClaims](ctx, v.Keys, rawJWT, "auth+jwt")
	if err != nil {
		return nil, nil, err
	}
	now := v.Now().Unix()
	if claims.Aud != aud {
		return nil, nil, fmt.Errorf("aud mismatch")
	}
	if now >= claims.Exp || claims.Exp-claims.Iat > 24*3600 {
		return nil, nil, fmt.Errorf("expired or over-long token")
	}
	if v.Replay.SeenJTI(claims.Jti, claims.Exp) {
		return nil, nil, fmt.Errorf("jti replay")
	}
	if claims.Cnf.JWK.Thumbprint() != requestSigKeyThumb {
		return nil, nil, fmt.Errorf("cnf/request-signature mismatch: token not presented by its agent")
	}
	return hdr, claims, nil
}

// ---------------------------------------------------------------------------
// Minimal JWT plumbing (EdDSA only; `none` is structurally impossible here)
// ---------------------------------------------------------------------------

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func signJWT(key IssuerKey, typ string, claims any) (string, error) {
	h, _ := json.Marshal(jwtHeader{Alg: "EdDSA", Typ: typ, Kid: key.Kid})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(h) + "." + b64(c)
	sig := ed25519.Sign(key.Priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseAndCheckSig[T any](ctx context.Context, keys JWKSResolver, raw, wantTyp string) (*jwtHeader, *T, error) {
	parts, err := split3(raw)
	if err != nil {
		return nil, nil, err
	}
	var hdr jwtHeader
	if err := decodeSeg(parts[0], &hdr); err != nil {
		return nil, nil, err
	}
	if hdr.Alg != "EdDSA" || hdr.Typ != wantTyp { // MUST NOT accept `none`; typ confusion refused
		return nil, nil, fmt.Errorf("unacceptable alg/typ %q/%q", hdr.Alg, hdr.Typ)
	}
	var claims T
	if err := decodeSeg(parts[1], &claims); err != nil {
		return nil, nil, err
	}
	iss := issFromAny(&claims)
	jwk, err := keys.Key(ctx, iss, hdr.Kid)
	if err != nil {
		return nil, nil, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("bad issuer key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig) {
		return nil, nil, fmt.Errorf("jwt signature invalid")
	}
	return &hdr, &claims, nil
}

// --- helpers (b64, split3, decodeSeg, issFromAny, issuerThumbFromHeader,
//     caipEq, applyVouched, containsStr, bigOrZero, newJTI) ---
// [elided to keep the skeleton readable — mechanical code, see repo TODOs]
