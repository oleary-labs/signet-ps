// resd: a whoami-style demo resource server. Two jobs:
//
//   - GET /            (cold, unauthenticated): mint an aa-resource+jwt stating
//     what this resource requires, and hand it back as `resource_token`.
//   - GET /whoami      (authenticated): run the enhanced verifier over the
//     presented auth+jwt and echo the claims it saw.
//
// The whole demo story is the --require-key-rooted flag:
//
//	--require-key-rooted=false  -> Layer 1 only (vanilla AAuth). A forged,
//	                               custodially-minted token is ACCEPTED.
//	--require-key-rooted=true   -> the non-custodial chain (Layer 2) is DEMANDED.
//	                               The same forged token is REJECTED.
//
// This is scaffolding-grade: the request "signature" is the dev header the
// agent presents (X-Dev-Agent-Thumb), matching psd's DevSigVerifier.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/tokens"
)

func main() {
	port := flag.String("port", "8095", "listen port")
	requireKeyRooted := flag.Bool("require-key-rooted", false, "demand the non-custodial chain (Layer 2)")
	amount := flag.String("amount", "", "if set, resource requires payment authorization of this many wei")
	scope := flag.String("scope", "read:whoami", "comma-separated required scope")
	flag.Parse()

	selfURL := "http://localhost:" + *port
	// resd's own signing key (for the aa-resource+jwt). Fresh per boot.
	_, rpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	rs := &resource{
		self:             selfURL,
		priv:             rpriv,
		requireKeyRooted: *requireKeyRooted,
		amount:           *amount,
		scope:            strings.Split(*scope, ","),
		verifier: &tokens.Verifier{
			Keys:   &jwksResolver{},
			Attest: &attestResolver{},
			Chain:  &attest.Verifier{Registry: alwaysLive{}, Now: time.Now},
			Replay: newReplayCache(),
			Now:    time.Now,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", rs.challenge)
	mux.HandleFunc("GET /whoami", rs.whoami)
	log.Printf("resd serving %s — require_key_rooted=%v", selfURL, *requireKeyRooted)
	log.Fatal(http.ListenAndServe(":"+*port, mux))
}

type resource struct {
	self             string
	priv             ed25519.PrivateKey
	requireKeyRooted bool
	amount           string
	scope            []string
	verifier         *tokens.Verifier
}

// challenge issues the aa-resource+jwt describing what the resource wants.
func (rs *resource) challenge(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	claims := tokens.ResourceClaims{
		Iss:       rs.self,
		Jti:       randHex(16),
		Iat:       now.Unix(),
		Exp:       now.Add(5 * time.Minute).Unix(),
		Scope:     rs.scope,
		AmountWei: rs.amount,
	}
	writeJSON(w, 200, map[string]any{
		"resource_token": rs.signResourceToken(claims),
		"required":       claims,
	})
}

// whoami verifies the presented auth+jwt and echoes the chain it saw.
func (rs *resource) whoami(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r.Header.Get("Authorization"))
	if tok == "" {
		writeJSON(w, 401, map[string]any{"error": "missing Authorization: AAuth <token>"})
		return
	}
	// Dev stand-in for the RFC 9421 request signature: the agent asserts which
	// key it holds; the verifier checks it equals the token's cnf.
	thumb := strings.TrimSpace(r.Header.Get("X-Dev-Agent-Thumb"))

	ctx := context.Background()
	var claims *tokens.AuthClaims
	var err error
	if rs.requireKeyRooted {
		claims, err = rs.verifier.Verify(ctx, tok, rs.self, thumb)
		if err == nil && claims.PSA == "" {
			err = fmt.Errorf("token is not key-rooted: no non-custodial chain present (PS asserted this identity on its own authority)")
		}
	} else {
		claims, err = rs.verifier.VerifyVanilla(ctx, tok, rs.self, thumb)
	}
	if err != nil {
		writeJSON(w, 403, map[string]any{"error": err.Error(), "require_key_rooted": rs.requireKeyRooted})
		return
	}

	chain := "vanilla" // Layer 1 only / no extension present
	if claims.PSA != "" {
		chain = "verified" // Layer 2 resolved: root -> PS key -> token -> agent key
	}
	writeJSON(w, 200, map[string]any{
		"sub":                claims.Sub,
		"agent":              claims.Agent,
		"iss":                claims.Iss,
		"chain":              chain,
		"require_key_rooted": rs.requireKeyRooted,
	})
}

func (rs *resource) signResourceToken(claims tokens.ResourceClaims) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "aa-resource+jwt", "kid": "resd"})
	body, _ := json.Marshal(claims)
	signing := b64(hdr) + "." + b64(body)
	sig := ed25519.Sign(rs.priv, []byte(signing))
	return signing + "." + b64(sig)
}

// --- resolvers ------------------------------------------------------------

// jwksResolver fetches the PS's JWKS. v0 single-key demo: return the first key
// (jwks.json carries no kid, and there is exactly one issuer key).
type jwksResolver struct{}

func (jwksResolver) Key(ctx context.Context, iss, kid string) (tokens.JWK, error) {
	var body struct {
		Keys []tokens.JWK `json:"keys"`
	}
	if err := getJSON(ctx, strings.TrimRight(iss, "/")+"/jwks.json", &body); err != nil {
		return tokens.JWK{}, err
	}
	if len(body.Keys) == 0 {
		return tokens.JWK{}, fmt.Errorf("jwks: no keys at %s", iss)
	}
	return body.Keys[0], nil
}

// attestResolver fetches PSAs and AgentGrants by-reference and checks the
// content hash the token committed to (tamper-evident resolution).
type attestResolver struct{}

func (attestResolver) PSA(ctx context.Context, ref string) (*attest.PersonServerAuthorization, error) {
	url, want := splitRef(ref) // ref = "<url>#s256=<hash>"
	var psa attest.PersonServerAuthorization
	if err := getJSON(ctx, url, &psa); err != nil {
		return nil, err
	}
	if want != "" {
		got, err := attest.ContentHash(&psa)
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, fmt.Errorf("psa content hash mismatch: token pinned %s, served %s", want, got)
		}
	}
	return &psa, nil
}

func (attestResolver) AgentGrant(ctx context.Context, iss, agS256 string) (*attest.AgentGrant, error) {
	var g attest.AgentGrant
	if err := getJSON(ctx, strings.TrimRight(iss, "/")+"/grants/"+agS256, &g); err != nil {
		return nil, err
	}
	got, err := attest.ContentHash(&g)
	if err != nil {
		return nil, err
	}
	if got != agS256 {
		return nil, fmt.Errorf("agentgrant content hash mismatch: token pinned %s, served %s", agS256, got)
	}
	return &g, nil
}

// alwaysLive: dev revocation registry. Real demos of exit-rights (Demo C) wire
// this to share the PS's revocation view; here every grant reads as live.
type alwaysLive struct{}

func (alwaysLive) IsRevoked(context.Context, int64, string, string, uint64) (bool, error) {
	return false, nil
}

// replayCache: in-memory jti set.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

func newReplayCache() *replayCache { return &replayCache{seen: map[string]int64{}} }

func (c *replayCache) SeenJTI(jti string, exp int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[jti]; ok {
		return true
	}
	c.seen[jti] = exp
	return false
}

// --- io helpers -----------------------------------------------------------

func splitRef(ref string) (url, s256 string) {
	url = ref
	if i := strings.IndexByte(ref, '#'); i >= 0 {
		url = ref[:i]
		frag := ref[i+1:]
		if kv := strings.SplitN(frag, "=", 2); len(kv) == 2 && kv[0] == "s256" {
			s256 = kv[1]
		}
	}
	return url, s256
}

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func bearer(h string) string {
	for _, scheme := range []string{"AAuth ", "Bearer "} {
		if strings.HasPrefix(h, scheme) {
			return strings.TrimSpace(h[len(scheme):])
		}
	}
	return ""
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
