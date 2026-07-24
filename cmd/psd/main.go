// psd: the person server daemon — multi-tenant edition.
//
// The bootstrap ceremony changes shape from the single-tenant version in a
// telling way: the SERVER now boots with zero tenants and full function,
// and each PERSON's ceremony happens at onboarding time, not boot time.
//
//	Server boot:   generate/load issuer keys -> serve. That's it.
//	Tenant onboard (per person, any time):
//	  1. Fetch /.well-known metadata -> issuer key thumbprints.
//	  2. Root reviews + signs PSA over those thumbprints.  (HUMAN, wallet/passkey)
//	  3. POST /psa -> tenancy exists.
//	  4. Per agent: root signs AgentGrant; agent enrolls.  (HUMAN)
//
// The single-tenant profile from the previous revision still exists — it is
// simply a deployment with one tenant, per the AAuth composition patterns.
//
// Open rotation caveat (documented in DESIGN.md §multi-tenancy): with leaf
// pinning, rotating an issuer key invalidates coverage for every tenant
// whose PSA doesn't include the new thumbprint. v0 mitigations: (a) publish
// next-period keys in metadata early so new PSAs cover both; (b) long-lived
// issuer keys in an HSM. v1 fix: PSAs pin a per-PS key authority that
// certifies short-lived leaf keys (one extra cert check for verifiers).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"

	"signet.dev/ps/internal/server"
	"signet.dev/ps/internal/store"
	"signet.dev/ps/internal/tokens"
)

func main() {
	issuerURL := envOr("PS_ISSUER_URL", "http://localhost:8090")

	// Issuer keys. v0: fresh per boot (dev); wired build loads from KMS.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	key := tokens.IssuerKey{
		Kid:  "ps-" + time.Now().Format("2006-01"),
		Priv: priv,
		Pub:  tokens.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)},
	}

	registry := store.NewMemoryRegistry() // wired: store.BaseRegistry{RPC: ...}

	srv := server.New(server.Config{
		IssuerURL: issuerURL, IssuerKeys: []tokens.IssuerKey{key},
		Registry: registry,
		ChainID:  8453, RegistryAddr: envOr("PS_REGISTRY_ADDR", "0x0000000000000000000000000000000000000000"),
	}, newHTTPSigVerifier(), newRootAuth())

	mux := http.NewServeMux()
	srv.Routes(mux)
	installDevRoutes(mux, registry) // no-op unless built with -tags dev
	log.Printf("signet-ps (multi-tenant) serving %s — issuer key %s — tenants onboard at POST /psa",
		issuerURL, key.Pub.Thumbprint())
	log.Fatal(http.ListenAndServe(":8090", mux))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
