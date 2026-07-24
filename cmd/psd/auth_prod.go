//go:build !dev

package main

import (
	"net/http"

	"signet.dev/ps/internal/server"
	"signet.dev/ps/internal/store"
)

// Production build: the real auth profile is not implemented yet, so a
// non-dev binary refuses to start rather than pretending to authenticate.
// TODO(v0): RFC 9421 request-signature verifier + SIWE-style root challenge.

func newHTTPSigVerifier() server.SigVerifier {
	panic("TODO(v0): wire RFC 9421 SigVerifier (build with -tags dev for the demo double)")
}
func newRootAuth() server.RootAuth {
	panic("TODO(v0): wire SIWE RootAuth (build with -tags dev for the demo double)")
}

// installDevRoutes is a no-op outside the dev build.
func installDevRoutes(_ *http.ServeMux, _ *store.MemoryRegistry) {}
