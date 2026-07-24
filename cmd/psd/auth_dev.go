//go:build dev

package main

import (
	"net/http"
	"strconv"

	"signet.dev/ps/internal/server"
	"signet.dev/ps/internal/store"
)

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// Dev build: header-trusting auth doubles + a dev-only revocation endpoint, so
// the single-machine walkthrough runs without the RFC 9421 / SIWE wire profile.

func newHTTPSigVerifier() server.SigVerifier { return server.DevSigVerifier{} }
func newRootAuth() server.RootAuth           { return server.DevRootAuth{} }

// installDevRoutes exposes the in-memory registry's revocation so `devtool
// revoke` can bump a (root, nonce) over HTTP — the dev stand-in for an
// on-chain registry write (I2/I4). Only present under -tags dev.
func installDevRoutes(mux *http.ServeMux, reg *store.MemoryRegistry) {
	mux.HandleFunc("POST /dev/revoke", func(w http.ResponseWriter, r *http.Request) {
		root := r.URL.Query().Get("root")
		nonce := parseUint(r.URL.Query().Get("nonce"))
		if root == "" {
			http.Error(w, `{"error":"missing root"}`, http.StatusBadRequest)
			return
		}
		reg.Revoke(root, nonce)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"revoked"}`))
	})
}
