//go:build dev

// Dev doubles for the two auth interfaces. These are SCAFFOLDING: they trust
// headers instead of verifying RFC 9421 request signatures / SIWE challenges,
// so single-machine demos don't block on the wire-signature profile. Phase 4
// replaces them with the real thing. They only compile under `-tags dev`, so
// a production build physically cannot link them.
package server

import (
	"fmt"
	"net/http"
	"strings"
)

// DevSigVerifier trusts the requesting agent's self-asserted identity:
//
//	X-Dev-Agent:       aauth:local@domain    (agent identifier)
//	X-Dev-Agent-Thumb: <rfc7638 thumbprint>  (agent key thumbprint)
//
// In the wired build these come from validating the request's RFC 9421
// signature against the agent's key; here we take the agent's word for it.
type DevSigVerifier struct{}

func (DevSigVerifier) Verify(r *http.Request) (agentKeyThumb, agentID string, err error) {
	agentID = strings.TrimSpace(r.Header.Get("X-Dev-Agent"))
	agentKeyThumb = strings.TrimSpace(r.Header.Get("X-Dev-Agent-Thumb"))
	if agentID == "" || agentKeyThumb == "" {
		return "", "", fmt.Errorf("dev sig verifier: missing X-Dev-Agent / X-Dev-Agent-Thumb")
	}
	return agentKeyThumb, agentID, nil
}

// DevRootAuth trusts a self-asserted root for governance calls:
//
//	X-Dev-Root: 0x…
//
// The wired build verifies a root-signed SIWE challenge instead.
type DevRootAuth struct{}

func (DevRootAuth) VerifyChallenge(r *http.Request) (root string, err error) {
	root = strings.TrimSpace(r.Header.Get("X-Dev-Root"))
	if root == "" {
		return "", fmt.Errorf("dev root auth: missing X-Dev-Root")
	}
	return root, nil
}
