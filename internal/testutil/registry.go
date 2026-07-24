package testutil

import (
	"context"
	"fmt"
)

// FakeRegistry implements attest.RevocationRegistry with three behaviours the
// suite needs: live, revoked, and *unavailable*.
//
// The third one matters as much as the other two. A registry that errors must
// make verification FAIL, never quietly read as "not revoked" — availability
// must not override revocation. That is a tested behaviour, not a comment,
// which is why the error mode is a first-class fixture.
type FakeRegistry struct {
	revoked map[string]bool
	err     error

	// Calls counts IsRevoked invocations, so tests can assert the registry is
	// actually consulted rather than short-circuited by an earlier check.
	Calls int
}

// LiveRegistry: nothing is revoked.
func LiveRegistry() *FakeRegistry { return &FakeRegistry{revoked: map[string]bool{}} }

// RevokedRegistry: exactly (root, nonce) is revoked, nothing else. Per-pair
// granularity is deliberate — revoking a PSA must not revoke that root's
// AgentGrants, which live under different nonces.
func RevokedRegistry(root string, nonce uint64) *FakeRegistry {
	return &FakeRegistry{revoked: map[string]bool{key(root, nonce): true}}
}

// ErrRegistry: the registry cannot be reached.
func ErrRegistry(err error) *FakeRegistry { return &FakeRegistry{err: err} }

func (f *FakeRegistry) IsRevoked(_ context.Context, _ int64, _ string, root string, nonce uint64) (bool, error) {
	f.Calls++
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[key(root, nonce)], nil
}

// Revoke flips a (root, nonce) pair at runtime, for tests that need a live
// grant to die mid-scenario.
func (f *FakeRegistry) Revoke(root string, nonce uint64) {
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[key(root, nonce)] = true
}

func key(root string, nonce uint64) string { return fmt.Sprintf("%s#%d", root, nonce) }
