// Package store: revocation registry implementations. The interface lives in
// attest (verification-side); implementations live here because they are
// deployment choices.
package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryRegistry: dev/test. Revocation is a (root, nonce) set.
type MemoryRegistry struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func NewMemoryRegistry() *MemoryRegistry { return &MemoryRegistry{revoked: map[string]bool{}} }

func (m *MemoryRegistry) Revoke(root string, nonce uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[key(root, nonce)] = true
}

func (m *MemoryRegistry) IsRevoked(_ context.Context, _ int64, _ string, root string, nonce uint64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revoked[key(root, nonce)], nil
}

func key(root string, nonce uint64) string { return fmt.Sprintf("%s#%d", root, nonce) }

// BaseRegistry: the I4 implementation. Sketch of the on-chain shape:
//
//	contract GrantRegistry {
//	  // root => nonce => revokedAt (0 = live). Only `root` (msg.sender or
//	  // ERC-1271-validated meta-tx) may revoke its own nonces. No admin.
//	  mapping(address => mapping(uint256 => uint64)) public revokedAt;
//	  function revoke(uint256 nonce) external;                  // by root
//	  function revokeFor(address root, uint256 nonce,           // gasless path:
//	    bytes calldata rootSig) external;                       // anyone relays a root-signed revocation
//	}
//
// Properties that matter:
//   - The PS cannot un-revoke, rate-limit, or censor a revocation: the
//     `revokeFor` path means any relayer (including a rival PS the user is
//     migrating to) can land it. Exit is permissionless (I2).
//   - Verifiers read a public mapping; disputes cite a block number.
//   - EAS on Base is the low-lift alternative (revocable attestations with
//     the same semantics) if we'd rather not deploy a contract in v0.
type BaseRegistry struct {
	RPC      string // Base RPC endpoint
	CacheTTL time.Duration
	// cache: (root,nonce) -> (revoked, fetchedAt); MUST fail closed when
	// stale beyond TTL and RPC unreachable — availability never overrides
	// revocation (a deliberate liveness/safety trade, chosen for safety).
}

func (b *BaseRegistry) IsRevoked(ctx context.Context, chainID int64, registry, root string, nonce uint64) (bool, error) {
	return false, fmt.Errorf("TODO(v0): eth_call revokedAt(root,nonce) via %s, cache %s, fail closed", b.RPC, b.CacheTTL)
}
