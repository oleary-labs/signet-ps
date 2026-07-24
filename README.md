# signet-ps

A non-custodial **AAuth Person Server** (PS) — an identity server that
*operates* a person's identity without *custodying* it.

It is wire-compatible with [AAuth](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
(`draft-hardt-oauth-aauth-protocol`): the non-custodial properties ride in an
extension claim set that standard verifiers ignore and enhanced verifiers
enforce. The extension is a strict superset — a conforming PS, plus a signature
chain rooted in the person's own key.

## The one-line inversion

> In AAuth as drafted, the person server asserts who it represents.
> In signet-ps, the person proves who represents them.

A rogue or compromised PS **cannot fabricate** a token for a person who has not
signed it into authority, and a person can **revoke** that authority — and
export their history — without the PS's cooperation. Every edge in the chain is
a signature, not a database row:

```
root ──PSA──▶ PS issuer key ──JWT sig──▶ auth_token ──cnf──▶ agent key ──req sig──▶ request
  └───────────────AgentGrant──────────────────────────────────▲
```

- **Root key** — secp256k1 EOA or ERC-1271 smart account. *The* person. Never
  held by the PS.
- **PSA** (PersonServerAuthorization) — root → PS: "these issuer keys may mint
  tokens for me, under this scope, revocable here."
- **AgentGrant** — root → agent: "this agent key may act for me under this
  mission scope."

Both attestations are EIP-712 and root-signed; the PS stores and serves them but
can never author them. See [`DESIGN.md`](./DESIGN.md) for the full model.

## Status

**v0 / Phase 0 — a runnable dev skeleton.** The crypto-bearing paths (EIP-712
attestation signing + recovery, the two-layer verifier, the token envelope, the
async consent + step-up flow) are real. The following are deliberately stubbed
for v0 and called out in code:

- **Revocation registry** — in-memory implementation; the Base/EAS on-chain
  adapter is sketched (`internal/store/registry.go`).
- **Request authentication** — dev doubles (header-trusting) stand in for the
  RFC 9421 / SIWE profile. They compile only under `-tags dev`; a production
  build refuses to start rather than fake authentication.
- **Mission judge**, **key rotation / recovery** — interfaces present, logic not
  built.

The phased plan (tests, demos, interop) lives in [`TESTING.md`](./TESTING.md).

## Quickstart

Requires Go 1.23+.

```bash
# Build (dev doubles require the `dev` build tag)
go build -tags dev ./...

# Run the full happy-path walkthrough: onboard a tenant with nothing but a
# signature, enroll an agent under a root-signed grant, mint an auth token
# through async consent, and present it to a resource that demands the
# non-custodial chain.
bash demo/walkthrough.sh
```

The final step prints `"chain": "verified"` — the resource resolved the PSA
by-reference, recovered the root's signature, and closed the chain
`root → PS key → token → agent key → request`.

## Components

| Path | What it is |
|------|------------|
| `cmd/psd`     | The Person Server daemon. Boots with zero tenants; a tenant is a root with a live PSA. |
| `cmd/resd`    | A demo resource. Runs the enhanced verifier; `--require-key-rooted` toggles whether the non-custodial chain is *demanded* (the core demo contrast). |
| `cmd/devtool` | The wallet stand-in — holds the root/agent keys and signs the PSA, AgentGrant, and step-up approvals. |
| `internal/attest`   | EIP-712 attestations (PSA, AgentGrant) + verification. |
| `internal/tokens`   | The `auth+jwt` envelope, minting discipline, and the two-layer verifier. |
| `internal/consent`  | Async authorization: tiers, approval codes, polling, and the step-up digest. |
| `internal/store`    | Multi-tenant state + the revocation registry. |
| `internal/missions` | The append-only, hash-chained mission log (dispute evidence). |
| `internal/server`   | The HTTP surface wiring it together. |

## License

[MIT](./LICENSE) © 2026 O'Leary Labs LLC
