# signet-ps — a non-custodial AAuth Person Server

A Person Server (PS) that **operates** a person's identity without **custodying** it.
Wire-compatible with AAuth (draft-hardt-oauth-aauth-protocol); the non-custodial
properties are carried in an extension claim set that standard verifiers ignore
and enhanced verifiers enforce.

## The one-line inversion

> In AAuth as drafted, the person server asserts who it represents.
> In signet-ps, the person proves who represents them.

## Roles and keys

```
Root key        secp256k1 (EOA) or ERC-1271 smart account (passkey-controlled).
                THE person. Never held by the PS. Signs attestations + step-ups.

PS issuer keys  Ed25519. Held by the PS. Sign auth tokens. Meaningless unless
                covered by a live PersonServerAuthorization from a root.

Agent keys      Ed25519, one per agent instance. Held by the agent. Bound into
                auth tokens via `cnf` (proof-of-possession, RFC 9421 sigs).
```

## The two attestations (EIP-712, root-signed)

1. **PersonServerAuthorization (PSA)** — root → PS.
   "Issuer keys {thumbprints} at {iss} may mint auth tokens with sub={root},
   under {scope}, between {nbf,exp}, revocable at {registry,nonce}."

2. **AgentGrant (AG)** — root → agent (witnessed/stored by PS).
   "Agent {identifier, key thumbprint} may act for {root} under {missionScope},
   between {nbf,exp}, revocable at {registry,nonce}."

An auth token minted by this PS therefore evidences a chain in which **every
edge is a signature and no edge is a database row**:

```
root ──PSA──▶ PS issuer key ──JWT sig──▶ auth_token ──cnf──▶ agent key ──RFC9421──▶ request
  └───────────────AG────────────────────────────────────────────▲
```

## Non-custodial invariants (what the code must make true)

I1  No fabrication: the PS cannot mint a valid-under-enhanced-verification token
    for a person who has not issued it a live PSA.
I2  Exit rights: revoking the PSA (registry nonce bump) kills the PS's authority
    without touching the root identity, its AgentGrants pattern, or its history.
I3  Step-up: actions above PSA scope thresholds require a fresh root signature
    over the specific approval digest; the PS can *relay* but not *replace* it.
I4  Neutral revocation: liveness of PSA/AG is read from a registry the PS does
    not control (on-chain; EAS-style on Base in v0). The PS checks it; so can
    any verifier and any dispute process.
I5  Portability: the person can export the association set + mission log, and
    the export is verifiable without trusting the exporter (everything that
    matters is signed or hash-chained).

## Endpoints

```
GET  /.well-known/aauth-issuer.json    metadata (+ signet_psa extension block)
GET  /jwks.json                        PS issuer keys
POST /token                            resource_token in, auth_token or 202 out   [RFC9421-signed]
GET  /pending/{id}                     poll; 202 ... 200 {auth_token}             [RFC9421-signed]
GET  /approve/{code}                   human approval surface (click or step-up)
POST /approve/{code}/signature         step-up: EIP-712 ApprovalDigest signature
POST /agents                           enroll agent: store AgentGrant             [RFC9421-signed]
GET  /agents / DELETE /agents/{id}     governance (delete = advise; truth is registry)
GET  /psa/current                      serve the live PSA (by-reference resolution)
GET  /export                           I5: signed portability bundle
```

## Token shape (auth+jwt, extension claims marked ★)

```jsonc
{
  "typ": "auth+jwt", "alg": "EdDSA", "kid": "ps-2026-07a",
  //--- payload ---
  "iss": "https://ps.signet.io",
  "dwk": "aauth-issuer.json",
  "aud": "https://api.merchant.example/orders",
  "jti": "9f8c…", "iat": 1752570000, "exp": 1752573600,      // ≤ 1h
  "agent": "aauth:trip-planner@agents.olearylabs.com",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…" } },
  "sub": "eip155:8453:0xRoot…",                              // ★ CAIP-10: subject IS the root
  "psa": "https://ps.signet.io/psa/current#s256=…",          // ★ by-ref + content hash
  "ag_s256": "…",                                            // ★ AgentGrant content hash
  "mission": { "approver": "https://ps.signet.io", "s256": "…" },
  "step_up": { "digest": "…", "sig": "0x…" }                 // ★ present iff elevated tier
}
```

`sub` as the CAIP-10 root address is the v0 simplicity choice; it is globally
correlatable. A `pairwise` mode (per-resource sub derived from root, with the
PSA binding disclosed only on demand) is a v1 privacy option — flagged, not built.

## Verification (enhanced verifier)

Layer 1 (standard AAuth): JWT sig against issuer JWKS · typ · aud · exp ·
jti replay · request RFC 9421 signature matches `cnf` key.
Layer 2 (★ non-custodial): resolve PSA → EIP-712 recover/1271-verify → signer
== `sub` root · signing `kid` thumbprint ∈ PSA keys · window · scope covers
this mint · registry says not revoked · same for AgentGrant · if amount/action
exceeds PSA step-up threshold, `step_up` present and verifies against root.

## Mapping to existing Signet

```
Signet parent key        → Root
create_payment_key       → AgentGrant issuance (+ key custody at agent)
mint_delegation          → POST /token (mint auth+jwt with cnf binding, ≤1h)
disable_key/enable_key   → registry nonce bump (AG revocation)
x402 / settlement flow   → the resource-side verifier for payment resources;
                           the mission log's payment subset gets settlement-anchored
```

## v0 scope cuts (deliberate)

- Registry = interface + in-memory impl; Base/EAS adapter is a stub with the
  contract interaction sketched in comments.
- RFC 9421: minimal profile (ed25519, covered components per AAuth profile),
  not a general implementation.
- Missions: blob store + hash refs + append-only log; the intent-consistency
  evaluator is an interface with a trivial (threshold/allowlist) impl.
- Rotation/recovery: types reserved (SuccessorStatement), logic not built.

## Multi-tenancy (revision 2)

One PS instance hosts many tenants. A tenant is nothing but a root with a
live PSA — there is no account object, and the server boots with zero
tenants and full function.

**Resolution rule.** Tenancy is derived from the grant chain, never a
session: request signature → agent key → AgentGrant → root → PSA. Governance
calls (/export) authenticate the person directly via a root-signed challenge
(SIWE-profile), because non-custodial tenants have no password to check —
or phish.

**Isolation property.** Everything tenant-scoped is root-signed (PSA, AGs)
or hash-chained per tenant (mission logs). Onboarding, revocation, and exit
of one tenant are invisible to all others; export bundles are verifiable
without trusting the exporter.

**The shared-key rotation trap (open, documented).** Tenants' PSAs pin
issuer-key thumbprints. With shared leaf keys, rotation would strand every
PSA that doesn't cover the new key. v0 lives with it: long-lived HSM-held
issuer keys + publishing next-period keys early so new/renewing PSAs cover
both. v1 fix: PSAs pin a per-PS *key authority* thumbprint; the authority
signs short-lived leaf-key certificates served alongside the JWKS; verifiers
add one certificate check. (This is deliberately NOT per-tenant issuer keys:
those make rotation lazy but explode the JWKS and leak the tenant set.)

**Note the economics this encodes.** The PS competes on operations —
uptime, UX, attestation partnerships, consent ergonomics — while the trust
relationships remain the tenants' property. Which is the business model
claim made structural: switching costs are operational, not existential.
