# signet-ps — Testing & Demo Cookbook

Ordered from "compiles" to "convinces a room." Each phase states what it
proves and what it deliberately doesn't. Times are honest estimates for one
person who knows the codebase.

---

## Phase 0 — Make it real enough to run (½–1 day)

The skeleton's crypto-bearing paths are complete; the mechanical stubs are
not. Fill, in this order:

1. **Elided helpers** in `tokens`, `consent`, `server` (b64/split3/hex/newID/
   keccakStrings/tierFor/etc.) — pure mechanics.
2. **`consent.Store.ByCode`** (referenced by `approveElevated`) and persist
   `ResourceClaims` on the `Request` instead of `resourceFromRequest()`
   reconstruction.
3. **Dev doubles for the two auth interfaces** so demos don't block on
   RFC 9421:
   - `DevSigVerifier`: trusts `X-Dev-Agent: <agentID>` +
     `X-Dev-Agent-Thumb: <thumbprint>` headers. Build tag `//go:build dev`.
   - `DevRootAuth`: trusts `X-Dev-Root: 0x…`.
   These are *scaffolding*, clearly quarantined; Phase 4 replaces them.
4. **`cmd/devtool`** — the wallet-stand-in. Subcommands:
   ```
   devtool gen-root                     # secp256k1 key -> testroot.json (addr + priv)
   devtool gen-agent --id aauth:x@y     # ed25519 -> agent.json (jwk + thumbprint)
   devtool sign-psa   --root testroot.json --psa psa.json     # fills .signature
   devtool sign-grant --root testroot.json --grant grant.json
   devtool sign-approval --root testroot.json --request req.json  # step-up
   devtool revoke     --root testroot.json --nonce N          # hits dev registry endpoint
   ```
   ~150 lines over `attest.PSADigest` / `AgentGrantDigest` /
   `consent.ApprovalDigest` + `ethcrypto.Sign`. This tool is also your
   future `psd init` in embryo.
5. **`cmd/resd`** — a whoami-style demo resource (~100 lines): issues
   `aa-resource+jwt` on unauthenticated hit; on authenticated hit runs
   `tokens.Verifier.Verify` and returns the claims it saw. Flag
   `--require-key-rooted` toggles whether Layer 2 is demanded. This flag is
   the whole demo story — see Demo B.

Definition of done: `go build ./... && go vet ./...` clean; `psd` boots and
serves metadata.

---

## Phase 1 — Unit tests that pin the invariants (1 day)

Write these as table-driven tests; they are the spec of record until the
extension doc exists.

**`attest` — the chain math.**
- Golden digest: fixed PSA -> fixed EIP-712 digest (catches accidental
  type/domain drift, which would strand every signed PSA in the wild).
- Round-trip: gen-root -> sign digest -> `VerifyPSA` passes.
- Tamper matrix, each expecting a distinct error: wrong issuer · expired ·
  not-yet-valid · signing-key thumbprint not in set · flipped byte in sig ·
  revoked (root,nonce) · **registry returns error -> verification FAILS**
  (fail-closed is a tested behavior, not a comment).
- Same matrix for `VerifyAgentGrant` (+ root mismatch, agent-key mismatch).

**`tokens` — the envelope (I1/I3 live here).**
- `Mint` refusal table: issuer key not covered · TTL request 4h -> clamped
  to PSA max -> clamped to 1h · vouch claim outside `AllowedClaims` ·
  amount > cap · amount > step-up threshold with nil StepUp.
- `Verify` with fake resolvers: happy path · aud mismatch · jti replay ·
  cnf/request-thumb mismatch ("stolen token" case) · `sub` ≠ PSA root
  (**the fabrication check**) · vanilla token (no `psa` claim) passes
  Layer 1 and returns — caller policy decides.

**`consent` — the tiers.**
- `ApproveRoutine` on an elevated request -> error (click ≠ signature,
  structurally).
- Approval digest binds: change amount/resource/requestId -> different
  digest -> stale signature rejected.
- Window expiry transitions and terminal-state immutability.

**`store` — tenancy discipline.**
- `Enroll` rebind to different root -> refused.
- Re-`Onboard` same root -> PSA replaced, grants + log survive (portability
  in the data model).
- Registry: revoke -> `IsRevoked` true; memory impl is per-(root,nonce).

Target: this suite is the CI gate; nothing merges that changes an invariant
without changing its test.

---

## Phase 2 — The single-machine walkthrough (½ day to script)

One terminal transcript, start to finish. Script it as `demo/walkthrough.sh`
so it never rots.

```bash
# 0. Boot (dev build tags on)
go run -tags dev ./cmd/psd &                      # :8090
go run -tags dev ./cmd/resd --port 8095 &          # demo resource

# 1. Who is this PS?
curl -s :8090/.well-known/aauth-issuer.json | jq
#    -> note signet_non_custodial block + issuer key; save thumbprint

# 2. Become a tenant with nothing but a signature
devtool gen-root                                   # -> testroot.json (0xROOT)
jq -n --arg thumb "$THUMB" '…' > psa.json          # template in demo/psa.tmpl.json
devtool sign-psa --root testroot.json --psa psa.json
curl -s -XPOST :8090/psa -d @psa.json | jq
#    -> 201 {"root":"0xROOT","psa_url":".../psa/0xROOT"}
#    THE LINE TO SAY OUT LOUD: no email, no password. The PSA is the account.

# 3. Enroll an agent under a root-signed grant
devtool gen-agent --id aauth:demo@olearylabs.com
devtool sign-grant --root testroot.json --grant grant.json
curl -s -XPOST :8090/agents -H "X-Dev-Agent: aauth:demo@olearylabs.com" \
     -H "X-Dev-Agent-Thumb: $(jq -r .thumbprint agent.json)" -d @grant.json | jq

# 4. Agent hits the resource cold -> gets a resource_token
RT=$(curl -s :8095/ | jq -r .resource_token)

# 5. Agent asks the PS -> async consent
curl -si -XPOST :8090/token -H "X-Dev-Agent: …" -H "X-Dev-Agent-Thumb: …" \
     -d "{\"resource_token\":\"$RT\"}"
#    -> 202, Location: /pending/{id}, approval_url + code + tier

# 6. Approve (routine tier: visit URL / POST the code), then poll
curl -s :8090/pending/$ID -H "X-Dev-Agent: …" …   # 202 … then 200 {"auth_token": …}

# 7. Present to resource with the agent key
curl -s :8095/whoami -H "Authorization: AAuth $TOKEN" -H "X-Dev-Agent-Thumb: …" | jq
#    -> { sub: "eip155:8453:0xROOT", agent: "aauth:demo@…", chain: "verified" }
```

Decode the token at step 6 (`jq -R 'split(".")|.[1]|@base64d|fromjson'`) and
walk the room through `sub`, `cnf`, `psa#s256`, `ag_s256` — the chain is
*visible in the artifact*.

---

## Phase 3 — The five demos that carry the argument (1 day to script all)

Each is a short scripted narrative with a punchline. Order matters.

**Demo A — "The PSA is the account."** Phase 2 steps 1–3, timed. Punchline:
tenant existence in under a minute, zero PII collected, and `GET /export`
(root-authed) returns everything, verifiable offline.

**Demo B — "A rogue PS cannot fabricate." (THE demo.)** Add a dev-only
endpoint `POST /dev/forge {sub}` that makes the PS mint a perfectly signed
auth token for a root that never onboarded — i.e., the PS *acts custodial*.
Then:
```
resd --require-key-rooted=false  ->  forged token ACCEPTED   (vanilla AAuth: Layer 1 passes)
resd --require-key-rooted=true   ->  forged token REJECTED: "sub is not the PSA root"
```
Side by side, same token. Punchline: in stock deployments the PS's word is
the security boundary; with the extension, the person's key is. This single
contrast is the entire pitch compressed to two curl commands.

**Demo C — "Exit rights."** Boot a *second* PS on :8091. Then:
`devtool revoke --nonce <psa-nonce>` -> next mint on :8090 fails
("psa: revoked"); re-sign a fresh PSA over :8091's keys, onboard there,
enroll the same agent under a new grant -> resource shows the *same*
`sub: 0xROOT`. Punchline: the provider changed; the identity — and the
exportable history — didn't. (Gasless `revokeFor` is the on-chain version;
say so.)

**Demo D — "A click cannot move real money."** Craft a resource token with
`amount` above the PSA's `stepUpAboveWei`. Show: click-approval path
refuses (structural, from the consent tests); `devtool sign-approval`
succeeds; then tamper the amount and replay the old signature -> digest
mismatch, rejected. Punchline: high-value approvals are signatures over the
*specific* action, not session state.

**Demo E — "Tenants can't touch each other."** Onboard roots A and B, one
agent each. B's root-signature attempts to approve A's pending elevated
request -> "signer is not root". A's `/export` with B's RootAuth -> 401.
Punchline: isolation falls out of signatures, not row-level security.

Capture every demo run as a JSON evidence bundle (`demo/bundle.sh`): PSA +
AgentGrant + token + request-signature metadata in one file, plus a tiny
`devtool verify-bundle` that re-runs the chain check-by-check and prints
PASS/FAIL per link. That bundle *is* the dispute-evidence story — the same
artifact you'd hand an issuer in a chargeback — and it makes every demo
reproducible by a skeptic without your server.

---

## Phase 4 — Interop reality check (1–2 days, the honest one)

Replace the dev doubles with the real RFC 9421 profile (AAuth headers:
`Signature`, `Signature-Input`, `Signature-Key`), then:

1. **Their resource, their PS**: run the aauth.dev walkthrough (whoami +
   Posta demo stack) untouched, to confirm your mental model of the wire
   format against the reference implementation.
2. **Their agent flow, your PS**: point the walkthrough's agent at signet-ps.
   Expected result, worth documenting precisely: the flow completes, and the
   vanilla side *ignores* `psa`/`ag_s256`/`step_up` — proving the extension
   is a strict superset, which is the interop claim you'll make in any
   standards conversation.
3. **Your agent, their resource**: signet-issued token at whoami — same
   ignore-the-extras expectation.

Any deviation found here is a finding worth posting in #aauth — that's
participation, not failure.

## Phase 5 — What to show whom

- **AAuth community / IETF**: Phase 4 results + Demo B. Frame: "conforming
  PS, extension claims, here's the fabrication problem they close."
- **Payments/risk people**: Demo D + the evidence bundle. Frame: "this is
  the artifact your dispute process wishes existed."
- **Prospective design partners**: Demo A + C. Frame: "onboarding without
  PII; churn without hostage-taking."

Known limits to state up front in any demo: registry is in-memory (Base
contract is sketched, not deployed); consent UI is curl-grade; the mission
judge is a stub; rotation/recovery is designed but unbuilt. None of these
weaken Demos A–E — they're orthogonal, and saying so first is cheaper than
being asked.
