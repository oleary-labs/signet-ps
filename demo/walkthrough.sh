#!/usr/bin/env bash
# End-to-end happy-path smoke of Phase 0: onboard a tenant, enroll an agent,
# mint an auth token through the async consent flow, present it to resd.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; cd "$WORK"
PS=http://localhost:8090
RES=http://localhost:8095
say(){ printf '\n\033[1m# %s\033[0m\n' "$*"; }

# --- boot -----------------------------------------------------------------
BIN="$WORK/bin"; mkdir -p "$BIN"
( cd "$REPO" && go build -tags dev -o "$BIN/psd" ./cmd/psd \
             && go build          -o "$BIN/resd" ./cmd/resd \
             && go build          -o "$BIN/devtool" ./cmd/devtool )
"$BIN/psd" >psd.log 2>&1 &
PSD=$!
"$BIN/resd" --port 8095 --require-key-rooted=true >resd.log 2>&1 &
RESD=$!
trap 'kill $PSD $RESD 2>/dev/null || true' EXIT
DEVTOOL(){ "$BIN/devtool" "$@"; }

# wait for psd
for i in $(seq 1 40); do curl -sf "$PS/.well-known/aauth-issuer.json" >/dev/null 2>&1 && break; sleep 0.5; done
for i in $(seq 1 40); do curl -sf "$RES/" >/dev/null 2>&1 && break; sleep 0.5; done

say "1. issuer key thumbprint"
X=$(curl -s "$PS/jwks.json" | jq -r '.keys[0].x')
THUMB=$(printf '{"crv":"Ed25519","kty":"OKP","x":"%s"}' "$X" \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "issuer thumb: $THUMB"

say "2. become a tenant (gen root, sign PSA, POST /psa)"
DEVTOOL gen-root >/dev/null
ROOT=$(jq -r .address testroot.json)
NOW=$(date +%s)
jq -n --arg iss "$PS" --arg thumb "$THUMB" --arg root "$ROOT" \
   --argjson nbf "$((NOW-60))" --argjson naf "$((NOW+3600))" '{
  root:$root, issuer:$iss, keyThumbprints:[$thumb],
  scope:{maxTokenTTLSeconds:3600, allowedClaims:[], paymentCapWei:"0", stepUpAboveWei:"0"},
  notBefore:$nbf, notAfter:$naf, registryChain:8453,
  registry:"0x0000000000000000000000000000000000000000", nonce:0
}' > psa.json
DEVTOOL sign-psa --root testroot.json --psa psa.json >/dev/null
curl -s -XPOST "$PS/psa" -d @psa.json | jq .

say "3. enroll an agent under a root-signed grant"
DEVTOOL gen-agent --id aauth:demo@olearylabs.com >/dev/null
ATHUMB=$(jq -r .thumbprint agent.json)
MISSION=$(printf 'demo-mission' | openssl dgst -sha256 -hex | awk '{print $2}')
jq -n --arg root "$ROOT" --arg m "$MISSION" \
   --argjson nbf "$((NOW-60))" --argjson naf "$((NOW+3600))" '{
  root:$root, missionScopeS256:$m,
  notBefore:$nbf, notAfter:$naf, registryChain:8453,
  registry:"0x0000000000000000000000000000000000000000", nonce:0
}' > grant.json
DEVTOOL sign-grant --root testroot.json --grant grant.json --agent agent.json >/dev/null
curl -s -XPOST "$PS/agents" \
  -H "X-Dev-Agent: aauth:demo@olearylabs.com" -H "X-Dev-Agent-Thumb: $ATHUMB" \
  -d @grant.json | jq .

say "4. agent hits the resource cold -> resource_token"
RT=$(curl -s "$RES/" | jq -r .resource_token)
echo "resource_token: ${RT:0:32}..."

say "5. agent asks the PS -> async consent (202)"
RESP=$(curl -si -XPOST "$PS/token" \
  -H "X-Dev-Agent: aauth:demo@olearylabs.com" -H "X-Dev-Agent-Thumb: $ATHUMB" \
  -d "{\"resource_token\":\"$RT\"}")
echo "$RESP" | grep -iE '^HTTP|^location' || true
ID=$(echo "$RESP" | grep -i '^location:' | sed 's#.*/pending/##' | tr -d '\r')
CODE=$(echo "$RESP" | tail -1 | jq -r .interaction.code)
echo "pending id=$ID code=$CODE"

say "6. approve (routine click) then poll -> auth_token"
curl -s "$PS/approve/$CODE" | jq .
TOKEN=$(curl -s "$PS/pending/$ID" \
  -H "X-Dev-Agent: aauth:demo@olearylabs.com" -H "X-Dev-Agent-Thumb: $ATHUMB" \
  | jq -r .auth_token)
echo "auth_token: ${TOKEN:0:40}..."

say "   decoded token payload (the chain is visible in the artifact):"
echo "$TOKEN" | jq -R 'split(".")|.[1]|@base64d|fromjson | {sub,agent,aud,psa,ag_s256,cnf}'

say "7. present to resd (require-key-rooted=true) -> chain verified"
curl -s "$RES/whoami" \
  -H "Authorization: AAuth $TOKEN" -H "X-Dev-Agent-Thumb: $ATHUMB" | jq .

echo; echo "psd.log tail:"; tail -3 psd.log || true
