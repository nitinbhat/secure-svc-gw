#!/usr/bin/env bash
# Render Kubernetes Secrets for the secure-svc-gw and secure-svc-backends charts.
#
# Outputs to stdout (pipe to kubectl apply -f -):
#
#   gateway-certs          -> $GW_NS  (ca.crt + gateway.crt + gateway.key)
#   backend-llm-tls        -> $BE_NS  (ca.crt + llm.crt + llm.key)
#   backend-embed-tls      -> $BE_NS  (ca.crt + embed.crt + embed.key)
#   backend-rogue-tls      -> $BE_NS  (rogue-ca.crt + rogue-llm.crt + rogue-llm.key)
#
# Also writes clients/values-clients.yaml (pass to the gateway chart via -f).
#
# Usage:
#   bash scripts/render-helm-secrets.sh <gw_ns> <be_ns>  | kubectl apply -f -
set -euo pipefail
GW_NS="${1:-secure-svc-gw}"
BE_NS="${2:-$GW_NS}"

if [[ ! -d certs || ! -d clients ]]; then
  echo "certs/ or clients/ not found. Run 'make certs' first." >&2
  exit 1
fi

_b64() { base64 < "$1" | tr -d '\n'; }

_secret() {
  local ns="$1" name="$2"; shift 2
  printf -- "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\ndata:\n" \
    "$name" "$ns"
  for pair in "$@"; do
    local src="${pair%%:*}" key="${pair##*:}"
    printf "  %s: %s\n" "$key" "$(_b64 "$src")"
  done
}

# ---- gateway certs (gateway namespace) ----
_secret "$GW_NS" gateway-certs \
  "certs/ca.crt:ca.crt" \
  "certs/gateway.crt:gateway.crt" \
  "certs/gateway.key:gateway.key"

# ---- backend TLS (backends namespace, signed by secure-svc-gw CA) ----
_secret "$BE_NS" backend-llm-tls \
  "certs/ca.crt:ca.crt" \
  "certs/llm.crt:tls.crt" \
  "certs/llm.key:tls.key"

_secret "$BE_NS" backend-embed-tls \
  "certs/ca.crt:ca.crt" \
  "certs/embed.crt:tls.crt" \
  "certs/embed.key:tls.key"

# ---- rogue backend TLS (backends namespace, signed by rogue-ca) ----
_secret "$BE_NS" backend-rogue-tls \
  "certs/rogue-ca.crt:ca.crt" \
  "certs/rogue-llm.crt:tls.crt" \
  "certs/rogue-llm.key:tls.key"

# ---- clients/values-clients.yaml (used by gateway chart -f flag) ----
{
  echo "clientKeys:"
  for kf in clients/*.json; do
    python3 - "$kf" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  - kid: {d['kid']!r}")
print(f"    sub: {d['sub']!r}")
print(f"    pubBase64: {d['pub']!r}")
print(f"    scopes: {d.get('scopes', [])!r}")
PY
  done
} > clients/values-clients.yaml
echo "# wrote clients/values-clients.yaml" >&2
