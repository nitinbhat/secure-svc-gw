#!/usr/bin/env bash
# Create a 2-node kind cluster with Calico as the CNI.
#
# We install Calico via the operator + a small Installation CR sized for
# kind (VXLAN, no BGP, small IP pool). This mirrors the pattern used by
# datkube/cluster/{kind.yaml,calico.yaml} but pulls Calico from upstream so
# we don't vendor a 5000-line manifest here.
set -euo pipefail
CLUSTER="${1:-secure-svc-gw}"
CALICO_VERSION="${CALICO_VERSION:-v3.28.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if kind get clusters | grep -qx "$CLUSTER"; then
  echo "kind cluster '$CLUSTER' already exists"
else
  kind create cluster --name "$CLUSTER" --config "$HERE/kind-2node.yaml"
fi

kubectl config use-context "kind-$CLUSTER"

echo "installing Calico operator ($CALICO_VERSION)..."
kubectl create -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml" 2>/dev/null || true

cat <<'EOF' | kubectl apply -f -
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    ipPools:
      - cidr: 10.244.0.0/16
        encapsulation: VXLAN
        natOutgoing: Enabled
        nodeSelector: all()
---
apiVersion: operator.tigera.io/v1
kind: APIServer
metadata:
  name: default
spec: {}
EOF

echo "waiting for Calico to become ready..."
# The operator creates the calico-system namespace asynchronously.
# Poll until it exists, then wait for the deployments to become ready.
for _ in $(seq 1 30); do
  if kubectl get ns calico-system >/dev/null 2>&1; then
    echo "  calico-system namespace found"
    break
  fi
  echo "  waiting for calico-system namespace..."
  sleep 2
done

if kubectl get ns calico-system >/dev/null 2>&1; then
  kubectl -n calico-system wait --for=condition=Available --timeout=300s deployment --all
else
  echo "WARNING: calico-system namespace never appeared — Calico may not be working"
fi

kubectl wait --for=condition=Ready --timeout=180s node --all

# ---- cert-manager (issues the gateway's listener TLS cert) -----------------
CERTMGR_VERSION="${CERTMGR_VERSION:-v1.16.3}"
echo "installing cert-manager ($CERTMGR_VERSION)..."
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERTMGR_VERSION}/cert-manager.yaml"
echo "waiting for cert-manager webhooks to be ready..."
kubectl -n cert-manager wait --for=condition=Available --timeout=120s deployment --all

echo
echo "cluster ready:"
kubectl get nodes -o wide
