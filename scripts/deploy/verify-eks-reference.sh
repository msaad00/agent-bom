#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="agent-bom"
REGION="${AWS_REGION:-us-east-1}"
NAMESPACE="agent-bom"
RELEASE_NAME="agent-bom"
BASE_URL=""
API_KEY="${AGENT_BOM_API_KEY:-}"
CHECK_GATEWAY=0

usage() {
  cat <<'EOF'
Post-deploy verification for the AWS / EKS reference install path.

Usage:
  scripts/deploy/verify-eks-reference.sh [options]

Options:
  --cluster-name NAME   EKS cluster name (default: agent-bom)
  --region REGION       AWS region (default: AWS_REGION or us-east-1)
  --namespace NAME      Kubernetes namespace (default: agent-bom)
  --release NAME        Helm release name (default: agent-bom)
  --base-url URL        Reachable control-plane base URL (required)
  --api-key VALUE       Operator API key for /v1/auth/debug verification
  --check-gateway       Also verify the gateway Deployment rollout and /healthz
  -h, --help            Show this help

Examples:
  scripts/deploy/verify-eks-reference.sh \
    --cluster-name corp-ai \
    --region us-east-1 \
    --base-url https://agent-bom.internal.example.com \
    --api-key "$AGENT_BOM_API_KEY"
EOF
}

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cluster-name) CLUSTER_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --release) RELEASE_NAME="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --check-gateway) CHECK_GATEWAY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

[ -n "${BASE_URL}" ] || fail "--base-url is required"

need_cmd aws
need_cmd kubectl
need_cmd helm
need_cmd curl

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

hdrs=()
if [ -n "${API_KEY}" ]; then
  hdrs=(-H "Authorization: Bearer ${API_KEY}" -H "X-Agent-Bom-Role: admin" -H "X-Agent-Bom-Tenant-ID: reference-verify")
fi

bold "1/7 Kubeconfig"
aws eks update-kubeconfig --name "${CLUSTER_NAME}" --region "${REGION}" >/dev/null
ok "kubeconfig updated for ${CLUSTER_NAME}"

bold "2/7 Helm release"
helm status "${RELEASE_NAME}" --namespace "${NAMESPACE}" >/dev/null || fail "helm release ${RELEASE_NAME} not found in namespace ${NAMESPACE}"
ok "helm release present"

bold "3/7 Control-plane rollouts"
kubectl rollout status deployment/"${RELEASE_NAME}"-api --namespace "${NAMESPACE}" --timeout=180s >/dev/null \
  || fail "API deployment did not become ready"
kubectl rollout status deployment/"${RELEASE_NAME}"-ui --namespace "${NAMESPACE}" --timeout=180s >/dev/null \
  || fail "UI deployment did not become ready"
ok "API and UI deployments are ready"

if [ "${CHECK_GATEWAY}" -eq 1 ]; then
  bold "4/7 Gateway rollout"
  kubectl rollout status deployment/"${RELEASE_NAME}"-gateway --namespace "${NAMESPACE}" --timeout=180s >/dev/null \
    || fail "gateway deployment did not become ready"
  kubectl get svc "${RELEASE_NAME}"-gateway --namespace "${NAMESPACE}" >/dev/null \
    || fail "gateway service missing"
  ok "gateway deployment and service are ready"
else
  bold "4/7 Gateway rollout"
  ok "skipped (pass --check-gateway to verify the shared gateway path)"
fi

bold "5/7 Control-plane health"
status=$(curl -sS -o "$tmp/health.json" -w "%{http_code}" "${BASE_URL}/healthz") || fail "control plane unreachable at ${BASE_URL}"
[ "$status" = "200" ] || fail "healthz returned ${status}"
ok "control plane /healthz returned 200"

bold "6/7 Browser UI"
status=$(curl -sS -o "$tmp/ui.html" -w "%{http_code}" "${BASE_URL}/") || fail "UI root unreachable at ${BASE_URL}/"
[ "$status" = "200" ] || fail "UI root returned ${status}"
ok "UI root returned 200"

bold "7/7 Auth resolution"
if [ -n "${API_KEY}" ]; then
  status=$(curl -sS -o "$tmp/auth.json" -w "%{http_code}" "${hdrs[@]}" "${BASE_URL}/v1/auth/debug") || fail "auth debug unreachable"
  [ "$status" = "200" ] || fail "auth debug returned ${status}"
  ok "auth resolved ($(python3 - <<'PY' "$tmp/auth.json"
import json
import sys
payload = json.load(open(sys.argv[1]))
print(payload.get("method", "unknown"))
PY
))"
else
  ok "skipped (pass --api-key to verify /v1/auth/debug resolution)"
fi

bold "reference verification passed"
echo "  cluster: ${CLUSTER_NAME}"
echo "  namespace: ${NAMESPACE}"
echo "  release: ${RELEASE_NAME}"
echo "  base: ${BASE_URL}"
