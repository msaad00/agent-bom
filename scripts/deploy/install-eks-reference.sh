#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CLUSTER_NAME="agent-bom"
REGION="${AWS_REGION:-us-east-1}"
NAMESPACE="agent-bom"
RELEASE_NAME="agent-bom"
HOSTNAME=""
INGRESS_CLASS="nginx"
CREATE_CLUSTER=0
ENABLE_GATEWAY=0
ENABLE_FLEET=1
OIDC_ISSUER="${AGENT_BOM_OIDC_ISSUER:-}"
OIDC_AUDIENCE="${AGENT_BOM_OIDC_AUDIENCE:-agent-bom}"
OIDC_TENANT_CLAIM="${AGENT_BOM_OIDC_TENANT_CLAIM:-tenant_id}"
OIDC_ROLE_CLAIM="${AGENT_BOM_OIDC_ROLE_CLAIM:-agent_bom_role}"
NODE_INSTANCE_TYPE="m7i.large"
NODE_COUNT="3"
K8S_VERSION="1.30"
STATE_DIR="${HOME}/.agent-bom/eks-reference"
DRY_RUN=0

usage() {
  cat <<'EOF'
Reference installer for self-hosted agent-bom on AWS / EKS.

This script is intentionally opinionated:
- it can create a reference EKS cluster with eksctl
- it provisions the agent-bom AWS baseline with Terraform/OpenTofu
- it installs the packaged Helm chart with production defaults plus generated overrides
- it prints the next-step commands for fleet onboarding and optional gateway rollout

Usage:
  scripts/deploy/install-eks-reference.sh [options]

Options:
  --cluster-name NAME         EKS cluster name (default: agent-bom)
  --region REGION             AWS region (default: AWS_REGION or us-east-1)
  --namespace NAME            Kubernetes namespace / Helm namespace (default: agent-bom)
  --release NAME              Helm release name (default: agent-bom)
  --hostname HOST             Optional ingress hostname for same-origin UI/API access
  --ingress-class NAME        IngressClass to use when --hostname is set (default: nginx)
  --create-cluster            Create a reference EKS cluster with eksctl before baseline + Helm
  --enable-gateway            Enable the packaged gateway Deployment and generate a bearer token
  --disable-fleet             Skip printing the endpoint onboarding bundle command
  --oidc-issuer URL           Configure AGENT_BOM_OIDC_ISSUER in the control-plane auth secret
  --oidc-audience VALUE       Configure AGENT_BOM_OIDC_AUDIENCE (default: agent-bom when OIDC is enabled)
  --oidc-tenant-claim CLAIM   Configure AGENT_BOM_OIDC_TENANT_CLAIM (default: tenant_id)
  --oidc-role-claim CLAIM     Configure AGENT_BOM_OIDC_ROLE_CLAIM (default: agent_bom_role)
  --node-instance-type TYPE   eksctl managed nodegroup instance type (default: m7i.large)
  --node-count COUNT          eksctl desired/min node count (default: 3)
  --k8s-version VERSION       EKS version for --create-cluster (default: 1.30)
  --state-dir PATH            Local state/output root (default: ~/.agent-bom/eks-reference)
  --dry-run                   Print actions and generated command paths without applying changes
  -h, --help                  Show this help

Examples:
  export AWS_REGION="<your-aws-region>"
  scripts/deploy/install-eks-reference.sh --create-cluster --cluster-name corp-ai --region "$AWS_REGION"

  scripts/deploy/install-eks-reference.sh \
    --cluster-name corp-ai \
    --region "$AWS_REGION" \
    --hostname agent-bom.internal.example.com \
    --enable-gateway
EOF
}

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" >&2; }
die() { printf "\n[error] %s\n" "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

version_ge() {
  python3 - "$1" "$2" <<'PY'
import re
import sys

def normalize(raw: str) -> list[int]:
    parts = [int(piece) for piece in re.findall(r"\d+", raw)]
    return (parts + [0, 0, 0])[:3]

current = normalize(sys.argv[1])
minimum = normalize(sys.argv[2])
raise SystemExit(0 if current >= minimum else 1)
PY
}

extract_first_semver() {
  python3 - "$1" <<'PY'
import re
import sys

match = re.search(r"(\d+\.\d+(?:\.\d+)?)", sys.argv[1])
if not match:
    raise SystemExit(1)
print(match.group(1))
PY
}

check_tool_version() {
  local tool="$1"
  local minimum="$2"
  shift 2
  local version
  version="$("$@")" || die "failed to determine ${tool} version"
  version="${version//$'\n'/ }"
  version="$(extract_first_semver "${version}")" || die "unable to parse ${tool} version from: ${version}"
  version_ge "${version}" "${minimum}" || die "${tool} ${minimum}+ is required (found ${version})"
}

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf "+ %q" "$1"
    shift
    for arg in "$@"; do
      printf " %q" "$arg"
    done
    printf "\n"
    return 0
  fi
  "$@"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cluster-name) CLUSTER_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --release) RELEASE_NAME="$2"; shift 2 ;;
    --hostname) HOSTNAME="$2"; shift 2 ;;
    --ingress-class) INGRESS_CLASS="$2"; shift 2 ;;
    --create-cluster) CREATE_CLUSTER=1; shift ;;
    --enable-gateway) ENABLE_GATEWAY=1; shift ;;
    --disable-fleet) ENABLE_FLEET=0; shift ;;
    --oidc-issuer) OIDC_ISSUER="$2"; shift 2 ;;
    --oidc-audience) OIDC_AUDIENCE="$2"; shift 2 ;;
    --oidc-tenant-claim) OIDC_TENANT_CLAIM="$2"; shift 2 ;;
    --oidc-role-claim) OIDC_ROLE_CLAIM="$2"; shift 2 ;;
    --node-instance-type) NODE_INSTANCE_TYPE="$2"; shift 2 ;;
    --node-count) NODE_COUNT="$2"; shift 2 ;;
    --k8s-version) K8S_VERSION="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if [ -n "${OIDC_ISSUER}" ]; then
  case "${OIDC_ISSUER}" in
    https://*) ;;
    *) die "--oidc-issuer must use https:// (got ${OIDC_ISSUER})" ;;
  esac
  [ -n "${HOSTNAME}" ] || die "--hostname is required when --oidc-issuer is set so browser auth has a stable same-origin entrypoint"
  [ -n "${OIDC_AUDIENCE}" ] || die "--oidc-audience is required when --oidc-issuer is set"
fi

need_cmd python3
TERRAFORM_BIN="terraform"
if [ "$DRY_RUN" -eq 0 ]; then
  need_cmd aws
  need_cmd kubectl
  need_cmd helm
  need_cmd eksctl
  TERRAFORM_BIN="${TERRAFORM_BIN:-$(command -v terraform || command -v tofu || true)}"
  [ -n "$TERRAFORM_BIN" ] || die "terraform or tofu is required"

  log "Running installer preflight checks"
  check_tool_version "aws" "2.15.0" aws --version
  check_tool_version "kubectl" "1.29.0" kubectl version --client=true
  check_tool_version "helm" "3.14.0" helm version --template '{{.Version}}'
  check_tool_version "eksctl" "0.178.0" eksctl version
  check_tool_version "$("${TERRAFORM_BIN}" version | head -n 1 | awk '{print $1}')" "1.5.0" "${TERRAFORM_BIN}" version
fi

STATE_ROOT="${STATE_DIR}/${CLUSTER_NAME}"
mkdir -p "${STATE_ROOT}"
TF_ROOT="${STATE_ROOT}/terraform"
GENERATED_DIR="${STATE_ROOT}/generated"
mkdir -p "${TF_ROOT}" "${GENERATED_DIR}"

if [ "$CREATE_CLUSTER" -eq 1 ]; then
  CLUSTER_CONFIG="${GENERATED_DIR}/eksctl-cluster.yaml"
  MAX_NODES=$((NODE_COUNT + 2))
  cat >"${CLUSTER_CONFIG}" <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${CLUSTER_NAME}
  region: ${REGION}
  version: "${K8S_VERSION}"

iam:
  withOIDC: true

managedNodeGroups:
  - name: ${CLUSTER_NAME}-workers
    instanceType: ${NODE_INSTANCE_TYPE}
    desiredCapacity: ${NODE_COUNT}
    minSize: ${NODE_COUNT}
    maxSize: ${MAX_NODES}
    privateNetworking: true
EOF
  log "Creating or reconciling reference EKS cluster ${CLUSTER_NAME} in ${REGION}"
  run eksctl create cluster -f "${CLUSTER_CONFIG}"
fi

log "Associating IAM OIDC provider for cluster ${CLUSTER_NAME}"
run eksctl utils associate-iam-oidc-provider --cluster "${CLUSTER_NAME}" --region "${REGION}" --approve

log "Updating kubeconfig"
run aws eks update-kubeconfig --name "${CLUSTER_NAME}" --region "${REGION}"

if [ "$DRY_RUN" -eq 1 ]; then
  ACCOUNT_ID="123456789012"
  OIDC_ISSUER="https://oidc.eks.${REGION}.amazonaws.com/id/REFERENCE"
  VPC_ID="vpc-00000000000000000"
  CLUSTER_SUBNETS="subnet-aaaaaaaaaaaaaaaaa subnet-bbbbbbbbbbbbbbbbb subnet-ccccccccccccccccc"
  VPC_CIDR="10.0.0.0/16"
else
  ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
  CLUSTER_JSON="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${REGION}")"
  OIDC_ISSUER="$(printf '%s' "${CLUSTER_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["cluster"]["identity"]["oidc"]["issuer"])')"
  VPC_ID="$(printf '%s' "${CLUSTER_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["cluster"]["resourcesVpcConfig"]["vpcId"])')"
  CLUSTER_SUBNETS="$(printf '%s' "${CLUSTER_JSON}" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["cluster"]["resourcesVpcConfig"]["subnetIds"]))')"
  VPC_CIDR="$(aws ec2 describe-vpcs --vpc-ids "${VPC_ID}" --region "${REGION}" --query 'Vpcs[0].CidrBlock' --output text)"
fi
OIDC_PROVIDER_HOSTPATH="${OIDC_ISSUER#https://}"
OIDC_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER_HOSTPATH}"
PRIVATE_SUBNET_IDS="$(python3 - <<PY
subnets = "${CLUSTER_SUBNETS}".split()
print("[{}]".format(", ".join(f'"{s}"' for s in subnets)))
PY
)"

TF_MAIN="${TF_ROOT}/main.tf"
cat >"${TF_MAIN}" <<EOF
terraform {
  required_version = ">= 1.5.0"
}

provider "aws" {
  region = "${REGION}"
}

module "agent_bom_baseline" {
  source = "${ROOT_DIR}/deploy/terraform/aws/baseline"

  name                      = "${CLUSTER_NAME}"
  namespace                 = "${NAMESPACE}"
  release_name              = "${RELEASE_NAME}"
  cluster_oidc_provider_arn = "${OIDC_PROVIDER_ARN}"
  cluster_oidc_issuer_url   = "${OIDC_ISSUER}"
  vpc_id                    = "${VPC_ID}"
  private_subnet_ids        = ${PRIVATE_SUBNET_IDS}
  db_allowed_cidr_blocks    = ["${VPC_CIDR}"]
  db_url_secret_name        = "${RELEASE_NAME}/control-plane-db"
  auth_secret_name          = "${RELEASE_NAME}/control-plane-auth"

  tags = {
    Environment = "reference"
    ManagedBy   = "agent-bom-reference-installer"
    Cluster     = "${CLUSTER_NAME}"
  }
}
EOF

log "Applying Terraform AWS baseline"
run "${TERRAFORM_BIN}" -chdir="${TF_ROOT}" init
run "${TERRAFORM_BIN}" -chdir="${TF_ROOT}" apply -auto-approve

HELM_VALUES_HINT="${GENERATED_DIR}/baseline-values.yaml"
if [ "$DRY_RUN" -eq 1 ]; then
  cat >"${HELM_VALUES_HINT}" <<'EOF'
# Dry-run placeholder. A real run writes Terraform-derived Helm values here.
EOF
else
  "${TERRAFORM_BIN}" -chdir="${TF_ROOT}" output -raw helm_values_hint >"${HELM_VALUES_HINT}"
fi

DB_SECRET_ARN=""
DB_URL_SECRET_NAME=""
AUTH_SECRET_NAME=""

if [ "$DRY_RUN" -eq 0 ]; then
  DB_SECRET_ARN="$("${TERRAFORM_BIN}" -chdir="${TF_ROOT}" output -raw db_secret_arn 2>/dev/null || true)"
  DB_URL_SECRET_NAME="$("${TERRAFORM_BIN}" -chdir="${TF_ROOT}" output -raw db_url_secret_name 2>/dev/null || true)"
  AUTH_SECRET_NAME="$("${TERRAFORM_BIN}" -chdir="${TF_ROOT}" output -raw auth_secret_name 2>/dev/null || true)"
fi

API_KEY=""
AUDIT_HMAC=""
GATEWAY_TOKEN=""

if [ "$DRY_RUN" -eq 0 ]; then
  [ -n "${DB_SECRET_ARN}" ] || die "terraform did not return db_secret_arn"
  DB_SECRET_JSON="$(aws secretsmanager get-secret-value --secret-id "${DB_SECRET_ARN}" --region "${REGION}" --query SecretString --output text)"
  DB_URL="$(printf '%s' "${DB_SECRET_JSON}" | python3 - <<'PY'
import json
import sys
from urllib.parse import quote

payload = json.load(sys.stdin)
username = quote(str(payload["username"]))
password = quote(str(payload["password"]))
host = payload["host"]
port = payload["port"]
dbname = payload.get("dbname") or payload.get("dbInstanceIdentifier") or "agent_bom"
print(f"postgresql://{username}:{password}@{host}:{port}/{dbname}")
PY
)"

  API_KEY="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  AUDIT_HMAC="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"

  log "Creating namespace and control-plane secrets"
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "${NAMESPACE}" create secret generic agent-bom-control-plane-db \
    --from-literal=AGENT_BOM_POSTGRES_URL="${DB_URL}" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "${NAMESPACE}" create secret generic agent-bom-control-plane-auth \
    --from-literal=AGENT_BOM_API_KEY="${API_KEY}" \
    --from-literal=AGENT_BOM_AUDIT_HMAC_KEY="${AUDIT_HMAC}" \
    --from-literal=AGENT_BOM_REQUIRE_AUDIT_HMAC=1 \
    $( [ -n "${OIDC_ISSUER}" ] && printf -- "--from-literal=AGENT_BOM_OIDC_ISSUER=%s " "${OIDC_ISSUER}" ) \
    $( [ -n "${OIDC_ISSUER}" ] && printf -- "--from-literal=AGENT_BOM_OIDC_AUDIENCE=%s " "${OIDC_AUDIENCE}" ) \
    $( [ -n "${OIDC_ISSUER}" ] && printf -- "--from-literal=AGENT_BOM_OIDC_TENANT_CLAIM=%s " "${OIDC_TENANT_CLAIM}" ) \
    $( [ -n "${OIDC_ISSUER}" ] && printf -- "--from-literal=AGENT_BOM_OIDC_ROLE_CLAIM=%s " "${OIDC_ROLE_CLAIM}" ) \
    $( [ -n "${OIDC_ISSUER}" ] && printf -- "--from-literal=AGENT_BOM_OIDC_REQUIRE_TENANT_CLAIM=1 " ) \
    --dry-run=client -o yaml | kubectl apply -f -

  if [ -n "${DB_URL_SECRET_NAME}" ]; then
    aws secretsmanager put-secret-value \
      --region "${REGION}" \
      --secret-id "${DB_URL_SECRET_NAME}" \
      --secret-string "{\"AGENT_BOM_POSTGRES_URL\":\"${DB_URL}\"}" >/dev/null
  fi

  if [ -n "${AUTH_SECRET_NAME}" ]; then
    AUTH_SECRET_PAYLOAD="$(python3 - <<PY
import json

payload = {
    "AGENT_BOM_API_KEY": "${API_KEY}",
    "AGENT_BOM_AUDIT_HMAC_KEY": "${AUDIT_HMAC}",
    "AGENT_BOM_REQUIRE_AUDIT_HMAC": "1",
}
if "${OIDC_ISSUER}":
    payload["AGENT_BOM_OIDC_ISSUER"] = "${OIDC_ISSUER}"
    payload["AGENT_BOM_OIDC_AUDIENCE"] = "${OIDC_AUDIENCE}"
    payload["AGENT_BOM_OIDC_TENANT_CLAIM"] = "${OIDC_TENANT_CLAIM}"
    payload["AGENT_BOM_OIDC_ROLE_CLAIM"] = "${OIDC_ROLE_CLAIM}"
    payload["AGENT_BOM_OIDC_REQUIRE_TENANT_CLAIM"] = "1"
print(json.dumps(payload))
PY
)"
    aws secretsmanager put-secret-value \
      --region "${REGION}" \
      --secret-id "${AUTH_SECRET_NAME}" \
      --secret-string "${AUTH_SECRET_PAYLOAD}" >/dev/null
  fi
fi

INSTALL_OVERRIDES="${GENERATED_DIR}/install-overrides.yaml"
cat >"${INSTALL_OVERRIDES}" <<EOF
controlPlane:
  externalSecrets:
    enabled: false
  api:
    envFrom:
      - secretRef:
          name: agent-bom-control-plane-db
      - secretRef:
          name: agent-bom-control-plane-auth
  ingress:
    enabled: $( [ -n "${HOSTNAME}" ] && printf true || printf false )
$( [ -n "${HOSTNAME}" ] && cat <<YAML
    className: ${INGRESS_CLASS}
    hosts:
      - host: ${HOSTNAME}
YAML
)
gateway:
  enabled: $( [ "$ENABLE_GATEWAY" -eq 1 ] && printf true || printf false )
EOF

if [ "$ENABLE_GATEWAY" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
  GATEWAY_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  kubectl -n "${NAMESPACE}" create secret generic agent-bom-gateway-auth \
    --from-literal=AGENT_BOM_GATEWAY_BEARER_TOKEN="${GATEWAY_TOKEN}" \
    --dry-run=client -o yaml | kubectl apply -f -
  cat >>"${INSTALL_OVERRIDES}" <<'EOF'
  envFrom:
    - secretRef:
        name: agent-bom-gateway-auth
EOF
fi

log "Installing Helm chart"
run python3 "${ROOT_DIR}/scripts/install_helm_profile.py" production \
  --release "${RELEASE_NAME}" \
  --namespace "${NAMESPACE}" \
  --values "${HELM_VALUES_HINT}" \
  --values "${INSTALL_OVERRIDES}"

BASE_URL="http://localhost:8080"
if [ -n "${HOSTNAME}" ]; then
  BASE_URL="https://${HOSTNAME}"
fi
VERIFY_GATEWAY_FLAG=""
if [ "${ENABLE_GATEWAY}" -eq 1 ]; then
  VERIFY_GATEWAY_FLAG=" --check-gateway"
fi

SUMMARY="${GENERATED_DIR}/operator-summary.txt"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/deploy/verify-eks-reference.sh"
cat >"${SUMMARY}" <<EOF
agent-bom reference install complete

cluster: ${CLUSTER_NAME}
region: ${REGION}
namespace: ${NAMESPACE}
release: ${RELEASE_NAME}
base url: ${BASE_URL}
terraform dir: ${TF_ROOT}
helm values: ${HELM_VALUES_HINT}
install overrides: ${INSTALL_OVERRIDES}
mode: $( [ "$DRY_RUN" -eq 1 ] && printf dry-run || printf applied )
auth mode: $( [ -n "${OIDC_ISSUER}" ] && printf 'oidc + api key fallback' || printf 'api key' )
verify script: ${VERIFY_SCRIPT}
EOF

if [ "$DRY_RUN" -eq 0 ]; then
  {
    echo
    echo "Dashboard:"
    if [ -n "${HOSTNAME}" ]; then
      echo "  ${BASE_URL}"
    else
      echo "  kubectl -n ${NAMESPACE} port-forward svc/${RELEASE_NAME}-ui 3000:3000"
      echo "  kubectl -n ${NAMESPACE} port-forward svc/${RELEASE_NAME}-api 8080:8422"
    fi
    echo
    echo "Operator API key:"
    echo "  ${API_KEY}"
    if [ "$ENABLE_FLEET" -eq 1 ]; then
      echo
      echo "Endpoint onboarding bundle:"
      echo "  agent-bom proxy-bootstrap --bundle-dir ./agent-bom-endpoint-bundle \\"
      echo "    --control-plane-url ${BASE_URL} \\"
      echo "    --control-plane-token ${API_KEY} \\"
      echo "    --push-url ${BASE_URL}/v1/fleet/sync \\"
      echo "    --push-api-key ${API_KEY}"
    fi
    if [ "$ENABLE_GATEWAY" -eq 1 ]; then
      echo
      echo "Gateway bearer token:"
      echo "  ${GATEWAY_TOKEN}"
      echo "Gateway rollout:"
      echo "  customize deploy/helm/agent-bom/examples/gateway-upstreams.example.yaml"
      echo "  then re-run Helm with --set-file gateway.upstreamsYaml=./my-upstreams.yaml"
    fi
    echo
    echo "Post-deploy verify:"
    echo "  ${VERIFY_SCRIPT} --cluster-name ${CLUSTER_NAME} --region ${REGION} --namespace ${NAMESPACE} --release ${RELEASE_NAME} --base-url ${BASE_URL} --api-key ${API_KEY}${VERIFY_GATEWAY_FLAG}"
  } | tee -a "${SUMMARY}"
else
  {
    echo
    echo "Dry run only. No AWS, Kubernetes, or Helm resources were changed."
    echo "Inspect the generated Terraform root and Helm values files, then rerun without --dry-run."
    echo "Verify flow after apply:"
    echo "  ${VERIFY_SCRIPT} --cluster-name ${CLUSTER_NAME} --region ${REGION} --namespace ${NAMESPACE} --release ${RELEASE_NAME} --base-url ${BASE_URL}${VERIFY_GATEWAY_FLAG}"
  } | tee -a "${SUMMARY}"
fi

log "Reference install outputs written to ${SUMMARY}"
