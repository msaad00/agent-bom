#!/usr/bin/env bash
# install.sh — unified deploy entrypoint for agent-bom control planes.
#
# One script, many targets. Delegates to existing compose, Helm, Terraform, and
# reference installers — does not duplicate infrastructure logic.
#
# Usage:
#   scripts/deploy/install.sh list
#   scripts/deploy/install.sh pilot
#   scripts/deploy/install.sh eks --create-cluster --region us-east-1
#   scripts/deploy/install.sh connect aws
#   scripts/deploy/install.sh onboard --url https://agent-bom.example.com --api-key "$KEY"
#
# See docs/DEPLOY_QUICKSTART.md for the Wiz-style onboarding story.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TARGET="${1:-}"
shift || true

CONNECT_CLOUD=""
HELM_PROFILE_ARG=""
case "$TARGET" in
  connect)
    CONNECT_CLOUD="${1:-}"
    shift || true
    ;;
  helm)
    HELM_PROFILE_ARG="${1:-}"
    shift || true
    ;;
esac

DRY_RUN=0
DEMO_ESTATE=0
CREATE_CLUSTER=0
ENABLE_GATEWAY=0
HELM_PROFILE="enterprise-demo"
HELM_RELEASE="agent-bom"
HELM_NAMESPACE="agent-bom"
AWS_REGION="${AWS_REGION:-us-east-1}"
ONBOARD_URL=""
ONBOARD_API_KEY=""
ONBOARD_TENANT="default"

usage() {
  cat <<'EOF'
agent-bom unified deploy installer

Deploy the control plane (API + UI + graph), then connect read-only cloud
accounts and endpoint fleet for inventory, scans, MCP/agents, and AI BOM.

Usage:
  scripts/deploy/install.sh <target> [options]

Targets (control plane):
  list              Show all targets and what you get out of the box
  pilot             Fastest local pilot (loopback Docker, SQLite, demo UI)
  docker            Full local stack (API + UI + Postgres via compose)
  platform-docker   Production-shaped single-host Docker (secrets + split nets)
  eks               AWS EKS reference installer (scripts/deploy/install-eks-reference.sh)
  eks-terraform     One terraform apply (deploy/terraform/platform-eks)
  aks               Helm on AKS + Azure collector overlay (BYO cluster)
  gke               Helm on GKE + GCP collector overlay (BYO cluster)
  helm <profile>    Shipped Helm profile (scripts/install_helm_profile.py --list)
  snowflake         Snowflake POV path (Helm snowflake-backend + connect module)
  snowflake-native  Snowflake Native App / SPCS lane (docs pointer)

Targets (connect read-only clouds — Wiz-style account onboarding):
  connect aws       Mint read-only IAM role (deploy/terraform/connect-aws)
  connect azure     Mint Reader RBAC (deploy/terraform/connect-azure)
  connect gcp       Mint viewer + securityReviewer (deploy/terraform/connect-gcp)
  connect snowflake Mint ABOM_READONLY role (deploy/terraform/connect-snowflake)

Post-deploy onboarding helper:
  onboard           Print/run fleet bootstrap + smoke checks after control plane is live

Common options:
  --dry-run         Print delegated commands without running them
  --demo-estate     Start API with curated demo graph + offline scan (pilots)
  --region REGION   AWS region for EKS/connect paths (default: AWS_REGION or us-east-1)
  --create-cluster  Pass through to EKS reference installer (create cluster with eksctl)
  --enable-gateway  Pass through to EKS reference installer (enable gateway Deployment)
  --profile NAME    Helm profile for aks/gke/helm targets (default: enterprise-demo)
  --release NAME    Helm release name (default: agent-bom)
  --namespace NAME  Kubernetes namespace (default: agent-bom)
  --url URL         Control-plane base URL (onboard target)
  --api-key KEY     Admin/API key (onboard target)
  --tenant ID       Tenant scope (onboard target, default: default)
  -h, --help        Show this help

Examples:
  # Fastest look — dashboard + demo inventory in under 2 minutes
  scripts/deploy/install.sh pilot

  # Production AWS / EKS (creates cluster + baseline + Helm + next-step hints)
  export AWS_REGION="<your-aws-region>"
  scripts/deploy/install.sh eks --create-cluster --region "$AWS_REGION" --enable-gateway

  # Connect a second AWS account read-only (after control plane is live)
  scripts/deploy/install.sh connect aws

  # Post-deploy: fleet bundle command + smoke
  scripts/deploy/install.sh onboard --url https://agent-bom.internal.example.com --api-key "$AGENT_BOM_API_KEY"

Docs:
  docs/DEPLOY_QUICKSTART.md   — onboarding story (deploy → connect → inventory → scans)
  docs/DEPLOY_PLATFORM.md     — three-tier architecture reference
  docs/CLOUD_CONNECT.md       — read-only multicloud connect model
EOF
}

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" >&2; }
die() { printf "\n[error] %s\n" "$*" >&2; exit 1; }

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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

print_list() {
  cat <<'EOF'
agent-bom deploy targets

After any control-plane target you get (out of the box once connected):
  • Unified security graph (cloud resources, identities, MCP servers, agents)
  • Findings queue with reach / blast-radius ranking
  • Fleet inventory from workstations and K8s collectors
  • Scheduled or on-demand scans (CLI, API, CronJob)
  • MCP server mode, optional gateway/proxy runtime enforcement
  • Compliance evidence, SBOM/SARIF exports, audit trail

Local / pilot
  pilot             Loopback Docker pilot (SQLite). Fastest product proof.
  docker            API + UI + Postgres on one machine.
  platform-docker   Production-shaped Docker on one host.

Kubernetes control plane
  eks               Opinionated AWS EKS installer (cluster optional).
  eks-terraform     Single terraform apply (EKS + RDS + Helm).
  aks               Helm enterprise-demo + AKS workload-identity collector overlay.
  gke               Helm enterprise-demo + GKE workload-identity collector overlay.
  helm <profile>    Any shipped profile (production, focused-pilot, snowflake-backend, …).

Snowflake
  snowflake         Self-hosted POV with Snowflake/Cortex inventory.
  snowflake-native  Customer-account Native App + SPCS scanner/MCP runtime.

Read-only cloud connect (per account / subscription / project / Snowflake account)
  connect aws | azure | gcp | snowflake

Post-deploy
  onboard           Fleet bootstrap hints + pilot-verify smoke wrapper.

Run: scripts/deploy/install.sh <target> --help  (via -h on this script)
Read: docs/DEPLOY_QUICKSTART.md
EOF
}

print_onboarding_card() {
  local url="${1:-http://localhost:3000}"
  local api_url="${2:-http://localhost:8422}"
  cat <<EOF

══════════════════════════════════════════════════════════════════════
 Next: Wiz-style onboarding (read-only — nothing is mutated in your cloud)
══════════════════════════════════════════════════════════════════════

1) Connect cloud accounts (inventory + posture, opt-in per provider)
   scripts/deploy/install.sh connect aws
   scripts/deploy/install.sh connect azure
   scripts/deploy/install.sh connect gcp
   scripts/deploy/install.sh connect snowflake

   Or via API after minting keys:
   POST ${api_url}/v1/cloud/connections  (test → scan)

2) Enable auto-discovery / scheduled scans
   • Helm: enterprise-demo profile schedules AWS inventory CronJob
   • API:  POST ${api_url}/v1/scan
   • CLI:  agent-bom agents --preset enterprise --aws

3) Endpoint + MCP/agent fleet (workstations, IDE agents, local MCP configs)
   agent-bom proxy-bootstrap \\
     --control-plane-url ${api_url} \\
     --push-url ${api_url}/v1/fleet/sync \\
     --push-api-key "<admin-or-tenant-key>"

4) Open the proof path in the dashboard
   ${url}  →  Queue · Graph · Runtime · Reports · Connections

5) Verify the five pilot capabilities
   scripts/pilot-verify.sh ${api_url} "<api-key>"

Trust boundary: docs/TRUST.md
Full connect model: docs/CLOUD_CONNECT.md
EOF
}

compose_up() {
  local file="$1"
  need_cmd docker
  if [ ! -f .env ] && [ -f .env.example ]; then
    warn ".env missing — copy .env.example and set POSTGRES_PASSWORD for non-pilot stacks"
  fi
  log "Starting compose stack: ${file}"
  if [ "$DEMO_ESTATE" -eq 1 ]; then
    export AGENT_BOM_DEMO_ESTATE=1
    log "Demo estate enabled (showcase graph + curated offline scan on API start)"
  fi
  run docker compose -f "$file" up -d
  log "Dashboard → http://localhost:3000"
  log "API docs  → http://localhost:8422/docs"
  print_onboarding_card "http://localhost:3000" "http://localhost:8422"
}

install_eks() {
  need_cmd bash
  local args=(--region "$AWS_REGION")
  [ "$CREATE_CLUSTER" -eq 1 ] && args+=(--create-cluster)
  [ "$ENABLE_GATEWAY" -eq 1 ] && args+=(--enable-gateway)
  [ "$DRY_RUN" -eq 1 ] && args+=(--dry-run)
  log "Delegating to install-eks-reference.sh"
  run bash scripts/deploy/install-eks-reference.sh "${args[@]}"
}

install_eks_terraform() {
  need_cmd terraform
  log "EKS platform module — one terraform apply"
  warn "Prereqs: ingress controller, cert-manager, External Secrets Operator — see deploy/terraform/platform-eks/README.md"
  run bash -c "cd deploy/terraform/platform-eks && terraform init && terraform apply"
  print_onboarding_card "https://<your-ingress-host>" "https://<your-ingress-host>"
}

install_helm_platform() {
  local profile="$1"
  local extra_values=()
  case "$TARGET" in
    aks)
      extra_values+=(deploy/helm/agent-bom/examples/aks-collector-workload-identity-values.yaml)
      ;;
    gke)
      extra_values+=(deploy/helm/agent-bom/examples/gke-collector-workload-identity-values.yaml)
      ;;
  esac
  need_cmd helm
  log "Installing Helm profile: ${profile}"
  local cmd=(python3 scripts/install_helm_profile.py "$profile" --release "$HELM_RELEASE" --namespace "$HELM_NAMESPACE")
  for vf in "${extra_values[@]}"; do
    cmd+=(--values "$vf")
  done
  [ "$DRY_RUN" -eq 1 ] && cmd+=(--print-command)
  run "${cmd[@]}"
  case "$TARGET" in
    aks)
      warn "Apply connect-azure in each subscription, then set workload identity on the scanner SA."
      run bash -c 'echo "  cd deploy/terraform/connect-azure && terraform apply"'
      ;;
    gke)
      warn "Apply connect-gcp, bind WI, then set iam.gke.io/gcp-service-account on the scanner SA."
      run bash -c 'echo "  cd deploy/terraform/connect-gcp && terraform apply"'
      ;;
  esac
  print_onboarding_card "https://<ingress-host>" "https://<ingress-host>"
}

install_snowflake_pov() {
  install_helm_platform "snowflake-backend"
  log "Mint Snowflake read-only role in the customer account"
  run bash -c 'echo "  cd deploy/terraform/connect-snowflake && terraform apply"'
  warn "See site-docs/deployment/snowflake-pov.md for Postgres + Cortex inventory smoke."
}

install_connect() {
  local cloud="$1"
  local module_dir=""
  case "$cloud" in
    aws) module_dir="deploy/terraform/connect-aws" ;;
    azure) module_dir="deploy/terraform/connect-azure" ;;
    gcp) module_dir="deploy/terraform/connect-gcp" ;;
    snowflake) module_dir="deploy/terraform/connect-snowflake" ;;
    *) die "unknown connect cloud: ${cloud}" ;;
  esac
  need_cmd terraform
  log "Read-only connect: ${cloud} (${module_dir})"
  cat <<EOF

This mints a least-privilege read-only principal in YOUR account.
agent-bom never mutates resources — only List/Describe/Get (or Snowflake SELECT/SHOW).

After apply, register the output with your control plane:
  • API: POST /v1/cloud/connections
  • Helm scanner: set scanner.cloud.${cloud}.inventory=true
  • CLI: export AGENT_BOM_$(echo "$cloud" | tr '[:lower:]' '[:upper:]')_INVENTORY=1

EOF
  if [ "$DRY_RUN" -eq 1 ]; then
    run bash -c "cd ${module_dir} && terraform init && terraform plan"
  else
    run bash -c "cd ${module_dir} && terraform init && terraform apply"
    log "Hand terraform outputs to the control plane (role ARN, external ID, etc.)"
  fi
}

install_onboard() {
  [ -n "$ONBOARD_URL" ] || die "onboard requires --url (control-plane base URL)"
  [ -n "$ONBOARD_API_KEY" ] || die "onboard requires --api-key"
  local api_url="${ONBOARD_URL%/}"
  log "Post-deploy onboarding for ${api_url}"

  cat <<EOF

Fleet bootstrap (run on a workstation or golden image):
  agent-bom proxy-bootstrap \\
    --control-plane-url ${api_url} \\
    --push-url ${api_url}/v1/fleet/sync \\
    --push-api-key "${ONBOARD_API_KEY}" \\
    --tenant-id ${ONBOARD_TENANT}

Cloud connect (repeat per account):
  scripts/deploy/install.sh connect aws
  scripts/deploy/install.sh connect azure
  scripts/deploy/install.sh connect gcp
  scripts/deploy/install.sh connect snowflake

EOF
  if [ "$DRY_RUN" -eq 1 ]; then
    run bash -c "echo scripts/pilot-verify.sh ${api_url} '<api-key>'"
  else
    need_cmd curl
    need_cmd jq
    run bash scripts/pilot-verify.sh "$api_url" "$ONBOARD_API_KEY"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --demo-estate) DEMO_ESTATE=1 ;;
    --create-cluster) CREATE_CLUSTER=1 ;;
    --enable-gateway) ENABLE_GATEWAY=1 ;;
    --region) shift; AWS_REGION="${1:?--region requires value}" ;;
    --profile) shift; HELM_PROFILE="${1:?--profile requires value}" ;;
    --release) shift; HELM_RELEASE="${1:?--release requires value}" ;;
    --namespace) shift; HELM_NAMESPACE="${1:?--namespace requires value}" ;;
    --url) shift; ONBOARD_URL="${1:?--url requires value}" ;;
    --api-key) shift; ONBOARD_API_KEY="${1:?--api-key requires value}" ;;
    --tenant) shift; ONBOARD_TENANT="${1:?--tenant requires value}" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try -h)" ;;
  esac
  shift
done

if [ -z "$TARGET" ] || [ "$TARGET" = "-h" ] || [ "$TARGET" = "--help" ]; then
  usage
  exit 0
fi

case "$TARGET" in
  list)
    print_list
    ;;
  pilot)
    compose_up deploy/docker-compose.pilot.yml
    ;;
  docker)
    compose_up deploy/docker-compose.fullstack.yml
    ;;
  platform-docker)
    compose_up deploy/docker-compose.platform.yml
    ;;
  eks)
    install_eks
    ;;
  eks-terraform|terraform-eks|platform-eks)
    install_eks_terraform
    ;;
  aks)
    install_helm_platform "$HELM_PROFILE"
    ;;
  gke)
    install_helm_platform "$HELM_PROFILE"
    ;;
  helm)
    install_helm_platform "${HELM_PROFILE_ARG:-$HELM_PROFILE}"
    ;;
  snowflake|snowflake-pov)
    install_snowflake_pov
    ;;
  snowflake-native|snowflake-spcs)
    log "Snowflake Native App + SPCS lane (customer-owned install)"
    cat <<'EOF'

Install in the Snowflake customer account (not a hosted SaaS):
  docs/snowflake-native-app/INSTALL.md
  deploy/snowflake/native-app/

Out of the box after install + enable:
  • SPCS scanner service (opt-in egress to advisory feeds)
  • MCP runtime service (opt-in, bearer-gated)
  • Native App security graph + findings in-account

Self-hosted API/UI POV (often faster first): scripts/deploy/install.sh snowflake
EOF
    ;;
  connect)
    [ -n "$CONNECT_CLOUD" ] || die "connect requires a cloud: aws | azure | gcp | snowflake"
    install_connect "$CONNECT_CLOUD"
    ;;
  onboard)
    install_onboard
    ;;
  *)
    die "unknown target: ${TARGET} (run: scripts/deploy/install.sh list)"
    ;;
esac
