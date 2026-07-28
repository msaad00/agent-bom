#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
The legacy EKS reference installer has been retired because it cannot safely
represent the app, maintenance, migration/admin, and auth credential boundaries.

Use the staged platform module instead:

  cp deploy/terraform/platform-eks/terraform.tfvars.example \
    deploy/terraform/platform-eks/terraform.tfvars
  # Populate the required secret names and cluster mode in terraform.tfvars.
  scripts/deploy/install.sh eks

For a fresh cluster, complete the cluster-first External Secrets bootstrap in:

  deploy/terraform/platform-eks/README.md

The supported path keeps the RDS-managed master credential migration-only and
never exposes it to the long-lived API workload.
EOF

exit 2
