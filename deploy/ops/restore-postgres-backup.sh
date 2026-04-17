#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <s3-uri> <postgres-url> <aws-region> [local-file]" >&2
  exit 1
fi

s3_uri="$1"
postgres_url="$2"
aws_region="$3"
local_file="${4:-/tmp/agent-bom-restore.dump}"

aws s3 cp "$s3_uri" "$local_file" --region "$aws_region"
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  --dbname "$postgres_url" \
  "$local_file"
