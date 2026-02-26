#!/usr/bin/env bash
# Scan AMD ROCm container images for vulnerabilities.
# Requires: agent-bom, Docker (or Grype/Syft)
set -euo pipefail

echo "=== AMD ROCm Image Scanning ==="

ROCM_IMAGES=(
    "rocm/pytorch:rocm6.0_ubuntu22.04_py3.10_pytorch_2.1.1"
    "rocm/tensorflow:rocm6.0-tf2.15"
    "rocm/rocm-terminal:latest"
)

OUTPUT_DIR="${1:-./rocm-scan-results}"
mkdir -p "$OUTPUT_DIR"

for img in "${ROCM_IMAGES[@]}"; do
    safe_name=$(echo "$img" | tr '/:' '_')
    echo ""
    echo "--- Scanning: $img ---"
    agent-bom scan --image "$img" \
        --enrich \
        -f json \
        -o "$OUTPUT_DIR/${safe_name}.json" \
        --fail-on-severity critical || true
done

echo ""
echo "=== Results saved to $OUTPUT_DIR ==="
ls -la "$OUTPUT_DIR"/*.json 2>/dev/null || echo "No results generated"
