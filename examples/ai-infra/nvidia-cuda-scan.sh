#!/usr/bin/env bash
# Scan NVIDIA CUDA and NGC container images for vulnerabilities.
# Requires: agent-bom, Docker (or Grype/Syft)
set -euo pipefail

echo "=== NVIDIA CUDA Image Scanning ==="

# CUDA base images
CUDA_IMAGES=(
    "nvcr.io/nvidia/cuda:12.4.1-devel-ubuntu22.04"
    "nvcr.io/nvidia/cuda:12.4.1-runtime-ubuntu22.04"
    "nvcr.io/nvidia/cuda:11.8.0-devel-ubuntu22.04"
)

# NGC ML container images
NGC_IMAGES=(
    "nvcr.io/nvidia/pytorch:24.01-py3"
    "nvcr.io/nvidia/tensorflow:24.01-tf2-py3"
    "nvcr.io/nvidia/tritonserver:24.01-py3"
)

OUTPUT_DIR="${1:-./nvidia-scan-results}"
mkdir -p "$OUTPUT_DIR"

for img in "${CUDA_IMAGES[@]}" "${NGC_IMAGES[@]}"; do
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
