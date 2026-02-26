#!/usr/bin/env bash
# Scan PyTorch and Triton inference server images.
# Requires: agent-bom, Docker (or Grype/Syft)
set -euo pipefail

echo "=== PyTorch + Inference Server Scanning ==="

IMAGES=(
    "nvcr.io/nvidia/pytorch:24.01-py3"
    "nvcr.io/nvidia/tritonserver:24.01-py3"
    "vllm/vllm-openai:latest"
    "ghcr.io/huggingface/text-generation-inference:latest"
)

OUTPUT_DIR="${1:-./inference-scan-results}"
mkdir -p "$OUTPUT_DIR"

for img in "${IMAGES[@]}"; do
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
