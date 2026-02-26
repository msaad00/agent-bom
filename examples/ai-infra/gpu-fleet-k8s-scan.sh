#!/usr/bin/env bash
# Scan Kubernetes GPU workloads across namespaces.
# Requires: agent-bom, kubectl configured
set -euo pipefail

echo "=== Kubernetes GPU Fleet Scanning ==="

# GPU-related namespaces to scan
NAMESPACES=(
    "gpu-operator"
    "gpu-workloads"
    "ml-training"
    "inference"
)

OUTPUT_DIR="${1:-./k8s-gpu-scan-results}"
mkdir -p "$OUTPUT_DIR"

# Scan GPU operator components
echo ""
echo "--- Scanning GPU Operator images ---"
GPU_OPERATOR_IMAGES=(
    "nvcr.io/nvidia/gpu-operator:v24.3.0"
    "nvcr.io/nvidia/k8s-device-plugin:v0.15.0"
    "nvcr.io/nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04"
)

for img in "${GPU_OPERATOR_IMAGES[@]}"; do
    safe_name=$(echo "$img" | tr '/:' '_')
    agent-bom scan --image "$img" \
        --enrich \
        -f json \
        -o "$OUTPUT_DIR/operator_${safe_name}.json" || true
done

# Scan GPU workload namespaces via kubectl
for ns in "${NAMESPACES[@]}"; do
    echo ""
    echo "--- Scanning namespace: $ns ---"
    if kubectl get namespace "$ns" &>/dev/null; then
        agent-bom scan --k8s --namespace "$ns" \
            --enrich \
            -f json \
            -o "$OUTPUT_DIR/k8s_${ns}.json" || true
    else
        echo "  Namespace $ns not found, skipping"
    fi
done

echo ""
echo "=== Results saved to $OUTPUT_DIR ==="
ls -la "$OUTPUT_DIR"/*.json 2>/dev/null || echo "No results generated"
