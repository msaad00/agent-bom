# AI Infrastructure Scanning

agent-bom treats AI infrastructure dependencies as first-class supply chain components. GPU drivers, CUDA libraries, ROCm runtimes, and ML framework packages all carry CVEs that propagate through your AI stack.

## Why AI infrastructure matters

A vulnerability in `nvidia-cudnn-cu12` or `hip-python` doesn't just affect one model — it affects every inference pipeline running on that GPU fleet. agent-bom maps these dependencies into the same blast radius analysis used for MCP servers.

## Supported AI infrastructure packages

### NVIDIA CUDA ecosystem

| Package | Description |
|---------|-------------|
| `cuda-python` | CUDA Python bindings |
| `cupy`, `cupy-cuda11x`, `cupy-cuda12x` | NumPy-like GPU arrays |
| `nvidia-cublas-cu11/cu12` | CUDA BLAS library |
| `nvidia-cudnn-cu11/cu12` | CUDA Deep Neural Network library |
| `nvidia-cufft-cu11/cu12` | CUDA FFT library |
| `nvidia-cusolver-cu11/cu12` | CUDA solver library |
| `nvidia-cusparse-cu11/cu12` | CUDA sparse matrix library |
| `nvidia-nccl-cu11/cu12` | NVIDIA Collective Communications Library |
| `nvidia-cuda-runtime-cu11/cu12` | CUDA runtime |
| `nvidia-cuda-nvrtc-cu11/cu12` | CUDA NVRTC (runtime compilation) |
| `tensorrt`, `nvidia-tensorrt` | NVIDIA TensorRT inference optimizer |
| `triton`, `tritonclient` | NVIDIA Triton Inference Server |

### AMD ROCm ecosystem

| Package | Description |
|---------|-------------|
| `hip-python` | HIP Python bindings (AMD GPU) |
| `rocm-smi` | ROCm System Management Interface |
| `torch` (ROCm build) | PyTorch with ROCm backend |
| `tensorflow-rocm` | TensorFlow with ROCm backend |

### ML frameworks with GPU backends

| Package | Description |
|---------|-------------|
| `torch`, `torchvision`, `torchaudio` | PyTorch ecosystem |
| `tensorflow`, `tensorflow-gpu` | TensorFlow ecosystem |
| `jax`, `jaxlib` | Google JAX |
| `vllm` | vLLM inference engine |
| `text-generation-inference` | HuggingFace TGI |
| `llama-cpp-python` | llama.cpp Python bindings |

### MLOps & experiment tracking

| Package | Description |
|---------|-------------|
| `mlflow` | ML experiment tracking |
| `wandb` | Weights & Biases |
| `ray` | Distributed computing |
| `clearml` | ML pipeline management |

## Scanning GPU container images

### NVIDIA CUDA images

```bash
# Scan official NVIDIA CUDA base image
agent-bom scan --image nvcr.io/nvidia/cuda:12.4.1-devel-ubuntu22.04

# Scan NVIDIA PyTorch NGC container
agent-bom scan --image nvcr.io/nvidia/pytorch:24.01-py3

# Scan NVIDIA Triton Inference Server
agent-bom scan --image nvcr.io/nvidia/tritonserver:24.01-py3
```

### AMD ROCm images

```bash
# Scan AMD ROCm PyTorch image
agent-bom scan --image rocm/pytorch:rocm6.0_ubuntu22.04_py3.10_pytorch_2.1.1

# Scan AMD ROCm base terminal
agent-bom scan --image rocm/rocm-terminal:latest

# Scan ROCm TensorFlow image
agent-bom scan --image rocm/tensorflow:rocm6.0-tf2.15
```

### Inference server images

```bash
# Scan vLLM GPU image
agent-bom scan --image vllm/vllm-openai:latest

# Scan HuggingFace TGI
agent-bom scan --image ghcr.io/huggingface/text-generation-inference:latest
```

## GPU fleet scanning patterns

### Kubernetes GPU operator

```bash
# Scan NVIDIA GPU Operator components
agent-bom scan --image nvcr.io/nvidia/gpu-operator:v24.3.0
agent-bom scan --image nvcr.io/nvidia/k8s-device-plugin:v0.15.0
agent-bom scan --image nvcr.io/nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04

# Scan all GPU pods in a namespace
agent-bom scan --k8s --namespace gpu-workloads -f json -o gpu-fleet-scan.json
```

### Multi-cloud GPU fleet

```bash
# CoreWeave GPU instances
agent-bom scan --image <your-gpu-workload-image> --enrich -f json

# Lambda Labs GPU cloud
agent-bom scan --image <lambda-workload-image> --enrich -f json

# Nebius AI cloud
agent-bom scan --nebius -f json -o nebius-ai-scan.json
```

## CI/CD integration

### GitHub Actions — GPU image gate

```yaml
- uses: msaad00/agent-bom@v0.36.0
  with:
    scan-type: image
    image: nvcr.io/nvidia/cuda:12.4.1-devel-ubuntu22.04
    fail-on-severity: high
    format: sarif
    output-file: gpu-scan.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gpu-scan.sarif
```

### Policy enforcement

```yaml
# policy.yml — block critical GPU library vulnerabilities
rules:
  - name: block-critical-gpu-vulns
    condition:
      severity: critical
      package_pattern: "nvidia-*|cuda-*|rocm-*|hip-*"
    action: fail
    message: "Critical GPU infrastructure vulnerability — blocks deployment"
```

## Example scan scripts

See [`examples/ai-infra/`](../examples/ai-infra/) for ready-to-run scan scripts:

- `nvidia-cuda-scan.sh` — Scan NVIDIA CUDA + NGC images
- `amd-rocm-scan.sh` — Scan AMD ROCm images
- `pytorch-triton-scan.sh` — Scan PyTorch + Triton inference
- `gpu-fleet-k8s-scan.sh` — Scan Kubernetes GPU workloads
