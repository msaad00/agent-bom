# agent-bom NVIDIA NGC / NIM Setup

NVIDIA's AI infrastructure spans two surfaces agent-bom scans:

1. **NGC (NVIDIA GPU Cloud)** — private container registry, model catalog, Helm charts
2. **NVIDIA NIM microservices** — deployed as containers (on CoreWeave, EKS, GKE, bare metal)

NVIDIA does not have a "cloud account" API like AWS/GCP. Discovery is container-based,
not account-based. The scan detects NIM containers by image prefix (`nvcr.io/nim/`)
wherever they are deployed.

---

## What agent-bom Discovers for NVIDIA

| Surface | How Discovered | What's Scanned |
|---|---|---|
| NIM containers | `kubectl` image prefix `nvcr.io/nim/*` | NIM version → CVEs in NVIDIA advisory |
| NGC base images | Container image manifest | `nvidia/cuda`, `nvidia/tensorrt`, `nvcr.io/nvidia/*` → CVEs |
| Triton Inference Server | `nvcr.io/nvidia/tritonserver:*` | Triton version + backend packages |
| NCCL/InfiniBand jobs | `rdma/ib` resource in pod spec | Multi-node training attack surface |
| Nebius NVIDIA GPU | Nebius API (`_discover_gpu_pods`) | H100/A100 GPU instance inventory |
| CoreWeave NVIDIA GPU | VirtualServer CRDs | GPU model, accelerator count |
| GPU infra scan | `--gpu-scan` flag (gpu_infra.py) | K8s GPU resource requests, DCGM exposure |

---

## NGC API Key (only needed for private NGC catalog access)

Most NIM containers are discovered via `kubectl` — no NGC API key needed.
An NGC API key is only required to:
- Pull private NIM containers from `nvcr.io`
- Access private NGC Catalog models

### Create a Read-Only NGC API Key

1. Log in to https://ngc.nvidia.com
2. Go to **Account** → **Setup** → **API Keys** → **Generate API Key**
3. Org Role: **Viewer** (never use **Admin** or **Manager**)
4. Save the key — shown only once

Docs: https://docs.ngc.nvidia.com/cli/cmd.html#ngc-config-set

### Key Rotation

NGC API keys do not expire. Rotate manually:
1. Generate a new key
2. Update the CI secret / env var
3. Revoke the old key at https://ngc.nvidia.com/setup/api-key

---

## DCGM Exporter (unauthenticated exposure detection)

agent-bom probes for unauthenticated DCGM (Data Center GPU Manager) exporters
at `http://<pod-ip>:9400/metrics`. This is a common misconfiguration that
exposes GPU health metrics to the network without auth.

No credential needed — the probe checks if the endpoint is open.

```bash
# Scan for DCGM exposure + GPU workload CVEs
agent-bom scan --gpu-scan

# Skip DCGM probe (if you know it's secured)
agent-bom scan --gpu-scan --no-dcgm-probe
```

---

## Usage

```bash
# NIM + GPU pods on EKS
agent-bom scan --aws --aws-include-eks --gpu-scan

# NIM + GPU pods on CoreWeave
agent-bom scan --coreweave --gpu-scan

# NIM + GPU pods on GKE
agent-bom scan --gcp --gpu-scan

# NIM + GPU pods on Nebius
agent-bom scan --nebius --gpu-scan

# Container image CVE scan for a specific NIM image
agent-bom scan --image nvcr.io/nim/meta/llama-3.1-8b-instruct:latest
```

---

## What CVE Sources Cover NVIDIA

agent-bom uses three sources specifically for NVIDIA packages:

| Source | What it covers |
|---|---|
| OSV.dev | `nvidia-*`, `cuda-*`, `tensorrt` PyPI packages |
| NVIDIA Security Bulletin | `nvcr.io/nvidia/*` container CVEs (NVIDIA advisory feed) |
| NVD enrichment | CVSS scores for all NVIDIA CVEs (90-day cache) |

Packages checked: `torch`, `torchvision`, `triton`, `vllm`, `nemo-toolkit`, `transformers`,
`nvidia-cuda-runtime-cu*`, `nvidia-cudnn-cu*`, `nvidia-tensorrt`, `nccl`.
