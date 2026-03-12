# agent-bom CoreWeave Read-Only Provisioning

CoreWeave is a Kubernetes-native GPU cloud built entirely on Kubernetes.
There is no proprietary API or SDK — all discovery uses `kubectl` against
CoreWeave's Kubernetes cluster with CoreWeave-specific CRDs.

Auth: kubeconfig only. CoreWeave provides a kubeconfig file per namespace
from the CoreWeave Cloud Console. No API keys, no passwords.

Docs:
- Cluster access: https://docs.coreweave.com/coreweave-kubernetes/getting-started
- RBAC: https://docs.coreweave.com/coreweave-kubernetes/networking/coreweave-cloud-native-networking/access-control

---

## What agent-bom Discovers on CoreWeave

| Resource | CRD / API | What's scanned |
|---|---|---|
| GPU VMs | `virtualservers.virtualservers.coreweave.com` | GPU model (H100/A100/L40S), image, accelerator count |
| Inference services | `inferenceservices.serving.kserve.io` | vLLM/Triton serving, model name, framework |
| NVIDIA NIM pods | `pods` (image prefix `nvcr.io/nim/`) | NIM microservice version → CVEs |
| InfiniBand training jobs | `pods` with `rdma/ib` resource | Multi-node NCCL jobs, framework packages |
| Standard K8s workloads | `pods`, `deployments` | Any AI container image → package CVEs |

---

## Step 1 — Get Your kubeconfig from CoreWeave Console

1. Log in to https://cloud.coreweave.com
2. Go to **API & Access** → **Kubeconfig**
3. Download the kubeconfig for your namespace
4. Merge into your local kubeconfig:

```bash
KUBECONFIG=~/.kube/config:~/Downloads/coreweave-kubeconfig.yaml \
  kubectl config view --flatten > ~/.kube/config
```

---

## Step 2 — Create a Read-Only Service Account (Namespace-Scoped)

Never use your personal kubeconfig for CI/CD automation. Create a dedicated
service account with the minimum permissions needed.

```bash
# Create the service account in your CoreWeave namespace
kubectl create serviceaccount agent-bom-scanner -n <YOUR_NAMESPACE>
```

Apply the RBAC:

```yaml
# coreweave_rbac.yaml — apply with: kubectl apply -f coreweave_rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agent-bom-readonly
  namespace: <YOUR_NAMESPACE>
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["get", "list", "watch"]
  # CoreWeave VirtualServer CRD
  - apiGroups: ["virtualservers.coreweave.com"]
    resources: ["virtualservers"]
    verbs: ["get", "list", "watch"]
  # KServe InferenceService CRD
  - apiGroups: ["serving.kserve.io"]
    resources: ["inferenceservices"]
    verbs: ["get", "list", "watch"]
  # Never: secrets, pods/exec, create/update/delete
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agent-bom-readonly-binding
  namespace: <YOUR_NAMESPACE>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: agent-bom-readonly
subjects:
  - kind: ServiceAccount
    name: agent-bom-scanner
    namespace: <YOUR_NAMESPACE>
```

```bash
kubectl apply -f coreweave_rbac.yaml
```

---

## Step 3 — Generate a Long-Lived Token for CI/CD

```bash
# Create a token secret bound to the service account
kubectl create token agent-bom-scanner -n <YOUR_NAMESPACE> --duration=8760h
```

Or create a long-lived secret (Kubernetes 1.24+ approach):

```bash
kubectl create secret generic agent-bom-token \
  --type=kubernetes.io/service-account-token \
  --from-literal=extra="agent-bom-scanner" \
  -n <YOUR_NAMESPACE>

kubectl annotate secret agent-bom-token \
  kubernetes.io/service-account.name=agent-bom-scanner \
  -n <YOUR_NAMESPACE>
```

---

## Usage

```bash
# Default kubectl context (uses current kubeconfig context)
agent-bom scan --coreweave

# Explicit context (if you have multiple clusters configured)
agent-bom scan --coreweave --coreweave-context coreweave-<namespace>

# GPU scan across CoreWeave + K8s GPU pods
agent-bom scan --coreweave --gpu-scan --gpu-k8s-context coreweave-<namespace>
```

---

## Credential Best Practices

- **Never use your personal kubeconfig in CI/CD** — use the service account token above
- **Namespace-scoped Role, not ClusterRole** — CoreWeave namespaces are tenant-isolated; namespace scope is sufficient and safer
- **Rotate tokens annually** — or use short-lived `kubectl create token` (1h–8760h)
- **Store tokens as CI secrets** — GitHub Secrets, GitLab CI variables, etc. Never commit
