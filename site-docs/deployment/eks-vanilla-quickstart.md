# Vanilla EKS Quickstart

Use this path for a production-shaped EKS install that does not depend on
Istio, External Secrets Operator, or cert-manager. The profile uses AWS Load
Balancer Controller, IRSA, RDS/Postgres, and Kubernetes Secrets.

Choose the right profile first:

| Need | Profile |
| --- | --- |
| Laptop-speed demo | `eks-control-plane-sqlite-pilot-values.yaml` |
| Vanilla EKS production | `eks-vanilla-values.yaml` |
| Mesh-hardened production | `eks-istio-kyverno-values.yaml` |

## Prerequisites

- EKS cluster with AWS Load Balancer Controller installed
- ACM certificate ARN for the control-plane hostname
- RDS/Postgres URL for `AGENT_BOM_POSTGRES_URL`
- IRSA role ARN for scanner/API AWS read access and backup access
- Helm 3

## 1. Create The Namespace

```bash
kubectl create namespace agent-bom
```

## 2. Create Secret Env Files

Create `agent-bom-db.env` locally:

```bash
AGENT_BOM_POSTGRES_URL=postgresql://agent_bom:REPLACE_ME@REPLACE_ME_RDS_ENDPOINT:5432/agent_bom
```

Create `agent-bom-auth.env` locally:

```bash
AGENT_BOM_AUDIT_HMAC_KEY=REPLACE_ME_32_BYTES_OR_LONGER
AGENT_BOM_AUDIT_HMAC_KEY_LAST_ROTATED=2026-04-26T00:00:00+00:00
AGENT_BOM_BROWSER_SESSION_SIGNING_KEY=REPLACE_ME_32_BYTES_OR_LONGER
AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED=2026-04-26T00:00:00+00:00
AGENT_BOM_RATE_LIMIT_KEY=REPLACE_ME_32_BYTES_OR_LONGER
AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED=2026-04-26T00:00:00+00:00
AGENT_BOM_TRUST_PROXY_AUTH_SECRET=REPLACE_ME_32_BYTES_OR_LONGER
AGENT_BOM_TRUST_PROXY_AUTH_ISSUER=aws-alb
```

Add OIDC, SAML, or SCIM values to the same auth env file when those features
are enabled. Keep the env files in your secret-management workflow, not in Git.

Apply the Kubernetes Secrets:

```bash
kubectl create secret generic agent-bom-control-plane-db \
  --namespace agent-bom \
  --from-env-file=agent-bom-db.env

kubectl create secret generic agent-bom-control-plane-auth \
  --namespace agent-bom \
  --from-env-file=agent-bom-auth.env
```

## 3. Customize The Values File

Copy the shipped profile and replace placeholders:

```bash
cp deploy/helm/agent-bom/examples/eks-vanilla-values.yaml ./agent-bom-eks-vanilla-values.yaml
```

Update:

- `alb.ingress.kubernetes.io/certificate-arn`
- `controlPlane.ingress.hosts[0].host`
- IRSA role ARNs
- backup bucket, region, and KMS key

## 4. Install

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom \
  --create-namespace \
  -f ./agent-bom-eks-vanilla-values.yaml
```

## 5. Verify

```bash
kubectl get ingress -n agent-bom
curl -fsS https://agent-bom.internal.example.com/health
curl -fsS https://agent-bom.internal.example.com/readyz
helm test agent-bom -n agent-bom
```

The API uses `/health` for liveness and `/readyz` for dependency readiness.
Gateway and sidecar runtime surfaces use `/healthz`.

## NetworkPolicy Note

The vanilla profile keeps NetworkPolicy enabled for egress controls, but it
does not enable restricted ingress by default. With ALB `target-type: ip`, data
traffic reaches pod IPs directly and cannot be selected as an in-cluster
controller pod. Enable restricted ingress only after you add environment-specific
CIDR or CNI policy controls that match your ALB data path.

## Going Further

- Mesh and policy-controller hardening:
  `deploy/helm/agent-bom/examples/eks-istio-kyverno-values.yaml`
- Full EKS operator guide: `site-docs/deployment/own-infra-eks.md`
- Postgres ownership: `site-docs/deployment/postgres-provisioning.md`
