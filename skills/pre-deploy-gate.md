# Pre-Deploy Gate

> CI/CD security gate for AI applications — block deployments with critical vulnerabilities or policy violations.

## Goal

Integrate agent-bom into your CI/CD pipeline to automatically scan AI supply chain dependencies, container images, and MCP server packages before deployment. Fail the build on critical/high CVEs, CISA KEV matches, policy violations, or excessive tool agency.

## Prerequisites

```bash
pip install agent-bom
```

## Steps

### 1. Choose Your Gate Criteria

Define what should block a deployment:

| Criteria | Flag | When to use |
|----------|------|-------------|
| Severity threshold | `--fail-on-severity high` | Block on HIGH or CRITICAL CVEs |
| Known exploited | `--fail-on-kev` | Block if any CVE is in CISA KEV (requires `--enrich`) |
| AI framework risk | `--fail-if-ai-risk` | Block if AI framework + credentials + CVE combination |
| Policy rules | `--policy policy.json` | Custom rules (unverified servers, tool count, etc.) |

### 2. GitHub Actions Integration

```yaml
name: AI Supply Chain Scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  ai-bom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install agent-bom
        run: pip install agent-bom

      - name: Scan AI supply chain dependencies
        run: |
          agent-bom scan \
            --enrich \
            --fail-on-severity high \
            --fail-on-kev \
            --policy policy.json \
            -f sarif -o results.sarif \
            -q

      - name: Upload to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### 3. Container Image Gate

Scan the built image before pushing to registry:

```yaml
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan image for AI supply chain CVEs
        run: |
          agent-bom scan \
            --image myapp:${{ github.sha }} \
            --enrich \
            --fail-on-severity high \
            -f sarif -o image-scan.sarif \
            -q
```

### 4. Pre-install Package Check

Before adding a new MCP server or package:

```bash
# Check a specific package before installing
agent-bom check express@4.18.2 -e npm
agent-bom check langchain@0.1.0 -e pypi
```

**Decision point**: If the package has CRITICAL CVEs, do not install. If MEDIUM, review blast radius before proceeding.

### 5. Policy File

Create `policy.json` in your repository root:

```json
[
  {
    "id": "no-critical-cves",
    "severity_gte": "CRITICAL",
    "action": "fail"
  },
  {
    "id": "no-unverified-servers-with-vulns",
    "unverified_server": true,
    "severity_gte": "HIGH",
    "action": "fail"
  },
  {
    "id": "warn-excessive-tools",
    "min_tools": 6,
    "action": "warn"
  },
  {
    "id": "block-kev",
    "severity_gte": "HIGH",
    "action": "fail"
  }
]
```

### 6. Kubernetes Admission Gate

Scan before deploying to K8s:

```yaml
      - name: Scan K8s manifests
        run: |
          # Extract images from manifests
          images=$(grep -r "image:" k8s/ | awk '{print $2}' | sort -u)

          # Scan each image
          args=""
          for img in $images; do
            args="$args --image $img"
          done

          agent-bom scan $args \
            --enrich \
            --fail-on-severity high \
            -f json -o k8s-scan.json \
            -q
```

### 7. SBOM Ingestion Gate

If upstream provides an SBOM, scan it:

```bash
agent-bom scan --sbom vendor-sbom.cdx.json --enrich --fail-on-severity high -q
```

### 8. Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no violations |
| `1` | Fail — vulnerabilities or policy violations found |

Use exit code 1 to block the pipeline.

## Outputs

| Artifact | Purpose |
|----------|---------|
| `results.sarif` | GitHub Security tab (visible on PR) |
| `scan.json` | Machine-readable for downstream tools |
| Exit code | Pipeline pass/fail signal |

## Pipeline Architecture

```
   Code Push / PR
        │
        ▼
   ┌─────────────┐
   │ Build Image  │
   └──────┬──────┘
          │
          ▼
   ┌──────────────────────┐
   │  agent-bom scan       │
   │  --image --enrich     │
   │  --fail-on-severity   │
   │  --policy policy.json │
   └──────┬───────────────┘
          │
     ┌────┴────┐
     │         │
  exit 0    exit 1
     │         │
     ▼         ▼
  Deploy    Block +
  to Prod   SARIF Report
```
