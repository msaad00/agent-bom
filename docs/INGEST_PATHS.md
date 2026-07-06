# Evidence ingest paths

First-command map for bringing external scanner output into agent-bom. Every
path normalizes into the same `Finding` / blast-radius model; the difference is
**where** enrichment runs and **what** artifact you get back.

## Quick pick

| Goal | First command | Artifact | Next step |
|------|---------------|----------|-----------|
| Full local scan depth (blast radius, graph, SBOM) | `agent-bom agents --external-scan <file>` | JSON / SARIF / HTML on disk | `agent-bom graph`, `agent-bom remediate`, or push to control plane |
| Bulk findings into a running control plane | `agent-bom findings push <file> --api-url …` | Rows in `GET /v1/findings` | Dashboard `/findings`, triage queue, compliance hub |
| VM / registry image only | Trivy → agent-bom (below) | Same as row above | See [VM and registry matrix](#vm-and-registry-matrix) |

## SARIF (SAST / Semgrep / CodeQL / Bandit)

SARIF is auto-detected by `detect_and_parse` (shipped #3585). For **full scan
depth** — package graph, blast radius, compliance mapping, and local exports —
ingest through the main scan path:

```bash
# After your SAST tool writes findings.sarif
agent-bom agents --external-scan findings.sarif -f json -o report.json
agent-bom agents --external-scan findings.sarif -f sarif -o merged.sarif
```

`--external-scan` merges the external report with any discovered MCP agents,
runs CVE enrichment, and emits the complete AI-BOM envelope. It does **not**
require a running control plane.

For **control-plane-only** intake (no local blast-radius pass), push normalized
or auto-detected scanner JSON instead:

```bash
agent-bom findings push findings.sarif \
  --api-url https://agent-bom.internal.example.com \
  --api-key "$AGENT_BOM_API_KEY"
```

## Trivy / Grype / Syft JSON

Both lanes accept Trivy, Grype, and Syft output via format auto-detection.

**Local full scan:**

```bash
trivy image --format json -o trivy.json my.registry/app:1.2.3
agent-bom agents --external-scan trivy.json -f json -o report.json
```

**Control-plane bulk push:**

```bash
agent-bom findings push trivy.json \
  --api-url https://agent-bom.internal.example.com \
  --api-key "$AGENT_BOM_API_KEY" \
  --source trivy
```

## `findings push` vs `--external-scan`

| | `agent-bom agents --external-scan <file>` | `agent-bom findings push <file>` |
|---|---|---|
| Requires control plane | No | Yes (`--api-url` + credentials) |
| Blast radius / graph | Yes — full local scan pipeline | No — findings rows only |
| MCP agent discovery | Merged with local agent context | N/A |
| Best for | CI gates, local reports, air-gap | Fleet queue, dashboard triage, MCP bulk ingest |

Honest limitation: `findings push` is the right headless path when operators
already run agent-bom as a control plane and want findings in the unified queue
without re-running enrichment on the laptop. `--external-scan` is the right path
when you need the same depth as `agent-bom agents -p .` but the primary signal
is an external scanner file (SARIF, Trivy, Grype, Syft).

## VM and registry matrix

Enterprise VM and registry coverage uses the same Trivy → agent-bom chain; agent-bom
does not replace the scanner — it ingests and correlates.

```bash
# 1. Scan a VM disk snapshot or golden image (read-only mount)
trivy rootfs --format json -o vm-rootfs.json /mnt/vm-disk

# 2. Full local depth
agent-bom agents --external-scan vm-rootfs.json -f json -o vm-report.json

# Or push to control plane for fleet triage
agent-bom findings push vm-rootfs.json \
  --api-url https://agent-bom.internal.example.com \
  --api-key "$AGENT_BOM_API_KEY" \
  --source trivy
```

Registry sweep (read-only, cloud credentials required):

```bash
# Enumerate and scan every tag in ECR / ACR / GAR
agent-bom cloud registry-scan --provider ecr --region us-east-1

# Or scan one image locally, then ingest
trivy image --format json -o trivy.json 123456789.dkr.ecr.us-east-1.amazonaws.com/app:latest
agent-bom agents --external-scan trivy.json -f json -o report.json
```

Container-first scans can also use `agent-bom image <ref>` when you want
agent-bom to orchestrate the pull and scan without a separate Trivy invocation.

## Related docs

- CLI reference: [site-docs/reference/cli.md](../site-docs/reference/cli.md)
- CLI map: [CLI_MAP.md](CLI_MAP.md)
- FinOps lane: [COST_MODEL.md](COST_MODEL.md)
- Quick wins roadmap: [ROADMAP_QUICK_WINS.md](ROADMAP_QUICK_WINS.md)
