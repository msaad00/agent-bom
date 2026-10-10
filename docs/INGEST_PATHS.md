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

SARIF is auto-detected by the shared typed importer. For **full scan
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

The importer retains file, line, rule and scanner provenance as SAST findings.
Control-plane persistence applies its existing redaction policy to raw paths and
evidence; stable finding and asset identities preserve correlation.
Dependency findings use the package coordinates supplied by the report. Missing
package identities or versions remain unresolved evidence; source files never
become synthetic packages. The same rules apply to MCP `ingest_external_scan`.
A push has no local inventory against which to resolve a name-only dependency;
use `--external-scan` alongside a project when that correlation is needed.

SAST findings map to the secure-development outcome PR.PS-06 in
[NIST CSF 2.0, Appendix A](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).
This is a finding-to-control association, not a compliance certification.

After ingestion, `GET /v1/overview` reports the vulnerability metric as **open
CVE findings**: current, open occurrences with a CVE identifier or validated
CVE alias. The same CVE on two assets is two findings. SAST, misconfigurations
and advisories with no retained CVE identity still contribute to overall
posture, but do not inflate this metric. Validated CVE aliases survive hub
persistence; arbitrary alias strings are not retained.

The metric's severity histogram and KEV count use the same selected rows.
`count_exact: false` marks a lower bound when the bounded hub read is incomplete
or scan rows have been compacted; `evidence_status` explains the missing
coverage. An incomplete zero has status `unknown`, not a clean verdict.

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

## Prowler / AWS Security Hub

Cloud posture reports are auto-detected on both lanes. Prowler JSON-OCSF
(`prowler aws --output-formats json-ocsf`) and Security Hub ASFF
(`aws securityhub get-findings --output json`) import as cloud posture findings
with account, region, resource ARN, vendor compliance references and
tool provenance; Security Hub vulnerability records import as CVE findings.

```bash
agent-bom agents --external-scan prowler-output.ocsf.json -f json -o report.json
agent-bom findings push securityhub.json --api-url https://agent-bom.internal.example.com \
  --api-key "$AGENT_BOM_API_KEY" --source securityhub
```

PASS, muted, archived, suppressed and resolved records are skipped and counted
in a scan notice. Field mapping, skip rules and the importer contract for
adding another scanner are in [Scanner importers](IMPORTERS.md).

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
- Quick wins roadmap: [ROADMAP_QUICK_WINS.md](archive/ROADMAP_QUICK_WINS.md) (archived)

## Page MCP scan results across workers

Call `scan(offline=True)` for a summary and `result_id`, then call
`scan(result_id="...", section="findings", offset=0, limit=25)` to retrieve
bounded pages of the redacted report. SQLite uses `mcp-scan-results.db` under
`AGENT_BOM_STATE_DIR`; local workers must share that directory. For replicas
on separate hosts, configure `AGENT_BOM_POSTGRES_URL` (or a Postgres
`AGENT_BOM_DB`) and run the deployment's Alembic migration before starting them.

The server's MCP tenant binding controls scope. HTTP reads require the same
verified bearer token that created the result; changing or revoking that token
removes access to its earlier result IDs. Stdio processes share their OS user's
local scope. Client-supplied IDs or metadata cannot select another caller.

By default, each tenant retains at most four results for 30 minutes, with a
128 MiB limit per serialized report. Configure count/TTL through
`AGENT_BOM_MCP_SCAN_RESULT_CACHE_SIZE` and `AGENT_BOM_MCP_SCAN_RESULT_TTL_SECONDS`.
Expired results cannot be read and are removed on the next successful write for
that tenant; this cache is not an audit archive. Eviction is transactional.
Missing migrations and unavailable storage fail closed, without an in-memory
fallback. Older binaries ignore the additive table on rollback.


## Upgrade finding ingest storage

Before upgrading an existing control plane, stop and drain every API, worker,
connector and MCP process that writes findings, then take a restorable database
backup. Mixed old/new writers and direct SQL ledger mutations are unsupported:
older writers do not maintain the transaction-owned tenant counters.

For PostgreSQL, run `alembic -c deploy/supabase/postgres/alembic.ini upgrade head`
with the migration-owner connection configured through `ALEMBIC_DATABASE_URL`.
Revision `20260929_01` creates the RLS-protected ingest state. The ordinary app
role cannot read or mutate another tenant's counters; an unbound write fails
closed. Use the separate maintenance role for authorized tenant cleanup.
The bootstrap SQL still requires the full Alembic migration chain.

SQLite upgrades on store initialization inside a writer-excluding transaction.
Schema version 3 repairs historical duplicate ordinals, preserves finding
payloads and current-state pointers, and enforces unique tenant ordinals.
Restart pagination from the first page after upgrading; saved pre-upgrade
cursors may reference moved ordinals. Allow space and downtime for the one-time
repair and index build on the existing ledger.

Restart compatible writers only after migration succeeds. Ingest totals are
captured inside the committing transaction; later concurrent writes may change
the total after a response is produced. First ingest per existing tenant reads
its count and maximum ordinal once. Subsequent batches use indexed durable
state, and ledger/current/reference/counter writes roll back together on error.
Clearing a tenant preserves SQLite's ordinal high-water mark.

Verify with a bounded ingest, an idempotent replay, and paged finding reads
before resuming all producers. To roll back, drain writers again and restore
the pre-upgrade backup with its compatible application version; the PostgreSQL
migration intentionally has no destructive downgrade. Transaction atomicity
does not establish independent audit retention or acknowledged-write survival
under host/storage loss. SQLite WAL uses NORMAL synchronous mode; replication,
backup recovery, failover and power-loss durability require separate qualification.
