# OCSF boundary

**Principle:** OCSF (Open Cybersecurity Schema Framework) is an **optional
wire-protocol for SIEM interop**, not agent-bom's internal data model.

## What this means

1. **Core scanning, enrichment, graph, and reporting code does not depend
   on OCSF.** If the two OCSF modules (`siem/ocsf.py`,
   `output/ocsf.py`) were deleted tomorrow, every core path still works
   — cloud scans, CIS benchmarks, CVE enrichment, skill audits,
   blast-radius graph queries, HTML / JSON / SARIF / CycloneDX
   reporting. You would lose SIEM push and the MCP tool's OCSF event
   output; everything else is unchanged.
2. **Internal schemas are product-shaped, not OCSF-shaped.** Each
   finding source keeps the dataclass that best models its domain:
   - `CISCheckResult` — check_id, status, evidence, resource_ids, remediation
   - `SkillFinding` — category, context, ai_analysis, ai_adjusted_severity
   - `Finding` (graph) — blast_radius, reachability, kev, epss_percentile
   - `RuntimeAlert` — alert dict from proxy / MCP tool telemetry

   Forcing these into OCSF would drop fields OCSF does not model
   (`ai_analysis`, `blast_radius`, `reachability`) and is the wrong
   direction.
3. **Per-cloud code stays cloud-native.** AWS API response →
   `CISCheckResult` directly. Azure / GCP / Snowflake the same. No
   AWS-→-OCSF-→-internal double hop. OCSF only appears on the way out to
   a SIEM.
4. **OCSF emission is one-way, at the wire boundary.** Translators live
   in `siem/ocsf.py` (SIEM push, Detection Finding, `class_uid=2004`)
   and `output/ocsf.py` (MCP tool output, Security Finding,
   `class_uid=2001`). Runtime alerts are the only source currently
   translated; CIS / skills / CVE findings stay in internal JSON today.

## What is allowed to depend on OCSF

- `siem/` — connector layer, may freely import OCSF.
- `output/ocsf.py` — OCSF serializer for MCP tool callers.
- `graph/ocsf.py` — a thin mapping table (`EntityType` → OCSF
  `category_uid` / `class_uid`) plus `ocsf_type_uid()`. The graph Node
  dataclass carries the resulting IDs as inert fields (reserved seats
  for SIEM export). **No core logic branches on these fields.**
- `graph/severity.py` — `OCSFSeverity` IntEnum (UNKNOWN=0 … CRITICAL=5)
  used as a stable integer severity scale. Coincidence of convention,
  not a dependency; would stay even without OCSF.

## What is **not** allowed to depend on OCSF

Anything under `scan`, `enrichment`, `parsers`, `cli`, `cloud`
(CIS benchmarks and cloud asset models), `skills`, `analyzers`,
`api`, `dashboard`, `db`, `ingestion` must not import from
`agent_bom.siem.ocsf` or `agent_bom.output.ocsf`. These modules
describe product behaviour; OCSF is an export format, not a product
concept.

**Enforcement:** a reverse-import check can be added to CI (
`grep -r "from agent_bom.siem.ocsf\|from agent_bom.output.ocsf" src/
| grep -v "^src/agent_bom/siem/\|^src/agent_bom/output/ocsf.py"`
should return zero lines).

## When to add a new OCSF translator

Only when a real customer / integration asks. Do **not** pre-emptively
author:

- CIS → Compliance Finding (`class_uid=2003`)
- Skill → Security Finding (`class_uid=2001`)
- CVE / SAST → Vulnerability Finding (`class_uid=2002`)
- Inbound OCSF-→-internal normalizer

These are legitimate follow-ups if and when a SIEM / XDR / Security
Lake integration needs them. Until then they are speculative work and
should stay off the roadmap.

## Why keep OCSF at all

AWS Security Lake, Google Chronicle, and Microsoft Sentinel all
standardize on OCSF. Dropping it eliminates a real enterprise-buyer
checkbox for ~130 lines of optional code. Keeping it as an opt-in
peripheral costs effectively zero and preserves integration upside.
