# Code Map: where does my code go?

A short guide for contributors. It answers one question: **which directory owns
the change I want to make?** For the full repository map, see
[`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md). For the layer diagram, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## The one rule that CI enforces

New Python code goes into a **subpackage** of `src/agent_bom/`, never into a
new `src/agent_bom/<name>.py` file. The flat top-level namespace is frozen by
`scripts/check_package_layout.py`, which runs in CI. If you add a top-level
module, the check fails, names the file, and suggests a subpackage:

```text
error: new top-level module(s) under src/agent_bom/. The flat namespace is frozen; add code to a subpackage instead:
  + mcp_widget.py  -> try src/agent_bom/mcp_tools/
See docs/CODE_MAP.md for which subpackage owns what. Ask in the PR if none fits.
```

Run it locally with `python scripts/check_package_layout.py`. It needs only the
standard library.

## Pick a home by what you are changing

| You are adding or fixing… | Put it in | Look at first |
|---|---|---|
| A CLI command or flag | `cli/` | `cli/agents/__init__.py` (scan path), `cli/_scanner_registry.py` |
| A REST endpoint | `api/routes/` (one module per area) | `api/server.py`; storage adapters in `api/storage/` |
| An MCP tool | `mcp_tools/` (one module per tool family) | `mcp_tools/scanning.py`, `mcp_tools/graph.py` |
| A package ecosystem or lockfile parser | `parsers/` | `parsers/python_parsers.py`, `parsers/node_lockfiles.py` |
| An importer for another scanner's output (SARIF, SBOM, scanner JSON) | `parsers/` | `parsers/external_scanners.py`, `parsers/external_import.py`, `parsers/sarif.py` |
| A vulnerability source or matcher | `scanners/` | `scanners/registry.py` |
| An IaC misconfiguration rule | `iac/` | `iac/dockerfile_rules.py`, `iac/cloudformation_rules.py`, `iac/terraform_security_*.py` |
| A cloud inventory or CIS benchmark check | `cloud/` | `cloud/aws_cis/` (one module per control family), `cloud/azure_cis/`, `cloud/gcp_cis/` |
| Non-human identity discovery (Okta, Entra) | `identity/` | `identity/__init__.py` |
| A new MCP client or agent config location | `discovery/` | `discovery/__init__.py` (`CONFIG_LOCATIONS`) |
| A graph node, edge, projection or traversal | `graph/` | `graph/container.py`, `graph/types.py`, `graph/builder.py` |
| A runtime detector, proxy or gateway behavior | `runtime/` | `runtime/detectors.py`, `runtime/patterns.py`, `runtime/gateway_relay.py` |
| An output format (SARIF, CycloneDX, HTML, …) | `output/` | existing formatter for the closest format |
| Severity, CVSS, version ordering, tenancy rules | `core/` | `core/severity.py`, `core/cvss.py`, `core/versions/` |
| Finding merge or remediation logic shared by many layers | `domain/` | `domain/finding_merge.py` |
| SIEM, ticketing or SaaS connectors | `siem/`, `ticketing/`, `connectors/`, `integrations/` | the sibling connector closest to yours |
| Language analysis for SAST and reachability | `ast/` | `ast/__init__.py` |
| An MCP registry entry | `mcp_registry.json` (data, not code) | neighbouring entries; keep `_total_servers` in sync |
| Dashboard UI | `ui/` (Next.js) | `ui/app/`, `ui/components/`, `ui/lib/` |

If two homes look plausible, choose the lower layer (see below) and say why in
the PR. Maintainers would rather discuss placement early than move code later.

## Canonical models

- **Finding**: `finding.py` defines `Finding`, the unified finding model.
  `FindingType` covers CVEs, CIS failures, credential exposure, SAST, runtime
  detections, skill risk and more. Emit `Finding` objects rather than defining
  a new result shape; add a `FindingType` only for a genuinely new category.
- **Packages and vulnerabilities**: `models.py` defines `Package`,
  `Vulnerability`, `Agent`, `MCPServer` and `BlastRadius`, the inventory side of
  a scan.
- **Graph**: `graph/container.py` defines `UnifiedGraph`. Entity and relationship
  enums live in `graph/types.py`; `graph/builder.py` builds the graph from a
  report. `context_graph.py` is a legacy bridge, so new graph features belong in
  `graph/` ([`GRAPH_MIGRATION.md`](GRAPH_MIGRATION.md)).
  HTTP graph contracts and OpenAPI evidence schemas live in
  `api/graph_contracts.py`; pure path cards, finding/identity links and path
  serialization live in `api/graph_presentation.py`. The route module retains
  authentication context, tenant scope, admission, generation checks and store
  calls. These presentation modules consume the canonical graph entities; they
  do not define parallel asset or identity models.

## Layering rules in plain language

`scripts/check_architecture.py` (with `scripts/check_import_graph.py`) enforces
these rules. [`ARCHITECTURE_BOUNDARIES.md`](ARCHITECTURE_BOUNDARIES.md) has the
details.

1. **`core/` imports only `core/`.** It holds shared security semantics
   (severity, CVSS, package identity, versions, tenancy) with no I/O at import
   time. Reuse those helpers instead of reimplementing thresholds. The check
   pins functions such as `normalize_severity` and `cvss_to_severity` to their
   owning module.
2. **Dependencies point down.** Domain code (`domain/`, `models.py`,
   `finding.py`) sits below `graph/`, `api/`, `cloud/`, `scanners/` and
   `output/`, and never imports them.
3. **`api/` never imports `cli/`.** If both need some logic, move it below both.
4. **Graph projections and ports do not import storage or API adapters.**
5. **No new module-level import cycles.** The largest runtime import tangle may
   only shrink.
6. **Size and complexity ratchet.** New code targets 600 lines per file,
   80 lines per function and complexity 15. Existing excess is recorded in
   `scripts/architecture-baseline.json` and may only shrink.
7. **Settings come from typed owners.** Read environment variables through
   `config.py` or `core/settings.py`, not `os.environ` scattered through modules.

## Legacy flat modules

The top-level files in `src/agent_bom/*.py` predate the package layout. They
still work and are imported widely, so **do not move them in a feature PR**. A
migration PR that moves one into a package (keeping a re-export at the old path
if needed) and deletes its name from `ALLOWED_TOP_LEVEL_MODULES` is welcome.

| Family | Examples | Likely home |
|---|---|---|
| MCP server and helpers | `mcp_server*.py`, `mcp_*.py` | `mcp_tools/` or a future `mcp/` package |
| Runtime enforcement | `proxy*.py`, `gateway*.py`, `firewall*.py`, `shield.py`, `enforcement.py` | `runtime/` |
| Source analysis | `ast_*.py`, `sast.py`, `js_ts_ast.py` | `ast/` |
| Compliance frameworks | `owasp*.py`, `nist_*.py`, `mitre_*.py`, `soc2.py`, `iso_27001.py`, `compliance_*.py` | a future `compliance/` package |
| Enrichment and intel | `enrichment*.py`, `intel_*.py`, `atlas*.py`, `exploitability.py` | `scanners/` or a future `intel/` package |
| Graph bridge | `context_graph.py`, `graph_schema.py`, `graph_backend.py` | `graph/` |

The allowlist in `scripts/check_package_layout.py` is the authoritative list.
