# Quick wins roadmap (validated 2026-07-06)

Ranked by value-per-effort. Each item was checked against the current codebase.
Claims marked **extend** build on shipped modules; **unify** closes a wiring gap;
**net-new** is honest greenfield.

For language reachability status see the reachability matrix in open issues
[#3242](https://github.com/msaad00/agent-bom/issues/3242) /
[#3499](https://github.com/msaad00/agent-bom/issues/3499).

---

## Sequencing

| Series | Items | Target |
|--------|-------|--------|
| Evidence intake parity | #1, #2 | Single PR series |
| Shadow MCP discovery | #3, #4 | Presentation + default-on process sweep |
| Docs / positioning | #7, #8 | Same-day docs PR |
| Runtime policy | #6 | Incremental schema PR |
| Fix automation | #5 | GH Action + CLI polish |

**In flight (reachability):** Gradle-only Java symbol join (reuse Maven coord map from
`parse_gradle_packages` when `pom.xml` is absent).

---

## 1. Generic SARIF ingest → SAST parity via integration

**Verdict:** **Unify** (partial today) — highest leverage.

| Exists | Gap |
|--------|-----|
| `compliance_hub_ingest.ingest_sarif_findings()` → `Finding` stream for compliance hub | Not wired into `parsers/external_scanners.detect_and_parse` or the main `agent-bom agents` scan path |
| `external_scanners.py` auto-detects Trivy / Grype / Syft JSON | No Semgrep / CodeQL / Bandit SARIF in the same ingest lane |
| SARIF **export** (`output/sarif.py`) | Ingest ≠ export |

**Work:** One parser (or reuse `_parse_sarif_findings` from SAST module) + `detect_and_parse`
branch + `findings push` / CLI flag docs.

**Outcome:** “Bring any SAST scanner output into the same graph, blast radius, and compliance evidence.”

---

## 2. CSAF and CycloneDX VEX ingest

**Verdict:** **Extend** — enterprise checkbox.

| Exists | Gap |
|--------|-----|
| `vex.py` — `load_vex`, `apply_vex`, OpenVEX export | OpenVEX JSON only |
| Triage auto-`not_affected` on `unreachable` symbol reach (#3577) | No CSAF / CycloneDX VEX parse |

**Work:** Parse-and-map into `VexDocument` / `VexStatement` (1–2 days).

---

## 3. “Verified MCP server” badge in inventory output

**Verdict:** **Extend** — mostly presentation.

| Exists | Gap |
|--------|-----|
| `MCPServer.registry_verified`, registry cross-ref (`mcp_registry.json`, Smithery, Glama sync) | Not a first-class badge in default CLI table / dashboard server row |
| `trust_score.py` penalty for unverified | Operators must infer from trust score |
| Policy rule `unverified_server` | No explicit `verified` / `known-publisher` / `unknown` enum surfaced |

**Work:** Scoring field + CLI/HTML/JSON column; reuse data already fetched.

---

## 4. Process / port-based shadow-MCP detection

**Verdict:** **Extend** — audit overstated “config only.”

| Exists | Gap |
|--------|-----|
| `discovery.discover_mcp_processes()` via **psutil** (opt-in `include_processes`) | Off by default; requires `psutil` extra |
| Editor/agent config parsers | No listening-port sweep for localhost MCP HTTP/SSE |
| `ai_components` “shadow AI” (undeclared SDK imports) | Different problem than shadow **servers** |

**Work:** Default-on process discovery in fleet agent profile; optional port listener pass;
defer full EDR/browser telemetry.

---

## 5. Fix-PR emission from remediation plans

**Verdict:** **Extend** — last mile is CI, not core logic.

| Exists | Gap |
|--------|-----|
| `remediation.py`, `remediation_apply.apply_remediation_plan(..., open_pr=True)` | No first-class GitHub Action step |
| `agent-bom remediate --open-pr` (CLI) | Not documented as the default fix-PR motion |
| `pr_url` on `RemediationApplyOutcome` | No evidence attachment template in PR body |

**Work:** GH Action job + PR body with blast-radius / finding links.

---

## 6. Attribute conditions on firewall / gateway rules

**Verdict:** **Net-new** on schema — skeleton exists.

| Exists | Gap |
|--------|-----|
| `firewall.py` pairwise allow / deny / warn | No tenant, tool-class, time window, or agent identity conditions |
| `proxy_policy.py` | Same flat rule model |

**Work:** Incremental condition fields + evaluation; no Cedar engine required for v1.

---

## 7. Docs: bless Trivy-ingest for VM images and registries

**Verdict:** **Docs only** — capability exists, legibility gap.

| Exists | Gap |
|--------|-----|
| `findings push` + `detect_and_parse` (Trivy/Grype/Syft) documented in `site-docs/reference/cli.md` | No “VM image / registry → Trivy → agent-bom” first-command path |
| Container image scan lane | Not positioned as the supported enterprise VM matrix row |

**Work:** One doc page: first command → artifact → next step (zero code).

---

## 8. Positioning: surface the FinOps lane

**Verdict:** **Docs only** — capability-framed.

| Exists | Gap |
|--------|-----|
| `agent-bom cost forecast`, `docs/COST_MODEL.md`, OTel GenAI usage paths | One table row in README; not a product lane in brief/docs site |
| MCP `cost_forecast` tool | Nearly invisible in buyer-facing narrative |

**Work:** README + docs site section with real command output screenshot.

---

## Validation notes (honest gaps)

- **Scanner breadth ≠ AST:** Package/OS/container coverage (npm, deb, rpm, apk, OCI, …) is
  separate from `--project` function-level symbol join (Python/npm/Go strong; Java/Rust/C#/Ruby
  conservative regex).
- **#1 is not greenfield SARIF** — compliance hub already ingests SARIF; the win is
  **unifying** into the main scan and external-scanner detect path.
- **#4 is not greenfield** — psutil process discovery ships; needs default-on + ports.
- **#5 is not greenfield** — `open_pr` exists; needs Action + positioning.
