# Quick wins queue (internal, validated 2026-07-06)

Operator-facing priority queue — **not** published on the docs site. Track customer-facing
progress via GitHub issues [#3242](https://github.com/msaad00/agent-bom/issues/3242) and
[#3499](https://github.com/msaad00/agent-bom/issues/3499).

Ranked by value-per-effort. Claims marked **extend** build on shipped modules; **unify**
closes a wiring gap; **net-new** is honest greenfield.

---

## Sequencing

| Series | Items | Status |
|--------|-------|--------|
| Evidence intake parity | #1, #2 | **Shipped** (#3585, #3586) |
| Shadow MCP discovery | #3, #4 | #3 shipped (#3587); #4 open |
| Docs / positioning | #7, #8 | **Shipped** (#3587) |
| Runtime policy | #6 | Open |
| Fix automation | #5 | Open |

---

## 1. Generic SARIF ingest → SAST parity via integration

**Verdict:** **Shipped** (#3585, docs #3587).

| Exists | Gap |
|--------|-----|
| `compliance_hub_ingest.ingest_sarif_findings()` → `Finding` stream for compliance hub | — |
| `external_scanners.py` auto-detects Trivy / Grype / Syft / SARIF JSON | — |
| `agent-bom agents --external-scan <file>` full scan depth | Compliance hub-only ingest without `--external-scan` still a separate lane |
| SARIF **export** (`output/sarif.py`) | Ingest ≠ export (by design) |

**Outcome:** Bring any SAST scanner SARIF into graph, blast radius, and compliance evidence via `--external-scan`. See `docs/INGEST_PATHS.md`.

---

## 2. CSAF and CycloneDX VEX ingest

**Verdict:** **Shipped** (#3586).

| Exists | Gap |
|--------|-----|
| `vex.py` — `load_vex`, `apply_vex`, OpenVEX export | — |
| CycloneDX + CSAF VEX branches in `load_vex` | — |
| Triage auto-`not_affected` on `unreachable` symbol reach (#3577) | — |

---

## 3. “Verified MCP server” badge in inventory output

**Verdict:** **Shipped** (#3587) — JSON + CLI tree badge.

| Exists | Gap |
|--------|-----|
| `registry_verified` + `registry_badge` in default JSON (`to_json`) | Dashboard server row still lacks explicit badge (UI follow-up) |
| CLI dependency tree shows `✓ registry` / `unknown registry` | — |

---

## 4. Process / port-based shadow-MCP detection

**Verdict:** **Extend** — audit overstated “config only.”

| Exists | Gap |
|--------|-----|
| `discovery.discover_mcp_processes()` via **psutil** (opt-in `include_processes`) | Off by default; requires `psutil` extra |
| Editor/agent config parsers | No listening-port sweep for localhost MCP HTTP/SSE |

**Work:** Default-on process discovery in fleet agent profile; optional port listener pass.

---

## 5. Fix-PR emission from remediation plans

**Verdict:** **Extend** — last mile is CI, not core logic.

**Work:** GH Action job + PR body with blast-radius / finding links.

---

## 6. Attribute conditions on firewall / gateway rules

**Verdict:** **Net-new** on schema — skeleton exists.

**Work:** Incremental condition fields + evaluation; no Cedar engine required for v1.

---

## 7. Docs: bless Trivy-ingest for VM images and registries

**Verdict:** **Shipped** (#3587) — `docs/INGEST_PATHS.md` + site-docs CLI updates.

---

## 8. Positioning: surface the FinOps lane

**Verdict:** **Shipped** (#3587) — README + site-docs quickstart lane.

---

## Validation notes (honest gaps)

- **Scanner breadth ≠ AST:** Package/OS/container coverage is separate from `--project`
  function-level symbol join.
- **#4 is not greenfield** — psutil process discovery ships; needs default-on + ports.
- **#5 is not greenfield** — `open_pr` exists; needs Action + positioning.
