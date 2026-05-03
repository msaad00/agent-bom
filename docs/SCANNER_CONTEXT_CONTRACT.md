# Scanner Context Contract

agent-bom's IaC scanner runs identically across deployment contexts —
standalone installs, Snowflake Native Apps, GitHub Actions, MCP tool calls.
What changes across contexts is **scope exposure**, not capability count.

This document describes how that is implemented and how to extend it.

---

## The two-gate model

Every scanner is evaluated against two orthogonal gates on each scan run,
applied in order:

```
Gate 1 — Authorization     Is this scanner in enabled_scanners?
              │
              ▼  NO → verdict: "disabled"   (never inspects files)
              │
              ▼  YES
Gate 2 — Applicability     Did the scanner match any files during the walk?
              │
              ▼  NO → verdict: "not-applicable"
              │
              ▼  YES → verdict: "ran", files_scanned = N
```

The gates are **orthogonal**: a scanner can be authorized but find nothing
(expected in a Terraform-only repo for the Dockerfile scanner), or it can be
locked out even when files exist (e.g. Snowflake Native App restricting scans
to DCM only).

---

## ScanContext

```python
from agent_bom.iac.models import ScanContext

ScanContext(
    deployment_mode="standalone",   # "standalone" | "native-app" | "github-action" | "mcp"
    enabled_scanners=None,          # None = all unlocked; frozenset = explicit allowlist
)
```

`deployment_mode` is recorded in verdicts and surfaced to callers for
rendering — it does not change scanner logic.

`enabled_scanners` is the authorization gate. `None` unlocks everything
(the default). A frozenset is an explicit allowlist; any scanner whose ID is
absent is locked out and emits `"disabled"`.

---

## ScanResult and ScannerVerdict

```python
from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.models import ScanContext

result = scan_iac_with_context("/path/to/project", ScanContext())
result.findings   # list[IaCFinding] — identical to scan_iac_directory()
result.verdicts   # list[ScannerVerdict] — one per scanner, always
```

Each `ScannerVerdict`:

| Field | Type | Description |
|---|---|---|
| `scanner_id` | `str` | `"helm"`, `"dockerfile"`, `"terraform"`, `"dcm"`, `"kubernetes"`, `"cloudformation"` |
| `status` | `str` | `"ran"` \| `"not-applicable"` \| `"disabled"` |
| `files_scanned` | `int` | > 0 only when status is `"ran"` |
| `reason` | `str` | Human-readable; set for `"not-applicable"` and `"disabled"` |

---

## Deployment contexts

### Standalone (bare-metal, Docker, Kubernetes, CI/CD)

```python
ctx = ScanContext(deployment_mode="standalone")
```

All scanners unlocked. Verdicts reflect what file types actually exist in the
scanned directory.

### Snowflake Native App (SPCS)

```python
ctx = ScanContext(
    deployment_mode="native-app",
    enabled_scanners=frozenset({"dcm", "terraform"}),
)
```

Bare-metal/OS-level scanners (Dockerfile, Kubernetes manifests) will naturally
emit `"not-applicable"` because there are no matching files inside SPCS. The
DCM scanner covers customer schema-as-code migrations; Terraform covers IaC
staged in artifact stages.

No special handling is required — the same codebase runs unchanged; scope
exposure differs, not capability count.

### GitHub Actions

The `GITHUB_ACTIONS=true` environment variable is detected automatically by
the CLI and sets `deployment_mode="github-action"`. SARIF output carries the
deployment mode in `tool.driver.properties`.

### MCP tool calls

`AGENT_BOM_MCP_MODE=1` sets `deployment_mode="mcp"`. MCP clients may pass
`enabled_scanners` as a tool argument to restrict which scanners run, giving
the LLM agent fine-grained control over scan scope.

---

## CLI rendering

The scanner capability table is emitted with `--verbose`:

```
  Scanner capability
  ✓  dcm                3 file(s)
  ✓  terraform          12 file(s)
  —  kubernetes         no targets
  —  dockerfile         no targets
  —  helm               no targets
  ✗  cloudformation     locked out by deployment context (native-app)
```

- `✓` green — `"ran"`
- `—` dim — `"not-applicable"`
- `✗` red — `"disabled"`

---

## Backward compatibility

`scan_iac_directory(root)` is unchanged and continues to return
`list[IaCFinding]`. It delegates to `scan_iac_with_context` internally and
discards the verdicts. Existing callers require no changes.

---

## Adding a new scanner

1. Implement `scan_<name>(path: Path) -> list[IaCFinding]` in a new module
   under `src/agent_bom/iac/`.
2. Add the scanner ID to `_SCANNER_IDS` in `src/agent_bom/iac/__init__.py`.
3. Add a dispatch branch in the walk loop inside `scan_iac_with_context`,
   incrementing `files_matched[scanner_id]` before calling the scanner.
4. Add tests in `tests/test_scanner_context.py` following the existing pattern.

No `probe()` function is required. Applicability tracking happens automatically
during the single directory walk.
