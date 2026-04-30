# `agent-bom remediate` Output Contract

Use this page when you need the machine-readable contract for
`agent-bom remediate`.

The command supports:

- `console`
- `json`
- `markdown`

The only format intended as a stable automation contract is `json`.

## Example command

```bash
agent-bom remediate -p . --format json --output plan.json
```

Optional grouping:

```bash
agent-bom remediate -p . --format json --server-group --output plan.json
```

## Top-level JSON shape

```json
{
  "version": "0.83.1",
  "generated_at": "2026-04-21T12:00:00+00:00",
  "remediation_plan": [],
  "summary": {
    "total_items": 0,
    "fixable": 0,
    "unfixable": 0,
    "p1_count": 0,
    "p2_count": 0,
    "p3_count": 0,
    "p4_count": 0
  }
}
```

When `--server-group` is set, one additional top-level field is present:

```json
{
  "server_groups": {
    "jira": ["urllib3", "requests"],
    "github": ["openssl"]
  }
}
```

## Per-item schema

Each entry in `remediation_plan` has this shape:

```json
{
  "package": "requests",
  "ecosystem": "pypi",
  "current_version": "2.28.0",
  "fixed_version": "2.32.0",
  "priority": "P1",
  "action": "",
  "command": "pip install 'requests>=2.32.0'",
  "verify_command": "agent-bom check requests@2.32.0 --ecosystem pypi",
  "max_severity": "high",
  "blast_radius_score": 7.5,
  "impact": 1,
  "vulnerabilities": ["CVE-2024-0001"],
  "affected_agents": ["mac-laptop-1"],
  "exposed_credentials": [],
  "exposed_tools": [],
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
  "has_kev": false,
  "ai_risk": false,
  "compliance_tags": {
    "owasp": [],
    "atlas": [],
    "nist": [],
    "owasp_mcp": [],
    "owasp_agentic": [],
    "eu_ai_act": [],
    "nist_csf": [],
    "iso_27001": [],
    "soc2": [],
    "cis": []
  }
}
```

## Stable vs advisory fields

### Stable contract

These keys are the supported JSON contract for automation:

- top level: `version`, `generated_at`, `remediation_plan`, `summary`
- optional top level with `--server-group`: `server_groups`
- item fields:
  - `package`
  - `ecosystem`
  - `current_version`
  - `fixed_version`
  - `priority`
  - `action`
  - `command`
  - `verify_command`
  - `max_severity`
  - `blast_radius_score`
  - `impact`
  - `vulnerabilities`
  - `affected_agents`
  - `exposed_credentials`
  - `exposed_tools`
  - `references`
  - `has_kev`
  - `ai_risk`
  - `compliance_tags`

### Advisory semantics

These values are intentionally advisory and may change as scoring or enrichment
improves:

- item ordering
- `blast_radius_score`
- `priority`
- `impact`
- suggested `command`
- suggested `verify_command`
- membership and size of `references`
- compliance tag population
- derived `summary` counts

Treat the JSON shape as stable, but treat prioritization and enrichment values
as versioned security analysis output.

## Nullability and empty values

Operators and automation should expect:

- `fixed_version` may be `null`
- `command` may be `null`
- `verify_command` may be `null`
- arrays may be empty
- `server_groups` is absent unless `--server-group` is used

## Empty-plan behavior

If no vulnerabilities are found, JSON output still uses the same top-level
shape with:

- `remediation_plan: []`
- all summary counts set to `0`

If filters remove every item, the same empty JSON shape is returned.

## Output modes

| Format | Best use | Contract strength |
|---|---|---|
| `console` | humans in a terminal | presentation only |
| `json` | CI, automation, dashboards, export | supported contract |
| `markdown` | PRs, tickets, review threads | presentation only |

## Related references

- [CLI Reference](cli.md)
- [MCP Tools Reference](mcp-tools.md)
