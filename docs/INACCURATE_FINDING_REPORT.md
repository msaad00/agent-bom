# Sanitized Inaccurate Finding Report

Use this example when opening a public
[Inaccurate Finding](https://github.com/msaad00/agent-bom/issues/new?template=inaccurate_finding.yml)
issue for a false positive, false negative, wrong advisory mapping, misleading
remediation, or missing blast-radius context.

## What to include

- exact `agent-bom` command
- `agent-bom --version`
- install method and whether the scan used `--offline`, `--enrich`, an SBOM,
  or a registry
- the smallest sanitized JSON or SARIF snippet that shows the issue
- public advisory, package metadata, SBOM, or lockfile evidence that supports
  the correction
- what result you expected instead

## What to remove

- secret values, tokens, cookies, credentials, and private registry URLs
- private repository names, private package names, customer names, and hostnames
- source code, prompt text, proprietary file paths, and local usernames
- full SBOMs, full SARIF files, or full dashboard exports when one finding row
  is enough

Keep package names public when they are already public packages such as
`requests`, `express`, or `@modelcontextprotocol/server-filesystem`. Replace
private names with stable placeholders like `private-pypi-package`.

## Copy-paste example

````markdown
### agent-bom version

agent-bom 0.86.3

### Finding type

Misleading remediation

### Command and sanitized output

```bash
agent-bom agents \
  --inventory sanitized-inventory.json \
  --project sanitized-sample \
  --offline \
  -f json \
  -o sanitized-report.json
```

```json
{
  "agent": "cursor",
  "server": "filesystem-server",
  "ecosystem": "pypi",
  "package": "private-pypi-package",
  "version": "1.2.3",
  "vulnerability_id": "CVE-2024-0000",
  "severity": "high",
  "fix_version": "9.9.9",
  "reachable_agents": 1,
  "credential_env_names": ["PRIVATE_SERVICE_TOKEN"]
}
```

### Expected result

The package should still be reported as vulnerable, but the remediation should
say "no fixed version known" instead of recommending `9.9.9`.

### Public evidence

- Advisory: `https://osv.dev/vulnerability/CVE-2024-0000`
- Package metadata: `https://pypi.org/project/public-upstream-package/`
- Public note: upstream has not published a fixed version as of the linked
  advisory timestamp.

### Environment

- OS: Ubuntu 24.04
- Python: 3.13
- Install method: pip
- Scan mode: `--offline`
````

## Notes for SARIF snippets

For SARIF, include only the affected `runs[].results[]` entry plus the matching
`rules[]` entry. Remove `artifactLocation.uri` values that expose private paths
and replace them with placeholders such as `sanitized/requirements.txt`.

## Good public report checklist

- The command is runnable against sanitized placeholders.
- The finding row is small enough to read in the issue body.
- The expected behavior is specific.
- Evidence links are public.
- No raw secrets, private source, or customer data are included.
