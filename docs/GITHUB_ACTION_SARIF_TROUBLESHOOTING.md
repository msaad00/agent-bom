# GitHub Action SARIF Troubleshooting

Use this when `agent-bom` runs in GitHub Actions but findings do not appear in
GitHub Code Scanning.

## Minimal working shape

```yaml
name: agent-bom

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: msaad00/agent-bom@v0.86.3
        with:
          scan-type: agents
          format: sarif
          upload-sarif: true
          pr-comment: true
```

`security-events: write` is required for SARIF upload. Without it,
`github/codeql-action/upload-sarif` cannot write code-scanning alerts even when
the SARIF file exists.

## Common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Action passes but no Code Scanning alert appears | Workflow lacks `security-events: write`. | Add job or workflow permissions with `security-events: write`. |
| SARIF upload is skipped | `format` is not `sarif`, or no SARIF file was generated. | Set `format: sarif` and check the action log for the report path. |
| `Resource not accessible by integration` | Pull request comes from a fork or the token lacks upload permission. | Run SARIF upload on `push` to a trusted branch, or keep fork PRs as artifact/PR-comment only. |
| Upload fails with path errors | The configured SARIF path does not match the generated report path. | Use the action output path, or keep the default `agent-bom-results.sarif`. |
| Alerts overwrite another scanner category | Multiple uploads share the same category. | Give each scanner a stable unique category when using manual `upload-sarif`. |
| Private repository shows no code scanning view | Code scanning may be unavailable for the plan or repository settings. | Check repository Security settings and GitHub Advanced Security availability. |

## Debug checklist

1. Confirm the workflow has `contents: read` and `security-events: write`.
2. Confirm `format: sarif` and `upload-sarif: true` are both set.
3. Confirm the action log says a SARIF file was produced.
4. Confirm the run is from a trusted branch when uploading SARIF.
5. Download the workflow artifact or generated report and validate it locally:

   ```bash
   jq -e '.version == "2.1.0" and (.runs | length > 0)' agent-bom-results.sarif
   ```

6. If upload still fails, keep the SARIF artifact and PR comment enabled so the
   security review still has evidence while token or repository settings are
   fixed.

## Manual upload fallback

When using `agent-bom` only to generate SARIF and uploading manually, keep the
same permission boundary:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - run: pipx run agent-bom agents -p . -f sarif -o agent-bom-results.sarif
  - uses: github/codeql-action/upload-sarif@v4
    if: always() && hashFiles('agent-bom-results.sarif') != ''
    with:
      sarif_file: agent-bom-results.sarif
      category: agent-bom
```

For fork PRs, prefer uploading the SARIF as a workflow artifact and reviewing
the PR comment until a trusted branch run can publish Code Scanning results.
