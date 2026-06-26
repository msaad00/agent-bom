# CLI Reference

The canonical command reference lives in
[site-docs/reference/cli.md](../site-docs/reference/cli.md).

## Release Contracts

- `agent-bom agents -f json -o -` writes JSON to stdout for automation.
- `agent-bom agents -f <format> -o <path>` validates output suffixes and
  appends the canonical suffix when `<path>` has no extension.
- JSON reports include `posture_scorecard` and root `posture_grade`.
- `agent-bom agents --posture` renders a compact card that includes the top
  exposure path as `agent → MCP server → package@version → CVE → tool` plus its
  blast-radius summary (`N cred(s), N tool(s) reachable`). The same chain is
  emitted in SARIF result messages, an `exposure_chain` property, and
  `relatedLocations`.
- `agent-bom agents --agent-mode` writes a stable JSON envelope for assistant
  and automation callers.
- `agent-bom profiles ...` manages named contexts in
  `~/.agent-bom/config.toml`; unknown profiles fail with the available profile
  list.
- `agent-bom cloud scan` runs one cloud-aware scan across every configured
  provider; `--provider all` (the default) auto-detects which clouds are
  configured, and `cloud aws` / `cloud azure` / `cloud gcp` are aliases for the
  provider-scoped form. CIS misconfigurations converge into the same `Finding`
  stream and `--fail-on-severity` exit-code gate as package vulnerabilities.
  An explicitly requested provider that hard-fails discovery or its CIS
  benchmark (missing SDK or absent/invalid credentials) makes the command exit
  non-zero, while a genuinely empty-but-successful scan and skipped
  auto-detected clouds still exit 0; one provider failing never aborts the
  others.
- `agent-bom secrets <dir>` accepts `--offline` as a no-op (secret scanning is
  always local) for parity with `agents`/`scan` so shared CI invocations work.
- `agent-bom cloud registry-scan --provider <ecr|acr|gar>` sweeps an entire
  container registry read-only, deduping by content digest and capping the work
  list with `AGENT_BOM_REGISTRY_MAX_IMAGES` / `AGENT_BOM_REGISTRY_MAX_TAGS_PER_REPO`.
- `agent-bom db freshness` emits the structured vuln-data freshness indicator
  (sources, age, staleness) — the same snapshot surfaced on every scan and
  returned by the API and MCP tool.
