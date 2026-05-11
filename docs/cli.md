# CLI Reference

The canonical command reference lives in
[site-docs/reference/cli.md](../site-docs/reference/cli.md).

## Release Contracts

- `agent-bom agents -f json -o -` writes JSON to stdout for automation.
- `agent-bom agents -f <format> -o <path>` validates output suffixes and
  appends the canonical suffix when `<path>` has no extension.
- JSON reports include `posture_scorecard` and root `posture_grade`.
- `agent-bom profiles ...` manages named contexts in
  `~/.agent-bom/config.toml`; unknown profiles fail with the available profile
  list.
