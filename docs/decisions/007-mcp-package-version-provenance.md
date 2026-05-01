# ADR-007: MCP Package Version Provenance

**Status:** Accepted
**Date:** 2026-05-01

## Context

MCP server package scanning must distinguish proven runtime facts from inferred
or speculative package versions. A server command such as
`npx @modelcontextprotocol/server-github@1.2.3` gives a different level of
evidence than `npx @modelcontextprotocol/server-github`, a lockfile, an
installed package directory, a container SBOM, or a live registry lookup.

Without explicit version provenance, downstream surfaces have to bluff:
scanner JSON, SARIF, graph nodes, blast-radius scoring, dashboard posture, and
workflow gates cannot tell whether a CVE is tied to the thing actually running
or only to a best-effort registry resolution at scan time.

This matters especially for MCP graphs. Packages and tools are sibling surfaces
under an MCP server: packages carry code-level CVEs, while tools are callable
capabilities exposed by the server. A vulnerable package can put sibling tools
at risk through server-scope blast-radius reasoning, but the scanner must not
claim exact tool-handler reachability unless it has implementation-level proof.

## Decision

Represent package version resolution as structured, validated provenance on the
package asset and propagate it through scanner output, graph output, SARIF, API
responses, and UI drilldowns.

The package model should expose a structured provenance object rather than a
free-form string:

```json
{
  "declared_name": "@modelcontextprotocol/server-github",
  "declared_version": "latest",
  "resolved_version": "1.2.3",
  "version_source": "registry_latest",
  "confidence": "low",
  "observed_at": "2026-05-01T18:58:00Z",
  "version_resolved_at": "2026-05-01T18:58:03Z",
  "evidence": [
    {
      "type": "registry",
      "url": "https://registry.npmjs.org/@modelcontextprotocol/server-github/latest"
    }
  ],
  "version_conflicts": []
}
```

`version_source` must be one of:

- `runtime_process`
- `image_sbom`
- `installed_package`
- `tool_cache`
- `lockfile`
- `command_pin`
- `registry_latest`
- `unknown`

`confidence` must be one of:

- `exact`
- `high`
- `medium`
- `low`
- `unknown`

Do not ship `registry_at_timestamp` as an active source until install-log
ingestion exists. Historical registry reconstruction is not reliable enough by
itself because dist-tags, yanked releases, mirrors, and caches can diverge.

When multiple sources resolve the same package, use deterministic precedence:

```text
runtime_process > image_sbom > installed_package > tool_cache > lockfile >
command_pin > registry_latest > unknown
```

Runtime and SBOM evidence win over intended state. Installed package metadata
wins over lockfiles when scanning an actual runtime directory. Command pins win
over registry lookup because they are user-stated intent. When sources
disagree, preserve the chosen version and emit `version_conflicts`, for example:

```json
[
  {"source": "command_pin", "version": "1.2.3"},
  {"source": "installed_package", "version": "1.2.4"}
]
```

Floating versions must preserve both intent and observation. For example,
`npx pkg@latest` should keep `declared_version: "latest"` and set
`resolved_version` from the actual source that resolved it. A floating version
is itself a security posture signal.

Scanner and workflow behavior:

- Exact CVE matching requires `resolved_version`.
- CVE severity remains factual and must not be rewritten by confidence.
- Risk and posture scoring may apply confidence multipliers.
- Fail gates should distinguish proven findings from speculative findings. By
  default, `--fail-on-severity` should gate on sufficient confidence, while an
  explicit speculative mode may include low-confidence registry-only findings.
- The dashboard should expose a Coverage Confidence measure: how many servers
  and packages are pinned, locked, installed, runtime-observed, or only
  registry-inferred.

Graph and UI behavior:

- MCP server to package remains `depends_on`.
- MCP server to tool remains `provides_tool`.
- Package to vulnerability remains `vulnerable_to`.
- Vulnerability to tool reachability is conservative unless the scanner has
  implementation-level tool-handler proof.
- UI labels must show version source and confidence near package and finding
  drilldowns, especially for `registry_latest` and `tool_cache`.

Structured evidence should be machine-readable and, when available, include
fields such as `type`, `path`, `line`, `sha256`, `url`, `process_id`,
`container_image`, or `sbom_ref`. Evidence should be bounded and sanitized like
other discovery provenance.

## Consequences

- **Positive:** Findings become auditable: users can see whether a package
  version came from runtime, SBOM, lockfile, cache, command pin, or registry.
- **Positive:** Graph, SARIF, JSON, and dashboard surfaces stop overstating
  registry-only guesses as runtime proof.
- **Positive:** Package/tool semantics stay honest. Packages and tools are
  siblings under a server; exact package-to-tool-handler claims require deeper
  proof.
- **Positive:** Floating MCP server commands become visible posture issues
  rather than silently resolving to whatever a registry returns at scan time.
- **Positive:** Risk scoring can account for measurement quality without
  mutating the underlying CVE severity.
- **Trade-off:** Provenance adds schema and UI complexity across scanner,
  graph, API, SARIF, and dashboard contracts.
- **Trade-off:** Some existing fields such as `version_source: "detected"` or
  `source_type: "unknown"` need migration into the structured contract.
- **Boundary:** This decision defines version provenance and confidence. It
  does not implement static source-to-tool-handler attribution or sandboxed tool
  execution. Those are separate tool-level analysis features.
