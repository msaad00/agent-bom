# Plugin Entry-Point Examples

These examples make the v0.88 plugin contract concrete without enabling
third-party code by default.

| Example | Entry-point group | Boundary |
| --- | --- | --- |
| `example_mcp_tools.py` | `agent_bom.mcp_tools` | registers a metadata-only posture tool when an operator explicitly enables the package |
| `example_advisory_source.py` | `agent_bom.advisory_sources` | reads advisory metadata from an operator-owned source and returns hashes, links, and summaries |
| `example_runtime_emitter.py` | `agent_bom.runtime_emitters` | emits redacted runtime event envelopes to an operator-owned telemetry sink |

Installable packages should expose the registration functions with:

```toml
[project.entry-points."agent_bom.mcp_tools"]
example-posture = "example_mcp_tools:registration"

[project.entry-points."agent_bom.advisory_sources"]
example-advisories = "example_advisory_source:registration"

[project.entry-points."agent_bom.runtime_emitters"]
example-runtime = "example_runtime_emitter:registration"
```

Runtime discovery remains opt-in:

```bash
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true agent-bom agents --demo --offline
```

The loader discovers and validates metadata only. Operators still decide when
to attach MCP tools, query advisory sources, or send runtime events.
