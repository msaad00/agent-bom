# Plugin Entry Points

`agent-bom` v0.88 introduces a metadata-only foundation for plugin authors.
The entry-point loader discovers plugin registrations, validates bounded
metadata, and reports sanitized loading warnings. It does not execute or attach
third-party plugins to MCP, advisory, or runtime paths by default.

Third-party entry-point loading is opt-in:

```bash
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true agent-bom agents --demo --offline
```

Operators can inspect the registry without loading third-party plugin code:

```bash
agent-bom plugins status --format json
curl -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  http://localhost:8422/v1/plugins/status
```

The status contract is metadata-only. It reports built-in registration counts,
installed entry-point declarations, and whether opt-in loading is enabled.

## Supported Groups

| Group | Purpose | Default runtime behavior |
|---|---|---|
| `agent_bom.mcp_tools` | Advertise an MCP tool registration module and function. | Not registered on the live MCP server. |
| `agent_bom.advisory_sources` | Advertise a private advisory lookup or sync source. | Not queried during scans. |
| `agent_bom.runtime_emitters` | Advertise a runtime event emitter. | Not added to proxy, gateway, or alert dispatch. |

The registry status view also includes existing built-in extension groups:
`agent_bom.cloud_providers`, `agent_bom.connectors`, and
`agent_bom.inventory_parsers`.

Each group is capped at 32 loaded entry points per process. Import, validation,
and coercion failures are non-fatal; built-in behavior remains available and
warnings are sanitized before they can leave the process.

## Author Contract

Expose a callable entry point that returns a registration object. The object may
be one of the dataclasses in `agent_bom.plugin_entrypoints` or any object with
the same public attributes.

```toml
[project.entry-points."agent_bom.advisory_sources"]
private-feed = "acme_agent_bom_advisories:registration"
```

```python
from agent_bom.extensions import ExtensionCapabilities
from agent_bom.plugin_entrypoints import AdvisorySourcePluginRegistration


def registration() -> AdvisorySourcePluginRegistration:
    return AdvisorySourcePluginRegistration(
        name="private-feed",
        module="acme_agent_bom_advisories.feed",
        lookup_attr="lookup",
        sync_attr="sync",
        capabilities=ExtensionCapabilities(
            scan_modes=("advisory_lookup",),
            required_scopes=("private_feed_read",),
            outbound_destinations=("advisories.example.internal",),
            data_boundary="customer_controlled_advisory_lookup",
            network_access=True,
        ),
        source="entry_point",
    )
```

Required fields:

- `name`: stable plugin identifier.
- `module`: import path for the implementation module.
- `capabilities`: declared permissions, outbound destinations, and data
  boundary. If omitted, agent-bom applies conservative metadata-only defaults.

Group-specific optional fields:

- `agent_bom.mcp_tools`: `register_attr`, default `register_tools`.
- `agent_bom.advisory_sources`: `lookup_attr`, default `lookup`; `sync_attr`,
  default `sync`.
- `agent_bom.runtime_emitters`: `emit_attr`, default `emit`; `flush_attr`,
  default `flush`.

## Runnable Examples

Concrete examples live in [`examples/plugin_entrypoints/`](../examples/plugin_entrypoints/):

- `example_mcp_tools.py` advertises a read-only MCP posture tool and a
  `register_tools(mcp)` function.
- `example_advisory_source.py` advertises a license-aware advisory lookup/sync
  source that returns summaries and source URLs instead of redistributing full
  advisory bodies.
- `example_runtime_emitter.py` advertises a runtime event emitter that keeps
  only redacted metadata envelopes and avoids raw prompts, arguments, and
  credential values.

These examples are covered by `tests/test_plugin_entrypoint_examples.py` so the
documented plugin contract stays importable.

## First Verification

For plugin package tests, monkeypatch `importlib.metadata.entry_points`, set
`AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true`, and call:

```python
from agent_bom.plugin_entrypoints import list_advisory_source_plugins

plugins = list_advisory_source_plugins()
assert plugins[0].name == "private-feed"
```

This verifies discovery only. Runtime activation remains a separate,
operator-controlled integration step.
