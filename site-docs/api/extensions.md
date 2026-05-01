# Extension Entry Points

agent-bom supports opt-in Python entry points for external inventory parsers,
cloud providers, and SaaS connectors. This lets teams ship ecosystem-specific
integrations as separate packages without modifying `src/agent_bom`.

Entry point loading is disabled by default. Enable it only in trusted
environments:

```bash
export AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true
```

## Entry Point Groups

| Group | Purpose | Registration type |
|---|---|---|
| `agent_bom.inventory_parsers` | Package or manifest parsers | `InventoryParserRegistration` |
| `agent_bom.cloud_providers` | Cloud inventory discovery | `CloudProviderRegistration` |
| `agent_bom.connectors` | SaaS connector discovery | `ConnectorRegistration` |

Built-in registrations use the same registry path, so `list_registered_*`
returns built-ins plus trusted entry-point extensions when enabled.

## Inventory Parser Example

```toml
[project.entry-points."agent_bom.inventory_parsers"]
acme_lock = "agent_bom_parser_acme:registration"
```

```python
from pathlib import Path

from agent_bom.extensions import ExtensionCapabilities
from agent_bom.models import MCPServer, Package
from agent_bom.parsers.base import InventoryParserRegistration


def parse_acme_lock(root: Path, server: MCPServer | None = None) -> list[Package]:
    lockfile = root / "acme.lock"
    if not lockfile.exists():
        return []
    return [Package(name="example", version="1.0.0", ecosystem="acme")]


def registration() -> InventoryParserRegistration:
    return InventoryParserRegistration(
        name="acme-lock",
        module="agent_bom_parser_acme",
        parse_attr="parse_acme_lock",
        manifest_names=("acme.lock",),
        capabilities=ExtensionCapabilities(
            scan_modes=("inventory",),
            required_scopes=("local_project_read",),
            outbound_destinations=(),
            data_boundary="local_manifest_read_only",
            writes=False,
            network_access=False,
            guarantees=("read_only", "no_secret_collection"),
        ),
        source="entry_point",
    )
```

## Capability Contract

Every extension should declare its operational boundary through
`ExtensionCapabilities`:

- `scan_modes`: inventory, cloud read-only, SaaS read-only, runtime probe, etc.
- `required_scopes`: local permissions, API scopes, IAM permissions, or roles.
- `permissions_used`: concrete read permissions used during discovery.
- `outbound_destinations`: API hosts or registries the extension contacts.
- `data_boundary`: what data is read and whether it leaves the local machine.
- `writes`: must be `False` for read-only discovery integrations.
- `network_access`: `True` only when the extension opens network connections.
- `guarantees`: read-only, redacted, no secret collection, bounded output, etc.

These fields are exposed through the provider/parser registries and are intended
to become part of scan evidence and control-plane discovery envelopes.

## Safety Rules

- Keep parser extensions read-only.
- Do not collect raw secret values; return names, references, and redacted
  evidence instead.
- Keep warnings user-safe. Registry load failures are sanitized before display.
- Avoid running subprocesses from parsers unless the extension documentation
  declares the command and its arguments.
- Prefer structured parser APIs over ad hoc shell commands.

## Local Verification

```bash
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true python - <<'PY'
from agent_bom.parsers import list_registered_inventory_parsers

for parser in list_registered_inventory_parsers():
    print(parser.name, parser.module, parser.source)
PY
```
