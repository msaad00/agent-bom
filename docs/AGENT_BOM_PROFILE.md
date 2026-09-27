# Per-agent BOM profile

`agent-bom.profile/v1` is an experimental, vendor-neutral JSON evidence profile
for **one agent**. It is not an adopted industry standard or a replacement for
CycloneDX, SPDX, or A2A. The `agent-bom.manifest/v1` fleet export stays unchanged.

The Python builder `agent_bom.evidence.agent_bom.build_agent_bom` accepts one
discovered `Agent` and returns an `AgentBomDocument`. Serialize it with
`model_dump_json(indent=2)`; validate untrusted JSON with
`agent_bom.evidence.agent_bom.validate_agent_bom_json(text)`, which enforces an
8 MiB input bound and rejects duplicate JSON keys. The interchange schema is
[profile-v1.json](schemas/agent-bom/profile-v1.json). Regenerate it with
`python scripts/generate_agent_bom_schema.py`; verify it with `--check`.

## Export and validate

For a project containing exactly one discovered agent:

```bash
agent-bom manifest --project . --single-agent --output agent.bom.json
agent-bom manifest --validate agent.bom.json
```

For multiple agents, run `agent-bom manifest --project .`, select an exact ID
from `agents[].id`, then export with `--agent-id ID` instead of `--single-agent`.
Display names are not selectors. An unknown or ambiguous ID fails without
writing a file. Existing fleet output remains the default.

The CLI validator accepts at most 8 MiB and rejects duplicate keys, non-finite
numbers, invalid references and changed content digests. It performs no agent
discovery and prints no imported content on failure. Python integrations should
use `validate_agent_bom_json` for the same parsing boundary. The next step after
validation is to inspect coverage: validation proves neither verified identity
nor control compliance.

## Contents and evidence boundary

The subject contains its existing canonical inventory ID, deployment source
ID when supplied, name, type, and version. Inventory identity is **observed**,
not authenticated workload identity. Names alone cannot establish a portable
cross-vendor identity; consumers must preserve tenant and provider scope.

Components describe MCP servers, tools, and available package versions.
Relationships carry a basis and evidence references. The inventory builder
emits **declared** membership; configuration does not prove successful execution
or effective privileges. Credentials, command arguments, arbitrary metadata,
prompts, and conversation bodies are excluded from this export.

Every document accounts for composition, models, data, identity, authority,
runtime, vulnerabilities, controls, and cost coverage. The current inventory
builder marks composition partial and all unassessed areas `not_assessed`.
An empty list is not evidence of absence. A valid document is not a clean
security verdict or compliance certification.

`snapshot_id` is SHA-256 over the UTF-8 content object, encoded with sorted
JSON keys, no separator whitespace, unescaped Unicode, and no non-finite
numbers. Array ordering is significant; the builder sorts components and
relationships. `generated_at` is outside the digest, so exporting unchanged
evidence again preserves the snapshot ID. This encoding is specific to the
profile and is not an RFC 8785 claim. The digest detects changes; it is not a
signature, trusted timestamp, producer authentication, or complete audit trail.

JSON Schema checks shape and bounds. The Python validator additionally checks
the digest, unique identities, all coverage areas, relationship endpoints,
evidence references, and timezone-aware dates. A producer from any vendor can
implement this contract; validation cannot establish the truth of its claims.
Importers must enforce authorization, payload limits, tenant binding,
redaction, and provenance separately.

## Interoperability

Use CycloneDX/SPDX artifacts for software/model composition and preserve their
identifiers and evidence when integrating them. This JSON profile is **not
itself** a conforming CycloneDX or SPDX document. An A2A Agent Card describes
discovery, capabilities, and authentication requirements; it does not establish
all runtime dependencies or permissions. Run histories should reference a
snapshot ID rather than grow this BOM on every tool call.

Persisted history, authenticated identity bindings, authority assessments,
run linking, and signed attestations require their own evidence integration;
the inventory builder does not infer them.
