# Canonical IDs

Agent BOM emits deterministic canonical IDs so repeat scans can join the same
entities, findings, and graph relationships without replacing existing readable
IDs or source-specific identifiers.

## Contract

- Canonical IDs are UUID v5 values in Agent BOM's fixed namespace.
- Inputs are normalized by lowercasing and trimming string parts. Structured
  parts such as tool schemas are serialized as sorted JSON before hashing.
- Existing `id` and `stable_id` fields remain backward-compatible. New
  consumers should prefer `canonical_id` when diffing scans, joining graph
  nodes, or linking findings over time.
- Source IDs stay as provenance in `source_ids` where available. They are not
  silently discarded when a canonical ID exists.

## Entity Rules

| Entity | Canonical input |
|---|---|
| Agent | agent type + name; graph fleet agents use source or endpoint ID when provided |
| MCP server | registry ID when available, otherwise server name + launch command |
| MCP tool | tool name + sorted input schema |
| MCP resource | resource URI + MIME type |
| MCP prompt | prompt name + sorted argument descriptors |
| Package | normalized ecosystem + package name + version, with valid PURL input authoritative |
| Finding | affected asset canonical ID + vulnerability or finding key + package qualifiers |
| Graph node | node `stable_id`/`canonical_id` when supplied, otherwise entity type + graph node ID |
| Graph edge | relationship + source graph ID + target graph ID |

## Compatibility Notes

Graph node IDs such as `agent:claude-desktop` and `pkg:npm:express@4.18.0`
remain readable and stable for existing API/UI consumers. `canonical_id` is an
additional join key for scan history, deduplication, and saved investigations.
