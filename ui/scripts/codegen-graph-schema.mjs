#!/usr/bin/env node
// Generate ui/lib/graph-schema.generated.ts from the canonical Python
// taxonomy at GET /v1/graph/schema (issue #2255).
//
// Why: agent_bom.graph.types.EntityType + RelationshipType is the single
// source of truth. The TypeScript dashboard previously hand-mirrored those
// enums in two places (ui/lib/graph-schema.ts + ui/components/lineage-
// nodes.tsx LineageNodeType union), which silently drifted whenever a new
// kind landed on the Python side. This script materialises the API
// response into typed TS so drift becomes a CI failure instead of a
// silent dropped node in the graph view.
//
// Usage:
//   node scripts/codegen-graph-schema.mjs            # rewrite generated file
//   node scripts/codegen-graph-schema.mjs --check    # exit 1 if drift
//
// Env:
//   AGENT_BOM_GRAPH_SCHEMA_URL  override URL
//                               (default http://127.0.0.1:8422/v1/graph/schema)

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const UI_ROOT = resolve(HERE, "..");
const OUT_PATH = resolve(UI_ROOT, "lib/graph-schema.generated.ts");

const DEFAULT_URL = "http://127.0.0.1:8422/v1/graph/schema";
const URL_ENV = process.env.AGENT_BOM_GRAPH_SCHEMA_URL || DEFAULT_URL;

const checkOnly = process.argv.includes("--check");

function fail(msg) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
}

function toEnumMember(key) {
  // "cloud_resource" → "CLOUD_RESOURCE"
  return key.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

function jsonStringify(value) {
  return JSON.stringify(value, null, 2);
}

async function fetchSchema() {
  let resp;
  try {
    resp = await fetch(URL_ENV, { headers: { accept: "application/json" } });
  } catch (err) {
    fail(
      `failed to GET ${URL_ENV}: ${err?.message ?? err}\n` +
        `Is the API running? Try:\n` +
        `  uv run agent-bom api --host 127.0.0.1 --port 8422 --allow-insecure-no-auth`,
    );
  }
  if (!resp.ok) {
    fail(`GET ${URL_ENV} returned ${resp.status} ${resp.statusText}`);
  }
  let data;
  try {
    data = await resp.json();
  } catch (err) {
    fail(`response from ${URL_ENV} was not valid JSON: ${err?.message ?? err}`);
  }
  if (
    typeof data !== "object" ||
    data === null ||
    !Array.isArray(data.node_kinds) ||
    !Array.isArray(data.edge_kinds)
  ) {
    fail(`unexpected schema shape from ${URL_ENV}: ${JSON.stringify(data).slice(0, 200)}`);
  }
  return data;
}

function render(schema) {
  const nodeKinds = [...schema.node_kinds].sort((a, b) =>
    a.key.localeCompare(b.key),
  );
  const edgeKinds = [...schema.edge_kinds].sort((a, b) =>
    a.key.localeCompare(b.key),
  );

  const nodeEnum = nodeKinds
    .map((n) => `  ${toEnumMember(n.key)} = ${JSON.stringify(n.key)},`)
    .join("\n");

  const edgeEnum = edgeKinds
    .map((e) => `  ${toEnumMember(e.key)} = ${JSON.stringify(e.key)},`)
    .join("\n");

  const nodeUnion = nodeKinds.map((n) => JSON.stringify(n.key)).join(" | ");
  const edgeUnion = edgeKinds.map((e) => JSON.stringify(e.key)).join(" | ");

  const nodeMetadataObj = nodeKinds
    .map(
      (n) =>
        `  ${JSON.stringify(n.key)}: ${jsonStringify({
          label: n.label,
          color: n.color,
          shape: n.shape,
          layer: n.layer,
          icon: n.icon,
          category_uid: n.category_uid,
          class_uid: n.class_uid,
        }).replace(/\n/g, "\n  ")},`,
    )
    .join("\n");

  const edgeMetadataObj = edgeKinds
    .map(
      (e) =>
        `  ${JSON.stringify(e.key)}: ${jsonStringify({
          label: e.label,
          color: e.color,
          category: e.category,
          direction: e.direction,
          source_types: e.source_types,
          target_types: e.target_types,
          traversable: e.traversable,
        }).replace(/\n/g, "\n  ")},`,
    )
    .join("\n");

  const nodeKindList = nodeKinds.map((n) => JSON.stringify(n.key)).join(", ");
  const edgeKindList = edgeKinds.map((e) => JSON.stringify(e.key)).join(", ");

  return `// AUTO-GENERATED — do not edit. Run \`npm run codegen:graph-schema\` to refresh.
//
// Source of truth: agent_bom.graph.types.EntityType + RelationshipType.
// The Python API at GET /v1/graph/schema is the canonical taxonomy; this
// file is materialised by ui/scripts/codegen-graph-schema.mjs and the CI
// "UI Validate" job fails when it drifts (see #2255).

export const GRAPH_SCHEMA_VERSION = ${schema.version ?? 1} as const;

// ═══════════════════════════════════════════════════════════════════════════
// Node kinds (entity types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphNodeKind {
${nodeEnum}
}

export type GraphNodeKindKey = ${nodeUnion};

export const GRAPH_NODE_KINDS: readonly GraphNodeKindKey[] = [${nodeKindList}] as const;

export interface GraphNodeKindMeta {
  label: string;
  color: string;
  shape: string;
  layer: string;
  icon: string;
  category_uid: number;
  class_uid: number;
}

export const GRAPH_NODE_KIND_META: Record<GraphNodeKindKey, GraphNodeKindMeta> = {
${nodeMetadataObj}
};

// ═══════════════════════════════════════════════════════════════════════════
// Edge kinds (relationship types)
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphEdgeKind {
${edgeEnum}
}

export type GraphEdgeKindKey = ${edgeUnion};

export const GRAPH_EDGE_KINDS: readonly GraphEdgeKindKey[] = [${edgeKindList}] as const;

export interface GraphEdgeKindMeta {
  label: string;
  color: string;
  category: string;
  direction: "directed" | "bidirectional";
  source_types: readonly GraphNodeKindKey[];
  target_types: readonly GraphNodeKindKey[];
  traversable: boolean;
}

export const GRAPH_EDGE_KIND_META: Record<GraphEdgeKindKey, GraphEdgeKindMeta> = {
${edgeMetadataObj}
};

// ═══════════════════════════════════════════════════════════════════════════
// Type guards
// ═══════════════════════════════════════════════════════════════════════════

export function isGraphNodeKind(value: unknown): value is GraphNodeKindKey {
  return (
    typeof value === "string" &&
    (GRAPH_NODE_KINDS as readonly string[]).includes(value)
  );
}

export function isGraphEdgeKind(value: unknown): value is GraphEdgeKindKey {
  return (
    typeof value === "string" &&
    (GRAPH_EDGE_KINDS as readonly string[]).includes(value)
  );
}
`;
}

const schema = await fetchSchema();
const expected = render(schema);

if (checkOnly) {
  if (!existsSync(OUT_PATH)) {
    fail(
      `${OUT_PATH} is missing.\n` +
        `Run \`npm run codegen:graph-schema\` and commit the result.`,
    );
  }
  const current = readFileSync(OUT_PATH, "utf8");
  if (current !== expected) {
    process.stderr.write(
      `error: ${OUT_PATH} is out of date relative to GET /v1/graph/schema.\n` +
        `\n` +
        `The Python graph taxonomy (agent_bom.graph.types) has new entries\n` +
        `that the dashboard does not know about, so nodes of those kinds\n` +
        `would silently disappear from the UI. Regenerate locally:\n` +
        `\n` +
        `  cd ui && npm run codegen:graph-schema\n` +
        `\n` +
        `Then commit ui/lib/graph-schema.generated.ts.\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`OK: ${OUT_PATH} matches /v1/graph/schema\n`);
  process.exit(0);
}

writeFileSync(OUT_PATH, expected);
process.stdout.write(
  `wrote ${OUT_PATH} (${schema.node_kinds.length} node kinds, ${schema.edge_kinds.length} edge kinds)\n`,
);
