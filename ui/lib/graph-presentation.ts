import type { Edge, Node, Viewport } from "@xyflow/react";

export type GraphPresentationScope = {
  tenantId: string;
  subject: string;
  snapshotId: string;
  lens: string;
  scope: string;
};

export type GraphPosition = { x: number; y: number };

export type GraphPresentationState = {
  version: 1;
  positions: Record<string, GraphPosition>;
  viewport: Viewport;
  layout: string;
  locked: boolean;
};

type StorageAdapter = Pick<Storage, "getItem" | "setItem" | "removeItem">;

const STORAGE_PREFIX = "agent-bom:graph-presentation:v1";
const MAX_COORDINATE = 10_000_000;
const MIN_ZOOM = 0.05;
const MAX_ZOOM = 4;

function stableHash(value: string): string {
  let left = 0x811c9dc5;
  let right = 0x9e3779b9;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    left = Math.imul(left ^ code, 0x01000193) >>> 0;
    right = Math.imul(right ^ code, 0x85ebca6b) >>> 0;
  }
  return `${left.toString(16).padStart(8, "0")}${right.toString(16).padStart(8, "0")}`;
}

export function graphPresentationStorageKey(scope: GraphPresentationScope): string {
  return `${STORAGE_PREFIX}:${stableHash(JSON.stringify([
    scope.tenantId,
    scope.subject,
    scope.snapshotId,
    scope.lens,
    scope.scope,
  ]))}`;
}

export function graphNodeStorageKey(nodeId: string): string {
  return `n:${stableHash(nodeId)}`;
}

export function graphNodeSetKey(nodes: Pick<Node, "id">[]): string {
  return stableHash(nodes.map((node) => node.id).sort().join("\u0000"));
}

export function graphTopologyKey(
  nodes: Pick<Node, "id">[],
  edges: Array<Pick<Edge, "source" | "target" | "data">>,
): string {
  const nodePart = nodes.map((node) => node.id).sort();
  const edgePart = edges.map((edge) => {
    const relationship = (edge.data as { relationship?: unknown } | undefined)?.relationship;
    return `${edge.source}\u0001${typeof relationship === "string" ? relationship : "relationship"}\u0001${edge.target}`;
  }).sort();
  return stableHash(JSON.stringify([nodePart, edgePart]));
}

function ownerRegistryKey(tenantId: string, subject: string): string {
  return `${STORAGE_PREFIX}:owner:${stableHash(`${tenantId}\u0000${subject}`)}`;
}

export function registerGraphPresentationKey(
  storage: StorageAdapter | null | undefined,
  scope: Pick<GraphPresentationScope, "tenantId" | "subject">,
  key: string,
): void {
  if (!storage) return;
  const registryKey = ownerRegistryKey(scope.tenantId, scope.subject);
  try {
    const parsed = JSON.parse(storage.getItem(registryKey) ?? "[]");
    const keys = Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string" && item.startsWith(STORAGE_PREFIX)) : [];
    if (!keys.includes(key)) storage.setItem(registryKey, JSON.stringify([...keys, key]));
  } catch {
    try { storage.setItem(registryKey, JSON.stringify([key])); } catch { /* optional storage */ }
  }
}

export function purgeGraphPresentationsForOwner(
  storage: StorageAdapter | null | undefined,
  tenantId: string,
  subject: string,
): void {
  if (!storage) return;
  const registryKey = ownerRegistryKey(tenantId, subject);
  try {
    const parsed = JSON.parse(storage.getItem(registryKey) ?? "[]");
    if (Array.isArray(parsed)) {
      for (const key of parsed) if (typeof key === "string" && key.startsWith(STORAGE_PREFIX)) storage.removeItem(key);
    }
    storage.removeItem(registryKey);
  } catch {
    try { storage.removeItem(registryKey); } catch { /* optional storage */ }
  }
}

function finiteCoordinate(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && Math.abs(value) <= MAX_COORDINATE
    ? value
    : null;
}

function sanitizeState(value: unknown): GraphPresentationState | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<GraphPresentationState>;
  if (candidate.version !== 1 || typeof candidate.layout !== "string") return null;
  const viewport = candidate.viewport as Partial<Viewport> | undefined;
  const viewportX = finiteCoordinate(viewport?.x);
  const viewportY = finiteCoordinate(viewport?.y);
  const zoom = viewport?.zoom;
  if (
    viewportX === null ||
    viewportY === null ||
    typeof zoom !== "number" ||
    !Number.isFinite(zoom) ||
    zoom < MIN_ZOOM ||
    zoom > MAX_ZOOM
  ) {
    return null;
  }
  const positions: Record<string, GraphPosition> = {};
  if (candidate.positions && typeof candidate.positions === "object") {
    for (const [id, position] of Object.entries(candidate.positions)) {
      if (!/^n:[a-f0-9]{16}$/.test(id) || !position || typeof position !== "object") continue;
      const x = finiteCoordinate((position as Partial<GraphPosition>).x);
      const y = finiteCoordinate((position as Partial<GraphPosition>).y);
      if (x !== null && y !== null) positions[id] = { x, y };
    }
  }
  return {
    version: 1,
    positions,
    viewport: { x: viewportX, y: viewportY, zoom },
    layout: candidate.layout.slice(0, 64),
    locked: candidate.locked === true,
  };
}

export function readGraphPresentation(
  storage: StorageAdapter | null | undefined,
  key: string,
): GraphPresentationState | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    return sanitizeState(JSON.parse(raw));
  } catch {
    return null;
  }
}

export function writeGraphPresentation(
  storage: StorageAdapter | null | undefined,
  key: string,
  state: GraphPresentationState,
): void {
  if (!storage) return;
  const sanitized = sanitizeState(state);
  if (!sanitized) return;
  try {
    storage.setItem(key, JSON.stringify(sanitized));
  } catch {
    // Storage can be unavailable in private browsing or quota-constrained clients.
  }
}

export function removeGraphPresentation(
  storage: StorageAdapter | null | undefined,
  key: string,
): void {
  try {
    storage?.removeItem(key);
  } catch {
    // Presentation persistence is optional and must never block graph review.
  }
}

export function applyGraphPresentation<T extends Node>(
  nodes: T[],
  state: GraphPresentationState | null,
): T[] {
  if (!state) return nodes;
  return nodes.map((node) => {
    const position = state.positions[graphNodeStorageKey(node.id)];
    return position ? { ...node, position } : node;
  });
}

export function graphPositions(nodes: Node[]): Record<string, GraphPosition> {
  return Object.fromEntries(
    nodes
      .filter((node) => finiteCoordinate(node.position.x) !== null && finiteCoordinate(node.position.y) !== null)
      .map((node) => [graphNodeStorageKey(node.id), { x: node.position.x, y: node.position.y }]),
  );
}

export function selectGraphSubgraph<T extends Node, E extends Edge>(
  nodes: T[],
  edges: E[],
  selectedIds: Set<string> | null | undefined,
): { nodes: T[]; edges: E[] } {
  if (!selectedIds || selectedIds.size === 0) return { nodes, edges };
  return {
    nodes: nodes.filter((node) => selectedIds.has(node.id)),
    edges: edges.filter(
      (edge) => selectedIds.has(edge.source) && selectedIds.has(edge.target),
    ),
  };
}
