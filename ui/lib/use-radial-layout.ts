/**
 * Radial / concentric layout for the agent mesh (`/mesh`).
 *
 * Hub-and-spoke topology: one or more agents anchor the centre, MCP servers
 * orbit at radius 1, packages / tools / vulnerabilities / credentials sit
 * further out. Dagre-TB collapses this shape into a long vertical ribbon and
 * loses the "agent at the centre" affordance — concentric rings preserve it.
 *
 * Ring assignment uses the typed schema from `graph-schema.ts` so that
 * EntityType changes propagate here automatically:
 *   ring 0 — agent
 *   ring 1 — server (MCP)
 *   ring 2 — tool, model, package
 *   ring 3 — credential, vulnerability, misconfiguration, anything else
 *
 * Determinism: angle around each ring is derived from a stable hash of the
 * node id seeded by the set of node ids in the current frame. The same scan
 * therefore renders to the same SVG every time, satisfying the visual-diff
 * CI guard tracked in #2259.
 */

"use client";

import { useMemo } from "react";
import { Position, type Edge, type Node } from "@xyflow/react";

import { EntityType } from "@/lib/graph-schema";
import { hashString, seedFromIds } from "@/lib/seed-random";

export interface RadialLayoutOptions {
  /** Pixel radius of the first orbit. */
  baseRadius?: number;
  /** Additional pixels added per ring. */
  ringSpacing?: number;
  /** Override ring assignment by entity type. */
  ringForEntity?: (entityType: string) => number;
}

const DEFAULT_BASE_RADIUS = 220;
const DEFAULT_RING_SPACING = 200;

function defaultRingForEntity(entityType: string): number {
  switch (entityType) {
    case EntityType.AGENT:
      return 0;
    case EntityType.SERVER:
    case EntityType.PROVIDER:
    case EntityType.CLUSTER:
    case EntityType.FLEET:
    case EntityType.ENVIRONMENT:
      return 1;
    case EntityType.TOOL:
    case EntityType.MODEL:
    case EntityType.PACKAGE:
    case EntityType.DATASET:
    case EntityType.CONTAINER:
    case EntityType.CLOUD_RESOURCE:
      return 2;
    default:
      // credential, vulnerability, misconfiguration, user, group, sa, …
      return 3;
  }
}

interface NodeLikeData {
  entityType?: string;
  nodeType?: string;
}

function entityTypeFromNode(node: Node): string {
  const data = (node.data ?? {}) as NodeLikeData;
  if (typeof data.entityType === "string" && data.entityType.length > 0) {
    return data.entityType;
  }
  if (typeof data.nodeType === "string" && data.nodeType.length > 0) {
    return data.nodeType;
  }
  return "";
}

export interface RadialLayoutResult {
  nodes: Node[];
  edges: Edge[];
  /** Stable seed used to derive node positions for this frame. */
  seed: number;
}

export function applyRadialLayout(
  nodes: Node[],
  edges: Edge[],
  options: RadialLayoutOptions = {},
): RadialLayoutResult {
  const baseRadius = options.baseRadius ?? DEFAULT_BASE_RADIUS;
  const ringSpacing = options.ringSpacing ?? DEFAULT_RING_SPACING;
  const ringFor = options.ringForEntity ?? defaultRingForEntity;

  if (nodes.length === 0) {
    return { nodes: [], edges, seed: 0 };
  }

  const seed = seedFromIds(nodes.map((n) => n.id));

  // Bucket nodes by ring.
  const rings = new Map<number, Node[]>();
  for (const node of nodes) {
    const ring = ringFor(entityTypeFromNode(node));
    const bucket = rings.get(ring);
    if (bucket) {
      bucket.push(node);
    } else {
      rings.set(ring, [node]);
    }
  }

  // Sort each ring deterministically and assign angles. We bias the angle
  // off a hash of the node id so neighbouring scans don't reshuffle wildly,
  // while still giving even angular coverage when ring counts shift.
  const positioned: Node[] = [];
  for (const [ring, bucket] of rings) {
    const sorted = [...bucket].sort((a, b) => a.id.localeCompare(b.id));
    const radius = ring === 0 ? 0 : baseRadius + (ring - 1) * ringSpacing;
    if (ring === 0) {
      // Stack agents in a tight inner cluster around (0, 0).
      const inner = Math.max(60, sorted.length * 16);
      sorted.forEach((node, index) => {
        const angle =
          ((hashString(`${seed}:${node.id}`) & 0xffff) / 0x10000) * Math.PI * 2;
        const innerR = sorted.length === 1 ? 0 : inner;
        positioned.push({
          ...node,
          position: {
            x: Math.cos(angle) * innerR + index * 0.0001,
            y: Math.sin(angle) * innerR,
          },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
        });
      });
      continue;
    }
    const slot = (Math.PI * 2) / sorted.length;
    sorted.forEach((node, index) => {
      const jitter =
        ((hashString(`${seed}:${ring}:${node.id}`) & 0x3ff) / 0x3ff - 0.5) *
        slot *
        0.35;
      const angle = index * slot + jitter;
      positioned.push({
        ...node,
        position: { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });
    });
  }

  // Preserve the original input order so React Flow render IDs are stable.
  const byId = new Map(positioned.map((n) => [n.id, n]));
  const final = nodes.map((n) => byId.get(n.id) ?? n);

  return { nodes: final, edges, seed };
}

export interface UseRadialLayoutResult {
  nodes: Node[];
  edges: Edge[];
  pending: false;
  seed: number;
}

export function useRadialLayout(
  nodes: Node[],
  edges: Edge[],
  options: RadialLayoutOptions = {},
): UseRadialLayoutResult {
  const baseRadius = options.baseRadius;
  const ringSpacing = options.ringSpacing;
  const ringForEntity = options.ringForEntity;
  return useMemo(() => {
    const opts: RadialLayoutOptions = {};
    if (baseRadius !== undefined) opts.baseRadius = baseRadius;
    if (ringSpacing !== undefined) opts.ringSpacing = ringSpacing;
    if (ringForEntity !== undefined) opts.ringForEntity = ringForEntity;
    const result = applyRadialLayout(nodes, edges, opts);
    return { ...result, pending: false as const };
  }, [nodes, edges, baseRadius, ringSpacing, ringForEntity]);
}
