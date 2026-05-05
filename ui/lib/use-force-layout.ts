/**
 * Force-directed layout for the security graph (`/graph`).
 *
 * Implementation choice: pure-JS force simulation (no Cytoscape dep).
 *
 * Why not cose-bilkent / fcose? Pulling in `cytoscape` + `cytoscape-cose-bilkent`
 * would add ~250 KB minified to the dashboard bundle and force a parallel
 * graph model (Cytoscape elements vs React Flow nodes). The 244-node /
 * 302-edge agent-bom self-scan converges in well under one frame with the
 * spring/repulsion simulation below, and a deterministic seed (see
 * `seed-random.ts`) keeps renders stable for the visual-diff CI guard
 * (#2259). If/when graphs grow past ~5 k nodes we can swap the inner loop
 * for a Barnes-Hut quadtree without changing the surface API.
 *
 * Algorithm:
 *   1. Seed each node at a deterministic point on a Fibonacci spiral keyed
 *      by hash(id, frame_seed). Prevents "first frame jiggle" between
 *      identical scans.
 *   2. Iterate a small number of steps (default 80) of Coulomb repulsion +
 *      Hooke spring attraction along edges, with a 1/√t cooling schedule.
 *   3. Snap to integer pixel coords so SVG output is byte-stable.
 *
 * The hook returns `{ nodes, edges, pending, seed }`. `pending` is always
 * false today (the simulation is synchronous and cheap); the field exists
 * so callers can swap useDagreLayout → useForceLayout without refactoring
 * loading-state handling.
 */

"use client";

import { useMemo } from "react";
import { Position, type Edge, type Node } from "@xyflow/react";

import { seedFromIds, seededPosition } from "@/lib/seed-random";

export interface ForceLayoutOptions {
  /** Total simulation iterations. */
  iterations?: number;
  /** Target edge length in pixels (Hooke rest length). */
  idealEdgeLength?: number;
  /** Coulomb repulsion strength. */
  nodeRepulsion?: number;
  /** Hooke spring strength along edges. */
  edgeStiffness?: number;
  /** Centring pull toward the origin to keep the graph framed. */
  centerPull?: number;
  /** Initial radius for the seeded layout. */
  initialRadius?: number;
  /**
   * Keep caller-positioned aggregate/group anchors fixed when node metadata
   * marks them as layout-pinned. This lets `/graph` compose this force pass
   * inside a future aggregation layer without the inner layout moving the
   * aggregate nodes themselves.
   */
  preservePinnedPositions?: boolean;
}

const DEFAULTS: Required<ForceLayoutOptions> = {
  iterations: 80,
  idealEdgeLength: 180,
  nodeRepulsion: 4200,
  edgeStiffness: 0.08,
  centerPull: 0.012,
  initialRadius: 320,
  preservePinnedPositions: true,
};

interface Particle {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  fixed: boolean;
}

interface LayoutPinData {
  layoutPinned?: unknown;
  layoutLocked?: unknown;
  layout?: {
    pinned?: unknown;
    locked?: unknown;
  };
}

function isPinnedLayoutNode(node: Node): boolean {
  const data = (node.data ?? {}) as LayoutPinData;
  return (
    data.layoutPinned === true ||
    data.layoutLocked === true ||
    data.layout?.pinned === true ||
    data.layout?.locked === true
  );
}

export interface ForceLayoutResult {
  nodes: Node[];
  edges: Edge[];
  seed: number;
}

export function applyForceLayout(
  nodes: Node[],
  edges: Edge[],
  options: ForceLayoutOptions = {},
): ForceLayoutResult {
  const opts = { ...DEFAULTS, ...options };
  if (nodes.length === 0) {
    return { nodes: [], edges, seed: 0 };
  }

  const seed = seedFromIds(nodes.map((n) => n.id));

  // 1. Seed positions deterministically off the seeded RNG.
  const particles: Particle[] = nodes.map((node) => {
    if (opts.preservePinnedPositions && isPinnedLayoutNode(node)) {
      return {
        id: node.id,
        x: Math.round(node.position.x),
        y: Math.round(node.position.y),
        vx: 0,
        vy: 0,
        fixed: true,
      };
    }
    const { x, y } = seededPosition(node.id, seed, opts.initialRadius);
    return { id: node.id, x, y, vx: 0, vy: 0, fixed: false };
  });
  const indexById = new Map(particles.map((p, i) => [p.id, i] as const));

  // Build adjacency for the spring force.
  const springs: Array<{ a: number; b: number }> = [];
  for (const edge of edges) {
    const a = indexById.get(edge.source);
    const b = indexById.get(edge.target);
    if (a == null || b == null) continue;
    springs.push({ a, b });
  }

  const ideal = opts.idealEdgeLength;
  const repulsion = opts.nodeRepulsion;
  const stiffness = opts.edgeStiffness;
  const centerPull = opts.centerPull;

  // 2. Iterate.
  for (let step = 0; step < opts.iterations; step += 1) {
    // Cooling schedule: damp velocity more aggressively as we converge.
    const cooling = 1 / Math.sqrt(step + 1);

    // Coulomb repulsion (O(n^2) — fine through ~2 k nodes).
    for (let i = 0; i < particles.length; i += 1) {
      const pi = particles[i]!;
      for (let j = i + 1; j < particles.length; j += 1) {
        const pj = particles[j]!;
        let dx = pi.x - pj.x;
        let dy = pi.y - pj.y;
        let distSq = dx * dx + dy * dy;
        if (distSq < 1) {
          // Fall back to a deterministic offset when points coincide.
          dx = ((i - j) % 7) + 0.5;
          dy = ((i + j) % 11) - 5.5;
          distSq = dx * dx + dy * dy;
        }
        const dist = Math.sqrt(distSq);
        const force = repulsion / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        if (!pi.fixed) {
          pi.vx += fx;
          pi.vy += fy;
        }
        if (!pj.fixed) {
          pj.vx -= fx;
          pj.vy -= fy;
        }
      }
    }

    // Hooke spring attraction along edges.
    for (const { a, b } of springs) {
      const pa = particles[a]!;
      const pb = particles[b]!;
      const dx = pb.x - pa.x;
      const dy = pb.y - pa.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const displacement = dist - ideal;
      const force = displacement * stiffness;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      if (!pa.fixed) {
        pa.vx += fx;
        pa.vy += fy;
      }
      if (!pb.fixed) {
        pb.vx -= fx;
        pb.vy -= fy;
      }
    }

    // Pull every particle toward the origin so loose components don't drift.
    // Integrate with cooling-scaled velocity.
    for (const p of particles) {
      if (p.fixed) {
        p.vx = 0;
        p.vy = 0;
        continue;
      }
      p.vx -= p.x * centerPull;
      p.vy -= p.y * centerPull;
      p.x += p.vx * cooling;
      p.y += p.vy * cooling;
      // Damp velocity each step so the system actually converges.
      p.vx *= 0.85;
      p.vy *= 0.85;
    }
  }

  // 3. Snap to integer coords for byte-stable SVG output.
  const byId = new Map(particles.map((p) => [p.id, p] as const));
  const positioned = nodes.map((node) => {
    const p = byId.get(node.id);
    if (!p) return node;
    return {
      ...node,
      position: { x: Math.round(p.x), y: Math.round(p.y) },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });

  return { nodes: positioned, edges, seed };
}

export interface UseForceLayoutResult {
  nodes: Node[];
  edges: Edge[];
  pending: false;
  seed: number;
}

export function useForceLayout(
  nodes: Node[],
  edges: Edge[],
  options: ForceLayoutOptions = {},
): UseForceLayoutResult {
  const iterations = options.iterations;
  const idealEdgeLength = options.idealEdgeLength;
  const nodeRepulsion = options.nodeRepulsion;
  const edgeStiffness = options.edgeStiffness;
  const centerPull = options.centerPull;
  const initialRadius = options.initialRadius;
  const preservePinnedPositions = options.preservePinnedPositions;
  return useMemo(() => {
    const opts: ForceLayoutOptions = {};
    if (iterations !== undefined) opts.iterations = iterations;
    if (idealEdgeLength !== undefined) opts.idealEdgeLength = idealEdgeLength;
    if (nodeRepulsion !== undefined) opts.nodeRepulsion = nodeRepulsion;
    if (edgeStiffness !== undefined) opts.edgeStiffness = edgeStiffness;
    if (centerPull !== undefined) opts.centerPull = centerPull;
    if (initialRadius !== undefined) opts.initialRadius = initialRadius;
    if (preservePinnedPositions !== undefined) opts.preservePinnedPositions = preservePinnedPositions;
    const result = applyForceLayout(nodes, edges, opts);
    return { ...result, pending: false as const };
  }, [
    nodes,
    edges,
    iterations,
    idealEdgeLength,
    nodeRepulsion,
    edgeStiffness,
    centerPull,
    initialRadius,
    preservePinnedPositions,
  ]);
}
