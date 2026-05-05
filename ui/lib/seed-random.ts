/**
 * Tiny seeded PRNG used by graph layouts to keep renders deterministic
 * scan-to-scan. Required by the visual-diff CI guard (#2259) — random init
 * positions must be derived from stable inputs (node IDs) so the same scan
 * produces the same SVG every render.
 *
 * Implementation:
 *   - hashString: FNV-1a 32-bit hash, deterministic across platforms.
 *   - mulberry32: PRNG seeded from a 32-bit integer; small, fast, and good
 *     enough for layout init. Not cryptographic.
 *
 * Public API:
 *   seedFromIds(nodeIds: string[]): number  — combines node IDs into one seed.
 *   makeRng(seed: number): () => number     — returns a [0, 1) generator.
 *   seededPosition(id, seed, radius): {x, y} — deterministic point per id.
 */

export function hashString(input: string): number {
  let hash = 0x811c9dc5; // FNV offset basis
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    // Multiply by FNV prime (16777619), keep to 32 bits.
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

export function seedFromIds(nodeIds: readonly string[]): number {
  let seed = 0x9e3779b1; // golden ratio bits
  for (const id of nodeIds) {
    seed = (Math.imul(seed ^ hashString(id), 0x85ebca6b)) >>> 0;
  }
  return seed >>> 0;
}

export function makeRng(seed: number): () => number {
  let state = seed >>> 0;
  return function rng(): number {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Deterministic 2-D point on a circle of given radius for a node id.
 * Used as the seed position for force-directed layouts so the layout
 * converges to the same shape on every run.
 */
export function seededPosition(
  id: string,
  seed: number,
  radius: number,
): { x: number; y: number } {
  const h = hashString(`${seed.toString(36)}:${id}`);
  const angle = ((h & 0xffff) / 0x10000) * Math.PI * 2;
  const r = radius * (0.5 + ((h >>> 16) & 0xffff) / 0x10000 / 2);
  return { x: Math.cos(angle) * r, y: Math.sin(angle) * r };
}
