// In-memory TTL cache + inflight-dedup for the dashboard's GET requests.
//
// Closes the "caching, deduplication, retries, invalidation" half of #1956.
// React 19's strict effects double-fire `useEffect`, and most of the
// dashboard pages re-mount their data fetchers on every navigation — so the
// API was being hit two-to-N times for the same payload on every interaction.
//
// This module is intentionally small (no React Query / SWR dep) so it can
// land independently of the broader UI virtualization work. The contract:
//
// - GET responses are memoized by URL for `ttlMs` (default 5s) so a quick
//   re-render of the same view returns the cached value instead of a new
//   fetch.
// - Concurrent identical GETs (same URL, no cache hit yet) share a single
//   in-flight Promise. The 2nd … Nth caller awaits the same response.
// - Mutating helpers (POST/PUT/DELETE) invalidate cache entries by prefix
//   so a write to /v1/scan/{id} flushes /v1/scan, /v1/scan/{id}, and any
//   nested children without the call site needing to remember every key.
// - Retain at most 64 responses, evict least-recently-used entries, and
//   reclaim expired entries on reads. Invalidation detaches pending requests
//   so an old response cannot repopulate the cache.
// - The cache is a plain Map. It does NOT survive a page reload. That's
//   intentional: server-side state is the source of truth, and the cache
//   exists only to absorb intra-page render storms.
//
// Designed so a future swap to React Query is a one-file change: this
// module's surface is `cachedGet`, `invalidate`, and `clearCache`. None
// of the call sites import the Map directly.

export interface CacheOptions {
  /** TTL in milliseconds. 0 = no cache, only inflight dedup. Default: 5000. */
  ttlMs?: number;
  /** Force a fresh fetch (skips cache lookup) but still populates on success. */
  noStore?: boolean;
}

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  estimatedBytes: number;
}

const CACHE = new Map<string, CacheEntry<unknown>>();
const INFLIGHT = new Map<string, Promise<unknown>>();

const DEFAULT_TTL_MS = 5_000;
const MAX_ENTRIES = 64;
// Retention accounting, not a browser heap guarantee. Bound traversal too so
// deeply nested or oversized responses cannot stall navigation during caching.
const MAX_RETAINED_BYTES = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
let retainedBytes = 0;

function estimateBytes(value: unknown): number {
  const pending = [value];
  const seen = new Set<object>();
  let bytes = 0;
  let visited = 0;
  while (pending.length) {
    if (++visited > 100_000 || bytes > MAX_RESPONSE_BYTES) return Infinity;
    const item = pending.pop();
    if (typeof item === "string") bytes += item.length * 2;
    else if (item && typeof item === "object") {
      if (seen.has(item)) continue;
      seen.add(item);
      if (!Array.isArray(item) && Object.getPrototypeOf(item) !== Object.prototype) return Infinity;
      bytes += 32;
      for (const key of Object.keys(item)) {
        bytes += key.length * 2 + 16;
        if (bytes > MAX_RESPONSE_BYTES || pending.length >= 100_000) return Infinity;
        pending.push((item as Record<string, unknown>)[key]);
      }
    } else bytes += 8;
  }
  return bytes;
}

function remove(key: string): void {
  const entry = CACHE.get(key);
  if (entry) retainedBytes -= entry.estimatedBytes;
  CACHE.delete(key);
}

function _now(): number {
  return Date.now();
}

export async function cachedGet<T>(key: string, fetcher: () => Promise<T>, options: CacheOptions = {}): Promise<T> {
  const ttl = options.ttlMs ?? DEFAULT_TTL_MS;
  for (const [entryKey, entry] of CACHE) {
    if (entry.expiresAt <= _now()) remove(entryKey);
  }

  if (!options.noStore) {
    const cached = CACHE.get(key) as CacheEntry<T> | undefined;
    if (cached && cached.expiresAt > _now()) {
      CACHE.delete(key);
      CACHE.set(key, cached);
      return cached.value;
    }
  }

  const inflight = INFLIGHT.get(key) as Promise<T> | undefined;
  if (inflight) return inflight;

  // Register before invoking the fetcher; invalidation detaches old requests.
  // Only the currently registered request may populate or clear this key.
  const promise: Promise<T> = Promise.resolve().then(fetcher).then((value) => {
    if (ttl > 0 && INFLIGHT.get(key) === promise) {
      remove(key);
      let estimatedBytes = Infinity;
      try { estimatedBytes = estimateBytes(value) + key.length * 2; } catch { /* Uninspectable values are delivered without retention. */ }
      if (estimatedBytes <= MAX_RESPONSE_BYTES) {
        CACHE.set(key, { value, expiresAt: _now() + ttl, estimatedBytes });
        retainedBytes += estimatedBytes;
        while (CACHE.size > MAX_ENTRIES || retainedBytes > MAX_RETAINED_BYTES) remove(CACHE.keys().next().value!);
      }
    }
    return value;
  }).finally(() => {
    if (INFLIGHT.get(key) === promise) INFLIGHT.delete(key);
  });

  INFLIGHT.set(key, promise);
  return promise;
}

/** Drop every cached entry whose key starts with `prefix`. */
export function invalidate(prefix: string): number {
  let dropped = 0;
  for (const key of CACHE.keys()) {
    if (key.startsWith(prefix)) {
      remove(key);
      dropped++;
    }
  }
  for (const key of INFLIGHT.keys()) {
    if (key.startsWith(prefix)) INFLIGHT.delete(key);
  }
  return dropped;
}

/** Drop every cached entry. Test/teardown helper. */
export function clearCache(): void {
  CACHE.clear();
  retainedBytes = 0;
  INFLIGHT.clear();
}

/** Inspect cache size (test helper; not exported via package public surface). */
export function _cacheSizeForTests(): { entries: number; inflight: number } {
  return { entries: CACHE.size, inflight: INFLIGHT.size };
}

export function _cacheBytesForTests(): number { return retainedBytes; }
