"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Laptop, Loader2, Search } from "lucide-react";

import { PaginationBar } from "@/components/pagination-bar";
import { api, formatDate, type FleetEndpoint } from "@/lib/api";

const PAGE_SIZE = 25;

function countLabel(endpoint: FleetEndpoint, key: string, label: string) {
  const count = endpoint.counts[key];
  return typeof count === "number" ? `${count.toLocaleString()} ${label}` : `${label} unavailable`;
}

export function EndpointFleetPanel() {
  const [endpoints, setEndpoints] = useState<FleetEndpoint[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [completeness, setCompleteness] = useState<"all" | "complete" | "partial">("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const requestId = useRef(0);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setOffset(0);
      setSearch(query.trim());
    }, 250);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = useCallback(async () => {
    const current = ++requestId.current;
    setLoading(true);
    setError(null);
    try {
      const response = await api.listFleetEndpoints({
        search: search || undefined,
        completeness: completeness === "all" ? undefined : completeness,
        limit: PAGE_SIZE,
        offset,
      });
      if (current !== requestId.current) return;
      setEndpoints(response.endpoints);
      setTotal(response.total);
    } catch (reason) {
      if (current !== requestId.current) return;
      setEndpoints([]);
      setTotal(0);
      setError(reason instanceof Error ? reason.message : "Endpoint inventory request failed");
    } finally {
      if (current === requestId.current) setLoading(false);
    }
  }, [completeness, offset, search]);

  useEffect(() => {
    void load();
    return () => {
      requestId.current += 1;
    };
  }, [load]);

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const partialCount = useMemo(
    () => endpoints.filter((endpoint) => endpoint.completeness === "partial").length,
    [endpoints],
  );

  return (
    <section className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4" aria-labelledby="endpoint-fleet-heading">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 id="endpoint-fleet-heading" className="flex items-center gap-2 text-base font-semibold text-[var(--foreground)]">
            <Laptop className="h-4 w-4 text-cyan-500 dark:text-cyan-300" />
            Developer endpoints
          </h2>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">
            Latest workstation sweep per endpoint. Process arguments and environment values are not collected.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="rounded-full border border-[var(--border-subtle)] px-2 py-1 text-[var(--text-secondary)]">{total} endpoints</span>
          {partialCount > 0 && (
            <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-700 dark:text-amber-300">
              {partialCount} partial on this page
            </span>
          )}
        </div>
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-[minmax(0,1fr)_180px]">
        <label className="relative">
          <span className="sr-only">Filter endpoints</span>
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[var(--text-tertiary)]" />
          <input
            aria-label="Filter endpoints"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter by ID or platform"
            className="w-full rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] py-2 pl-9 pr-3 text-sm text-[var(--foreground)] placeholder:text-[var(--text-tertiary)]"
          />
        </label>
        <select
          aria-label="Filter endpoint completeness"
          value={completeness}
          onChange={(event) => {
            setOffset(0);
            setCompleteness(event.target.value as typeof completeness);
          }}
          className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)]"
        >
          <option value="all">All evidence states</option>
          <option value="complete">Complete</option>
          <option value="partial">Partial</option>
        </select>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-8 text-sm text-[var(--text-secondary)]"><Loader2 className="h-4 w-4 animate-spin" /> Loading endpoints…</div>
      ) : error ? (
        <p role="alert" className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-300">{error}</p>
      ) : endpoints.length === 0 ? (
        <div className="mt-4 rounded-lg border border-dashed border-[var(--border-subtle)] p-4 text-sm text-[var(--text-secondary)]">
          <p className="font-medium text-[var(--foreground)]">No workstation evidence yet</p>
          <p className="mt-1">Run <code className="rounded bg-[var(--surface-elevated)] px-1.5 py-0.5">agent-bom scan --preset workstation --push-url https://&lt;control-plane&gt;</code>.</p>
        </div>
      ) : (
        <div className="mt-4 grid gap-2 xl:grid-cols-2">
          {endpoints.map((endpoint) => {
            const isExpanded = expanded.has(endpoint.endpoint_id);
            const unavailable = Object.entries(endpoint.collector_status).filter(([, status]) => status !== "complete");
            return (
              <article key={endpoint.endpoint_id} data-testid="endpoint-row" className="min-w-0 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-3">
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  onClick={() => setExpanded((current) => {
                    const next = new Set(current);
                    if (next.has(endpoint.endpoint_id)) next.delete(endpoint.endpoint_id); else next.add(endpoint.endpoint_id);
                    return next;
                  })}
                  className="flex w-full items-start justify-between gap-3 text-left"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold text-[var(--foreground)]">{endpoint.endpoint_id}</span>
                    <span className="mt-0.5 block text-xs text-[var(--text-secondary)]">
                      {[endpoint.platform.system, endpoint.platform.release, endpoint.platform.machine].filter(Boolean).join(" · ")}
                    </span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${endpoint.completeness === "complete" ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" : "bg-amber-500/10 text-amber-700 dark:text-amber-300"}`}>
                      {endpoint.completeness}
                    </span>
                    {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                  </span>
                </button>
                <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[var(--text-secondary)]">
                  <span>{countLabel(endpoint, "applications", "apps")}</span>
                  <span>{countLabel(endpoint, "processes", "processes")}</span>
                  <span>{countLabel(endpoint, "services", "services")}</span>
                  <span>{countLabel(endpoint, "listeners", "listeners")}</span>
                </div>
                {isExpanded && (
                  <div className="mt-3 border-t border-[var(--border-subtle)] pt-3 text-xs text-[var(--text-secondary)]">
                    <div className="flex flex-wrap gap-x-3 gap-y-1">
                      <span>{countLabel(endpoint, "containers", "containers")}</span>
                      <span>{countLabel(endpoint, "images", "images")}</span>
                      <span>Observed {formatDate(endpoint.observed_at)}</span>
                    </div>
                    {unavailable.length > 0 && (
                      <ul className="mt-2 space-y-1 text-amber-700 dark:text-amber-300">
                        {unavailable.map(([name, status]) => (
                          <li key={name}>{name}: {status}{endpoint.collector_messages[name] ? ` — ${endpoint.collector_messages[name]}` : ""}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}

      {total > 0 && (
        <PaginationBar
          className="mt-4 border-t border-[var(--border-subtle)] pt-3"
          page={page}
          totalPages={totalPages}
          totalItems={total}
          itemLabel="endpoints"
          onPrevious={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
          onNext={() => setOffset((value) => value + PAGE_SIZE)}
        />
      )}
    </section>
  );
}
