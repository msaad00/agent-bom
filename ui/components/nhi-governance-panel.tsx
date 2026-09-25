"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, ShieldAlert } from "lucide-react";

import { api, type NhiGovernancePosture } from "@/lib/api";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";

/**
 * Non-human identity governance posture from GET /v1/graph/nhi/governance.
 */
export function NhiGovernancePanel({ scanId, refreshKey = 0 }: { scanId?: string | undefined; refreshKey?: number }) {
  const [query, setQuery] = useState("");
  const [posture, setPosture] = useState<NhiGovernancePosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getNhiGovernance(scanId)
      .then((result) => {
        if (cancelled) return;
        setPosture(result);
      })
      .catch(() => {
        if (cancelled) return;
        setError("Could not load NHI governance posture");
        setPosture(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, refreshKey]);

  const rawCounts = posture?.counts ?? {};
  const identities = Array.isArray(posture?.identities) ? posture.identities : [];

  const matches = identities.filter(identity => [identity.name, identity.label, identity.node_id].some(value => typeof value === "string" && value.toLowerCase().includes(query.trim().toLowerCase())));

  // `/v1/graph/nhi/governance` returns scalar rollups alongside at least one
  // NESTED breakdown (`by_risk_band` → {critical, medium, low}). Rendering a
  // value with String() turned that object into the literal text
  // "[object Object]" on the Identity page. Flatten one level so a breakdown
  // becomes its own pills — which is the useful reading anyway: "critical 1"
  // says something, "[object Object]" says the page is broken.
  const words = (value: string) => value.replaceAll("_", " ");
  const counts = Object.entries(rawCounts).flatMap(([key, value]) => {
    const entries = value !== null && typeof value === "object" && !Array.isArray(value)
      ? Object.entries(value).map(([child, count]) => [`${words(key.replace(/^by_/, ""))} · ${words(child)}`, count] as const)
      : [[words(key), value] as const];
    return entries.filter(([, count]) => count != null && typeof count !== "object")
      .map(([label, count]) => ({ key: `${key}.${label}`, label, value: String(count) }));
  });

  return (
    <section
      data-testid="nhi-governance-panel"
      className="rounded-2xl border border-outline bg-surface p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-foreground">
            NHI governance posture
          </h2>
          <p className="mt-1 text-xs text-ink-tertiary">
            Discovered identities in {scanId ? "the selected" : "the latest available"} graph snapshot.
            Separate from identities issued and managed here.
          </p>
        </div>
        {loading ? <Loader2 className="h-4 w-4 animate-spin text-ink-tertiary" /> : null}
      </div>

      {error ? (
        <p className="mt-3 text-xs text-red-400">{error}</p>
      ) : loading ? null : (
        <>
          <div className="mt-3 flex flex-wrap gap-2">
            {counts.slice(0, 8).map((entry) => (
              <div
                key={entry.key}
                className="rounded-lg border border-outline bg-surface-elevated px-2.5 py-1.5"
              >
                <p className="text-[10px] uppercase tracking-[0.12em] text-ink-tertiary">
                  {entry.label}
                </p>
                <p className="font-mono text-sm text-foreground">{entry.value}</p>
              </div>
            ))}
            {!loading && counts.length === 0 ? (
              <p className="text-xs text-ink-tertiary">
                No NHI count rollups for this snapshot.
              </p>
            ) : null}
          </div>

          {identities.length > 0 && <label className="mt-3 block text-xs text-ink-secondary">
            Find a discovered identity
            <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Name or exact identifier" className="mt-1 w-full rounded-lg border border-outline bg-background px-3 py-2 text-foreground" />
            <span className="mt-1 block">Showing {Math.min(8, matches.length)} of {matches.length} matches · {identities.length} loaded. Refine search for more.</span>
          </label>}
          {matches.length > 0 ? (
            <ul className="mt-3 space-y-1.5">
              {matches.slice(0, 8).map((identity, index) => {
                const id = String(identity.node_id || identity.identity_id || index);
                const score =
                  typeof identity.risk_score === "number" ? String(identity.risk_score) : "—";
                const label = String(
                  identity.name || identity.label || identity.node_id || "identity",
                );
                const evidenceScan = posture?.scan_id || scanId;
                const href = identity.node_id
                  ? buildGraphInvestigationHref({
                      rootId: String(identity.node_id), rootLabel: label, scanId: evidenceScan,
                    })
                  : `/security-graph${evidenceScan ? `?${new URLSearchParams({ scan: evidenceScan })}` : ""}`;
                return (
                  <li key={id}>
                    <Link
                      href={href}
                      className="flex items-center justify-between gap-2 rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-xs transition hover:border-outline-strong"
                    >
                      <span className="inline-flex min-w-0 items-center gap-2">
                        <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-amber-500" />
                        <span className="min-w-0 text-foreground"><span className="block break-words">{label}</span><code className="mt-1 block break-all text-[10px] text-ink-secondary">{id}</code></span>
                      </span>
                      <span className="font-mono text-ink-secondary">{score}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          ) : null}
        </>
      )}
    </section>
  );
}
