"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, ShieldAlert } from "lucide-react";

import { api, type NhiGovernancePosture } from "@/lib/api";

/**
 * Non-human identity governance posture from GET /v1/graph/nhi/governance.
 */
export function NhiGovernancePanel({ scanId }: { scanId?: string | undefined }) {
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
  }, [scanId]);

  const counts = posture?.counts ?? {};
  const identities = Array.isArray(posture?.identities) ? posture.identities : [];

  return (
    <section
      data-testid="nhi-governance-panel"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">
            NHI governance posture
          </h2>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
            Graph-backed non-human identity risk from{" "}
            <span className="font-mono">/v1/graph/nhi/governance</span>
          </p>
        </div>
        {loading ? <Loader2 className="h-4 w-4 animate-spin text-[color:var(--text-tertiary)]" /> : null}
      </div>

      {error ? (
        <p className="mt-3 text-xs text-red-400">{error}</p>
      ) : (
        <>
          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(counts).slice(0, 6).map(([key, value]) => (
              <div
                key={key}
                className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1.5"
              >
                <p className="text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
                  {key.replaceAll("_", " ")}
                </p>
                <p className="font-mono text-sm text-[color:var(--foreground)]">{String(value)}</p>
              </div>
            ))}
            {!loading && Object.keys(counts).length === 0 ? (
              <p className="text-xs text-[color:var(--text-tertiary)]">
                No NHI count rollups for this snapshot.
              </p>
            ) : null}
          </div>

          {identities.length > 0 ? (
            <ul className="mt-3 space-y-1.5">
              {identities.slice(0, 8).map((identity, index) => {
                const id = String(identity.node_id || identity.identity_id || index);
                const score =
                  typeof identity.risk_score === "number" ? String(identity.risk_score) : "—";
                const label = String(
                  identity.name || identity.label || identity.node_id || "identity",
                );
                const href = identity.node_id
                  ? `/security-graph?${new URLSearchParams({
                      ...(scanId ? { scan: scanId } : {}),
                      agent: label,
                    }).toString()}`
                  : "/security-graph";
                return (
                  <li key={id}>
                    <Link
                      href={href}
                      className="flex items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs transition hover:border-[color:var(--border-strong)]"
                    >
                      <span className="inline-flex min-w-0 items-center gap-2">
                        <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-amber-500" />
                        <span className="truncate text-[color:var(--foreground)]">{label}</span>
                      </span>
                      <span className="font-mono text-[color:var(--text-secondary)]">{score}</span>
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
