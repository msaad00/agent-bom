"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Loader2, ShieldAlert, XCircle } from "lucide-react";

import { api } from "@/lib/api";
import type { HitlApprovalQueueItem } from "@/lib/api-types";

export function HitlApprovalQueuePanel() {
  const [items, setItems] = useState<HitlApprovalQueueItem[]>([]);
  const [pendingCount, setPendingCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getHitlApprovalQueue(undefined, 120);
      setItems(response.items);
      setPendingCount(response.pending_count);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function decide(itemId: string, decision: "approve" | "deny") {
    setBusyId(itemId);
    setError(null);
    try {
      await api.decideHitlApproval(itemId, decision);
      await load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 px-4 py-10 text-sm text-[var(--text-secondary)]">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading approval queue…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-2xl border border-red-500/30 dark:border-red-900/50 bg-red-500/10 dark:bg-red-950/30 px-4 py-3 text-sm text-red-700 dark:text-red-300">
        {error}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-[var(--border-subtle)] bg-[var(--surface)]/40 px-4 py-10 text-center text-sm text-[var(--text-tertiary)]">
        No blocked tool calls in the approval queue. Gateway/proxy blocks appear here for human review.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/50 px-4 py-3 text-sm text-[var(--text-secondary)]">
        <span>
          <span className="font-semibold text-[var(--foreground)]">{pendingCount}</span> pending · {items.length} total blocked spans
        </span>
        <button
          type="button"
          onClick={() => void load()}
          className="rounded-lg border border-[var(--border-subtle)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
        >
          Refresh
        </button>
      </div>

      <div className="overflow-hidden rounded-2xl border border-[var(--border-subtle)]">
        <table className="w-full text-sm">
          <thead className="border-b border-[var(--border-subtle)] bg-[var(--surface)]">
            <tr>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Agent / tool</th>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Findings</th>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Controls</th>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Status</th>
              <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wide text-[var(--text-tertiary)]">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-subtle)] bg-[var(--background)]">
            {items.map((item) => (
              <tr key={item.item_id} className="align-top hover:bg-[var(--surface)]/60">
                <td className="px-4 py-3">
                  <div className="font-medium text-[var(--foreground)]">{item.agent || "unknown agent"}</div>
                  <div className="mt-1 font-mono text-xs text-[var(--text-secondary)]">{item.tool}</div>
                  {item.detail ? <p className="mt-2 text-xs text-[var(--text-tertiary)]">{item.detail}</p> : null}
                  <p className="mt-1 text-[11px] text-[var(--text-tertiary)]">session {item.session_id}</p>
                </td>
                <td className="px-4 py-3">
                  {item.linked_finding_ids.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {item.linked_finding_ids.slice(0, 4).map((fid) => (
                        <Link
                          key={fid}
                          href={`/findings?search=${encodeURIComponent(fid)}`}
                          className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[10px] text-emerald-300 hover:underline"
                        >
                          {fid}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-[var(--text-tertiary)]">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {item.compliance_controls.slice(0, 4).map((tag) => (
                      <span key={tag} className="rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">
                        {tag}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium capitalize ${
                      item.status === "approved"
                        ? "border-emerald-800 bg-emerald-950 text-emerald-300"
                        : item.status === "denied"
                          ? "border-rose-800 bg-rose-950 text-rose-300"
                          : "border-amber-800 bg-amber-950 text-amber-300"
                    }`}
                  >
                    <ShieldAlert className="h-3 w-3" />
                    {item.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  {item.status === "pending" ? (
                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        disabled={busyId === item.item_id}
                        onClick={() => void decide(item.item_id, "approve")}
                        className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 dark:border-emerald-800 bg-emerald-500/10 dark:bg-emerald-950/50 px-2.5 py-1.5 text-xs text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 dark:hover:bg-emerald-900/40 disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Approve
                      </button>
                      <button
                        type="button"
                        disabled={busyId === item.item_id}
                        onClick={() => void decide(item.item_id, "deny")}
                        className="inline-flex items-center gap-1 rounded-lg border border-rose-500/30 dark:border-rose-800 bg-rose-500/10 dark:bg-rose-950/50 px-2.5 py-1.5 text-xs text-rose-700 dark:text-rose-300 hover:bg-rose-500/10 dark:hover:bg-rose-900/40 disabled:opacity-50"
                      >
                        <XCircle className="h-3.5 w-3.5" />
                        Deny
                      </button>
                    </div>
                  ) : (
                    <span className="text-xs text-[var(--text-tertiary)]">{item.decided_by || "—"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
