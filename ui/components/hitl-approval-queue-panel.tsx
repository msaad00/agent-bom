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
      <div className="flex items-center gap-2 rounded-2xl border border-zinc-800 bg-zinc-900/50 px-4 py-10 text-sm text-zinc-400">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading approval queue…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-2xl border border-red-900/50 bg-red-950/30 px-4 py-3 text-sm text-red-300">
        {error}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-zinc-800 bg-zinc-900/40 px-4 py-10 text-center text-sm text-zinc-500">
        No blocked tool calls in the approval queue. Gateway/proxy blocks appear here for human review.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-sm text-zinc-300">
        <span>
          <span className="font-semibold text-zinc-100">{pendingCount}</span> pending · {items.length} total blocked spans
        </span>
        <button
          type="button"
          onClick={() => void load()}
          className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:border-zinc-600 hover:text-zinc-100"
        >
          Refresh
        </button>
      </div>

      <div className="overflow-hidden rounded-2xl border border-zinc-800">
        <table className="w-full text-sm">
          <thead className="border-b border-zinc-800 bg-zinc-900">
            <tr>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Agent / tool</th>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Findings</th>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Controls</th>
              <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">Status</th>
              <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wide text-zinc-500">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800 bg-zinc-950">
            {items.map((item) => (
              <tr key={item.item_id} className="align-top hover:bg-zinc-900/60">
                <td className="px-4 py-3">
                  <div className="font-medium text-zinc-200">{item.agent || "unknown agent"}</div>
                  <div className="mt-1 font-mono text-xs text-zinc-400">{item.tool}</div>
                  {item.detail ? <p className="mt-2 text-xs text-zinc-500">{item.detail}</p> : null}
                  <p className="mt-1 text-[11px] text-zinc-600">session {item.session_id}</p>
                </td>
                <td className="px-4 py-3">
                  {item.linked_finding_ids.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {item.linked_finding_ids.slice(0, 4).map((fid) => (
                        <Link
                          key={fid}
                          href={`/findings?search=${encodeURIComponent(fid)}`}
                          className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300 hover:underline"
                        >
                          {fid}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-zinc-600">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {item.compliance_controls.slice(0, 4).map((tag) => (
                      <span key={tag} className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
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
                        className="inline-flex items-center gap-1 rounded-lg border border-emerald-800 bg-emerald-950/50 px-2.5 py-1.5 text-xs text-emerald-300 hover:bg-emerald-900/40 disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Approve
                      </button>
                      <button
                        type="button"
                        disabled={busyId === item.item_id}
                        onClick={() => void decide(item.item_id, "deny")}
                        className="inline-flex items-center gap-1 rounded-lg border border-rose-800 bg-rose-950/50 px-2.5 py-1.5 text-xs text-rose-300 hover:bg-rose-900/40 disabled:opacity-50"
                      >
                        <XCircle className="h-3.5 w-3.5" />
                        Deny
                      </button>
                    </div>
                  ) : (
                    <span className="text-xs text-zinc-500">{item.decided_by || "—"}</span>
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
