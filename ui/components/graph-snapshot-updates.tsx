"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { useAuthState } from "@/components/auth-provider";
import { useNewerGraphSnapshot } from "@/hooks/use-newer-graph-snapshot";

export function GraphSnapshotUpdates() {
  const params = useSearchParams();
  const { session, loading } = useAuthState();
  const scanId = params.get("scan") ?? "";
  if (loading || !session || !scanId || params.get("capture") === "1" || params.get("scenario")) return null;
  const owner = JSON.stringify(session);
  return <SnapshotUpdates key={JSON.stringify([owner, scanId])} scanId={scanId} owner={owner} />;
}

function SnapshotUpdates({ scanId, owner }: { scanId: string; owner: string }) {
  const params = useSearchParams();
  const { newer, error, checked, checking, refresh } = useNewerGraphSnapshot(scanId, owner, true);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const available = newer && newer.scan_id !== dismissed;
  const next = new URLSearchParams(params.toString());
  if (newer) next.set("scan", newer.scan_id);
  // Routine polling must not move the investigation canvas. Announce the
  // pinned state accessibly; expand the controls only when action is useful.
  if (!available && !error && !dismissed) return <p role="status" className="sr-only">
    {checked ? "Viewing a pinned snapshot. Updates never switch this investigation automatically." : "Checking saved snapshots…"}
  </p>;
  return <aside aria-label="Saved snapshot updates" className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-outline bg-surface px-3 py-2 text-xs text-ink-secondary">
    <p role="status" className="min-w-0 basis-full sm:basis-auto sm:flex-1">
      {available ? <>Newer saved snapshot available: <span className="break-all font-mono">{newer.scan_id}</span> · {new Date(newer.created_at).toLocaleString()}. Your current investigation stays pinned.</>
        : error ? "Snapshot update check unavailable. Your current investigation stays pinned."
        : checked ? "Viewing a pinned snapshot. Updates never switch this investigation automatically."
        : "Checking saved snapshots…"}
    </p>
    {available ? <>
      <a className="graph-page-action" href={`/security-graph?${next.toString()}`}>Open newer snapshot</a>
      <button type="button" className="graph-page-action" onClick={() => setDismissed(newer.scan_id)}>Keep current</button>
    </> : <button type="button" className="graph-page-action" disabled={checking} onClick={() => void refresh(true)}>Check for updates</button>}
  </aside>;
}
