"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api, type GraphSnapshot } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { SnapshotNeighborhood } from "@/components/persisted-context-view";

/** Agent relationships from the selected persisted snapshot, across its sources. */
export function MeshLensView() {
  const { session } = useAuthState();
  const params = useSearchParams();
  if (!session) return <p role="status" className="p-4">Resolving access to persisted evidence…</p>;
  const owner = JSON.stringify(session);
  return <OwnedMesh key={JSON.stringify([owner, params?.get("scan"), params?.get("agent"), params?.get("root"), params?.get("node")])} owner={owner} />;
}

function OwnedMesh({ owner }: { owner: string }) {
  const params = useSearchParams();
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>([]);
  const [scanId, setScanId] = useState(params?.get("scan") ?? "");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const requestedAgent = params?.get("agent") ?? params?.get("root") ?? params?.get("node") ?? "";
  useEffect(() => {
    let active = true;
    api.getGraphSnapshots(50, 0).then(data => {
      if (!active) return;
      setSnapshots(data);
      setScanId(current => current || data[0]?.scan_id || "");
    }).catch(() => { if (active) setError("Snapshot list unavailable. Retry or open an exact snapshot link."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [owner]);
  return <section aria-label="Persisted agent mesh" className="min-w-0 space-y-2 p-3">
    <GraphLensSwitcher variant="compact" scanId={scanId || undefined} />
    <header className="flex flex-wrap items-center justify-between gap-2">
      <div><h1 className="text-lg font-semibold">Agent Mesh</h1>
        <p className="text-xs text-[var(--text-secondary)]">Recorded agent connections across the selected snapshot’s sources. Expand relationships as needed.</p></div>
      <label className="min-w-0 max-w-full text-sm">Snapshot <select aria-label="Mesh snapshot" className="context-action max-w-full" value={scanId} onChange={event => setScanId(event.target.value)}>
        {!scanId && <option value="">{loading ? "Loading snapshots…" : "No persisted snapshots"}</option>}
        {scanId && !snapshots.some(snapshot => snapshot.scan_id === scanId) && <option value={scanId}>{scanId}</option>}
        {snapshots.map(snapshot => <option key={snapshot.scan_id} value={snapshot.scan_id}>{snapshot.scan_id}{snapshot.snapshot_kind === "correlation" ? " · correlated" : ""}</option>)}
      </select></label>
    </header>
    {snapshots.length === 50 && <p className="text-xs text-[var(--text-secondary)]">Showing the latest 50 retained snapshots. Older snapshots can be opened by their exact link.</p>}
    {error && <p role="alert">{error}</p>}
    {scanId ? <SnapshotNeighborhood key={JSON.stringify([owner, scanId, requestedAgent])} scanId={scanId} owner={owner} initialRootId={requestedAgent} />
      : <p role="status">{loading ? "Loading persisted snapshots…" : "No persisted agent relationships available. Connect a source or ingest scan evidence to populate a snapshot."}</p>}
  </section>;
}
