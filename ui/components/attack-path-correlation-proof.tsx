import { completeDirectedHopCount } from "@/lib/security-graph-focus";
import type { FixFirstRiskReason, GraphAttackPath } from "@/lib/api-types";
import type { UnifiedNode } from "@/lib/graph-schema";

function badgeTone(kind: string): string {
  if (kind === "runtime_observed") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  if (kind === "runtime_blocked") return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300";
  if (kind === "modeled_infrastructure") return "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300";
  if (kind === "stale_allowed" || kind === "bounded_analysis") return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
  return "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300";
}

export function AttackPathCorrelationProof({
  path,
  riskReasons = [],
  nodes = [],
}: {
  path: GraphAttackPath;
  riskReasons?: FixFirstRiskReason[] | undefined;
  nodes?: UnifiedNode[] | undefined;
}) {
  const receipts = Array.isArray(path.hop_evidence) ? path.hop_evidence.filter((receipt) => receipt && typeof receipt === "object") : [];

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const anchors = path.hops
    .map((nodeId) => nodeById.get(nodeId))
    .filter((node): node is UnifiedNode => Boolean(node))
    .filter((node) => {
      const kind = node.entity_type.toLowerCase();
      return kind === "container" || kind === "package" || kind === "vulnerability" || kind === "finding";
    });
  const expectedHopCount = Math.max(path.hops.length - 1, 0);
  const completeHopCount = completeDirectedHopCount(path);
  const pathVerified = path.reachability === "confirmed" && completeHopCount !== null;
  const proofLabel = pathVerified ? "Path verified" : "Path evidence incomplete";
  const missingNodes = path.hops.filter((id) => !nodeById.has(id));
  const sourceCount = new Set(receipts.flatMap((receipt) =>
    Array.isArray(receipt?.source_snapshot_ids) ? receipt.source_snapshot_ids.filter(Boolean) : [],
  )).size;

  const kinds = new Map<string, string>();
  for (const receipt of receipts) {
    if (receipt.evidence_tier === "static_evidence") kinds.set("static_evidence", "Static evidence");
    if (receipt.evidence_tier === "modeled_infrastructure") kinds.set("modeled_infrastructure", "Modeled infrastructure");
    if (receipt.runtime_observed_state === "observed") kinds.set("runtime_observed", "Runtime observed");
    if (receipt.runtime_observed_state === "blocked") kinds.set("runtime_blocked", "Runtime blocked");
    if (receipt.freshness === "stale_allowed") kinds.set("stale_allowed", "Stale allowed");
  }
  if (riskReasons.some((reason) => reason.kind === "runtime_blocked")) {
    kinds.set("runtime_blocked", "Runtime block verified");
  }
  if (path.analysis?.status && path.analysis.status !== "complete") {
    kinds.set("bounded_analysis", "Bounded analysis");
  }

  return (
    <section
      aria-label="Correlation path proof"
      data-testid="attack-path-correlation-proof"
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/70 p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-base font-semibold text-[color:var(--foreground)]">{proofLabel}</p>
          <p className="mt-0.5 text-[15px] text-[color:var(--text-tertiary)]">
            {completeHopCount === null ? "Unavailable" : `${completeHopCount}/${expectedHopCount}`} directed traversable hops evidenced
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {[...kinds].map(([kind, label]) => (
            <span key={kind} className={`rounded-full border px-2 py-1 text-[15px] font-medium ${badgeTone(kind)}`}>
              {label}
            </span>
          ))}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2.5">
        <span className="text-[15px] font-medium text-[color:var(--text-tertiary)]">Exact anchors</span>
        {missingNodes.length > 0 && <span role="status">{missingNodes.length} path nodes unavailable</span>}
        {anchors.map((node) => (
          <span key={node.id} className="max-w-full rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-1 font-mono text-[15px] text-[color:var(--foreground)] [overflow-wrap:anywhere]">
            {node.label || node.id}
          </span>
        ))}
        <span className="ml-auto text-[15px] text-[color:var(--text-tertiary)]">{sourceCount} source snapshots</span>
      </div>
      <details className="group mt-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <summary className="cursor-pointer list-none px-3 py-2 text-[15px] font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
          Inspect {receipts.length} hop receipts
        </summary>
        <div className="grid gap-1.5 border-t border-[color:var(--border-subtle)] p-2 sm:grid-cols-2">
          {receipts.map((receipt, index) => (
            <div key={`${receipt.source_node_id}-${receipt.target_node_id}-${index}`} className="min-w-0 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-2 text-[10px]">
              <p className="break-words font-mono text-[color:var(--foreground)]">{index + 1}. {receipt.relationship}</p>
              <p className="mt-1 break-words text-[color:var(--text-secondary)]">{Array.isArray(receipt.source_snapshot_ids) ? receipt.source_snapshot_ids.join(" + ") : "Sources unavailable"}</p>
              <p className="mt-1 text-[color:var(--text-tertiary)]">{String(receipt.evidence_tier ?? "unknown").replaceAll("_", " ")} · {String(receipt.freshness ?? "unknown").replaceAll("_", " ")} · {String(receipt.runtime_observed_state ?? "unknown").replaceAll("_", " ")}</p>
            </div>
          ))}
        </div>
      </details>
    </section>
  );
}
