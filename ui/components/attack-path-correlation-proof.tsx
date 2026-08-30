import type { FixFirstRiskReason, GraphAttackPath } from "@/lib/api-types";
import type { UnifiedNode } from "@/lib/graph-schema";

function badgeTone(kind: string): string {
  if (kind === "runtime_observed") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  if (kind === "runtime_blocked") return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300";
  if (kind === "modeled_infrastructure") return "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300";
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
  const receipts = path.hop_evidence ?? [];
  if (receipts.length === 0) return null;
  const nodeById = new Map(nodes.map((node) => [node.id, node]));

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
          <p className="text-xs font-semibold text-[color:var(--foreground)]">Correlation provenance</p>
          <p className="mt-0.5 text-[10px] text-[color:var(--text-tertiary)]">
            {receipts.filter((receipt) => receipt.complete).length}/{Math.max(path.hops.length - 1, 0)} directed traversable hops evidenced · freshness retained per source
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {[...kinds].map(([kind, label]) => (
            <span key={kind} className={`rounded-full border px-2 py-1 text-[10px] font-medium ${badgeTone(kind)}`}>
              {label}
            </span>
          ))}
        </div>
      </div>
      <div className="mt-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2.5">
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
          Exact joined chain
        </p>
        <ol className="mt-2 grid gap-1.5 sm:grid-cols-2 xl:grid-cols-4">
          {path.hops.map((nodeId, index) => {
            const node = nodeById.get(nodeId);
            return (
              <li
                key={`${nodeId}-${index}`}
                className="min-w-0 rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-1.5"
              >
                <p className="text-[9px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
                  {index + 1}. {node?.entity_type?.replaceAll("_", " ") ?? "entity"}
                </p>
                <p className="mt-0.5 break-all font-mono text-[9px] leading-3 text-[color:var(--foreground)]">
                  {node?.label || nodeId}
                </p>
              </li>
            );
          })}
        </ol>
      </div>
      <div className="mt-2 grid gap-1.5 sm:grid-cols-2 xl:grid-cols-4">
        {receipts.map((receipt, index) => (
          <div key={`${receipt.source_node_id}-${receipt.target_node_id}-${index}`} className="min-w-0 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-2 text-[10px]">
            <p className="truncate font-mono text-[color:var(--foreground)]">{index + 1}. {receipt.relationship}</p>
            <p className="mt-1 truncate text-[color:var(--text-secondary)]">{receipt.source_snapshot_ids.join(" + ")}</p>
            <p className="mt-1 text-[color:var(--text-tertiary)]">{receipt.evidence_tier.replaceAll("_", " ")} · {receipt.freshness.replaceAll("_", " ")} · {receipt.runtime_observed_state.replaceAll("_", " ")}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
