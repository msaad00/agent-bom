"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { GraphNodeDetailResponse } from "@/lib/api-types";
import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Loader2, Network, Radar, ShieldAlert } from "lucide-react";

import { LineageDetailPanel } from "@/components/lineage-detail";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { api } from "@/lib/api";
import {
  evidenceTierLabel,
  mergeGraphNodeDetail,
  nodeIdFromLineageData,
  resolveInvestigationNextAction,
  semanticLayerForNodeType,
} from "@/lib/graph-entity-detail";

/**
 * Shared investigation entity drawer used by security-graph, lineage, mesh,
 * and context lenses. Composes LineageDetailPanel with rubric fields
 * (stable ID, semantic layer, evidence tier, in/out counts, next action)
 * and optional expand / impact actions against the live graph API.
 */
export function GraphEntityDrawer({
  data,
  onClose,
  scanId,
  variant = "overlay",
  onShowBlastRadius,
  blastRadiusActive = false,
  blastRadiusLoading = false,
  onInspectNode,
  onExpandNeighbors,
  onShowImpact,
  onQuarantine,
  quarantineState = "idle",
  quarantineMessage = "",
  remediationHref,
  enrich = true,
}: {
  data: LineageNodeData;
  onClose: () => void;
  scanId?: string | undefined;
  variant?: "overlay" | "inline" | "docked";
  onShowBlastRadius?: (() => void) | undefined;
  blastRadiusActive?: boolean;
  blastRadiusLoading?: boolean;
  onInspectNode?: ((nodeId: string) => void) | undefined;
  onExpandNeighbors?: (() => void) | undefined;
  onShowImpact?: (() => void) | undefined;
  /** Contain this agent at the gateway. Agent nodes only; drawer stays presentational. */
  onQuarantine?: (() => void) | undefined;
  quarantineState?: "idle" | "confirming" | "pending" | "done" | "error";
  quarantineMessage?: string;
  remediationHref?: string | undefined;
  /** When true and scanId is set, refresh node detail from /v1/graph/node. */
  enrich?: boolean;
}) {
  const [loading, setLoading] = useState(false);
  const nodeId = nodeIdFromLineageData(data);

  const [loadedDetail, setLoadedDetail] = useState<{
    scanId: string;
    response: GraphNodeDetailResponse;
  } | null>(null);
  // Canvas and detail requests may finish in either order. Reapply the richer
  // evidence to each canvas update, but only for the same node and snapshot.
  const detail = enrich && loadedDetail && loadedDetail.scanId === scanId && loadedDetail.response.node.id === nodeId
    ? loadedDetail.response : null;
  const enriched = useMemo(() => detail ? mergeGraphNodeDetail(data, detail) : data, [data, detail]);
  const pathname = usePathname();
  const [showAllRelationships, setShowAllRelationships] = useState(false);

  useEffect(() => {
    setLoadedDetail(null);
    setShowAllRelationships(false);
    setLoading(false);
    if (!enrich || !scanId || !nodeId) return;
    let cancelled = false;
    setLoading(true);
    void api
      .getGraphNode(nodeId, scanId)
      .then((detail) => {
        if (cancelled) return;
        setLoadedDetail({ scanId, response: detail });
      })
      .catch(() => {
        /* keep canvas-local fields when detail fetch fails */
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [enrich, nodeId, scanId]);

  const layer = useMemo(
    () => semanticLayerForNodeType(enriched.nodeType),
    [enriched.nodeType],
  );
  const nextAction = useMemo(
    () =>
      resolveInvestigationNextAction(enriched, {
        scanId,
        remediationHref,
      }),
    [enriched, remediationHref, scanId],
  );
  const evidenceLabel = evidenceTierLabel(enriched);

  const relationships = detail && detail.node.id === nodeId
    ? [...new Map([...detail.edges_in, ...detail.edges_out].map((edge) => [edge.id, edge])).values()] : [];
  const relationshipSlot = relationships.length > 0 ? (
    <div className="space-y-2 border-t border-outline pt-3">
      <p className="text-xs text-ink-secondary">Direct relationships · {relationships.length} returned</p>
      {(showAllRelationships ? relationships : relationships.slice(0, 8)).map((edge) => {
        const incoming = edge.target === nodeId;
        const neighbor = incoming ? edge.source : edge.target;
        const label = `${incoming ? "Incoming" : "Outgoing"} · ${edge.relationship.replaceAll("_", " ")} · ${neighbor}`;
        return onInspectNode ? (
          <button key={edge.id} type="button" onClick={() => onInspectNode(neighbor)}
            className="block w-full break-words rounded-lg border border-outline p-2 text-left text-xs text-foreground hover:bg-surface-muted">
            {label}
          </button>
        ) : <p key={edge.id} className="break-words text-xs text-ink-secondary">{label}</p>;
      })}
      {relationships.length > 8 && <button type="button" aria-expanded={showAllRelationships}
        className="text-xs text-emerald-700 dark:text-emerald-300" onClick={() => setShowAllRelationships(!showAllRelationships)}>
        {showAllRelationships ? "Show fewer relationships" : `Show all ${relationships.length} relationships`}
      </button>}
    </div>
  ) : undefined;
  const showNextAction = !(pathname === "/graph" && nextAction.label === "Inspect in lineage");

  const headerSlot = (
    <div className="space-y-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
      <div className="flex flex-wrap items-center gap-2 text-[11px]">
        <span className="rounded border border-[color:var(--border-subtle)] px-1.5 py-0.5 font-mono text-[color:var(--text-secondary)]">
          {layer.label}
        </span>
        <span className="rounded border border-[color:var(--border-subtle)] px-1.5 py-0.5 text-[color:var(--text-tertiary)]">
          evidence · {evidenceLabel}
        </span>
        {loading ? (
          <span className="inline-flex items-center gap-1 text-[color:var(--text-tertiary)]">
            <Loader2 className="h-3 w-3 animate-spin" />
            syncing
          </span>
        ) : null}
      </div>
      {nodeId ? (
        <p className="truncate font-mono text-[10px] text-[color:var(--text-tertiary)]" title={nodeId}>
          id · {nodeId}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-3 text-[11px] text-[color:var(--text-secondary)]">
        <span>in {enriched.incomingEdgeCount ?? "—"}</span>
        <span>out {enriched.outgoingEdgeCount ?? "—"}</span>
        <span>neighbors {enriched.neighborCount ?? "—"}</span>
        <span title="Upstream graph connections within the reported hop limit; not confirmed compromise">upstream connections {enriched.impactCount ?? "—"}</span>
      </div>
    </div>
  );

  const footerSlot = (
    <div className="space-y-2 border-t border-[color:var(--border-subtle)] pt-3">
      {showNextAction && <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Next action</p>}
      {showNextAction && <Link
        href={nextAction.href}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-600/40 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-800 transition hover:border-emerald-500/60 dark:text-emerald-200"
      >
        {nextAction.label}
        <ArrowRight className="h-3.5 w-3.5" />
      </Link>}
      {(onExpandNeighbors || onShowImpact) && (
        <div className="grid grid-cols-2 gap-2">
          {onExpandNeighbors ? (
            <button
              type="button"
              onClick={onExpandNeighbors}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-2 text-[11px] font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <Network className="h-3.5 w-3.5" />
              Expand
            </button>
          ) : (
            <span />
          )}
          {onShowImpact ? (
            <button
              type="button"
              onClick={onShowImpact}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-2 text-[11px] font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <Radar className="h-3.5 w-3.5" />
              Impact
            </button>
          ) : null}
        </div>
      )}
      {onQuarantine && enriched.nodeType === "agent" && (
        <div className="space-y-1.5 border-t border-[color:var(--border-subtle)] pt-2">
          <button
            type="button"
            onClick={onQuarantine}
            disabled={quarantineState === "pending" || quarantineState === "done"}
            data-testid="graph-quarantine-agent"
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/10 px-2 py-2 text-[11px] font-medium text-red-700 transition hover:border-red-500/60 disabled:opacity-60 dark:text-red-200"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            {quarantineState === "confirming"
              ? "Confirm — block every tool call"
              : quarantineState === "pending"
                ? "Quarantining…"
                : quarantineState === "done"
                  ? "Quarantined"
                  : "Quarantine agent"}
          </button>
          {quarantineMessage && (
            <p
              className={`text-[10px] ${quarantineState === "error" ? "text-red-600 dark:text-red-300" : "text-[color:var(--text-tertiary)]"}`}
            >
              {quarantineMessage}
            </p>
          )}
        </div>
      )}
    </div>
  );

  return (
    <LineageDetailPanel
      data={enriched}
      onClose={onClose}
      variant={variant}
      onShowBlastRadius={onShowBlastRadius}
      blastRadiusActive={blastRadiusActive}
      blastRadiusLoading={blastRadiusLoading}
      relationshipSlot={relationshipSlot}
      headerSlot={headerSlot}
      footerSlot={footerSlot}
    />
  );
}
