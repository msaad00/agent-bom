"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Loader2, Network, Radar } from "lucide-react";

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
  onExpandNeighbors,
  onShowImpact,
  remediationHref,
  enrich = true,
}: {
  data: LineageNodeData;
  onClose: () => void;
  scanId?: string | undefined;
  variant?: "overlay" | "inline";
  onShowBlastRadius?: (() => void) | undefined;
  blastRadiusActive?: boolean;
  blastRadiusLoading?: boolean;
  onExpandNeighbors?: (() => void) | undefined;
  onShowImpact?: (() => void) | undefined;
  remediationHref?: string | undefined;
  /** When true and scanId is set, refresh node detail from /v1/graph/node. */
  enrich?: boolean;
}) {
  const [enriched, setEnriched] = useState<LineageNodeData>(data);
  const [loading, setLoading] = useState(false);
  const nodeId = nodeIdFromLineageData(data) ?? nodeIdFromLineageData(enriched);

  useEffect(() => {
    setEnriched(data);
  }, [data]);

  useEffect(() => {
    if (!enrich || !scanId || !nodeId) return;
    let cancelled = false;
    setLoading(true);
    void api
      .getGraphNode(nodeId, scanId)
      .then((detail) => {
        if (cancelled) return;
        setEnriched((current) => mergeGraphNodeDetail(current, detail));
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
        <span>impact {enriched.impactCount ?? "—"}</span>
      </div>
    </div>
  );

  const footerSlot = (
    <div className="space-y-2 border-t border-[color:var(--border-subtle)] pt-3">
      <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
        Next action
      </p>
      <Link
        href={nextAction.href}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-600/40 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-800 transition hover:border-emerald-500/60 dark:text-emerald-200"
      >
        {nextAction.label}
        <ArrowRight className="h-3.5 w-3.5" />
      </Link>
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
      headerSlot={headerSlot}
      footerSlot={footerSlot}
    />
  );
}
