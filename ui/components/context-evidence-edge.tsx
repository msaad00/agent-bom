"use client";

import { memo } from "react";
import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from "@xyflow/react";

/** Separate branches, with a naturally sized label that stays correct after zoom. */
export const ContextEvidenceEdge = memo(function ContextEvidenceEdge({
  sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition,
  markerEnd, style, label, labelStyle, data,
}: EdgeProps) {
  const [path, x, y] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  return <>
    <BaseEdge path={path} {...(markerEnd ? { markerEnd } : {})} style={style ?? {}} interactionWidth={24} />
    {typeof label === "string" && <EdgeLabelRenderer>
      <button type="button" className="nodrag nopan absolute whitespace-nowrap border border-[var(--border-strong)] bg-[var(--surface-metric)] px-2 py-1 text-xs font-medium text-[var(--foreground)] shadow-sm"
        aria-label={`Inspect relationship: ${label}`}
        style={{ pointerEvents: "all", borderRadius: 6, fontSize: labelStyle?.fontSize ?? 12, transform: `translate(-50%, -50%) translate(${x}px, ${y}px)` }}
        onClick={() => { if (typeof data?.onInspect === "function") data.onInspect(); }}>
        {label}
      </button>
    </EdgeLabelRenderer>}
  </>;
});
