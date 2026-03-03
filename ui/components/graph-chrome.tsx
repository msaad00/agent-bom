"use client";

/**
 * Shared graph chrome components — Legend bar, fullscreen toggle, export button.
 * Used across all graph views for consistent UX.
 */

import { useState, useCallback } from "react";
import { Maximize2, Minimize2, Download } from "lucide-react";
import { useReactFlow } from "@xyflow/react";
import type { LegendItem } from "@/lib/graph-utils";

// ─── Legend Bar ──────────────────────────────────────────────────────────────

export function GraphLegend({ items }: { items: LegendItem[] }) {
  return (
    <div className="flex items-center gap-3 text-[10px] text-zinc-500">
      {items.map((item) => (
        <span key={item.label} className="flex items-center gap-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor: item.color,
              border: item.dashed ? `1px dashed ${item.color}` : undefined,
              background: item.dashed ? "transparent" : item.color,
            }}
          />
          {item.label}
        </span>
      ))}
    </div>
  );
}

// ─── Fullscreen Toggle ──────────────────────────────────────────────────────

export function useFullscreen() {
  const [isFullscreen, setIsFullscreen] = useState(false);

  const toggle = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  }, []);

  return { isFullscreen, toggle };
}

export function FullscreenButton() {
  const { isFullscreen, toggle } = useFullscreen();

  return (
    <button
      onClick={toggle}
      className="flex items-center gap-1.5 px-2.5 py-1.5 bg-zinc-800/80 border border-zinc-700 rounded-lg text-xs text-zinc-300 hover:bg-zinc-700 transition-colors backdrop-blur-sm"
      title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
    >
      {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
    </button>
  );
}

// ─── Export Button ───────────────────────────────────────────────────────────

export function GraphExportButton({ filename }: { filename?: string }) {
  const { getNodes, getEdges } = useReactFlow();

  const handleExport = useCallback(() => {
    const flowData = { nodes: getNodes(), edges: getEdges() };
    const blob = new Blob([JSON.stringify(flowData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename ?? `graph-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [getNodes, getEdges, filename]);

  return (
    <button
      onClick={handleExport}
      className="flex items-center gap-1.5 px-2.5 py-1.5 bg-zinc-800/80 border border-zinc-700 rounded-lg text-xs text-zinc-300 hover:bg-zinc-700 transition-colors backdrop-blur-sm"
    >
      <Download className="w-3.5 h-3.5" />
      Export
    </button>
  );
}
