"use client";

/**
 * Shared graph chrome components — Legend bar, fullscreen toggle, export button.
 * Used across all graph views for consistent UX.
 */

import { useState, useCallback } from "react";
import { Maximize2, Minimize2, Download, ChevronDown } from "lucide-react";
import { useReactFlow } from "@xyflow/react";
import type { LegendItem } from "@/lib/graph-utils";

// ─── Legend Bar ──────────────────────────────────────────────────────────────

export function GraphLegend({ items }: { items: LegendItem[] }) {
  const [open, setOpen] = useState(false);

  if (items.length === 0) return null;

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800/80 px-2.5 py-1.5 text-xs text-zinc-300 transition-colors hover:bg-zinc-700 backdrop-blur-sm"
        aria-expanded={open}
        aria-label={open ? "Hide legend" : "Show legend"}
      >
        <span className="font-medium">Legend</span>
        <span className="rounded-full bg-zinc-900 px-1.5 py-0.5 text-[10px] text-zinc-400">{items.length}</span>
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="absolute right-0 top-full z-20 mt-2 w-[min(22rem,calc(100vw-2rem))] rounded-xl border border-zinc-700 bg-zinc-900/95 p-3 shadow-2xl shadow-black/30 backdrop-blur-md">
          <div className="grid grid-cols-2 gap-x-3 gap-y-2 text-[11px] text-zinc-300 sm:grid-cols-3">
            {items.map((item) => (
              <span key={item.label} className="flex items-center gap-2 whitespace-nowrap">
                <LegendMarker item={item} />
                {item.label}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function LegendMarker({ item }: { item: LegendItem }) {
  const className =
    item.shape === "square"
      ? "h-2.5 w-2.5 rounded-[3px]"
      : item.shape === "diamond"
        ? "h-2.5 w-2.5 rotate-45 rounded-[2px]"
        : item.shape === "pill"
          ? "h-2 w-3.5 rounded-full"
          : "h-2.5 w-2.5 rounded-full";

  return (
    <span
      className={className}
      style={{
        backgroundColor: item.color,
        border: item.dashed ? `1px dashed ${item.color}` : undefined,
        background: item.dashed ? "transparent" : item.color,
      }}
    />
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
