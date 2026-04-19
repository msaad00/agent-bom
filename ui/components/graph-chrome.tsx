"use client";

/**
 * Shared graph chrome components — Legend bar, fullscreen toggle, export button.
 * Used across all graph views for consistent UX.
 */

import { useState, useCallback } from "react";
import {
  Brain,
  Boxes,
  Bug,
  ChevronDown,
  Cloud,
  Database,
  Download,
  FolderTree,
  KeyRound,
  Maximize2,
  Minimize2,
  Server,
  Shield,
  Wrench,
} from "lucide-react";
import { useReactFlow } from "@xyflow/react";
import type { LegendItem } from "@/lib/graph-utils";

// ─── Legend Bar ──────────────────────────────────────────────────────────────

export function GraphLegend({ items }: { items: LegendItem[] }) {
  const [open, setOpen] = useState(false);

  if (items.length === 0) return null;

  const nodeItems = items.filter((item) => item.kind !== "edge");
  const edgeItems = items.filter((item) => item.kind === "edge");

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
          {nodeItems.length > 0 && (
            <LegendSection title="Entities" items={nodeItems} />
          )}
          {edgeItems.length > 0 && (
            <LegendSection title="Relationships" items={edgeItems} />
          )}
        </div>
      )}
    </div>
  );
}

function LegendSection({ title, items }: { title: string; items: LegendItem[] }) {
  return (
    <div className="first:mt-0 mt-3">
      <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-zinc-500">{title}</div>
      <div className="grid grid-cols-2 gap-x-3 gap-y-2 text-[11px] text-zinc-300 sm:grid-cols-3">
        {items.map((item) => (
          <span key={`${title}:${item.label}`} className="flex items-center gap-2 whitespace-nowrap">
            <LegendMarker item={item} />
            <LegendIcon item={item} />
            {item.label}
          </span>
        ))}
      </div>
    </div>
  );
}

function LegendMarker({ item }: { item: LegendItem }) {
  if (item.kind === "edge") {
    return (
      <span className="relative inline-flex h-2.5 w-5 shrink-0 items-center">
        <span
          className="block w-full border-t"
          style={{
            borderTopColor: item.color,
            borderTopStyle: item.lineStyle === "dashed" ? "dashed" : "solid",
            borderTopWidth: 2,
          }}
        />
        <span
          className="absolute right-0 h-2 w-2 rotate-45 border-r-2 border-t-2"
          style={{ borderColor: item.color }}
        />
      </span>
    );
  }

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

function LegendIcon({ item }: { item: LegendItem }) {
  const label = item.label.toLowerCase();
  const className = "h-3.5 w-3.5 shrink-0";

  if (label.includes("agent")) return <Shield className={className} style={{ color: item.color }} />;
  if (label.includes("server")) return <Server className={className} style={{ color: item.color }} />;
  if (label.includes("package")) return <Boxes className={className} style={{ color: item.color }} />;
  if (label.includes("cred")) return <KeyRound className={className} style={{ color: item.color }} />;
  if (label.includes("tool")) return <Wrench className={className} style={{ color: item.color }} />;
  if (label.includes("vuln") || label.includes("cve")) return <Bug className={className} style={{ color: item.color }} />;
  if (label.includes("model")) return <Brain className={className} style={{ color: item.color }} />;
  if (label.includes("dataset")) return <Database className={className} style={{ color: item.color }} />;
  if (label.includes("cloud")) return <Cloud className={className} style={{ color: item.color }} />;
  if (label.includes("provider") || label.includes("fleet") || label.includes("cluster")) {
    return <FolderTree className={className} style={{ color: item.color }} />;
  }
  return null;
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
