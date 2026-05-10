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
  Loader2,
  Maximize2,
  Minimize2,
  Server,
  Shield,
  Wrench,
} from "lucide-react";
import { useReactFlow } from "@xyflow/react";
import { api, type GraphExportFormat } from "@/lib/api";
import type { LegendItem } from "@/lib/graph-utils";

// ─── Legend Bar ──────────────────────────────────────────────────────────────

const LAYER_ORDER = [
  "user",
  "identity",
  "app",
  "api_gateway",
  "orchestration",
  "mcp_server",
  "tool",
  "package",
  "runtime_evidence",
  "asset",
  "infra",
  "finding",
] as const;

const LAYER_LABELS: Record<string, string> = {
  user: "User",
  identity: "Identity",
  app: "Application",
  api_gateway: "API / Gateway",
  orchestration: "Orchestration",
  mcp_server: "MCP Servers",
  tool: "Tools",
  package: "Packages",
  runtime_evidence: "Runtime Evidence",
  asset: "Assets",
  infra: "Infrastructure",
  finding: "Findings",
  other: "Other",
};

export function GraphLegend({
  items,
  defaultOpen = false,
  embedded = false,
}: {
  items: LegendItem[];
  defaultOpen?: boolean;
  embedded?: boolean;
}) {
  const [open, setOpen] = useState(false);

  if (items.length === 0) return null;

  const nodeItems = items.filter((item) => item.kind !== "edge");
  const edgeItems = items.filter((item) => item.kind === "edge");

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className={`${embedded ? "hidden" : "flex"} items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800/80 px-2.5 py-1.5 text-xs text-zinc-300 transition-colors hover:bg-zinc-700 backdrop-blur-sm`}
        aria-expanded={open}
        aria-label={open ? "Hide legend" : "Show legend"}
      >
        <span className="font-medium">Legend</span>
        <span className="rounded-full bg-zinc-900 px-1.5 py-0.5 text-[10px] text-zinc-400">{items.length}</span>
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {(open || defaultOpen || embedded) && (
        <div className={`${embedded ? "relative w-[min(30rem,calc(100vw-2rem))] shadow-none" : "absolute right-0 top-full z-20 mt-2 w-[min(30rem,calc(100vw-2rem))] shadow-2xl shadow-black/30"} max-h-[60vh] overflow-y-auto rounded-xl border border-zinc-700 bg-zinc-900/95 p-3 backdrop-blur-md`}>
          {nodeItems.length > 0 && <LayeredLegendSections items={nodeItems} />}
          {edgeItems.length > 0 && (
            <LegendSection title="Relationships" items={edgeItems} />
          )}
        </div>
      )}
    </div>
  );
}

function LayeredLegendSections({ items }: { items: LegendItem[] }) {
  const grouped = new Map<string, LegendItem[]>();
  for (const item of items) {
    const layer = item.layer || "other";
    const existing = grouped.get(layer);
    if (existing) {
      existing.push(item);
    } else {
      grouped.set(layer, [item]);
    }
  }

  const orderedLayers = [
    ...LAYER_ORDER.filter((layer) => grouped.has(layer)),
    ...[...grouped.keys()].filter((layer) => !(LAYER_ORDER as readonly string[]).includes(layer)).sort(),
  ];

  return (
    <>
      {orderedLayers.map((layer) => (
        <LegendSection key={layer} title={LAYER_LABELS[layer] ?? layer.replace(/_/g, " ")} items={grouped.get(layer) ?? []} />
      ))}
    </>
  );
}

function LegendSection({ title, items }: { title: string; items: LegendItem[] }) {
  return (
    <div className="first:mt-0 mt-3">
      <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-zinc-500">{title}</div>
      <div className="grid grid-cols-1 gap-x-3 gap-y-2 text-[11px] text-zinc-300 sm:grid-cols-2">
        {items.map((item) => (
          <span key={`${title}:${item.label}`} className="flex min-w-0 items-center gap-2">
            <LegendMarker item={item} />
            <LegendIcon item={item} />
            <span className="min-w-0 truncate" title={item.label}>{item.label}</span>
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

const GRAPH_EVIDENCE_FORMATS: GraphExportFormat[] = ["json", "mermaid", "graphml"];

function extensionForGraphFormat(format: GraphExportFormat): string {
  return format === "json" ? "json" : format;
}

export function GraphEvidenceExportButton({
  scanId,
  formats = GRAPH_EVIDENCE_FORMATS,
  filenamePrefix,
}: {
  scanId?: string | undefined;
  formats?: GraphExportFormat[];
  filenamePrefix?: string | undefined;
}) {
  const [format, setFormat] = useState<GraphExportFormat>(formats[0] ?? "json");
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");

  const handleDownload = useCallback(async () => {
    if (!scanId) return;
    setExporting(true);
    setError("");
    try {
      const blob = await api.downloadScanGraph(scanId, format);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${filenamePrefix ?? `scan-${scanId}-graph`}.${extensionForGraphFormat(format)}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export graph evidence");
    } finally {
      setExporting(false);
    }
  }, [filenamePrefix, format, scanId]);

  return (
    <div className="flex flex-wrap items-center gap-2">
      <select
        aria-label="Graph evidence format"
        value={format}
        onChange={(event) => setFormat(event.target.value as GraphExportFormat)}
        className="rounded-lg border border-zinc-700 bg-zinc-900/90 px-2.5 py-1.5 text-xs text-zinc-300 focus:border-sky-600 focus:outline-none"
      >
        {formats.map((item) => (
          <option key={item} value={item}>
            {item.toUpperCase()}
          </option>
        ))}
      </select>
      <button
        type="button"
        onClick={() => void handleDownload()}
        disabled={!scanId || exporting}
        className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-900/60 bg-cyan-950/30 px-2.5 py-1.5 text-xs font-medium text-cyan-200 transition-colors hover:border-cyan-800 hover:bg-cyan-950/50 disabled:cursor-not-allowed disabled:opacity-50"
        title="Download the selected scan graph in an evidence format for review, import, or audit handoff."
      >
        {exporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
        Download graph evidence
      </button>
      {error ? <span className="text-xs text-red-300">{error}</span> : null}
    </div>
  );
}
