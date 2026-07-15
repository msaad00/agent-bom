"use client";

import Link from "next/link";
import { ExternalLink, Route } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { buildFindingsHref } from "@/lib/attack-paths";
import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import type { PageStateAction } from "@/components/states/page-state";
import type { LineageNodeData } from "./lineage-nodes";

const FINDINGS_VIRTUALIZE_THRESHOLD = 80;
const FINDING_ROW_HEIGHT = 92;
const FINDING_OVERSCAN = 4;

export function GraphControlGroup({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-[10px] uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">{label}</span>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

export function GraphEmptyState({
  title,
  detail,
  suggestions,
  command,
  actions,
}: {
  title: string;
  detail: string;
  suggestions: string[];
  command?: string | undefined;
  actions?: PageStateAction[] | undefined;
}) {
  return (
    <PageEmptyState
      title={title}
      detail={detail}
      suggestions={suggestions}
      command={command}
      actions={actions}
    />
  );
}

export function GraphPanelSkeleton({
  title = "Loading graph",
  detail = "Fetching a bounded graph window and preparing the visible topology.",
}: {
  title?: string;
  detail?: string;
}) {
  return (
    <PageLoadingState title={title} detail={detail} data-testid="graph-panel-skeleton" />
  );
}

export function GraphRefreshOverlay({ label = "Refreshing graph window" }: { label?: string }) {
  return (
    <div
      className="pointer-events-none absolute right-4 top-4 z-10 rounded-xl border border-sky-500/30 bg-sky-950/80 px-3 py-2 text-xs text-sky-100 shadow-lg backdrop-blur"
      data-testid="graph-refresh-overlay"
    >
      {label}
    </div>
  );
}

export function GraphFindingsFallback({
  nodes,
  onSelect,
  onExpandScope,
  scanId,
}: {
  nodes: Array<{ id: string; data: LineageNodeData }>;
  onSelect: (id: string, data: LineageNodeData) => void;
  scanId?: string | undefined;
  // Optional: when provided, a "Show full graph" button replaces the dead
  // "relax the scope to recover the graph" prose with an actual click target
  // that swaps the active filters to the expanded preset. The graph page
  // wires this so memory-only mode (no persisted graph backend) and focused
  // filters that drop the surrounding agent/server context can recover the
  // topology in one click instead of hunting through filter checkboxes.
  onExpandScope?: () => void;
}) {
  const shouldVirtualize = nodes.length > FINDINGS_VIRTUALIZE_THRESHOLD;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-orange-400">Findings scope</p>
            <h3 className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">This filter currently resolves to findings only</h3>
            <p className="mt-1 max-w-3xl text-xs leading-5 text-[color:var(--text-secondary)]">
              You are looking at the vulnerability slice without enough surrounding package, server, or agent context to form a topology.
              Use this list for evidence and remediation, or switch to the expanded topology scope.
            </p>
            {onExpandScope ? (
              <button
                type="button"
                onClick={onExpandScope}
                className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/20 hover:border-emerald-400 transition-colors"
              >
                Show expanded topology
              </button>
            ) : null}
          </div>
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs text-[color:var(--text-secondary)]">
            {nodes.length} finding{nodes.length !== 1 ? "s" : ""} in scope
          </div>
        </div>
      </div>

      {shouldVirtualize ? (
        <VirtualizedFindingList nodes={nodes} onSelect={onSelect} scanId={scanId} />
      ) : (
        <div className="flex-1 overflow-y-auto p-4">
          <div className="overflow-hidden rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
          {nodes.map(({ id, data }) => (
            <FindingRow key={id} id={id} data={data} onSelect={onSelect} scanId={scanId} />
          ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VirtualizedFindingList({
  nodes,
  onSelect,
  scanId,
}: {
  nodes: Array<{ id: string; data: LineageNodeData }>;
  onSelect: (id: string, data: LineageNodeData) => void;
  scanId?: string | undefined;
}) {
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(720);

  useEffect(() => {
    const element = scrollerRef.current;
    if (!element) return;

    const measure = () => setViewportHeight(element.clientHeight || 720);
    measure();

    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure);
      return () => window.removeEventListener("resize", measure);
    }

    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const { beforeHeight, visibleNodes, totalHeight } = useMemo(() => {
    const start = Math.max(0, Math.floor(scrollTop / FINDING_ROW_HEIGHT) - FINDING_OVERSCAN);
    const visibleCount = Math.ceil(viewportHeight / FINDING_ROW_HEIGHT) + FINDING_OVERSCAN * 2;
    const end = Math.min(nodes.length, start + visibleCount);
    return {
      beforeHeight: start * FINDING_ROW_HEIGHT,
      visibleNodes: nodes.slice(start, end),
      totalHeight: nodes.length * FINDING_ROW_HEIGHT,
    };
  }, [nodes, scrollTop, viewportHeight]);

  return (
    <div
      ref={scrollerRef}
      className="flex-1 overflow-y-auto p-4"
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
      data-testid="virtualized-graph-findings"
    >
      <div style={{ height: totalHeight, position: "relative" }}>
        <div
          className="grid gap-3"
          style={{ position: "absolute", left: 0, right: 0, top: beforeHeight }}
        >
          {visibleNodes.map(({ id, data }) => (
            <div key={id} style={{ minHeight: FINDING_ROW_HEIGHT }}>
              <FindingRow id={id} data={data} onSelect={onSelect} scanId={scanId} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function FindingRow({
  id,
  data,
  onSelect,
  scanId,
}: {
  id: string;
  data: LineageNodeData;
  onSelect: (id: string, data: LineageNodeData) => void;
  scanId?: string | undefined;
}) {
  const severity = data.severity?.toUpperCase() ?? "UNKNOWN";
  const cvss = typeof data.cvssScore === "number" ? data.cvssScore.toFixed(1) : "N/A";
  const epss = typeof data.epssScore === "number" ? `${(data.epssScore * 100).toFixed(1)}%` : "N/A";
  const risk = typeof data.riskScore === "number" ? data.riskScore.toFixed(1) : "N/A";
  const osvUrl = getOsvVulnerabilityUrl(data.label);
  const severityClass =
    data.severity === "critical"
      ? "border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-200"
      : data.severity === "high"
        ? "border-orange-500/25 bg-orange-500/10 text-orange-700 dark:text-orange-200"
        : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]";

  return (
    <div className="grid gap-3 border-b border-[color:var(--border-subtle)] px-4 py-3 last:border-b-0 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className={`rounded-lg border px-2 py-0.5 text-[10px] font-medium tracking-[0.14em] ${severityClass}`}>
            {severity}
          </span>
          {data.isKev && (
            <span className="rounded-lg border border-red-500/25 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium tracking-[0.14em] text-red-700 dark:text-red-200">
              KEV
            </span>
          )}
          <h4 className="truncate font-mono text-sm font-semibold text-[color:var(--foreground)]">{data.label}</h4>
        </div>
        <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-[color:var(--text-tertiary)]">
          <span>CVSS {cvss}</span>
          <span>EPSS {epss}</span>
          <span>Risk {risk}</span>
          {data.ecosystem && <span>{data.ecosystem}</span>}
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onSelect(id, data)}
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
        >
          Open evidence
        </button>
        <Link
          href={buildFindingsHref({ scanId, cve: data.label })}
          className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 dark:border-emerald-800 bg-emerald-500/10 dark:bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-300 transition-colors hover:bg-emerald-500/10 dark:hover:bg-emerald-950/70"
        >
          <Route className="h-3 w-3" />
          Findings
        </Link>
        {osvUrl && (
          <a
            href={osvUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          >
            OSV
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>
    </div>
  );
}
