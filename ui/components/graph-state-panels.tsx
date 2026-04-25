"use client";

import Link from "next/link";
import { ExternalLink, Route, SearchX } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";
import type { LineageNodeData } from "./lineage-nodes";

const FINDINGS_VIRTUALIZE_THRESHOLD = 80;
const FINDING_ROW_HEIGHT = 260;
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
}: {
  title: string;
  detail: string;
  suggestions: string[];
}) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="max-w-xl rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-6 text-left shadow-lg">
        <div className="flex items-start gap-3">
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2">
            <SearchX className="h-5 w-5 text-[color:var(--text-secondary)]" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-[color:var(--foreground)]">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-[color:var(--text-secondary)]">{detail}</p>
          </div>
        </div>
        <ul className="mt-4 space-y-2 text-sm text-[color:var(--text-secondary)]">
          {suggestions.map((suggestion) => (
            <li key={suggestion} className="flex items-start gap-2">
              <span className="mt-1 h-1.5 w-1.5 rounded-full bg-[color:var(--text-tertiary)]" />
              <span>{suggestion}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
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
    <div className="flex h-full items-center justify-center p-6" data-testid="graph-panel-skeleton">
      <div className="w-full max-w-4xl rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="h-3 w-28 animate-pulse rounded-full bg-[color:var(--surface-elevated)]" />
            <h3 className="mt-3 text-base font-semibold text-[color:var(--foreground)]">{title}</h3>
            <p className="mt-2 max-w-xl text-sm leading-6 text-[color:var(--text-secondary)]">{detail}</p>
          </div>
          <div className="h-10 w-24 animate-pulse rounded-xl bg-[color:var(--surface-elevated)]" />
        </div>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <SkeletonColumn bars={4} />
          <SkeletonColumn bars={5} />
          <SkeletonColumn bars={4} />
        </div>
      </div>
    </div>
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

function SkeletonColumn({ bars }: { bars: number }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
      <div className="h-4 w-24 animate-pulse rounded-full bg-[color:var(--surface-elevated)]" />
      <div className="mt-4 space-y-3">
        {Array.from({ length: bars }, (_, index) => (
          <div
            key={index}
            className="h-3 animate-pulse rounded-full bg-[color:var(--surface-elevated)]"
            style={{ width: `${92 - index * 11}%` }}
          />
        ))}
      </div>
    </div>
  );
}

export function GraphFindingsFallback({
  nodes,
  onSelect,
}: {
  nodes: Array<{ id: string; data: LineageNodeData }>;
  onSelect: (id: string, data: LineageNodeData) => void;
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
              Use this list for evidence and remediation, or relax the scope to recover the graph.
            </p>
          </div>
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs text-[color:var(--text-secondary)]">
            {nodes.length} finding{nodes.length !== 1 ? "s" : ""} in scope
          </div>
        </div>
      </div>

      {shouldVirtualize ? (
        <VirtualizedFindingList nodes={nodes} onSelect={onSelect} />
      ) : (
        <div className="grid flex-1 gap-3 overflow-y-auto p-4 lg:grid-cols-2">
          {nodes.map(({ id, data }) => (
            <FindingCard key={id} id={id} data={data} onSelect={onSelect} />
          ))}
        </div>
      )}
    </div>
  );
}

function VirtualizedFindingList({
  nodes,
  onSelect,
}: {
  nodes: Array<{ id: string; data: LineageNodeData }>;
  onSelect: (id: string, data: LineageNodeData) => void;
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
            <div key={id} style={{ minHeight: FINDING_ROW_HEIGHT - 12 }}>
              <FindingCard id={id} data={data} onSelect={onSelect} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function FindingCard({
  id,
  data,
  onSelect,
}: {
  id: string;
  data: LineageNodeData;
  onSelect: (id: string, data: LineageNodeData) => void;
}) {
  const severity = data.severity?.toUpperCase() ?? "UNKNOWN";
  const cvss = typeof data.cvssScore === "number" ? data.cvssScore.toFixed(1) : "N/A";
  const epss = typeof data.epssScore === "number" ? `${(data.epssScore * 100).toFixed(1)}%` : "N/A";
  const osvUrl = getOsvVulnerabilityUrl(data.label);
  const tone =
    data.severity === "critical"
      ? "border-red-800 bg-red-950/20"
      : data.severity === "high"
        ? "border-orange-800 bg-orange-950/20"
        : "border-[color:var(--border-subtle)] bg-[color:var(--surface)]";

  return (
    <div className={`rounded-2xl border p-4 ${tone}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[10px] font-medium tracking-[0.16em] text-[color:var(--text-secondary)]">
              {severity}
            </span>
            {data.isKev && (
              <span className="rounded-lg border border-red-800 bg-red-950/70 px-2 py-0.5 text-[10px] font-medium tracking-[0.16em] text-red-300">
                KEV
              </span>
            )}
          </div>
          <h4 className="mt-2 font-mono text-sm font-semibold text-[color:var(--foreground)]">{data.label}</h4>
          {data.description && (
            <p className="mt-2 line-clamp-3 text-sm leading-6 text-[color:var(--text-secondary)]">{data.description}</p>
          )}
        </div>
        <button
          type="button"
          onClick={() => onSelect(id, data)}
          className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
        >
          Open evidence
        </button>
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-3">
        <Stat label="CVSS" value={cvss} />
        <Stat label="EPSS" value={epss} />
        <Stat label="Risk" value={typeof data.riskScore === "number" ? data.riskScore.toFixed(1) : "N/A"} />
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <Link
          href={`/findings?cve=${encodeURIComponent(data.label)}`}
          className="inline-flex items-center gap-1 rounded-lg border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-950/70"
        >
          <Route className="h-3 w-3" />
          Open in findings
        </Link>
        {osvUrl && (
          <a
            href={osvUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          >
            View on OSV
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 text-sm font-mono text-[color:var(--foreground)]">{value}</div>
    </div>
  );
}
