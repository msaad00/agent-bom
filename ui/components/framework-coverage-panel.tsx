"use client";

import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Filter } from "lucide-react";

import { FrameworkIcon } from "@/components/framework-icon";

export type FrameworkCoverageItem = {
  id: string;
  label: string;
  pass: number;
  warn: number;
  fail: number;
  total: number;
  category: "ai" | "governance" | "cloud";
};

type CategoryFilter = "all" | "ai" | "governance" | "cloud";
type StatusFilter = "all" | "attention" | "fail";

type FrameworkCoveragePanelProps = {
  items: FrameworkCoverageItem[];
  onFocusFramework?: ((id: string) => void) | undefined;
  cloudCisHref?: string | undefined;
};

function statusTone(item: FrameworkCoverageItem): "pass" | "warning" | "fail" {
  if (item.fail > 0) return "fail";
  if (item.warn > 0) return "warning";
  return "pass";
}

function CompactBar({ pass, warn, fail, total }: Pick<FrameworkCoverageItem, "pass" | "warn" | "fail" | "total">) {
  const pPct = total > 0 ? (pass / total) * 100 : 0;
  const wPct = total > 0 ? (warn / total) * 100 : 0;
  const fPct = total > 0 ? (fail / total) * 100 : 0;
  return (
    <div className="h-1.5 w-full min-w-[96px] max-w-[180px] overflow-hidden rounded-full bg-[color:var(--surface-muted)] flex">
      {pass > 0 ? <div className="bg-emerald-500" style={{ width: `${pPct}%` }} /> : null}
      {warn > 0 ? <div className="bg-yellow-500" style={{ width: `${wPct}%` }} /> : null}
      {fail > 0 ? <div className="bg-red-500" style={{ width: `${fPct}%` }} /> : null}
    </div>
  );
}

function ExpandedBar({ label, pass, warn, fail, total }: FrameworkCoverageItem) {
  const pPct = total > 0 ? (pass / total) * 100 : 0;
  const wPct = total > 0 ? (warn / total) * 100 : 0;
  const fPct = total > 0 ? (fail / total) * 100 : 0;
  return (
    <div className="space-y-2 pt-1">
      <div className="h-2.5 overflow-hidden rounded-full bg-[color:var(--surface-muted)] flex">
        {pass > 0 ? <div className="bg-emerald-500 transition-all duration-500" style={{ width: `${pPct}%` }} /> : null}
        {warn > 0 ? <div className="bg-yellow-500 transition-all duration-500" style={{ width: `${wPct}%` }} /> : null}
        {fail > 0 ? <div className="bg-red-500 transition-all duration-500" style={{ width: `${fPct}%` }} /> : null}
      </div>
      <div className="flex flex-wrap gap-4 text-xs text-[color:var(--text-tertiary)]">
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-emerald-500" /> {pass} pass
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-yellow-500" /> {warn} warning
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-red-500" /> {fail} fail
        </span>
        <span className="text-[color:var(--text-secondary)]">{label}</span>
      </div>
    </div>
  );
}

export function FrameworkCoveragePanel({ items, onFocusFramework, cloudCisHref }: FrameworkCoveragePanelProps) {
  const [category, setCategory] = useState<CategoryFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const summary = useMemo(() => {
    const failing = items.filter((item) => item.fail > 0).length;
    const warning = items.filter((item) => item.warn > 0 && item.fail === 0).length;
    const passing = items.filter((item) => item.fail === 0 && item.warn === 0).length;
    return { failing, warning, passing, total: items.length };
  }, [items]);

  const filtered = useMemo(() => {
    return items.filter((item) => {
      if (category !== "all" && item.category !== category) return false;
      const tone = statusTone(item);
      if (statusFilter === "fail") return tone === "fail";
      if (statusFilter === "attention") return tone === "fail" || tone === "warning";
      return true;
    });
  }, [category, items, statusFilter]);

  const allExpanded = filtered.length > 0 && filtered.every((item) => expanded[item.id]);

  function toggle(id: string) {
    setExpanded((current) => ({ ...current, [id]: !current[id] }));
  }

  function expandAll(open: boolean) {
    setExpanded((current) => {
      const next = { ...current };
      for (const item of filtered) {
        next[item.id] = open;
      }
      return next;
    });
  }

  return (
    <section
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5"
      data-testid="framework-coverage-panel"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-[color:var(--text-secondary)]">
            Framework coverage
          </h2>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
            Summary first — expand a row or jump to controls below.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-700 dark:text-emerald-300">
            {summary.passing} passing
          </span>
          <span className="rounded-full border border-yellow-500/30 bg-yellow-500/10 px-2.5 py-1 text-yellow-700 dark:text-yellow-200">
            {summary.warning} warning
          </span>
          <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-700 dark:text-red-300">
            {summary.failing} failing
          </span>
        </div>
      </div>

      <div className="mt-4 flex flex-col gap-3 border-b border-[color:var(--border-subtle)] pb-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap gap-1">
          {(
            [
              ["all", "All"],
              ["ai", "AI safety"],
              ["governance", "Governance"],
              ["cloud", "Cloud & ops"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              onClick={() => setCategory(value)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                category === value
                  ? "bg-emerald-600 text-white"
                  : "bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-[color:var(--text-tertiary)]" aria-hidden="true" />
          {(
            [
              ["all", "All statuses"],
              ["attention", "Needs attention"],
              ["fail", "Failing only"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              onClick={() => setStatusFilter(value)}
              className={`rounded-md px-2.5 py-1 text-xs transition-colors ${
                statusFilter === value
                  ? "bg-[color:var(--surface-muted)] text-[color:var(--foreground)]"
                  : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
              }`}
            >
              {label}
            </button>
          ))}
          <button
            type="button"
            onClick={() => expandAll(!allExpanded)}
            className="rounded-md px-2.5 py-1 text-xs text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
          >
            {allExpanded ? "Collapse all" : "Expand all"}
          </button>
        </div>
      </div>

      <ul className="mt-3 divide-y divide-[color:var(--border-subtle)]">
        {filtered.map((item) => {
          const open = Boolean(expanded[item.id]);
          const tone = statusTone(item);
          return (
            <li key={item.id} className="py-2">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <button
                  type="button"
                  onClick={() => toggle(item.id)}
                  aria-expanded={open}
                  className="flex min-w-0 flex-1 items-center gap-2 text-left"
                >
                  {open ? (
                    <ChevronDown className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)]" />
                  ) : (
                    <ChevronRight className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)]" />
                  )}
                  <FrameworkIcon frameworkId={item.id} size={28} />
                  <span className="truncate text-sm font-medium text-[color:var(--foreground)]">{item.label}</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                      tone === "fail"
                        ? "bg-red-500/15 text-red-700 dark:text-red-300"
                        : tone === "warning"
                          ? "bg-yellow-500/15 text-yellow-700 dark:text-yellow-200"
                          : "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                    }`}
                  >
                    {tone === "fail" ? "Fail" : tone === "warning" ? "Warn" : "Pass"}
                  </span>
                </button>
                <div className="flex items-center gap-3 pl-6 sm:pl-0">
                  {!open ? <CompactBar {...item} /> : null}
                  <span className="shrink-0 text-xs tabular-nums text-[color:var(--text-tertiary)]">
                    {item.pass}/{item.total}
                  </span>
                  {onFocusFramework ? (
                    <button
                      type="button"
                      onClick={() => onFocusFramework(item.id)}
                      className="shrink-0 text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      Controls
                    </button>
                  ) : null}
                </div>
              </div>
              {open ? <ExpandedBar {...item} /> : null}
            </li>
          );
        })}
      </ul>

      {filtered.length === 0 ? (
        <p className="py-6 text-center text-sm text-[color:var(--text-tertiary)]">No frameworks match these filters.</p>
      ) : null}

      {cloudCisHref ? (
        <div className="mt-4 border-t border-[color:var(--border-subtle)] pt-3">
          <a href={cloudCisHref} className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
            <ChevronRight className="h-3.5 w-3.5" />
            Cloud CIS benchmarks (AWS / Azure / GCP / Snowflake / Databricks)
          </a>
        </div>
      ) : null}
    </section>
  );
}
