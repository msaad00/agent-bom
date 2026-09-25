"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { TrendPointResponse } from "@/lib/api-types";

const number = (value: number | null | undefined) => value == null ? "Unavailable" : value.toLocaleString(undefined, { maximumFractionDigits: 1 });

function HistoryPlot({ points, field, label }: {
  points: TrendPointResponse[];
  field: "new_findings" | "no_longer_detected" | "open_finding_age_days" | "evidence_age_days";
  label: string;
}) {
  const values = points.map(point => field === "new_findings" || field === "no_longer_detected"
    ? (point.comparison?.status === "comparable" ? point.comparison[field] : null)
    : point[field]);
  const valid = values.filter((value): value is number => typeof value === "number" && Number.isFinite(value));
  const times = points.map(point => Date.parse(point.timestamp));
  const start = Math.min(...times), span = Math.max(...times) - start || 1;
  const max = Math.max(1, ...valid);
  return <figure className="min-w-0 rounded-xl border border-outline p-3">
    <figcaption className="text-sm font-medium">{label}</figcaption>
    {valid.length ? <>
      <svg viewBox="0 0 320 100" role="img" aria-label={`${label}: ${valid.length} observations. Values are in the history table.`} className={`mt-2 h-28 w-full ${field === "new_findings" ? "text-amber-800 dark:text-amber-300" : field === "no_longer_detected" ? "text-emerald-700 dark:text-emerald-300" : "text-blue-700 dark:text-blue-300"}`}>
        <path d="M24 8V82H310" fill="none" stroke="currentColor" opacity="0.3" />
        {values.map((value, index) => value == null || !Number.isFinite(value) ? null : <circle key={`${points[index]!.scan_id}:${index}`} cx={24 + (times[index]! - start) / span * 280} cy={78 - value / max * 64} r="4" fill="currentColor"><title>{`${points[index]!.timestamp}: ${number(value)}`}</title></circle>)}
        <text x="1" y="15" fontSize="10" fill="currentColor">{number(max)}</text><text x="8" y="82" fontSize="10" fill="currentColor">0</text>
      </svg>
      <p className="text-xs text-ink-secondary">{new Date(start).toLocaleDateString()} – {new Date(Math.max(...times)).toLocaleDateString()} · Gaps are not zero.</p>
    </> : <p className="py-6 text-sm text-ink-secondary">No supported observations in this window.</p>}
  </figure>;
}

export function OverviewHistory() {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<"changes" | "age">("changes");
  const [days, setDays] = useState(30);
  const [points, setPoints] = useState<TrendPointResponse[]>([]);
  const [scope, setScope] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [page, setPage] = useState(0);
  const [undated, setUndated] = useState(0);
  const [limited, setLimited] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setStatus("loading");
    api.getTrends(365, { days }).then(result => {
      if (cancelled) return;
      const valid = (result.data_points ?? []).filter(point => Number.isFinite(Date.parse(point.timestamp)));
      setUndated((result.data_points ?? []).length - valid.length);
      setLimited(Boolean(result.history_limited));
      setPoints(valid);
      setScope(current => valid.some(point => point.scope_id === current) ? current : valid.find(point => point.scope_id)?.scope_id ?? "");
      setPage(0); setStatus("ready");
    }, () => { if (!cancelled) setStatus("error"); });
    return () => { cancelled = true; };
  }, [open, days, retry]);
  const scopes = [...new Set(points.flatMap(point => point.scope_id ? [point.scope_id] : []))];
  const selected = points.filter(point => scope ? point.scope_id === scope : !point.scope_id).sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const rows = [...selected].reverse().slice(page * 30, (page + 1) * 30);
  return <details className="rounded-2xl border border-outline bg-surface p-5 sm:p-6" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary className="cursor-pointer text-base font-semibold">Changes over time</summary>
    {open && <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-end gap-4">
        <label className="min-w-0 text-sm">History window<select aria-label="History window" value={days} onChange={event => setDays(Number(event.target.value))} className="ml-2 rounded border border-outline bg-surface p-2">{[7, 30, 90].map(value => <option key={value} value={value}>{value} days</option>)}</select></label>
        {scopes.length > 0 && <label className="min-w-0 text-sm">Scan scope<select aria-label="History scan scope" value={scope} onChange={event => { setScope(event.target.value); setPage(0); }} className="ml-2 max-w-full rounded border border-outline bg-surface p-2">{points.some(point => !point.scope_id) && <option value="">Scope unavailable</option>}{scopes.map(value => <option key={value} value={value}>{value}</option>)}</select></label>}
      </div>
      <p className="text-sm text-ink-secondary">Scan history has its own scope; it does not represent the aggregate posture above. No longer detected does not establish verified remediation.</p>
      {status === "ready" && undated > 0 && <p role="status" className="text-sm text-ink-secondary">{undated} retained observations have no valid timestamp and cannot be plotted.</p>}
      {status === "ready" && limited && <p role="status" className="text-sm text-ink-secondary">History is limited to the latest 365 retained observations. Earlier changes may be unavailable.</p>}
      {status === "loading" ? <p role="status">Loading history…</p> : status === "error" ? <div className="flex flex-wrap items-center gap-3"><p role="status">History unavailable.</p><button type="button" onClick={() => setRetry(value => value + 1)} className="rounded-lg border border-outline px-3 py-2 text-sm">Retry history</button></div> : selected.length === 0 ? <p role="status">No recorded history in this window.</p> : <>
        <p className="[overflow-wrap:anywhere] text-sm text-ink-secondary">{scope ? `Scope: ${scope}` : "History scope unavailable"} · {selected.length} observations · Up to 365 retained points requested</p>
        <div role="group" aria-label="History charts" className="flex flex-wrap gap-2 text-sm">
          <button aria-pressed={view === "changes"} onClick={() => setView("changes")} className="rounded-lg border border-outline px-3 py-2 aria-pressed:bg-surface-elevated">Finding changes</button>
          <button aria-pressed={view === "age"} onClick={() => setView("age")} className="rounded-lg border border-outline px-3 py-2 aria-pressed:bg-surface-elevated">Age & freshness</button>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          {view === "changes" ? <>
          <HistoryPlot points={selected} field="new_findings" label="Newly detected findings" />
          <HistoryPlot points={selected} field="no_longer_detected" label="No longer detected" />
          </> : <>
          <HistoryPlot points={selected} field="open_finding_age_days" label="Median open-finding age (days)" />
          <HistoryPlot points={selected} field="evidence_age_days" label="Median evidence age at scan (days)" />
          </>}
        </div>
        <p className="text-xs text-ink-secondary">Age and freshness use recorded timestamps and available samples. Missing timestamps are unavailable. Older observations without comparable scope cannot establish change.</p>
        <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="History values">
          <table className="w-full text-left text-sm"><caption className="sr-only">Recorded history and comparison evidence</caption><thead><tr>{["Completed", "New", "Still open", "No longer detected", "Median open age (days)", "Median evidence age (days)", "Comparison"].map(title => <th key={title} scope="col" className="p-2">{title}</th>)}</tr></thead>
          <tbody>{rows.map((point, index) => <tr key={`${point.scan_id}:${point.timestamp}:${index}`} className="border-t border-outline">
            <td className="p-2 whitespace-nowrap">{point.scan_id ? <Link className="underline" href={`/findings?${new URLSearchParams({scan_id: point.scan_id})}`}>{new Date(point.timestamp).toLocaleString()}</Link> : new Date(point.timestamp).toLocaleString()}</td>
            <td className="p-2">{number(point.comparison?.new_findings)}</td><td className="p-2">{number(point.comparison?.still_open)}</td><td className="p-2">{number(point.comparison?.no_longer_detected)}</td>
            <td className="p-2">{number(point.open_finding_age_days)} · {point.age_sample_count ?? 0} samples</td><td className="p-2">{number(point.evidence_age_days)} · {point.evidence_sample_count ?? 0} samples</td>
            <td className="p-2">{point.comparison?.status === "comparable" ? "Comparable" : point.comparison?.reason?.replaceAll("_", " ") ?? "Comparison metadata unavailable"}</td>
          </tr>)}</tbody></table>
        </div>
        {selected.length > 30 && <div className="flex gap-4 text-sm"><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} of {Math.ceil(selected.length / 30)}</span><button disabled={(page + 1) * 30 >= selected.length} onClick={() => setPage(page + 1)}>Next</button></div>}
      </>}
    </div>}
  </details>;
}
