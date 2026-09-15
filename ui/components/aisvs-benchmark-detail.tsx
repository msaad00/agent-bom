"use client";

import { useState } from "react";
import type { AISVSComplianceResponse } from "@/lib/api-types";
import { FrameworkIcon } from "@/components/framework-icon";

const labels = { pass: "Pass", fail: "Fail", error: "Evaluation error", not_applicable: "Not applicable" };

export function AISVSBenchmarkDetail({ data }: { data: AISVSComplianceResponse }) {
  const [status, setStatus] = useState("all");
  const checks = data?.benchmark?.checks ?? [];
  const visible = checks.filter((check) => status === "all" || check.status === status);
  return (
    <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <div className="flex items-center gap-2">
        <FrameworkIcon frameworkId="aisvs" size={22} />
        <h2 className="text-base font-semibold">OWASP AISVS benchmark</h2>
      </div>
      {data?.scan_id && <p className="mt-2 break-all text-xs text-[color:var(--text-secondary)]">Source scan: {data.scan_id}</p>}
      {data?.measured_at && <p className="text-xs text-[color:var(--text-secondary)]">Measured {new Date(data.measured_at).toLocaleString()}</p>}
      {checks.length === 0 ? <p className="mt-3 text-sm text-[color:var(--text-secondary)]">No AISVS benchmark checks have been recorded.</p> : <>
        <div className="my-3 flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-[color:var(--text-secondary)]">{visible.length} of {checks.length} checks shown</p>
          <select aria-label="AISVS check status" value={status} onChange={(event) => setStatus(event.target.value)} className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1.5 text-sm">
            <option value="all">All statuses</option>
            {Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </div>
        <div className="space-y-2">
          {visible.map((check) => <details key={check.check_id} className="rounded-lg border border-[color:var(--border-subtle)] p-3">
            <summary className="cursor-pointer text-sm">
              <span className="font-medium">{check.title || check.check_id}</span>
              <span className="ml-2 text-[color:var(--text-secondary)]">{labels[check.status] ?? "Unknown"}</span>
            </summary>
            <div className="mt-3 space-y-2 break-words text-sm text-[color:var(--text-secondary)]">
              <p>Check: {check.check_id}</p>
              <p>{check.evidence || "Evidence details unavailable."}</p>
              {check.recommendation && <p>Recommendation: {check.recommendation}</p>}
            </div>
          </details>)}
          {visible.length === 0 && <p className="text-sm text-[color:var(--text-secondary)]">No checks match this status.</p>}
        </div>
      </>}
    </section>
  );
}
