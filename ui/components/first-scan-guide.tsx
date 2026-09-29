"use client";

import Link from "next/link";
import type { ScanResult } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { LocalReportImport } from "@/components/local-report-import";

export function FirstScanGuide({ onImport }: { onImport: (data: ScanResult) => void }) {
  const { loading, hasCapability } = useAuthState();
  return (
    <section aria-labelledby="first-scan-title" className="rounded-xl border border-outline bg-surface p-4 sm:p-6">
      <h2 id="first-scan-title" className="text-lg font-semibold">Start with evidence</h2>
      <p className="mt-2 text-sm text-ink-secondary">
        No scans or findings are recorded in the current overview window. This is not a clean security verdict.
      </p>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div className="space-y-3 rounded-lg border border-outline p-4">
          <h3 className="font-medium">Scan a repository or connected source</h3>
          <p className="text-sm text-ink-secondary">Choose an explicit target in the scan form. The browser does not scan your workstation automatically.</p>
          {loading ? <p role="status" className="text-sm text-ink-secondary">Checking scan access…</p> : hasCapability("scan.run") ? (
            <Link href="/scan" className="inline-flex rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600">Choose a scan target</Link>
          ) : <p className="text-sm text-ink-secondary">Ask an administrator for scan access, or preview a saved report below.</p>}
          <p className="text-sm text-ink-secondary">A completed scan produces findings to review and graph evidence to investigate. Check its coverage before interpreting counts.</p>
          <Link href="/connections" className="inline-block text-sm text-emerald-800 dark:text-emerald-300">Review connected sources →</Link>
        </div>
        <div className="space-y-3 rounded-lg border border-outline p-4">
          <h3 className="font-medium">Scan locally, then review</h3>
          <p className="text-sm text-ink-secondary">From your repository root, save a JSON report. Package advisory lookup uses the network.</p>
          <code className="block break-words rounded-lg bg-surface-muted p-3 text-xs [overflow-wrap:anywhere]">agent-bom scan . -f json -o report.json</code>
          <p className="text-sm text-ink-secondary">For a bundled sample, use the offline demo command below. Sample results do not assess your environment.</p>
        </div>
      </div>
      <LocalReportImport onImport={onImport} />
    </section>
  );
}
