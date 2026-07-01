"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  api,
  ScanJob,
  Agent,
  BlastRadius,
} from "@/lib/api";
import {
  SupplyChainTreemap,
  BlastRadiusRadial,
  PipelineFlow,
} from "@/components/charts";
import { buildPipelineStats, effectiveBlastRadius } from "@/lib/insights-risk";
import { BarChart3, RefreshCw, AlertTriangle, ArrowRight } from "lucide-react";

// ─── Page ───────────────────────────────────────────────────────────────────
//
// Supply-chain deep-dive for the latest scan. The vulnerability trend and the
// EPSS × CVSS risk map live on the dashboard (one source of truth); this page
// deliberately does NOT re-render them and instead deep-links back so operators
// aren't shown the same charts twice.

export default function InsightsPage() {
  const router = useRouter();
  const [latestJob, setLatestJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    setLatestJob(null);
    api
      .listJobs()
      .then(async (res) => {
        const doneJobs = res.jobs.filter((j) => j.status === "done");
        if (doneJobs.length === 0) {
          setLatestJob(null);
          return;
        }

        const latest = await api.getScan(doneJobs[0]!.job_id);
        setLatestJob(latest.result ? latest : null);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      fetchData();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  // Use the most recent completed scan for single-scan charts
  const latest = latestJob;
  const result = latest?.result ?? null;
  const agents: Agent[] = result?.agents ?? [];
  const blasts = useMemo<BlastRadius[]>(() => effectiveBlastRadius(result), [result]);

  const pipelineStats = useMemo(
    () => (result ? buildPipelineStats(result) : null),
    [result]
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] text-zinc-500 text-sm font-mono">
        <div className="flex items-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin" />
          Loading insights...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="flex items-center gap-3 p-4 bg-red-950/30 border border-red-800/40 rounded-xl text-red-400 text-sm">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-center">
        <BarChart3 className="w-10 h-10 text-zinc-700 mx-auto mb-3" />
        <p className="text-zinc-500 text-sm">No completed scans yet.</p>
        <p className="text-zinc-600 text-xs mt-1">
          Run a scan to populate this page.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-emerald-400" />
            Insights
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            Supply-chain composition for the latest scan:{" "}
            <span className="font-mono text-zinc-400">{latest?.job_id?.slice(0, 8)}</span>
          </p>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 px-3 py-1.5 rounded-lg border border-zinc-800 hover:border-zinc-700 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Pipeline flow — full width */}
      {pipelineStats && <PipelineFlow stats={pipelineStats} />}

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.15fr)_minmax(340px,0.85fr)] gap-4">
        {/* Supply chain treemap; click a package → /vulns */}
        {agents.length > 0 && (
          <div>
            <SupplyChainTreemap
              agents={agents}
              onPackageClick={(pkg) => router.push(`/vulns?search=${encodeURIComponent(pkg)}`)}
            />
            <p className="text-[10px] text-zinc-700 mt-1 text-right">Click a package to drill down → Vulns</p>
          </div>
        )}

        <div className="grid gap-4">
          {blasts.length > 0 && <BlastRadiusRadial data={blasts} />}
        </div>
      </div>

      {/* Trend + EPSS×CVSS risk map are owned by the dashboard — deep-link, don't duplicate */}
      <Link
        href="/"
        className="flex items-center justify-between gap-3 rounded-xl border border-zinc-800 bg-zinc-950/40 px-4 py-3 text-xs text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-200"
      >
        <span>
          Vulnerability trend and the EPSS × CVSS risk map live on the dashboard.
        </span>
        <span className="flex items-center gap-1 whitespace-nowrap text-emerald-500">
          Open dashboard <ArrowRight className="w-3 h-3" />
        </span>
      </Link>
    </div>
  );
}
