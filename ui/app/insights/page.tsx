"use client";

import { useEffect, useMemo, useState } from "react";
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
  EpssVsCvssChart,
  VulnTrendChart,
  type TrendDataPoint,
} from "@/components/charts";
import { buildEpssVsCvss, buildPipelineStats, effectiveBlastRadius } from "@/lib/insights-risk";
import { BarChart3, RefreshCw, AlertTriangle } from "lucide-react";

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildTrendData(jobs: ScanJob[]): TrendDataPoint[] {
  return jobs
    .filter((j) => j.status === "done" && j.result)
    .slice(-10)
    .map((j) => {
      const blasts = j.result!.blast_radius ?? [];
      let critical = 0, high = 0, medium = 0, low = 0;
      const seen = new Set<string>();
      for (const br of blasts) {
        if (seen.has(br.vulnerability_id)) continue;
        seen.add(br.vulnerability_id);
        if (br.severity === "critical") critical++;
        else if (br.severity === "high") high++;
        else if (br.severity === "medium") medium++;
        else low++;
      }
      const date = new Date(j.completed_at ?? j.created_at);
      const label = `${date.getMonth() + 1}/${date.getDate()} ${date.getHours()}:${String(date.getMinutes()).padStart(2, "0")}`;
      return { label, critical, high, medium, low };
    });
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function InsightsPage() {
  const router = useRouter();
  const [latestJob, setLatestJob] = useState<ScanJob | null>(null);
  const [trendJobs, setTrendJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [trendLoading, setTrendLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    setLatestJob(null);
    setTrendJobs([]);
    setTrendLoading(false);
    api
      .listJobs()
      .then(async (res) => {
        const doneJobs = res.jobs.filter((j) => j.status === "done");
        if (doneJobs.length === 0) {
          setLatestJob(null);
          setTrendJobs([]);
          return;
        }

        const latest = await api.getScan(doneJobs[0]!.job_id);
        setLatestJob(latest.result ? latest : null);

        setTrendLoading(true);
        void Promise.all(doneJobs.slice(0, 10).map((job) => api.getScan(job.job_id).catch(() => null)))
          .then((fullJobs) => {
            setTrendJobs(fullJobs.filter((job): job is ScanJob => Boolean(job?.result)));
          })
          .finally(() => setTrendLoading(false));
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

  const epssVsCvss = useMemo(() => buildEpssVsCvss(blasts), [blasts]);
  const trendData = useMemo(() => buildTrendData(trendJobs), [trendJobs]);

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
            Supply chain visualizations · latest scan:{" "}
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
          {epssVsCvss.length > 0 && <EpssVsCvssChart data={epssVsCvss} />}
        </div>
      </div>

      {/* Trend (multi-scan history) — full width */}
      {trendData.length >= 2 && (
        <div>
          <VulnTrendChart data={trendData} />
        </div>
      )}

      {trendLoading && (
        <div className="text-center py-6 text-zinc-600 text-xs border border-zinc-800 border-dashed rounded-xl">
          Loading trend history...
        </div>
      )}

      {!trendLoading && trendData.length < 2 && (
        <div className="text-center py-6 text-zinc-600 text-xs border border-zinc-800 border-dashed rounded-xl">
          Run 2+ scans to see vulnerability trend over time
        </div>
      )}
    </div>
  );
}
