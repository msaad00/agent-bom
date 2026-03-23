"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  api,
  ScanJob,
  ScanResult,
  Agent,
  BlastRadius,
} from "@/lib/api";
import {
  SupplyChainTreemap,
  BlastRadiusRadial,
  PipelineFlow,
  EpssVsCvssChart,
  VulnTrendChart,
  type PipelineStats,
  type EpssVsCvssPoint,
  type TrendDataPoint,
} from "@/components/charts";
import { BarChart3, RefreshCw, AlertTriangle } from "lucide-react";

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildPipelineStats(result: ScanResult): PipelineStats {
  let servers = 0;
  let packages = 0;
  for (const agent of result.agents) {
    servers += agent.mcp_servers.length;
    for (const srv of agent.mcp_servers) {
      packages += srv.packages.length;
    }
  }

  const blasts = result.blast_radius ?? [];
  let critical = 0;
  let high = 0;
  let vulnerabilities = 0;
  let kev = 0;

  // Deduplicate vuln IDs across all packages
  const seen = new Set<string>();
  for (const br of blasts) {
    if (!seen.has(br.vulnerability_id)) {
      seen.add(br.vulnerability_id);
      vulnerabilities++;
      if (br.severity === "critical") critical++;
      if (br.severity === "high") high++;
      if (br.is_kev ?? br.cisa_kev) kev++;
    }
  }

  return {
    agents: result.agents.length,
    servers,
    packages,
    vulnerabilities,
    critical,
    high,
    kev,
  };
}

function buildEpssVsCvss(blasts: BlastRadius[]): EpssVsCvssPoint[] {
  const seen = new Set<string>();
  const out: EpssVsCvssPoint[] = [];
  for (const br of blasts) {
    if (seen.has(br.vulnerability_id)) continue;
    seen.add(br.vulnerability_id);
    if (!br.cvss_score && !br.epss_score) continue;
    out.push({
      cve: br.vulnerability_id,
      cvss: br.cvss_score ?? 0,
      epss: br.epss_score ?? 0,
      blast: br.risk_score ?? br.blast_score,
      severity: br.severity ?? "low",
      kev: !!(br.is_kev ?? br.cisa_kev),
      package: br.package,
    });
  }
  return out;
}

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
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    api
      .listJobs()
      .then(async (res) => {
        const doneIds = res.jobs
          .filter((j) => j.status === "done")
          .slice(0, 10)
          .map((j) => j.job_id);

        const fullJobs = await Promise.all(
          doneIds?.map((id) => api.getScan(id).catch(() => null))
        );
        setJobs(fullJobs.filter(Boolean) as ScanJob[]);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Use the most recent completed scan for single-scan charts
  const latest = useMemo(
    () => jobs.find((j) => j.status === "done" && j.result) ?? null,
    [jobs]
  );
  const result = latest?.result ?? null;
  const agents: Agent[] = result?.agents ?? [];
  const blasts: BlastRadius[] = result?.blast_radius ?? [];

  const pipelineStats = useMemo(
    () => (result ? buildPipelineStats(result) : null),
    [result]
  );

  const epssVsCvss = useMemo(() => buildEpssVsCvss(blasts), [blasts]);
  const trendData = useMemo(() => buildTrendData(jobs), [jobs]);

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

      {/* Supply chain treemap — full width; click a package → /vulns */}
      {agents.length > 0 && (
        <div>
          <SupplyChainTreemap
            agents={agents}
            onPackageClick={(pkg) => router.push(`/vulns?search=${encodeURIComponent(pkg)}`)}
          />
          <p className="text-[10px] text-zinc-700 mt-1 text-right">Click a package to drill down → Vulns</p>
        </div>
      )}

      {/* 2-col: blast radius radial + EPSS×CVSS scatter */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {blasts.length > 0 && <BlastRadiusRadial data={blasts} />}
        {epssVsCvss.length > 0 && <EpssVsCvssChart data={epssVsCvss} />}
      </div>

      {/* Trend (multi-scan history) — full width */}
      {trendData.length >= 2 && (
        <div>
          <VulnTrendChart data={trendData} />
        </div>
      )}

      {trendData.length < 2 && (
        <div className="text-center py-6 text-zinc-600 text-xs border border-zinc-800 border-dashed rounded-xl">
          Run 2+ scans to see vulnerability trend over time
        </div>
      )}
    </div>
  );
}
