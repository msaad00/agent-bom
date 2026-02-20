"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ScanJob, ScanResult, formatDate } from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";
import { ShieldAlert, Server, Package, Bug, Zap, ArrowRight, Clock, AlertTriangle } from "lucide-react";

export default function Dashboard() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [agents, setAgents] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [jobsRes, agentsRes] = await Promise.all([
          api.listJobs(),
          api.listAgents(),
        ]);
        // Fetch full job details for completed jobs
        const fullJobs = await Promise.all(
          jobsRes.jobs.map((j) => api.getScan(j.job_id))
        );
        setJobs(fullJobs.sort((a, b) => b.created_at.localeCompare(a.created_at)));
        setAgents(agentsRes.count);
      } catch {
        setApiError(true);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const latestDone = jobs.find((j) => j.status === "done");
  const result: ScanResult | undefined = latestDone?.result as ScanResult | undefined;
  const summary = result?.summary;

  // Aggregate blast radius across all done jobs
  const allBlast = jobs
    .filter((j) => j.status === "done" && j.result)
    .flatMap((j) => (j.result as ScanResult)?.blast_radius ?? []);

  const criticalBlast = allBlast.filter((b) => b.severity === "critical");
  const highBlast = allBlast.filter((b) => b.severity === "high");

  if (apiError) {
    return <ApiDown />;
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-zinc-400 text-sm mt-1">
            AI supply chain security — agents → MCP servers → packages → CVEs
          </p>
        </div>
        <Link
          href="/scan"
          className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          New Scan
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          icon={Server}
          label="Agents discovered"
          value={loading ? "—" : String(agents)}
          color="emerald"
        />
        <StatCard
          icon={Package}
          label="Packages scanned"
          value={loading ? "—" : String(summary?.total_packages ?? 0)}
          color="blue"
        />
        <StatCard
          icon={Bug}
          label="Vulnerabilities"
          value={loading ? "—" : String(summary?.total_vulnerabilities ?? 0)}
          color="orange"
        />
        <StatCard
          icon={Zap}
          label="Critical blast radius"
          value={loading ? "—" : String(criticalBlast.length)}
          color="red"
        />
      </div>

      {/* Blast radius highlights */}
      {!loading && criticalBlast.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Critical blast radius
          </h2>
          <div className="space-y-2">
            {criticalBlast.slice(0, 5).map((b) => (
              <BlastCard key={b.vulnerability_id} blast={b} />
            ))}
          </div>
        </section>
      )}

      {/* High blast radius */}
      {!loading && highBlast.length > 0 && criticalBlast.length === 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            High blast radius
          </h2>
          <div className="space-y-2">
            {highBlast.slice(0, 5).map((b) => (
              <BlastCard key={b.vulnerability_id} blast={b} />
            ))}
          </div>
        </section>
      )}

      {/* Recent scans */}
      <section>
        <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
          Recent scans
        </h2>
        {loading ? (
          <div className="text-zinc-500 text-sm">Loading...</div>
        ) : jobs.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="space-y-2">
            {jobs.slice(0, 8).map((job) => (
              <JobRow key={job.job_id} job={job} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: "emerald" | "blue" | "orange" | "red";
}) {
  const colors = {
    emerald: "text-emerald-400",
    blue: "text-blue-400",
    orange: "text-orange-400",
    red: "text-red-400",
  };
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <Icon className={`w-4 h-4 mb-3 ${colors[color]}`} />
      <div className="text-2xl font-bold font-mono">{value}</div>
      <div className="text-xs text-zinc-500 mt-1">{label}</div>
    </div>
  );
}

function BlastCard({ blast }: { blast: NonNullable<ScanResult["blast_radius"]>[0] }) {
  return (
    <div className="flex items-start gap-4 bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <SeverityBadge severity={blast.severity} />
      <div className="flex-1 min-w-0">
        <div className="font-mono text-sm font-semibold text-zinc-100 truncate">
          {blast.vulnerability_id}
        </div>
        <div className="flex flex-wrap gap-3 mt-1.5 text-xs text-zinc-500">
          <span>{blast.affected_agents.length} agent{blast.affected_agents.length !== 1 ? "s" : ""}</span>
          {blast.exposed_credentials.length > 0 && (
            <span className="text-orange-400">{blast.exposed_credentials.length} credential{blast.exposed_credentials.length !== 1 ? "s" : ""} exposed</span>
          )}
          <span>{blast.reachable_tools.length} tool{blast.reachable_tools.length !== 1 ? "s" : ""} reachable</span>
          {blast.cisa_kev && (
            <span className="text-red-400 font-semibold">CISA KEV</span>
          )}
          {blast.cvss_score && (
            <span>CVSS {blast.cvss_score.toFixed(1)}</span>
          )}
        </div>
        {((blast.owasp_tags && blast.owasp_tags.length > 0) || (blast.atlas_tags && blast.atlas_tags.length > 0)) && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {blast.owasp_tags?.map((tag) => (
              <span key={tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1 py-0.5">{tag}</span>
            ))}
            {blast.atlas_tags?.map((tag) => (
              <span key={tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1 py-0.5">{tag}</span>
            ))}
          </div>
        )}
      </div>
      {blast.blast_score > 0 && (
        <div className="text-right">
          <div className="text-lg font-bold font-mono text-red-400">{blast.blast_score.toFixed(0)}</div>
          <div className="text-xs text-zinc-600">score</div>
        </div>
      )}
    </div>
  );
}

function JobRow({ job }: { job: ScanJob }) {
  const statusColor: Record<string, string> = {
    done: "bg-emerald-500",
    failed: "bg-red-500",
    running: "bg-yellow-500 animate-pulse",
    pending: "bg-zinc-500",
    cancelled: "bg-zinc-600",
  };
  const result = job.result as ScanResult | undefined;
  const vulnCount = result?.summary?.total_vulnerabilities ?? 0;
  const critCount = result?.summary?.critical_findings ?? 0;

  return (
    <Link
      href={`/scan/${job.job_id}`}
      className="flex items-center gap-4 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 rounded-xl p-4 transition-colors group"
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColor[job.status] ?? "bg-zinc-500"}`} />
      <div className="flex-1 min-w-0">
        <div className="font-mono text-xs text-zinc-400 truncate">{job.job_id.slice(0, 8)}…</div>
        <div className="text-xs text-zinc-600 flex items-center gap-1 mt-0.5">
          <Clock className="w-3 h-3" />
          {formatDate(job.created_at)}
        </div>
      </div>
      <div className="flex items-center gap-3 text-xs">
        {job.status === "done" && (
          <>
            {critCount > 0 && (
              <span className="text-red-400 font-mono font-semibold">{critCount} CRIT</span>
            )}
            {vulnCount > 0 && (
              <span className="text-zinc-400">{vulnCount} vuln{vulnCount !== 1 ? "s" : ""}</span>
            )}
          </>
        )}
        {job.status === "failed" && (
          <span className="text-red-400 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Failed
          </span>
        )}
        {job.status === "running" && (
          <span className="text-yellow-400">Running…</span>
        )}
      </div>
      <ArrowRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-400 transition-colors flex-shrink-0" />
    </Link>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
      <ShieldAlert className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
      <p className="text-zinc-500 text-sm">No scans yet.</p>
      <Link
        href="/scan"
        className="inline-flex items-center gap-1.5 mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors"
      >
        Run your first scan
        <ArrowRight className="w-3.5 h-3.5" />
      </Link>
    </div>
  );
}

function ApiDown() {
  return (
    <div className="text-center py-24">
      <AlertTriangle className="w-10 h-10 text-orange-400 mx-auto mb-4" />
      <h2 className="text-lg font-semibold mb-2">Cannot connect to agent-bom API</h2>
      <p className="text-zinc-500 text-sm mb-6">
        Make sure the API server is running at{" "}
        <code className="font-mono bg-zinc-900 px-1.5 py-0.5 rounded text-zinc-300">
          {process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422"}
        </code>
      </p>
      <code className="block bg-zinc-900 border border-zinc-800 rounded-lg px-6 py-4 text-sm font-mono text-emerald-400 inline-block">
        pip install &apos;agent-bom[api]&apos;<br />
        agent-bom api
      </code>
    </div>
  );
}
