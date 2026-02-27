"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { api, ScanJob, ScanResult, BlastRadius, Agent, formatDate, OWASP_LLM_TOP10, MITRE_ATLAS } from "@/lib/api";
import { AgentTopology } from "@/components/agent-topology";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ShieldAlert, Server, Package, Bug, Zap, ArrowRight, Clock,
  AlertTriangle, Container, Layers, FileText, ExternalLink,
} from "lucide-react";

// ─── Aggregation helpers ──────────────────────────────────────────────────────

interface AggregatedPackage {
  name: string;
  version: string;
  ecosystem: string;
  vulnCount: number;
  critCount: number;
  highCount: number;
  agents: string[];
}

function aggregatePackages(jobs: ScanJob[]): AggregatedPackage[] {
  const pkgMap = new Map<string, AggregatedPackage>();
  for (const job of jobs) {
    if (job.status !== "done" || !job.result) continue;
    const result = job.result as ScanResult;
    for (const agent of result.agents) {
      for (const srv of agent.mcp_servers) {
        for (const pkg of srv.packages) {
          const key = `${pkg.name}@${pkg.version}`;
          const existing = pkgMap.get(key);
          const vulns = pkg.vulnerabilities ?? [];
          const crit = vulns.filter((v) => v.severity === "critical").length;
          const high = vulns.filter((v) => v.severity === "high").length;
          if (existing) {
            existing.vulnCount = Math.max(existing.vulnCount, vulns.length);
            existing.critCount = Math.max(existing.critCount, crit);
            existing.highCount = Math.max(existing.highCount, high);
            if (!existing.agents.includes(agent.name)) existing.agents.push(agent.name);
          } else {
            pkgMap.set(key, {
              name: pkg.name,
              version: pkg.version,
              ecosystem: pkg.ecosystem,
              vulnCount: vulns.length,
              critCount: crit,
              highCount: high,
              agents: [agent.name],
            });
          }
        }
      }
    }
  }
  return Array.from(pkgMap.values())
    .filter((p) => p.vulnCount > 0)
    .sort((a, b) => b.critCount - a.critCount || b.highCount - a.highCount || b.vulnCount - a.vulnCount);
}

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

function aggregateSeverity(allBlast: BlastRadius[]): SeverityCounts {
  const c = { critical: 0, high: 0, medium: 0, low: 0, total: allBlast.length };
  for (const b of allBlast) {
    const s = b.severity?.toLowerCase();
    if (s === "critical") c.critical++;
    else if (s === "high") c.high++;
    else if (s === "medium") c.medium++;
    else if (s === "low") c.low++;
  }
  return c;
}

interface ScanSource {
  label: string;
  icon: React.ElementType;
  count: number;
  vulns: number;
  critical: number;
}

function aggregateSources(jobs: ScanJob[]): ScanSource[] {
  let agentScans = 0, agentVulns = 0, agentCrit = 0;
  let imageScans = 0, imageVulns = 0, imageCrit = 0;
  let k8sScans = 0, sbomScans = 0;

  for (const job of jobs) {
    if (job.status !== "done") continue;
    const req = job.request;
    const result = job.result as ScanResult | undefined;
    const blast = result?.blast_radius ?? [];

    // Detect scan sources from the request
    if (req.images && req.images.length > 0) {
      imageScans += req.images.length;
      imageVulns += blast.length;
      imageCrit += blast.filter((b) => b.severity === "critical").length;
    }
    if (req.k8s) k8sScans++;
    if (req.sbom) sbomScans++;

    // Agent discovery (default scan or inventory)
    if (!req.images?.length && !req.k8s && !req.sbom) {
      agentScans++;
      agentVulns += blast.length;
      agentCrit += blast.filter((b) => b.severity === "critical").length;
    }
  }

  const sources: ScanSource[] = [];
  if (agentScans > 0) sources.push({ label: "MCP Agents", icon: Server, count: agentScans, vulns: agentVulns, critical: agentCrit });
  if (imageScans > 0) sources.push({ label: "Container Images", icon: Container, count: imageScans, vulns: imageVulns, critical: imageCrit });
  if (k8sScans > 0) sources.push({ label: "Kubernetes", icon: Layers, count: k8sScans, vulns: 0, critical: 0 });
  if (sbomScans > 0) sources.push({ label: "SBOM Imports", icon: FileText, count: sbomScans, vulns: 0, critical: 0 });
  return sources;
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [agentCount, setAgentCount] = useState<number>(0);
  const [agentList, setAgentList] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [jobsRes, agentsRes] = await Promise.all([
          api.listJobs(),
          api.listAgents(),
        ]);
        const fullJobs = await Promise.all(
          jobsRes.jobs.map((j) => api.getScan(j.job_id))
        );
        setJobs(fullJobs.sort((a, b) => b.created_at.localeCompare(a.created_at)));
        setAgentCount(agentsRes.count);
        setAgentList(agentsRes.agents);
      } catch {
        setApiError(true);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const doneJobs = useMemo(() => jobs.filter((j) => j.status === "done" && j.result), [jobs]);

  const allBlast = useMemo(
    () => doneJobs.flatMap((j) => (j.result as ScanResult)?.blast_radius ?? []),
    [doneJobs]
  );

  const severity = useMemo(() => aggregateSeverity(allBlast), [allBlast]);
  const topPackages = useMemo(() => aggregatePackages(jobs), [jobs]);
  const sources = useMemo(() => aggregateSources(jobs), [jobs]);

  // Unique CVE count
  const uniqueCVEs = useMemo(() => {
    const ids = new Set(allBlast.map((b) => b.vulnerability_id));
    return ids.size;
  }, [allBlast]);

  // Total packages scanned across all jobs
  const totalPackages = useMemo(() => {
    const pkgs = new Set<string>();
    for (const job of doneJobs) {
      const result = job.result as ScanResult;
      for (const agent of result.agents) {
        for (const srv of agent.mcp_servers) {
          for (const pkg of srv.packages) {
            pkgs.add(`${pkg.name}@${pkg.version}`);
          }
        }
      }
    }
    return pkgs.size;
  }, [doneJobs]);

  if (apiError) return <ApiDown />;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Security Posture</h1>
          <p className="text-zinc-400 text-sm mt-1">
            Aggregated across {doneJobs.length} scan{doneJobs.length !== 1 ? "s" : ""} — {agentCount} agent{agentCount !== 1 ? "s" : ""} · {totalPackages} packages · {uniqueCVEs} unique CVEs
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

      {/* Fleet stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <StatCard icon={Layers} label="Total scans" value={loading ? "—" : String(doneJobs.length)} color="zinc" />
        <StatCard icon={Server} label="Agents" value={loading ? "—" : String(agentCount)} color="emerald" />
        <StatCard icon={Package} label="Packages" value={loading ? "—" : String(totalPackages)} color="blue" />
        <StatCard icon={Bug} label="Unique CVEs" value={loading ? "—" : String(uniqueCVEs)} color="orange" />
        <StatCard icon={Zap} label="Critical" value={loading ? "—" : String(severity.critical)} color="red" />
      </div>

      {/* Severity distribution + Sources — side by side */}
      {!loading && allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SeverityChart severity={severity} />
          <SourceBreakdown sources={sources} />
        </div>
      )}

      {/* Agent topology */}
      {!loading && agentList.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Agent Topology
            </h2>
            <Link href="/agents" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <AgentTopology agents={agentList} />
        </section>
      )}

      {/* Top vulnerable packages */}
      {!loading && topPackages.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Top vulnerable packages
          </h2>
          <div className="border border-zinc-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900 border-b border-zinc-800">
                <tr>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Package</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Ecosystem</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">CVEs</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Crit</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">High</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Agents</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {topPackages.slice(0, 10).map((pkg) => (
                  <tr key={`${pkg.name}@${pkg.version}`} className="hover:bg-zinc-900 transition-colors">
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-xs text-zinc-200">{pkg.name}</span>
                      <span className="font-mono text-xs text-zinc-600 ml-1">@{pkg.version}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-zinc-500">{pkg.ecosystem}</td>
                    <td className="px-4 py-2.5 text-center">
                      <span className="font-mono text-xs text-zinc-300">{pkg.vulnCount}</span>
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      {pkg.critCount > 0 ? (
                        <span className="font-mono text-xs font-semibold text-red-400">{pkg.critCount}</span>
                      ) : (
                        <span className="text-zinc-700">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      {pkg.highCount > 0 ? (
                        <span className="font-mono text-xs font-semibold text-orange-400">{pkg.highCount}</span>
                      ) : (
                        <span className="text-zinc-700">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-zinc-500">
                      {pkg.agents.slice(0, 3).join(", ")}
                      {pkg.agents.length > 3 && <span className="text-zinc-600"> +{pkg.agents.length - 3}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {topPackages.length > 10 && (
            <p className="text-xs text-zinc-600 text-right mt-1">
              Showing 10 of {topPackages.length} — <Link href="/vulns" className="text-emerald-500 hover:text-emerald-400">view all</Link>
            </p>
          )}
        </section>
      )}

      {/* Blast radius highlights */}
      {!loading && allBlast.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Highest risk findings
            </h2>
            <Link href="/vulns" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-2">
            {[...allBlast]
              .sort((a, b) => b.blast_score - a.blast_score)
              .slice(0, 5)
              .map((b) => (
                <BlastCard key={b.vulnerability_id} blast={b} />
              ))}
          </div>
        </section>
      )}

      {/* Recent scans */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
            Recent scans
          </h2>
          {jobs.length > 8 && (
            <Link href="/jobs" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          )}
        </div>
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

// ─── Components ───────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: "emerald" | "blue" | "orange" | "red" | "zinc";
}) {
  const colors = {
    emerald: "text-emerald-400",
    blue: "text-blue-400",
    orange: "text-orange-400",
    red: "text-red-400",
    zinc: "text-zinc-400",
  };
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <Icon className={`w-4 h-4 mb-2 ${colors[color]}`} />
      <div className="text-2xl font-bold font-mono">{value}</div>
      <div className="text-xs text-zinc-500 mt-0.5">{label}</div>
    </div>
  );
}

function SeverityChart({ severity }: { severity: SeverityCounts }) {
  const total = severity.total || 1;
  const bars = [
    { label: "Critical", count: severity.critical, color: "bg-red-500", text: "text-red-400" },
    { label: "High", count: severity.high, color: "bg-orange-500", text: "text-orange-400" },
    { label: "Medium", count: severity.medium, color: "bg-yellow-500", text: "text-yellow-400" },
    { label: "Low", count: severity.low, color: "bg-blue-500", text: "text-blue-400" },
  ];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">Severity Distribution</h3>

      {/* Stacked bar */}
      <div className="flex h-4 rounded-full overflow-hidden bg-zinc-800 mb-4">
        {bars.map((b) =>
          b.count > 0 ? (
            <div
              key={b.label}
              className={`${b.color} transition-all duration-500`}
              style={{ width: `${(b.count / total) * 100}%` }}
              title={`${b.label}: ${b.count}`}
            />
          ) : null
        )}
      </div>

      {/* Legend */}
      <div className="grid grid-cols-4 gap-2">
        {bars.map((b) => (
          <div key={b.label} className="text-center">
            <div className={`text-lg font-bold font-mono ${b.text}`}>{b.count}</div>
            <div className="text-xs text-zinc-500">{b.label}</div>
            <div className="text-xs text-zinc-600">{total > 0 ? Math.round((b.count / total) * 100) : 0}%</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SourceBreakdown({ sources }: { sources: ScanSource[] }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">Scan Sources</h3>
      {sources.length === 0 ? (
        <p className="text-zinc-600 text-sm">No completed scans yet.</p>
      ) : (
        <div className="space-y-3">
          {sources.map((s) => (
            <div key={s.label} className="flex items-center gap-3">
              <s.icon className="w-4 h-4 text-zinc-400 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-200">{s.label}</span>
                  <span className="text-xs font-mono text-zinc-400">{s.count} scanned</span>
                </div>
                <div className="flex items-center gap-3 mt-0.5 text-xs text-zinc-500">
                  <span>{s.vulns} findings</span>
                  {s.critical > 0 && (
                    <span className="text-red-400 font-semibold">{s.critical} critical</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BlastCard({ blast }: { blast: BlastRadius }) {
  return (
    <div className="flex items-start gap-4 bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <SeverityBadge severity={blast.severity} />
      <div className="flex-1 min-w-0">
        <a
          href={`https://osv.dev/vulnerability/${blast.vulnerability_id}`}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-sm font-semibold text-zinc-100 hover:text-emerald-400 flex items-center gap-1.5 group"
        >
          {blast.vulnerability_id}
          <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
        </a>
        <div className="flex flex-wrap gap-3 mt-1.5 text-xs text-zinc-500">
          <span>{blast.affected_agents.length} agent{blast.affected_agents.length !== 1 ? "s" : ""}</span>
          {blast.exposed_credentials.length > 0 && (
            <span className="text-orange-400">{blast.exposed_credentials.length} credential{blast.exposed_credentials.length !== 1 ? "s" : ""}</span>
          )}
          <span>{blast.reachable_tools.length} tool{blast.reachable_tools.length !== 1 ? "s" : ""}</span>
          {blast.cisa_kev && <span className="text-red-400 font-semibold">CISA KEV</span>}
          {blast.cvss_score != null && <span>CVSS {blast.cvss_score.toFixed(1)}</span>}
          {blast.epss_score != null && <span>EPSS {(blast.epss_score * 100).toFixed(0)}%</span>}
        </div>
        {((blast.owasp_tags && blast.owasp_tags.length > 0) || (blast.atlas_tags && blast.atlas_tags.length > 0)) && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {blast.owasp_tags?.map((tag) => (
              <span key={tag} title={OWASP_LLM_TOP10[tag] ?? tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1 py-0.5 cursor-help">{tag}</span>
            ))}
            {blast.atlas_tags?.map((tag) => (
              <span key={tag} title={MITRE_ATLAS[tag] ?? tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1 py-0.5 cursor-help">{tag}</span>
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
  const statusColors: Record<string, string> = {
    done: "bg-emerald-500",
    failed: "bg-red-500",
    running: "bg-yellow-500 animate-pulse",
    pending: "bg-zinc-500",
    cancelled: "bg-zinc-600",
  };
  const result = job.result as ScanResult | undefined;
  const vulnCount = result?.summary?.total_vulnerabilities ?? 0;
  const critCount = result?.summary?.critical_findings ?? 0;

  // Detect scan source tags
  const tags: string[] = [];
  if (job.request.images && job.request.images.length > 0) tags.push(`${job.request.images.length} image${job.request.images.length > 1 ? "s" : ""}`);
  if (job.request.k8s) tags.push("k8s");
  if (job.request.sbom) tags.push("sbom");
  if (job.request.inventory) tags.push("inventory");
  if (tags.length === 0 && job.status === "done") tags.push("agents");

  return (
    <Link
      href={`/scan/${job.job_id}`}
      className="flex items-center gap-4 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 rounded-xl p-4 transition-colors group"
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColors[job.status] ?? "bg-zinc-500"}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-zinc-400">{job.job_id.slice(0, 8)}…</span>
          {tags.map((t) => (
            <span key={t} className="text-xs bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-500">{t}</span>
          ))}
        </div>
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
