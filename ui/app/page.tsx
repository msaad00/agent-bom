"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { api, ScanJob, ScanResult, BlastRadius, Agent, formatDate, OWASP_LLM_TOP10, MITRE_ATLAS } from "@/lib/api";
import { checkFileSize, validateScanReport } from "@/lib/validators";
import { AgentTopology } from "@/components/agent-topology";
import { TrustStack } from "@/components/trust-stack";
import { SeverityBadge } from "@/components/severity-badge";
import { ActivityFeed } from "@/components/activity-feed";
import {
  ShieldAlert, Server, Package, Bug, Zap, ArrowRight, Clock,
  AlertTriangle, Container, Layers, FileText, ExternalLink,
} from "lucide-react";
import { VulnTrendChart, EpssDistributionChart, EpssVsCvssChart, TrendDataPoint, EpssDataPoint, EpssVsCvssPoint } from "@/components/charts";

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

const SOURCE_META: Record<string, { label: string; icon: React.ElementType }> = {
  agent_discovery: { label: "MCP Agents", icon: Server },
  image: { label: "Container Images", icon: Container },
  k8s: { label: "Kubernetes", icon: Layers },
  sbom: { label: "SBOM Imports", icon: FileText },
  filesystem: { label: "Filesystem", icon: FileText },
  terraform: { label: "Terraform", icon: Layers },
  github_actions: { label: "GitHub Actions", icon: Layers },
  browser_extensions: { label: "Browser Extensions", icon: ExternalLink },
  jupyter: { label: "Jupyter Notebooks", icon: FileText },
  gpu_infra: { label: "GPU Infrastructure", icon: Server },
};

function aggregateSources(jobs: ScanJob[]): ScanSource[] {
  const srcMap = new Map<string, ScanSource>();

  for (const job of jobs) {
    if (job.status !== "done") continue;
    const result = job.result as ScanResult | undefined;
    const blast = result?.blast_radius ?? [];
    // Prefer scan_sources from result (auto-detected), fall back to request inference
    const sources = result?.scan_sources ?? [];

    if (sources.length > 0) {
      for (const src of sources) {
        const meta = SOURCE_META[src] ?? { label: src, icon: FileText };
        const existing = srcMap.get(src);
        if (existing) {
          existing.count++;
          existing.vulns += blast.length;
          existing.critical += blast.filter((b) => b.severity === "critical").length;
        } else {
          srcMap.set(src, {
            label: meta.label,
            icon: meta.icon,
            count: 1,
            vulns: blast.length,
            critical: blast.filter((b) => b.severity === "critical").length,
          });
        }
      }
    } else {
      // Legacy fallback: infer from request
      const req = job.request;
      if (req.images && req.images.length > 0) {
        const e = srcMap.get("image") ?? { label: "Container Images", icon: Container, count: 0, vulns: 0, critical: 0 };
        e.count += req.images.length;
        e.vulns += blast.length;
        e.critical += blast.filter((b) => b.severity === "critical").length;
        srcMap.set("image", e);
      } else {
        const e = srcMap.get("agent_discovery") ?? { label: "MCP Agents", icon: Server, count: 0, vulns: 0, critical: 0 };
        e.count++;
        e.vulns += blast.length;
        e.critical += blast.filter((b) => b.severity === "critical").length;
        srcMap.set("agent_discovery", e);
      }
    }
  }
  return Array.from(srcMap.values());
}

function aggregateTrend(jobs: ScanJob[]): TrendDataPoint[] {
  const done = jobs
    .filter((j) => j.status === "done" && j.result)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
  return done?.map((j) => {
    const blast = (j.result as ScanResult)?.blast_radius ?? [];
    const sev = aggregateSeverity(blast);
    const d = new Date(j.created_at);
    return {
      label: `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`,
      critical: sev.critical,
      high: sev.high,
      medium: sev.medium,
      low: sev.low,
    };
  });
}

function aggregateEpss(allBlast: BlastRadius[]): EpssDataPoint[] {
  const buckets = [
    { range: "0-10%", min: 0, max: 0.1, count: 0 },
    { range: "10-30%", min: 0.1, max: 0.3, count: 0 },
    { range: "30-50%", min: 0.3, max: 0.5, count: 0 },
    { range: "50-70%", min: 0.5, max: 0.7, count: 0 },
    { range: "70-90%", min: 0.7, max: 0.9, count: 0 },
    { range: "90-100%", min: 0.9, max: 1.01, count: 0 },
  ];
  for (const b of allBlast) {
    if (b.epss_score == null) continue;
    for (const bucket of buckets) {
      if (b.epss_score >= bucket.min && b.epss_score < bucket.max) {
        bucket.count++;
        break;
      }
    }
  }
  return buckets?.map(({ range, count }) => ({ range, count }));
}

function aggregateEpssVsCvss(allBlast: BlastRadius[]): EpssVsCvssPoint[] {
  return allBlast
    .filter((b) => b.cvss_score != null && b.epss_score != null)
    .map((b) => ({
      cve: b.vulnerability_id,
      cvss: b.cvss_score!,
      epss: b.epss_score!,
      blast: b.blast_score,
      severity: b.severity?.toLowerCase() ?? "low",
      kev: !!(b.cisa_kev ?? b.is_kev),
      package: b.package,
    }));
}

// Compound issue: a finding that meets 2+ independent risk signals simultaneously.
// Each rule returns a subset of blast radius entries.
export interface CompoundIssue {
  id: string;
  title: string;
  description: string;
  count: number;
  severity: "critical" | "high";
  findings: BlastRadius[];
  filter: string; // URL param for /vulns deep-link
}

const SEVERITY_ORDER_MAP: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

function aggregateCompoundIssues(allBlast: BlastRadius[]): CompoundIssue[] {
  const issues: CompoundIssue[] = [];

  // 1. CISA KEV + reachable tool exposure
  const kevReachable = allBlast.filter(
    (b) => (b.cisa_kev ?? b.is_kev) && b.reachable_tools.length > 0
  );
  if (kevReachable.length > 0) {
    issues.push({
      id: "kev-reachable",
      title: "Actively Exploited + Tool Reachability",
      description:
        "Known-exploited vulnerabilities (CISA KEV) in packages reachable by MCP tools — immediate patching required.",
      count: kevReachable.length,
      severity: "critical",
      findings: kevReachable.sort((a, b) => b.blast_score - a.blast_score),
      filter: "kev=true",
    });
  }

  // 2. CISA KEV + credential exposure
  const kevCredential = allBlast.filter(
    (b) => (b.cisa_kev ?? b.is_kev) && b.exposed_credentials.length > 0
  );
  if (kevCredential.length > 0) {
    issues.push({
      id: "kev-credential",
      title: "Actively Exploited + Credential Exposure",
      description:
        "Known-exploited CVEs co-located with exposed credentials — data exfiltration risk.",
      count: kevCredential.length,
      severity: "critical",
      findings: kevCredential.sort((a, b) => b.blast_score - a.blast_score),
      filter: "kev=true",
    });
  }

  // 3. High EPSS (≥30%) + Critical/High CVSS (≥7) — imminent exploitation likely
  const epssHighCvss = allBlast.filter(
    (b) =>
      (b.epss_score ?? 0) >= 0.3 &&
      (b.cvss_score ?? 0) >= 7 &&
      !b.cisa_kev &&
      !b.is_kev
  );
  if (epssHighCvss.length > 0) {
    issues.push({
      id: "epss-cvss",
      title: "High Exploit Probability + Critical Severity",
      description:
        "CVEs with EPSS ≥ 30% and CVSS ≥ 7.0 — statistically likely to be exploited in the wild within 30 days.",
      count: epssHighCvss.length,
      severity: "high",
      findings: epssHighCvss.sort((a, b) => b.blast_score - a.blast_score),
      filter: "severity=high",
    });
  }

  // 4. Credential exposure + reachable exec tools
  const credExec = allBlast.filter(
    (b) =>
      b.exposed_credentials.length > 0 &&
      b.reachable_tools.some((t) =>
        ["bash", "exec", "shell", "run", "execute", "subprocess"].some((kw) =>
          t.toLowerCase().includes(kw)
        )
      )
  );
  if (credExec.length > 0) {
    issues.push({
      id: "cred-exec",
      title: "Credential Exposure + Code Execution Path",
      description:
        "Exposed credentials reachable from tools with code execution capability — privilege escalation vector.",
      count: credExec.length,
      severity: "critical",
      findings: credExec.sort((a, b) => b.blast_score - a.blast_score),
      filter: "severity=critical",
    });
  }

  return issues.sort(
    (a, b) =>
      (SEVERITY_ORDER_MAP[b.severity] ?? 0) -
      (SEVERITY_ORDER_MAP[a.severity] ?? 0)
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [agentCount, setAgentCount] = useState<number>(0);
  const [agentList, setAgentList] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);
  const [importedReport, setImportedReport] = useState<ScanResult | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [jobsRes, agentsRes] = await Promise.all([
          api.listJobs(),
          api.listAgents(),
        ]);
        const jobsList = jobsRes?.jobs ?? [];
        const fullJobs = await Promise.all(
          jobsList?.map((j) => api.getScan(j.job_id))
        );
        setJobs(fullJobs.sort((a, b) => b.created_at.localeCompare(a.created_at)));
        setAgentCount(agentsRes?.count ?? 0);
        setAgentList(agentsRes?.agents ?? []);
      } catch {
        setApiError(true);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  // When API is down but user imported a local report, synthesise a fake job
  // so all downstream useMemo aggregators work without changes.
  const effectiveJobs = useMemo<ScanJob[]>(() => {
    if (!apiError || !importedReport) return jobs;
    return [{
      job_id: "imported",
      status: "done",
      created_at: importedReport.scan_timestamp ?? new Date().toISOString(),
      request: {} as ScanJob["request"],
      progress: [],
      result: importedReport as unknown as Record<string, unknown>,
    } as unknown as ScanJob];
  }, [jobs, apiError, importedReport]);

  const doneJobs = useMemo(
    () => effectiveJobs.filter((j) => j.status === "done" && j.result),
    [effectiveJobs]
  );

  const allBlast = useMemo(
    () => doneJobs.flatMap((j) => (j.result as ScanResult)?.blast_radius ?? []),
    [doneJobs]
  );

  const severity = useMemo(() => aggregateSeverity(allBlast), [allBlast]);
  const topPackages = useMemo(() => aggregatePackages(effectiveJobs), [effectiveJobs]);
  const sources = useMemo(() => aggregateSources(effectiveJobs), [effectiveJobs]);
  const trendData = useMemo(() => aggregateTrend(effectiveJobs), [effectiveJobs]);
  const epssData = useMemo(() => aggregateEpss(allBlast), [allBlast]);
  const scatterData = useMemo(() => aggregateEpssVsCvss(allBlast), [allBlast]);
  const compoundIssues = useMemo(() => aggregateCompoundIssues(allBlast), [allBlast]);

  // Unique CVE count
  const uniqueCVEs = useMemo(() => {
    const ids = new Set(allBlast?.map((b) => b.vulnerability_id));
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

  // Derive agent count from imported report when API is unavailable
  const effectiveAgentCount = importedReport
    ? (importedReport.agents?.length ?? 0)
    : agentCount;
  const isLoading = loading && !importedReport;

  if (apiError && !importedReport) return <ApiDown onImport={setImportedReport} />;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Security Posture</h1>
          <p className="text-zinc-400 text-sm mt-1">
            Aggregated across {doneJobs.length} scan{doneJobs.length !== 1 ? "s" : ""} — {effectiveAgentCount} agent{effectiveAgentCount !== 1 ? "s" : ""} · {totalPackages} packages · {uniqueCVEs} unique CVEs
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
        <StatCard icon={Layers} label="Total scans" value={isLoading ? "—" : String(doneJobs.length)} color="zinc" href="/jobs" />
        <StatCard icon={Server} label="Agents" value={isLoading ? "—" : String(effectiveAgentCount)} color="emerald" href="/agents" />
        <StatCard icon={Package} label="Packages" value={isLoading ? "—" : String(totalPackages)} color="blue" href="/vulns" />
        <StatCard icon={Bug} label="Unique CVEs" value={isLoading ? "—" : String(uniqueCVEs)} color="orange" href="/vulns" />
        <StatCard icon={Zap} label="Critical" value={isLoading ? "—" : String(severity.critical)} color="red" href="/vulns?severity=critical" />
      </div>

      {/* AI Agent Trust Stack */}
      {(!isLoading) && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            AI Agent Trust Stack
          </h2>
          <TrustStack />
        </section>
      )}

      {/* Severity distribution + Sources — side by side */}
      {(!isLoading) && allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SeverityChart severity={severity} />
          <SourceBreakdown sources={sources} />
        </div>
      )}

      {/* Trend charts */}
      {(!isLoading) && allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <VulnTrendChart data={trendData} />
          <EpssDistributionChart data={epssData} />
        </div>
      )}

      {/* EPSS × CVSS risk map */}
      {(!isLoading) && scatterData.length > 0 && (
        <EpssVsCvssChart data={scatterData} />
      )}

      {/* Compound Issues */}
      {(!isLoading) && compoundIssues.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
                Compound Issues
              </h2>
              <p className="text-[10px] text-zinc-600 mt-0.5">
                Findings that meet multiple independent risk criteria simultaneously
              </p>
            </div>
            <Link href="/vulns" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {compoundIssues?.map((issue) => (
              <CompoundIssueCard key={issue.id} issue={issue} />
            ))}
          </div>
        </section>
      )}

      {/* Agent topology */}
      {(!isLoading) && agentList.length > 0 && (
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
      {(!isLoading) && topPackages.length > 0 && (
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
      {(!isLoading) && allBlast.length > 0 && (
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
                <Link key={b.vulnerability_id} href={`/vulns?cve=${b.vulnerability_id}`}>
                  <BlastCard blast={b} />
                </Link>
              ))}
          </div>
        </section>
      )}

      {/* Recent scans + Activity feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <section className="lg:col-span-2">
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
          {isLoading ? (
            <div className="text-zinc-500 text-sm">Loading...</div>
          ) : effectiveJobs.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="space-y-2">
              {effectiveJobs.slice(0, 8).map((job) => (
                <JobRow key={job.job_id} job={job} />
              ))}
            </div>
          )}
        </section>

        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Activity
          </h2>
          <ActivityFeed maxItems={15} />
        </section>
      </div>
    </div>
  );
}

// ─── Components ───────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  href,
  trend,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: "emerald" | "blue" | "orange" | "red" | "zinc";
  href?: string;
  trend?: { direction: "up" | "down" | "flat"; label: string };
}) {
  const colors = {
    emerald: { text: "text-emerald-400", glow: "shadow-emerald-500/5", accent: "bg-emerald-500" },
    blue: { text: "text-blue-400", glow: "shadow-blue-500/5", accent: "bg-blue-500" },
    orange: { text: "text-orange-400", glow: "shadow-orange-500/5", accent: "bg-orange-500" },
    red: { text: "text-red-400", glow: "shadow-red-500/5", accent: "bg-red-500" },
    zinc: { text: "text-zinc-400", glow: "shadow-zinc-500/5", accent: "bg-zinc-500" },
  };
  const c = colors[color];
  const inner = (
    <div className={`bg-zinc-900 border border-zinc-800 rounded-xl p-4 ${href ? "hover:border-zinc-600 transition-all cursor-pointer" : ""} shadow-lg ${c.glow}`}>
      <div className="flex items-center justify-between mb-2">
        <Icon className={`w-4 h-4 ${c.text}`} />
        {trend && (
          <span className={`text-[10px] font-medium ${
            trend.direction === "down" ? "text-emerald-400" : trend.direction === "up" ? "text-red-400" : "text-zinc-500"
          }`}>
            {trend.direction === "up" ? "\u2191" : trend.direction === "down" ? "\u2193" : "\u2022"} {trend.label}
          </span>
        )}
      </div>
      <div className="text-2xl font-bold font-mono tracking-tight">{value}</div>
      <div className="flex items-center justify-between mt-1">
        <div className="text-xs text-zinc-500">{label}</div>
        <div className={`w-8 h-1 rounded-full ${c.accent} opacity-30`} />
      </div>
    </div>
  );
  if (href) return <Link href={href}>{inner}</Link>;
  return inner;
}

function SeverityChart({ severity }: { severity: SeverityCounts }) {
  const total = severity.total || 1;
  const bars = [
    { label: "Critical", count: severity.critical, color: "bg-red-500", text: "text-red-400", ring: "ring-red-500/20" },
    { label: "High", count: severity.high, color: "bg-orange-500", text: "text-orange-400", ring: "ring-orange-500/20" },
    { label: "Medium", count: severity.medium, color: "bg-yellow-500", text: "text-yellow-400", ring: "ring-yellow-500/20" },
    { label: "Low", count: severity.low, color: "bg-blue-500", text: "text-blue-400", ring: "ring-blue-500/20" },
  ];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-zinc-300">Severity Distribution</h3>
        <span className="text-xs text-zinc-600 font-mono">{total} total</span>
      </div>

      {/* Stacked bar */}
      <div className="flex h-3 rounded-full overflow-hidden bg-zinc-800/50 mb-5">
        {bars?.map((b) =>
          b.count > 0 ? (
            <Link
              key={b.label}
              href={`/vulns?severity=${b.label.toLowerCase()}`}
              className={`${b.color} transition-all duration-500 hover:brightness-125`}
              style={{ width: `${(b.count / total) * 100}%` }}
              title={`${b.label}: ${b.count}`}
            />
          ) : null
        )}
      </div>

      {/* Legend with hover rings */}
      <div className="grid grid-cols-4 gap-2">
        {bars?.map((b) => (
          <Link key={b.label} href={`/vulns?severity=${b.label.toLowerCase()}`} className={`text-center hover:bg-zinc-800/50 rounded-lg py-2 transition-all hover:ring-1 ${b.ring}`}>
            <div className={`text-xl font-bold font-mono ${b.text}`}>{b.count}</div>
            <div className="text-[10px] text-zinc-500 font-medium uppercase tracking-wide">{b.label}</div>
            <div className="text-[10px] text-zinc-600 font-mono">{total > 0 ? Math.round((b.count / total) * 100) : 0}%</div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function SourceBreakdown({ sources }: { sources: ScanSource[] }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">Scan Sources</h3>
      {sources.length === 0 ? (
        <p className="text-zinc-600 text-sm">No completed scans yet.</p>
      ) : (
        <div className="space-y-3">
          {sources?.map((s) => (
            <div key={s.label} className="flex items-center gap-3 bg-zinc-800/30 rounded-lg px-3 py-2.5 border border-zinc-800/50">
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
      href={`/scan?id=${job.job_id}`}
      className="flex items-center gap-4 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 rounded-xl p-4 transition-colors group"
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColors[job.status] ?? "bg-zinc-500"}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-zinc-400">{job.job_id.slice(0, 8)}…</span>
          {tags?.map((t) => (
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

function CompoundIssueCard({ issue }: { issue: CompoundIssue }) {
  const isCrit = issue.severity === "critical";
  const borderColor = isCrit ? "border-red-900" : "border-orange-900/60";
  const badgeColor = isCrit
    ? "bg-red-950 border border-red-800 text-red-400"
    : "bg-orange-950 border border-orange-800 text-orange-400";
  const countColor = isCrit ? "text-red-400" : "text-orange-400";

  return (
    <Link href={`/vulns?${issue.filter}`}>
      <div
        className={`bg-zinc-900 border ${borderColor} rounded-xl p-4 hover:bg-zinc-800/80 transition-colors cursor-pointer`}
      >
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <AlertTriangle
              className={`w-4 h-4 shrink-0 ${isCrit ? "text-red-400" : "text-orange-400"}`}
            />
            <span className="text-sm font-semibold text-zinc-200 leading-tight">
              {issue.title}
            </span>
          </div>
          <span className={`text-xs font-mono font-bold ${countColor} shrink-0`}>
            {issue.count}
          </span>
        </div>
        <p className="text-xs text-zinc-500 leading-relaxed mb-3">
          {issue.description}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {issue.findings.slice(0, 4).map((f) => (
            <span
              key={f.vulnerability_id}
              className={`text-[10px] font-mono rounded px-1.5 py-0.5 ${badgeColor}`}
            >
              {f.vulnerability_id}
              {(f.cisa_kev ?? f.is_kev) && " ⚡"}
            </span>
          ))}
          {issue.findings.length > 4 && (
            <span className="text-[10px] text-zinc-600 font-mono px-1 py-0.5">
              +{issue.findings.length - 4} more
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}

function ApiDown({ onImport }: { onImport: (data: ScanResult) => void }) {
  const [importError, setImportError] = useState<string | null>(null);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError(null);

    // Reject oversized files before loading into memory
    const sizeCheck = checkFileSize(file);
    if (!sizeCheck.ok) {
      setImportError(sizeCheck.error);
      e.target.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => setImportError("Failed to read file.");
    reader.onload = (ev) => {
      const text = ev.target?.result;
      if (typeof text !== "string") {
        setImportError("Could not read file contents.");
        return;
      }
      const result = validateScanReport(text);
      if (!result.ok) {
        setImportError(result.error);
        return;
      }
      onImport(result.data as ScanResult);
    };
    reader.readAsText(file);
  };

  return (
    <div className="text-center py-16">
      <AlertTriangle className="w-10 h-10 text-orange-400 mx-auto mb-4" />
      <h2 className="text-lg font-semibold mb-2">Cannot connect to agent-bom API</h2>
      <p className="text-zinc-500 text-sm mb-6">
        Make sure the API server is running at{" "}
        <code className="font-mono bg-zinc-900 px-1.5 py-0.5 rounded text-zinc-300">
          {process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422"}
        </code>
      </p>
      <code className="block bg-zinc-900 border border-zinc-800 rounded-lg px-6 py-4 text-sm font-mono text-emerald-400 mb-8 inline-block">
        pip install &apos;agent-bom[api]&apos;<br />
        agent-bom api
      </code>
      <div className="border border-dashed border-zinc-700 rounded-xl p-8 max-w-md mx-auto">
        <FileText className="w-8 h-8 text-zinc-500 mx-auto mb-3" />
        <p className="text-sm text-zinc-400 mb-1 font-medium">Or import a local report</p>
        <p className="text-xs text-zinc-600 mb-4">
          Generated with{" "}
          <code className="font-mono">agent-bom scan -f json -o report.json</code>
          <span className="block mt-1 text-zinc-700">Max 10 MB · schema-validated</span>
        </p>
        {importError && (
          <div className="mb-4 px-3 py-2 bg-red-950/40 border border-red-800/50 rounded-lg text-left">
            <p className="text-xs text-red-400 font-mono break-words">{importError}</p>
          </div>
        )}
        <label className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-sm text-zinc-300 transition-colors">
          <FileText className="w-4 h-4" />
          Choose report.json
          <input
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleFile}
          />
        </label>
      </div>
    </div>
  );
}
