"use client";

import Link from "next/link";
import { AlertTriangle, ArrowRight, ExternalLink } from "lucide-react";

import { type Agent, type BlastRadius, OWASP_LLM_TOP10, MITRE_ATLAS } from "@/lib/api";
import { AgentTopology } from "@/components/agent-topology";
import { TrustStack, type TrustStackSignals } from "@/components/trust-stack";
import { SeverityBadge } from "@/components/severity-badge";
import {
  VulnTrendChart,
  EpssDistributionChart,
  EpssVsCvssChart,
  type TrendDataPoint,
  type EpssDataPoint,
  type EpssVsCvssPoint,
} from "@/components/charts";
import { useAuthState } from "@/components/auth-provider";
import {
  type AggregatedPackage,
  type CompoundIssue,
  type ScanSource,
  type SeverityCounts,
  blastAgents,
  blastCredentials,
  blastTools,
} from "@/lib/dashboard-data";

export interface DashboardAnalyticsProps {
  severity: SeverityCounts;
  sources: ScanSource[];
  trendData: TrendDataPoint[];
  epssData: EpssDataPoint[];
  scatterData: EpssVsCvssPoint[];
  compoundIssues: CompoundIssue[];
  agentList: Agent[];
  trustSignals: TrustStackSignals;
  topPackages: AggregatedPackage[];
  allBlast: BlastRadius[];
}

// Heavy, below-the-fold analytics for the home dashboard. Split into its own
// module and mounted lazily (next/dynamic + a tab) so the recharts-backed charts
// and long tables stay out of the home route's first-paint bundle.
export default function DashboardAnalytics({
  severity,
  sources,
  trendData,
  epssData,
  scatterData,
  compoundIssues,
  agentList,
  trustSignals,
  topPackages,
  allBlast,
}: DashboardAnalyticsProps) {
  const { session } = useAuthState();

  return (
    <div className="space-y-8">
      {/* Severity distribution + Sources — side by side */}
      {allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SeverityChart severity={severity} />
          <SourceBreakdown sources={sources} />
        </div>
      )}

      {/* Trend charts */}
      {allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <VulnTrendChart data={trendData} />
          <EpssDistributionChart data={epssData} />
        </div>
      )}

      {/* EPSS × CVSS risk map */}
      {scatterData.length > 0 && <EpssVsCvssChart data={scatterData} />}

      {/* Compound Issues */}
      {compoundIssues.length > 0 && (
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
            <Link href="/findings" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
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
      {agentList.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Agent Topology
            </h2>
            <Link href="/agents" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <AgentTopology agents={agentList} session={session} />
        </section>
      )}

      {/* AI Agent Trust Stack */}
      <section>
        <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
          AI Agent Trust Stack
        </h2>
        <TrustStack signals={trustSignals} />
      </section>

      {/* Top vulnerable packages */}
      {topPackages.length > 0 && (
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
              Showing 10 of {topPackages.length} — <Link href="/findings" className="text-emerald-500 hover:text-emerald-400">view all</Link>
            </p>
          )}
        </section>
      )}

      {/* Blast radius highlights */}
      {allBlast.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Highest risk findings
            </h2>
            <Link href="/findings" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-2">
            {[...allBlast]
              .sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score))
              .slice(0, 5)
              .map((b, index) => (
                <BlastCard
                  key={`${b.vulnerability_id}:${b.package ?? "unknown"}:${index}`}
                  blast={b}
                  detailHref={`/findings?cve=${b.vulnerability_id}`}
                />
              ))}
          </div>
        </section>
      )}
    </div>
  );
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
    <div
      className="rounded-xl border p-5 shadow-lg"
      style={{
        backgroundColor: "var(--surface)",
        borderColor: "var(--border-subtle)",
        boxShadow: "0 18px 36px -24px var(--shadow-color)",
      }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-zinc-300">Severity Distribution</h3>
        <span className="text-xs font-mono text-[var(--text-tertiary)]">{total} total</span>
      </div>

      {/* Stacked bar */}
      <div className="mb-5 flex h-3 overflow-hidden rounded-full bg-[var(--surface-muted)]">
        {bars?.map((b) =>
          b.count > 0 ? (
            <Link
              key={b.label}
              href={`/findings?severity=${b.label.toLowerCase()}`}
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
          <Link key={b.label} href={`/findings?severity=${b.label.toLowerCase()}`} className={`rounded-lg py-2 text-center transition-all hover:bg-[var(--surface-muted)] hover:ring-1 ${b.ring}`}>
            <div className={`text-xl font-bold font-mono ${b.text}`}>{b.count}</div>
            <div className="text-[10px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">{b.label}</div>
            <div className="text-[10px] font-mono text-[var(--text-tertiary)]">{total > 0 ? Math.round((b.count / total) * 100) : 0}%</div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function SourceBreakdown({ sources }: { sources: ScanSource[] }) {
  return (
    <div
      className="rounded-xl border p-5 shadow-lg"
      style={{
        backgroundColor: "var(--surface)",
        borderColor: "var(--border-subtle)",
        boxShadow: "0 18px 36px -24px var(--shadow-color)",
      }}
    >
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">Scan Sources</h3>
      {sources.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">No completed scans yet.</p>
      ) : (
        <div className="space-y-3">
          {sources?.map((s) => (
            <div
              key={s.label}
              className="flex items-center gap-3 rounded-lg border px-3 py-2.5"
              style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
            >
              <s.icon className="h-4 w-4 flex-shrink-0 text-[var(--text-secondary)]" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-200">{s.label}</span>
                  <span className="text-xs font-mono text-[var(--text-secondary)]">{s.count} scanned</span>
                </div>
                <div className="mt-0.5 flex items-center gap-3 text-xs text-[var(--text-tertiary)]">
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

function BlastCard({ blast, detailHref }: { blast: BlastRadius; detailHref: string }) {
  return (
    <div className="flex items-start gap-4 bg-zinc-900 border border-zinc-800 rounded-xl p-4 transition-colors hover:border-zinc-700">
      <SeverityBadge severity={blast.severity} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <Link
            href={detailHref}
            className="font-mono text-sm font-semibold text-zinc-100 hover:text-emerald-400"
          >
            {blast.vulnerability_id}
          </Link>
          <a
            href={`https://osv.dev/vulnerability/${blast.vulnerability_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-full border border-zinc-700 px-2 py-0.5 text-[11px] font-medium text-zinc-400 transition-colors hover:border-zinc-600 hover:text-zinc-200"
          >
            OSV
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
        <div className="flex flex-wrap gap-3 mt-1.5 text-xs text-zinc-500">
          <span>{blastAgents(blast).length} agent{blastAgents(blast).length !== 1 ? "s" : ""}</span>
          {blastCredentials(blast).length > 0 && (
            <span className="text-orange-400">{blastCredentials(blast).length} credential{blastCredentials(blast).length !== 1 ? "s" : ""}</span>
          )}
          <span>{blastTools(blast).length} tool{blastTools(blast).length !== 1 ? "s" : ""}</span>
          {(blast.is_kev ?? blast.cisa_kev) && <span className="text-red-400 font-semibold">CISA KEV</span>}
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
        {blast.attack_vector_summary && (
          <p className="mt-2 line-clamp-2 text-xs leading-5 text-zinc-400">{blast.attack_vector_summary}</p>
        )}
      </div>
      <div className="flex flex-col items-end gap-2">
        {(blast.risk_score ?? blast.blast_score) > 0 && (
          <div className="text-right">
            <div className="text-lg font-bold font-mono text-red-400">{(blast.risk_score ?? blast.blast_score).toFixed(0)}</div>
            <div className="text-xs text-zinc-600">score</div>
          </div>
        )}
        <Link
          href={detailHref}
          className="text-xs font-medium text-emerald-400 transition-colors hover:text-emerald-300"
        >
          Review evidence
        </Link>
      </div>
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
    <Link href={`/findings?${issue.filter}`}>
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
          {issue.findings.slice(0, 4).map((f, index) => (
            <span
              key={`${issue.id}:${f.vulnerability_id}:${f.package ?? "unknown"}:${index}`}
              className={`text-[10px] font-mono rounded px-1.5 py-0.5 ${badgeColor}`}
            >
              {f.vulnerability_id}
              {(f.is_kev ?? f.cisa_kev) && " ⚡"}
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
