"use client";

import { use, useEffect, useState, useRef } from "react";
import Link from "next/link";
import { api, ScanJob, ScanResult, BlastRadius, formatDate } from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";
import { ArrowLeft, CheckCircle, XCircle, Loader2, Clock, Zap, Shield, Key, Wrench } from "lucide-react";

export default function ScanResultPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [streaming, setStreaming] = useState(true);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Load initial state
    api.getScan(id).then(setJob).catch(() => {});

    // Subscribe to SSE stream
    const cleanup = api.streamScan(
      id,
      (data) => {
        const d = data as { type: string; message?: string };
        if (d.type === "progress" && d.message) {
          setMessages((m) => [...m, d.message!]);
          // Also refresh job state
          api.getScan(id).then(setJob).catch(() => {});
        }
      },
      () => {
        setStreaming(false);
        api.getScan(id).then(setJob).catch(() => {});
      }
    );
    return cleanup;
  }, [id]);

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [messages]);

  const result = job?.result as ScanResult | undefined;
  const summary = result?.summary;
  const blastRadius = result?.blast_radius ?? [];

  return (
    <div className="space-y-8">
      {/* Back + header */}
      <div className="flex items-center gap-4">
        <Link href="/" className="text-zinc-500 hover:text-zinc-300 transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold">Scan Results</h1>
            <JobStatusBadge status={job?.status ?? "pending"} streaming={streaming} />
          </div>
          <p className="text-xs text-zinc-500 font-mono mt-0.5">{id}</p>
        </div>
      </div>

      {/* Live log */}
      {(streaming || messages.length > 0) && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            {streaming ? (
              <Loader2 className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
            ) : (
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
            )}
            <span className="text-xs font-semibold text-zinc-400">
              {streaming ? "Scanning…" : "Complete"}
            </span>
          </div>
          <div ref={logRef} className="max-h-48 overflow-y-auto space-y-1">
            {messages.map((m, i) => (
              <p key={i} className="text-xs font-mono text-zinc-400">{m}</p>
            ))}
            {streaming && messages.length === 0 && (
              <p className="text-xs font-mono text-zinc-600 animate-pulse">Waiting for scan to start…</p>
            )}
          </div>
        </div>
      )}

      {/* Error */}
      {job?.status === "failed" && (
        <div className="bg-red-950 border border-red-900 rounded-xl p-4 text-sm text-red-300">
          <strong>Scan failed:</strong> {job.error ?? "Unknown error"}
        </div>
      )}

      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MiniStat label="Agents" value={summary.total_agents} />
          <MiniStat label="Packages" value={summary.total_packages} />
          <MiniStat label="Vulnerabilities" value={summary.total_vulnerabilities} />
          <MiniStat label="Critical" value={summary.critical_findings} accent="red" />
        </div>
      )}

      {/* Blast radius */}
      {blastRadius.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Blast Radius ({blastRadius.length})
          </h2>
          <div className="space-y-3">
            {blastRadius
              .sort((a, b) => b.blast_score - a.blast_score)
              .map((b) => (
                <BlastRadiusCard key={b.vulnerability_id} blast={b} />
              ))}
          </div>
        </section>
      )}

      {/* Agent inventory */}
      {result && result.agents.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Agents ({result.agents.length})
          </h2>
          <div className="space-y-3">
            {result.agents.map((agent, i) => (
              <div key={i} className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <span className="font-semibold text-sm">{agent.name}</span>
                    <span className="ml-2 text-xs text-zinc-500 font-mono">{agent.agent_type}</span>
                  </div>
                  <span className="text-xs text-zinc-600">{agent.source}</span>
                </div>
                <div className="space-y-2">
                  {agent.mcp_servers.map((srv, j) => (
                    <div key={j} className="bg-zinc-800 rounded-lg p-3">
                      <div className="text-xs font-mono text-zinc-300 mb-1.5">{srv.name}</div>
                      <div className="flex flex-wrap gap-2">
                        {srv.packages.slice(0, 8).map((pkg, k) => {
                          const hasCrit = pkg.vulnerabilities?.some((v) => v.severity === "critical");
                          const hasHigh = pkg.vulnerabilities?.some((v) => v.severity === "high");
                          return (
                            <span
                              key={k}
                              className={`text-xs font-mono px-2 py-0.5 rounded ${
                                hasCrit
                                  ? "bg-red-950 border border-red-900 text-red-300"
                                  : hasHigh
                                  ? "bg-orange-950 border border-orange-900 text-orange-300"
                                  : "bg-zinc-700 border border-zinc-600 text-zinc-400"
                              }`}
                            >
                              {pkg.name}@{pkg.version}
                              {pkg.vulnerabilities && pkg.vulnerabilities.length > 0 && (
                                <span className="ml-1 opacity-70">({pkg.vulnerabilities.length})</span>
                              )}
                            </span>
                          );
                        })}
                        {srv.packages.length > 8 && (
                          <span className="text-xs text-zinc-600">+{srv.packages.length - 8} more</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Warnings */}
      {result?.warnings && result.warnings.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Warnings
          </h2>
          <div className="space-y-1">
            {result.warnings.map((w, i) => (
              <p key={i} className="text-xs text-yellow-400 font-mono bg-yellow-950/30 rounded px-3 py-2">
                ⚠ {w}
              </p>
            ))}
          </div>
        </section>
      )}

      {/* Scan metadata */}
      {job?.completed_at && (
        <div className="text-xs text-zinc-600 flex items-center gap-2">
          <Clock className="w-3 h-3" />
          Completed {formatDate(job.completed_at)}
        </div>
      )}
    </div>
  );
}

function JobStatusBadge({ status, streaming }: { status: string; streaming: boolean }) {
  if (status === "done") return <span className="text-xs bg-emerald-950 border border-emerald-900 text-emerald-400 rounded-full px-2 py-0.5 font-mono">done</span>;
  if (status === "failed") return <span className="text-xs bg-red-950 border border-red-900 text-red-400 rounded-full px-2 py-0.5 font-mono">failed</span>;
  if (status === "running" || streaming) return (
    <span className="text-xs bg-yellow-950 border border-yellow-900 text-yellow-400 rounded-full px-2 py-0.5 font-mono flex items-center gap-1">
      <Loader2 className="w-3 h-3 animate-spin" /> running
    </span>
  );
  return <span className="text-xs bg-zinc-800 border border-zinc-700 text-zinc-400 rounded-full px-2 py-0.5 font-mono">{status}</span>;
}

function MiniStat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 text-center">
      <div className={`text-2xl font-bold font-mono ${accent === "red" && value > 0 ? "text-red-400" : ""}`}>
        {value}
      </div>
      <div className="text-xs text-zinc-500 mt-1">{label}</div>
    </div>
  );
}

function BlastRadiusCard({ blast }: { blast: BlastRadius }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <SeverityBadge severity={blast.severity} />
            {blast.cisa_kev && (
              <span className="text-xs bg-red-950 border border-red-900 text-red-400 rounded px-2 py-0.5 font-mono font-semibold">
                CISA KEV
              </span>
            )}
          </div>
          <h3 className="font-mono font-semibold text-zinc-100">{blast.vulnerability_id}</h3>
        </div>
        <div className="text-right flex-shrink-0">
          {blast.blast_score > 0 && (
            <>
              <div className="text-2xl font-bold font-mono text-red-400">{blast.blast_score.toFixed(0)}</div>
              <div className="text-xs text-zinc-600">blast score</div>
            </>
          )}
          {blast.cvss_score && (
            <div className="text-xs text-zinc-500 mt-1">CVSS {blast.cvss_score.toFixed(1)}</div>
          )}
          {blast.epss_score && (
            <div className="text-xs text-zinc-500">EPSS {(blast.epss_score * 100).toFixed(1)}%</div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <ImpactPill icon={Zap} label="Agents affected" items={blast.affected_agents} />
        <ImpactPill icon={Key} label="Credentials exposed" items={blast.exposed_credentials} accent="orange" />
        <ImpactPill icon={Wrench} label="Tools reachable" items={blast.reachable_tools} />
      </div>

      {/* OWASP + ATLAS threat tags */}
      {((blast.owasp_tags && blast.owasp_tags.length > 0) || (blast.atlas_tags && blast.atlas_tags.length > 0)) && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {blast.owasp_tags?.map((tag) => (
            <span key={tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1.5 py-0.5">
              {tag}
            </span>
          ))}
          {blast.atlas_tags?.map((tag) => (
            <span key={tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1.5 py-0.5">
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ImpactPill({
  icon: Icon, label, items, accent,
}: {
  icon: React.ElementType;
  label: string;
  items: string[];
  accent?: string;
}) {
  const accentClass = accent === "orange" && items.length > 0 ? "text-orange-400" : "text-zinc-300";
  return (
    <div className="bg-zinc-800 rounded-lg p-3">
      <div className={`flex items-center gap-1.5 text-xs font-semibold mb-2 ${accentClass}`}>
        <Icon className="w-3.5 h-3.5" />
        <span>{label} ({items.length})</span>
      </div>
      {items.length > 0 ? (
        <div className="space-y-1">
          {items.slice(0, 4).map((item, i) => (
            <p key={i} className="text-xs font-mono text-zinc-400 truncate">{item}</p>
          ))}
          {items.length > 4 && (
            <p className="text-xs text-zinc-600">+{items.length - 4} more</p>
          )}
        </div>
      ) : (
        <p className="text-xs text-zinc-600">None</p>
      )}
    </div>
  );
}
