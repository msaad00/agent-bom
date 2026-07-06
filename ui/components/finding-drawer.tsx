"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { ExternalLink, FileSearch, Loader2, Radar, ShieldAlert, X } from "lucide-react";

import { severityColor, type FindingTriageDecision, type FindingTriageItem, type FindingTriageJustification } from "@/lib/api";
import { type EnrichedVuln, uniqueStrings, formatFindingTimestamp, findingStatusClass, findingStatusLabel } from "@/lib/findings-view";

export function FindingDrawer({
  vuln,
  triage,
  triageBusy,
  onTriageDecision,
  onClose,
}: {
  vuln: EnrichedVuln;
  triage: FindingTriageItem | undefined;
  triageBusy: boolean;
  onTriageDecision: (
    vuln: EnrichedVuln,
    decision: FindingTriageDecision,
    justification?: FindingTriageJustification,
  ) => void;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/45 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={`Finding details for ${vuln.id}`}>
      <button type="button" className="absolute inset-0 cursor-default" aria-label="Close finding details" onClick={onClose} />
      <aside className="relative h-full w-full max-w-3xl overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-5 shadow-2xl">
        <div className="mb-4 flex items-start justify-between gap-4 border-b border-zinc-800 pb-4">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500">Evidence drawer</p>
            <h2 className="mt-1 break-all font-mono text-lg font-semibold text-zinc-100">{vuln.id}</h2>
            <p className="mt-1 text-sm text-zinc-500">
              Reachability, impacted packages, agent exposure, remediation, and VEX decisioning.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-zinc-800 bg-zinc-900 p-2 text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-100"
            aria-label="Close finding drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <VulnDetailPanel
          vuln={vuln}
          triage={triage}
          triageBusy={triageBusy}
          onTriageDecision={onTriageDecision}
        />
      </aside>
    </div>
  );
}

function VulnDetailPanel({
  vuln,
  triage,
  triageBusy,
  onTriageDecision,
}: {
  vuln: EnrichedVuln;
  triage: FindingTriageItem | undefined;
  triageBusy: boolean;
  onTriageDecision: (
    vuln: EnrichedVuln,
    decision: FindingTriageDecision,
    justification?: FindingTriageJustification,
  ) => void;
}) {
  const summary = vuln.attack_vector_summary ?? vuln.summary ?? vuln.description ?? "No advisory summary available.";
  const cweMatches = summary.match(/CWE-\d+/gi) ?? [];
  const published = vuln.published_at ?? vuln.published ?? vuln.nvd_published;
  const modified = vuln.modified_at;
  const hasLifecycle =
    Boolean(vuln.lifecycle_status?.trim()) ||
    Boolean(vuln.first_seen?.trim()) ||
    Boolean(vuln.last_seen?.trim()) ||
    Boolean(vuln.resolved_at?.trim()) ||
    Boolean(vuln.reopened_at?.trim()) ||
    typeof vuln.scan_count === "number";
  const references = uniqueStrings(vuln.references).slice(0, 6);
  const fixCandidates = vuln.remediation_items.filter((item) => item.fixed_version || item.command || item.verify_command);
  const investigationSources = uniqueStrings([
    ...vuln.sources,
    ...vuln.advisory_sources,
  ]);

  return (
    <div className="ml-6 rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
        <div className="space-y-4">
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Attack summary</h4>
            <p className="mt-2 text-sm leading-6 text-zinc-300">{summary}</p>
            {cweMatches.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {[...new Set(cweMatches)].map((cwe) => (
                  <span key={cwe} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-xs font-mono text-zinc-400">
                    {cwe}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <DetailStat label="Severity" value={vuln.severity} accent={severityColor(vuln.severity)} />
            <DetailStat label="CVSS" value={typeof vuln.cvss_score === "number" ? vuln.cvss_score.toFixed(1) : "Not published"} />
            <DetailStat label="EPSS" value={typeof vuln.epss_score === "number" ? `${(vuln.epss_score * 100).toFixed(1)}%` : "Not available"} />
          </div>
          {(vuln.effective_reach_band || vuln.runtime_evidence?.state) && (
            <div className="flex flex-wrap gap-2">
              {vuln.effective_reach_band && (
                <span className="rounded border border-amber-800/60 bg-amber-950/40 px-2 py-0.5 text-xs font-medium uppercase tracking-wide text-amber-300">
                  Reach {vuln.effective_reach_band}
                  {typeof vuln.effective_reach_score === "number" ? ` (${vuln.effective_reach_score.toFixed(0)})` : ""}
                </span>
              )}
              {vuln.runtime_evidence?.state && vuln.runtime_evidence.state !== "static" && (
                <span className={`rounded border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${
                  vuln.runtime_evidence.state === "blocked"
                    ? "border-rose-800/60 bg-rose-950/40 text-rose-300"
                    : "border-sky-800/60 bg-sky-950/40 text-sky-300"
                }`}>
                  Runtime {vuln.runtime_evidence.state}
                </span>
              )}
            </div>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            <ContextCard
              icon={Radar}
              title="Asset and reach context"
              items={[
                `${vuln.packages.length} package${vuln.packages.length === 1 ? "" : "s"}`,
                `${vuln.agents.length} agent${vuln.agents.length === 1 ? "" : "s"}`,
                `${vuln.affected_servers.length} server${vuln.affected_servers.length === 1 ? "" : "s"}`,
                vuln.risk_score ? `Risk score ${vuln.risk_score.toFixed(1)}` : null,
                vuln.impact_category ? `Impact ${vuln.impact_category}` : null,
              ]}
              detail={
                <>
                  <TagList label="Packages" values={vuln.packages} mono />
                  <TagList label="Agents" values={vuln.agents} />
                  <TagList label="Servers" values={vuln.affected_servers} />
                </>
              }
            />
            <ContextCard
              icon={ShieldAlert}
              title="Exposure at risk"
              items={[
                `${vuln.exposed_credentials.length} credential${vuln.exposed_credentials.length === 1 ? "" : "s"} exposed`,
                `${vuln.reachable_tools.length} confirmed tool${vuln.reachable_tools.length === 1 ? "" : "s"}`,
                vuln.phantom_tools?.length
                  ? `${vuln.phantom_tools.length} registry-only tool${vuln.phantom_tools.length === 1 ? "" : "s"} (excluded from score)`
                  : null,
              ]}
              detail={
                <>
                  <TagList label="Credentials" values={vuln.exposed_credentials} mono />
                  <TagList label="Confirmed tools" values={vuln.reachable_tools} mono />
                  {vuln.phantom_tools && vuln.phantom_tools.length > 0 && (
                    <TagList label="Registry-only tools" values={vuln.phantom_tools} mono />
                  )}
                </>
              }
            />
          </div>
          {vuln.framework_tags && vuln.framework_tags.length > 0 && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
              <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Compliance controls</h4>
              <div className="mt-3 flex flex-wrap gap-1">
                {vuln.framework_tags.slice(0, 24).map((tag) => (
                  <span key={tag} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-[11px] font-mono text-zinc-300">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="space-y-4">
          {hasLifecycle && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
              <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Lifecycle</h4>
              <div className="mt-3 space-y-2 text-sm text-zinc-300">
                {vuln.lifecycle_status && (
                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500">Status:</span>
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${findingStatusClass(vuln.lifecycle_status)}`}>
                      {findingStatusLabel(vuln.lifecycle_status)}
                    </span>
                  </div>
                )}
                {vuln.first_seen && <div><span className="text-zinc-500">First seen:</span> {formatFindingTimestamp(vuln.first_seen)}</div>}
                {vuln.last_seen && <div><span className="text-zinc-500">Last seen:</span> {formatFindingTimestamp(vuln.last_seen)}</div>}
                {vuln.resolved_at && <div><span className="text-zinc-500">Resolved:</span> {formatFindingTimestamp(vuln.resolved_at)}</div>}
                {vuln.reopened_at && <div><span className="text-zinc-500">Reopened:</span> {formatFindingTimestamp(vuln.reopened_at)}</div>}
                {typeof vuln.scan_count === "number" && (
                  <div><span className="text-zinc-500">Scan count:</span> {vuln.scan_count}</div>
                )}
              </div>
            </div>
          )}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
            <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Fix context</h4>
            <div className="mt-3 space-y-2 text-sm text-zinc-300">
              <div><span className="text-zinc-500">Fix:</span> {vuln.fixed_version ?? "No published fix"}</div>
              {published && <div><span className="text-zinc-500">Published:</span> {new Date(published).toLocaleDateString()}</div>}
              {modified && <div><span className="text-zinc-500">Modified:</span> {new Date(modified).toLocaleDateString()}</div>}
              {typeof vuln.confidence === "number" && <div><span className="text-zinc-500">Confidence:</span> {(vuln.confidence * 100).toFixed(0)}%</div>}
              {vuln.severity_source && <div><span className="text-zinc-500">Severity source:</span> {vuln.severity_source}</div>}
            </div>
            {fixCandidates.length > 0 && (
              <div className="mt-4 space-y-3">
                {fixCandidates.slice(0, 2).map((item) => (
                  <div key={`${item.package}:${item.current_version}`} className="rounded-lg border border-zinc-800 bg-zinc-900/70 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-medium text-zinc-200">{item.package}</span>
                      <span className="text-[11px] font-mono text-emerald-400">
                        {item.current_version} → {item.fixed_version ?? "monitor"}
                      </span>
                    </div>
                    {item.action && <p className="mt-2 text-xs text-zinc-400">{item.action}</p>}
                    {item.command && <CodeLine label="Apply" value={item.command} />}
                    {item.verify_command && <CodeLine label="Verify" value={item.verify_command} />}
                  </div>
                ))}
              </div>
            )}
            {vuln.remediation_items[0]?.risk_narrative && (
              <p className="mt-3 text-xs leading-5 text-zinc-400">{vuln.remediation_items[0].risk_narrative}</p>
            )}
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
            <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Investigation sources</h4>
            <div className="mt-3 space-y-3">
              <TagList label="Signals" values={investigationSources} />
              <TagList label="Aliases" values={vuln.aliases ?? []} mono />
              {references.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">Advisories</div>
                  <div className="flex flex-col gap-2">
                    {references.map((ref) => (
                      <a
                        key={ref}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/70 px-3 py-2 text-xs text-zinc-300 transition-colors hover:border-zinc-700 hover:text-zinc-100"
                      >
                        <FileSearch className="h-3.5 w-3.5 text-zinc-500" />
                        <span className="truncate">{ref}</span>
                        <ExternalLink className="ml-auto h-3 w-3 shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Review queue</h4>
                <p className="mt-2 text-xs leading-5 text-zinc-400">
                  Record analyst disposition for this package finding. Not affected decisions require an OpenVEX justification and become eligible for signed VEX export.
                </p>
              </div>
              {triage && (
                <span className="rounded-full border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-[11px] font-medium text-zinc-300">
                  {triage.queue_state}
                </span>
              )}
            </div>
            {triage ? (
              <div className="mt-3 grid gap-2 text-xs text-zinc-400 sm:grid-cols-2">
                <div><span className="text-zinc-500">Decision:</span> {triage.decision}</div>
                <div><span className="text-zinc-500">Assignee:</span> {triage.assignee || "unassigned"}</div>
                {triage.justification && <div className="sm:col-span-2"><span className="text-zinc-500">Justification:</span> {triage.justification}</div>}
                {triage.decision_reason && <div className="sm:col-span-2"><span className="text-zinc-500">Reason:</span> {triage.decision_reason}</div>}
              </div>
            ) : (
              <p className="mt-3 text-xs text-zinc-500">No triage item recorded for this finding/package pair.</p>
            )}
            <div className="mt-4 flex flex-wrap gap-2">
              <TriageButton
                label="Investigate"
                busy={triageBusy}
                disabled={Boolean(triage)}
                onClick={() => onTriageDecision(vuln, "under_investigation")}
              />
              <TriageButton
                label="Affected"
                busy={triageBusy}
                onClick={() => onTriageDecision(vuln, "affected")}
              />
              <TriageButton
                label="Not affected"
                busy={triageBusy}
                tone="green"
                onClick={() => onTriageDecision(vuln, "not_affected", "vulnerable_code_not_in_execute_path")}
              />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <a
              href={`https://osv.dev/vulnerability/${vuln.id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:border-zinc-600 hover:text-zinc-100"
            >
              Open on OSV
              <ExternalLink className="h-3 w-3" />
            </a>
            <Link
              href={`/vulns?cve=${vuln.id}`}
              className="inline-flex items-center gap-1 rounded-lg border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-950/70"
            >
              Keep this CVE scoped
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function TriageButton({
  label,
  busy,
  disabled = false,
  tone = "zinc",
  onClick,
}: {
  label: string;
  busy: boolean;
  disabled?: boolean;
  tone?: "zinc" | "green";
  onClick: () => void;
}) {
  const classes =
    tone === "green"
      ? "border-emerald-800 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-950/70"
      : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-zinc-600 hover:text-zinc-100";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy || disabled}
      className={`inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${classes}`}
    >
      {busy && <Loader2 className="h-3 w-3 animate-spin" />}
      {label}
    </button>
  );
}

function DetailStat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
      <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={`mt-2 text-sm font-medium text-zinc-100 ${accent ?? ""}`}>{value}</div>
    </div>
  );
}

function ContextCard({
  icon: Icon,
  title,
  items,
  detail,
}: {
  icon: typeof Radar;
  title: string;
  items: Array<string | null | undefined>;
  detail: ReactNode;
}) {
  const visibleItems = items.filter(Boolean) as string[];
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
      <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-zinc-500">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {visibleItems.length > 0 && (
        <ul className="mt-3 space-y-1 text-xs text-zinc-300">
          {visibleItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
      <div className="mt-3 space-y-2">{detail}</div>
    </div>
  );
}

function TagList({ label, values, mono = false }: { label: string; values: string[]; mono?: boolean }) {
  if (values.length === 0) {
    return null;
  }
  return (
    <div className="space-y-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {values.map((value) => (
          <span
            key={`${label}:${value}`}
            className={`rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-300 ${mono ? "font-mono" : ""}`}
          >
            {value}
          </span>
        ))}
      </div>
    </div>
  );
}

function CodeLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="mt-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</div>
      <code className="mt-1 block overflow-x-auto rounded bg-black/30 px-2 py-1.5 text-[11px] text-emerald-300">
        {value}
      </code>
    </div>
  );
}
