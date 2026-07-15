"use client";

import Link from "next/link";
import { useState, type ReactNode } from "react";
import { ChevronRight, ExternalLink, FileSearch, Loader2, Radar, ShieldAlert } from "lucide-react";

import { severityColor, type FindingTriageDecision, type FindingTriageItem, type FindingTriageJustification } from "@/lib/api";
import { buildWhyItMatters } from "@/lib/finding-why-matters";
import { Drawer } from "@/components/drawer";
import {
  findingsDrawerEyebrow,
  findingsDrawerSubtitle,
  findingsTriageDetail,
  findingsTriageTitle,
  type FindingsLens,
} from "@/lib/findings-lens";
import { type EnrichedVuln, uniqueStrings, formatFindingTimestamp, findingStatusClass, findingStatusLabel } from "@/lib/findings-view";

type TabKey = "overview" | "path" | "evidence" | "triage";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "path", label: "Exposure path" },
  { key: "evidence", label: "Evidence" },
  { key: "triage", label: "Triage" },
];

export function FindingDrawer({
  vuln,
  triage,
  triageBusy,
  onTriageDecision,
  onClose,
  lens = "ops",
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
  lens?: FindingsLens | undefined;
}) {
  const [tab, setTab] = useState<TabKey>("overview");

  return (
    <Drawer
      open
      onClose={onClose}
      size="5xl"
      ariaLabel={`Finding details for ${vuln.id}`}
      eyebrow={findingsDrawerEyebrow(lens)}
      title={<span className="break-all font-mono">{vuln.id}</span>}
      subtitle={findingsDrawerSubtitle(lens)}
      headerAside={
        <span className={`rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 text-xs font-medium uppercase tracking-wide ${severityColor(vuln.severity)}`}>
          {vuln.severity}
        </span>
      }
    >
      <div className="mb-4 flex flex-wrap gap-1 border-b border-[color:var(--border-subtle)]">
        {TABS.map((entry) => {
          const active = tab === entry.key;
          return (
            <button
              key={entry.key}
              type="button"
              onClick={() => setTab(entry.key)}
              className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
                active
                  ? "border-emerald-500 text-[color:var(--foreground)]"
                  : "border-transparent text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
              }`}
            >
              {entry.label}
              {entry.key === "triage" && triage ? (
                <span className="ml-1.5 rounded-full bg-[color:var(--surface-muted)] px-1.5 py-0.5 text-[10px] text-[color:var(--text-secondary)]">
                  {triage.queue_state}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      {tab === "overview" ? <OverviewTab vuln={vuln} /> : null}
      {tab === "path" ? <PathTab vuln={vuln} /> : null}
      {tab === "evidence" ? <EvidenceTab vuln={vuln} /> : null}
      {tab === "triage" ? (
        <TriageTab
          vuln={vuln}
          triage={triage}
          triageBusy={triageBusy}
          onTriageDecision={onTriageDecision}
          lens={lens}
        />
      ) : null}
    </Drawer>
  );
}

// ── Overview ──────────────────────────────────────────────────────────────────

function OverviewTab({ vuln }: { vuln: EnrichedVuln }) {
  const summary = vuln.attack_vector_summary ?? vuln.summary ?? vuln.description ?? "No advisory summary available.";
  const cweMatches = [...new Set(summary.match(/CWE-\d+/gi) ?? [])];
  const whyItMatters = buildWhyItMatters(vuln);
  const published = vuln.published_at ?? vuln.published ?? vuln.nvd_published;
  const fixCandidates = vuln.remediation_items.filter((item) => item.fixed_version || item.command || item.verify_command);

  // Severity is already the header badge — the stat row leads with exploit
  // signal (CVSS / EPSS) plus one KEV-or-risk tile, never re-showing severity.
  const stats: { label: string; value: string }[] = [
    { label: "CVSS", value: typeof vuln.cvss_score === "number" ? vuln.cvss_score.toFixed(1) : "Not published" },
    { label: "EPSS", value: typeof vuln.epss_score === "number" ? `${(vuln.epss_score * 100).toFixed(1)}%` : "Not available" },
  ];
  if (vuln.is_kev) stats.push({ label: "KEV", value: "Known-exploited" });
  else if (typeof vuln.risk_score === "number") stats.push({ label: "Risk", value: vuln.risk_score.toFixed(1) });

  return (
    <div className="space-y-3">
      <div className={`grid gap-2 ${stats.length >= 3 ? "sm:grid-cols-3" : "sm:grid-cols-2"}`}>
        {stats.map((stat) => (
          <DetailStat key={stat.label} label={stat.label} value={stat.value} />
        ))}
      </div>

      <ReachBadges vuln={vuln} />

      <Section title="Attack summary">
        <p className="text-sm leading-6 text-[color:var(--text-secondary)]">{summary}</p>
        {cweMatches.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1">
            {cweMatches.map((cwe) => (
              <Chip key={cwe} mono>{cwe}</Chip>
            ))}
          </div>
        ) : null}
      </Section>

      {whyItMatters ? (
        <Section title="Why it matters" accent>
          <p className="text-sm font-medium text-[color:var(--foreground)]">{whyItMatters.headline}</p>
          {whyItMatters.paragraphs.length > 0 ? (
            <div className="mt-1.5 space-y-1.5 text-sm leading-6 text-[color:var(--text-secondary)]">
              {whyItMatters.paragraphs.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </div>
          ) : null}
          {whyItMatters.complianceTags.length > 0 ? (
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-medium text-[color:var(--text-tertiary)]">
                {whyItMatters.complianceTags.length} compliance control{whyItMatters.complianceTags.length === 1 ? "" : "s"}
              </span>
              {whyItMatters.complianceTags.slice(0, 3).map((tag) => (
                <Chip key={tag} mono>{tag}</Chip>
              ))}
              {whyItMatters.complianceTags.length > 3 ? (
                <span className="text-[11px] text-[color:var(--text-tertiary)]">
                  +{whyItMatters.complianceTags.length - 3} more
                </span>
              ) : null}
              <Link href="/compliance" className="text-xs text-[color:var(--accent-mint)] hover:underline">
                View evidence
              </Link>
            </div>
          ) : null}
          {whyItMatters.links.length > 0 ? (
            <div className="mt-2.5 flex flex-wrap gap-3">
              {whyItMatters.links.map((link) => (
                <Link key={link.href} href={link.href} className="text-xs text-[color:var(--accent-mint)] hover:underline">
                  {link.label}
                </Link>
              ))}
            </div>
          ) : null}
        </Section>
      ) : null}

      <Section title="Fix context">
        <div className="grid gap-x-4 gap-y-1.5 text-sm text-[color:var(--text-secondary)] sm:grid-cols-2">
          <KeyVal label="Fix" value={vuln.fixed_version ?? "No published fix"} />
          {published ? <KeyVal label="Published" value={new Date(published).toLocaleDateString()} /> : null}
          {vuln.modified_at ? <KeyVal label="Modified" value={new Date(vuln.modified_at).toLocaleDateString()} /> : null}
          {typeof vuln.confidence === "number" ? <KeyVal label="Confidence" value={`${(vuln.confidence * 100).toFixed(0)}%`} /> : null}
          {vuln.severity_source ? <KeyVal label="Severity source" value={vuln.severity_source} /> : null}
        </div>
        {fixCandidates.length > 0 ? (
          <div className="mt-3 divide-y divide-[color:var(--border-subtle)] overflow-hidden rounded-lg border border-[color:var(--border-subtle)]">
            {fixCandidates.slice(0, 2).map((item) => (
              <div key={`${item.package}:${item.current_version}`} className="p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-[color:var(--foreground)]">{item.package}</span>
                  <span className="font-mono text-[11px] text-[color:var(--accent-mint)]">
                    {item.current_version} → {item.fixed_version ?? "monitor"}
                  </span>
                </div>
                {item.action ? <p className="mt-1.5 text-xs text-[color:var(--text-tertiary)]">{item.action}</p> : null}
                {item.command ? <CodeLine label="Apply" value={item.command} /> : null}
                {item.verify_command ? <CodeLine label="Verify" value={item.verify_command} /> : null}
              </div>
            ))}
          </div>
        ) : null}
        {vuln.remediation_items[0]?.risk_narrative ? (
          <p className="mt-3 text-xs leading-5 text-[color:var(--text-tertiary)]">{vuln.remediation_items[0].risk_narrative}</p>
        ) : null}
      </Section>
    </div>
  );
}

// Flat section with a subtle top divider (and an optional left accent) — used
// in the Overview tab so related content reads as tighter sections instead of
// chunky cards-within-cards.
function Section({
  title,
  children,
  accent = false,
}: {
  title: string;
  children: ReactNode;
  accent?: boolean;
}) {
  return (
    <section
      className={`border-t border-[color:var(--border-subtle)] pt-3 ${
        accent ? "border-l-2 border-l-[color:var(--accent-mint)] pl-3" : ""
      }`}
    >
      <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[color:var(--text-tertiary)]">{title}</h4>
      <div className="mt-2">{children}</div>
    </section>
  );
}

// ── Exposure path (the visual) ────────────────────────────────────────────────

const PATH_META: Record<string, { dot: string; ring: string }> = {
  cve: { dot: "bg-red-500", ring: "border-red-500/40" },
  package: { dot: "bg-violet-500", ring: "border-violet-500/40" },
  server: { dot: "bg-sky-500", ring: "border-sky-500/40" },
  agent: { dot: "bg-emerald-500", ring: "border-emerald-500/40" },
  credential: { dot: "bg-amber-500", ring: "border-amber-500/40" },
};

function PathTab({ vuln }: { vuln: EnrichedVuln }) {
  const stages = [
    { type: "cve", label: "CVE", items: [vuln.id] },
    { type: "package", label: "Package", items: vuln.packages },
    { type: "server", label: "MCP / runtime", items: vuln.affected_servers },
    { type: "agent", label: "Agent", items: vuln.agents },
    {
      type: "credential",
      label: "Credential / tool",
      items: uniqueStrings([...vuln.exposed_credentials, ...vuln.reachable_tools]),
    },
  ].filter((stage) => stage.items.length > 0);

  return (
    <div className="space-y-4">
      <ReachBadges vuln={vuln} />

      <Panel title="Correlated exposure path">
        {stages.length > 1 ? (
          <div className="flex flex-wrap items-stretch gap-2">
            {stages.map((stage, index) => (
              <div key={stage.type} className="flex items-stretch gap-2">
                {index > 0 ? (
                  <div className="flex items-center text-[color:var(--text-tertiary)]">
                    <ChevronRight className="h-4 w-4" />
                  </div>
                ) : null}
                <div className={`min-w-[8.5rem] max-w-[13rem] rounded-xl border ${PATH_META[stage.type]?.ring ?? "border-[color:var(--border-subtle)]"} bg-[color:var(--surface-muted)] p-2.5`}>
                  <div className="flex items-center gap-1.5">
                    <span className={`h-1.5 w-1.5 rounded-full ${PATH_META[stage.type]?.dot ?? "bg-[color:var(--text-tertiary)]"}`} />
                    <span className="text-[10px] font-semibold uppercase tracking-wide text-[color:var(--text-tertiary)]">
                      {stage.label}
                    </span>
                    {stage.items.length > 1 ? (
                      <span className="ml-auto text-[10px] text-[color:var(--text-tertiary)]">{stage.items.length}</span>
                    ) : null}
                  </div>
                  <div className="mt-1.5 space-y-1">
                    {stage.items.slice(0, 4).map((item) => (
                      <p key={item} className="truncate font-mono text-[11px] text-[color:var(--text-secondary)]" title={item}>
                        {item}
                      </p>
                    ))}
                    {stage.items.length > 4 ? (
                      <p className="text-[10px] text-[color:var(--text-tertiary)]">+{stage.items.length - 4} more</p>
                    ) : null}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-[color:var(--text-secondary)]">
            No correlated blast-radius path recorded for this finding yet.
          </p>
        )}
        <Link
          href={`/security-graph?focus=${encodeURIComponent(vuln.id)}`}
          className="mt-3 inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
        >
          Open in security graph <ChevronRight className="h-3 w-3" />
        </Link>
      </Panel>

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
              {vuln.phantom_tools && vuln.phantom_tools.length > 0 ? (
                <TagList label="Registry-only tools" values={vuln.phantom_tools} mono />
              ) : null}
            </>
          }
        />
      </div>
    </div>
  );
}

// ── Evidence ──────────────────────────────────────────────────────────────────

function EvidenceTab({ vuln }: { vuln: EnrichedVuln }) {
  const references = uniqueStrings(vuln.references).slice(0, 6);
  const investigationSources = uniqueStrings([...vuln.sources, ...vuln.advisory_sources]);
  const hasLifecycle =
    Boolean(vuln.lifecycle_status?.trim()) ||
    Boolean(vuln.first_seen?.trim()) ||
    Boolean(vuln.last_seen?.trim()) ||
    Boolean(vuln.resolved_at?.trim()) ||
    Boolean(vuln.reopened_at?.trim()) ||
    typeof vuln.scan_count === "number";

  return (
    <div className="space-y-4">
      <Panel title="Investigation sources">
        <div className="space-y-3">
          <TagList label="Signals" values={investigationSources} />
          <TagList label="Aliases" values={vuln.aliases ?? []} mono />
          {references.length > 0 ? (
            <div className="space-y-2">
              <div className="text-[11px] font-medium uppercase tracking-wide text-[color:var(--text-tertiary)]">Advisories</div>
              <div className="flex flex-col gap-2">
                {references.map((ref) => (
                  <a
                    key={ref}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                  >
                    <FileSearch className="h-3.5 w-3.5 text-[color:var(--text-tertiary)]" />
                    <span className="truncate">{ref}</span>
                    <ExternalLink className="ml-auto h-3 w-3 shrink-0" />
                  </a>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </Panel>

      {vuln.framework_tags && vuln.framework_tags.length > 0 ? (
        <Panel title="Compliance controls">
          <div className="flex flex-wrap gap-1">
            {vuln.framework_tags.slice(0, 24).map((tag) => (
              <Chip key={tag} mono>{tag}</Chip>
            ))}
          </div>
        </Panel>
      ) : null}

      {hasLifecycle ? (
        <Panel title="Lifecycle">
          <div className="space-y-2 text-sm text-[color:var(--text-secondary)]">
            {vuln.lifecycle_status ? (
              <div className="flex items-center gap-2">
                <span className="text-[color:var(--text-tertiary)]">Status:</span>
                <span className={`rounded border px-2 py-0.5 text-xs font-medium ${findingStatusClass(vuln.lifecycle_status)}`}>
                  {findingStatusLabel(vuln.lifecycle_status)}
                </span>
              </div>
            ) : null}
            {vuln.first_seen ? <KeyVal label="First seen" value={formatFindingTimestamp(vuln.first_seen)} /> : null}
            {vuln.last_seen ? <KeyVal label="Last seen" value={formatFindingTimestamp(vuln.last_seen)} /> : null}
            {vuln.resolved_at ? <KeyVal label="Resolved" value={formatFindingTimestamp(vuln.resolved_at)} /> : null}
            {vuln.reopened_at ? <KeyVal label="Reopened" value={formatFindingTimestamp(vuln.reopened_at)} /> : null}
            {typeof vuln.scan_count === "number" ? <KeyVal label="Scan count" value={String(vuln.scan_count)} /> : null}
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

// ── Triage ────────────────────────────────────────────────────────────────────

function TriageTab({
  vuln,
  triage,
  triageBusy,
  onTriageDecision,
  lens,
}: {
  vuln: EnrichedVuln;
  triage: FindingTriageItem | undefined;
  triageBusy: boolean;
  onTriageDecision: (
    vuln: EnrichedVuln,
    decision: FindingTriageDecision,
    justification?: FindingTriageJustification,
  ) => void;
  lens: FindingsLens;
}) {
  return (
    <div className="space-y-4">
      <Panel title={findingsTriageTitle(lens)}>
        <p className="text-xs leading-5 text-[color:var(--text-tertiary)]">{findingsTriageDetail(lens)}</p>
        {triage ? (
          <div className="mt-3 grid gap-2 text-xs text-[color:var(--text-secondary)] sm:grid-cols-2">
            <KeyVal label="Decision" value={triage.decision} />
            <KeyVal label="Assignee" value={triage.assignee || "unassigned"} />
            {triage.justification ? (
              <div className="sm:col-span-2">
                <KeyVal label="Justification" value={triage.justification} />
              </div>
            ) : null}
            {triage.decision_reason ? (
              <div className="sm:col-span-2">
                <KeyVal label="Reason" value={triage.decision_reason} />
              </div>
            ) : null}
          </div>
        ) : (
          <p className="mt-3 text-xs text-[color:var(--text-tertiary)]">No triage item recorded for this finding/package pair.</p>
        )}
        <div className="mt-4 flex flex-wrap gap-2">
          <TriageButton label="Investigate" busy={triageBusy} disabled={Boolean(triage)} onClick={() => onTriageDecision(vuln, "under_investigation")} />
          <TriageButton label="Affected" busy={triageBusy} onClick={() => onTriageDecision(vuln, "affected")} />
          <TriageButton label="Not affected" busy={triageBusy} tone="green" onClick={() => onTriageDecision(vuln, "not_affected", "vulnerable_code_not_in_execute_path")} />
        </div>
      </Panel>

      <div className="flex flex-wrap gap-2">
        <a
          href={`https://osv.dev/vulnerability/${vuln.id}`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
        >
          Open on OSV <ExternalLink className="h-3 w-3" />
        </a>
        <Link
          href={`/findings?cve=${vuln.id}`}
          className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 dark:border-emerald-800 bg-emerald-500/10 dark:bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-300 transition-colors hover:bg-emerald-500/10 dark:hover:bg-emerald-950/70"
        >
          Keep this CVE scoped
        </Link>
      </div>
    </div>
  );
}

// ── Shared bits ───────────────────────────────────────────────────────────────

function ReachBadges({ vuln }: { vuln: EnrichedVuln }) {
  if (!vuln.effective_reach_band && !vuln.runtime_evidence?.state) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {vuln.effective_reach_band ? (
        <span className="rounded border border-amber-500/30 dark:border-amber-800/60 bg-amber-500/10 dark:bg-amber-950/40 px-2 py-0.5 text-xs font-medium uppercase tracking-wide text-amber-700 dark:text-amber-300">
          Reach {vuln.effective_reach_band}
          {typeof vuln.effective_reach_score === "number" ? ` (${vuln.effective_reach_score.toFixed(0)})` : ""}
        </span>
      ) : null}
      {vuln.runtime_evidence?.state && vuln.runtime_evidence.state !== "static" ? (
        <span
          className={`rounded border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${
            vuln.runtime_evidence.state === "blocked"
              ? "border-rose-500/30 dark:border-rose-800/60 bg-rose-500/10 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300"
              : "border-sky-500/30 dark:border-sky-800/60 bg-sky-500/10 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300"
          }`}
        >
          Runtime {vuln.runtime_evidence.state}
        </span>
      ) : null}
      {vuln.runtime_evidence?.state === "blocked" ? (
        <Link href="/traces" className="text-xs text-emerald-300 hover:underline">
          Open trace explorer
        </Link>
      ) : null}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
      <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[color:var(--text-tertiary)]">{title}</h4>
      <div className="mt-2.5">{children}</div>
    </div>
  );
}

function KeyVal({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-[color:var(--text-tertiary)]">{label}:</span> {value}
    </div>
  );
}

function Chip({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return (
    <span className={`rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[11px] text-[color:var(--text-secondary)] ${mono ? "font-mono" : ""}`}>
      {children}
    </span>
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
      ? "border-emerald-500/30 dark:border-emerald-800 bg-emerald-500/10 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 dark:hover:bg-emerald-950/70"
      : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy || disabled}
      className={`inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${classes}`}
    >
      {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
      {label}
    </button>
  );
}

function DetailStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-2.5">
      <div className="text-[11px] font-medium uppercase tracking-wide text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1.5 text-sm font-semibold text-[color:var(--foreground)]">{value}</div>
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
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
      <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-[color:var(--text-tertiary)]">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {visibleItems.length > 0 ? (
        <ul className="mt-3 space-y-1 text-xs text-[color:var(--text-secondary)]">
          {visibleItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : null}
      <div className="mt-3 space-y-2">{detail}</div>
    </div>
  );
}

function TagList({ label, values, mono = false }: { label: string; values: string[]; mono?: boolean }) {
  if (values.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-[color:var(--text-tertiary)]">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {values.map((value) => (
          <Chip key={`${label}:${value}`} mono={mono}>{value}</Chip>
        ))}
      </div>
    </div>
  );
}

function CodeLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="mt-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-[color:var(--text-tertiary)]">{label}</div>
      <code className="mt-1 block overflow-x-auto rounded bg-[color:var(--surface)] px-2 py-1.5 text-[11px] text-[color:var(--foreground)]">{value}</code>
    </div>
  );
}
