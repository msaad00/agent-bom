"use client";

import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";
import { ExternalLink, FileSearch, Loader2 } from "lucide-react";

import { severityColor, type FindingTriageDecision, type FindingTriageItem, type FindingTriageJustification } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
import { remediationHref } from "@/lib/page-links";
import { buildWhyItMatters } from "@/lib/finding-why-matters";
import { Drawer } from "@/components/drawer";
import { DetailTabs } from "@/components/detail-tabs";
import {
  findingsDrawerEyebrow,
  findingsDrawerSubtitle,
  findingsTriageDetail,
  findingsTriageTitle,
  type FindingsLens,
} from "@/lib/findings-lens";
import {
  type EnrichedVuln,
  uniqueStrings,
  findingWorkloadScope,
  sbomSourceName,
  formatFindingTimestamp,
  findingStatusLabel,
  cvssVersion,
  officialAdvisoryLinks,
} from "@/lib/findings-view";

type TabKey = "overview" | "evidence" | "triage";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
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
  const { hasCapability } = useAuthState();
  const canManageExceptions = hasCapability("exceptions.manage");
  const [tab, setTab] = useState<TabKey>(lens === "trust" ? "evidence" : "overview");

  useEffect(() => {
    setTab(lens === "trust" ? "evidence" : "overview");
  }, [lens, vuln.finding_id, vuln.id]);

  return (
    <Drawer
      open
      onClose={onClose}
      size="2xl"
      ariaLabel={`Finding details for ${vuln.id}`}
      eyebrow={findingsDrawerEyebrow(lens)}
      title={<span className="break-all font-mono">{vuln.id}</span>}
      subtitle={findingsDrawerSubtitle(lens)}
      headerAside={
        <span className={`rounded-full border border-outline bg-surface-muted px-2.5 py-1 text-xs font-medium uppercase tracking-wide ${severityColor(vuln.severity)}`}>
          {vuln.severity}
        </span>
      }
    >
      <DetailTabs
        tabs={TABS.map((entry) => ({
          ...entry,
          ...(entry.key === "triage" && triage ? { badge: triage.queue_state } : {}),
        }))}
        value={tab}
        onChange={setTab}
        ariaLabel="Finding detail views"
      />

      {tab === "overview" ? <OverviewTab vuln={vuln} /> : null}
      {tab === "evidence" ? <EvidenceTab vuln={vuln} /> : null}
      {tab === "triage" ? (
        <TriageTab
          vuln={vuln}
          triage={triage}
          triageBusy={triageBusy}
          onTriageDecision={onTriageDecision}
          lens={lens}
          canTriage={canManageExceptions}
        />
      ) : null}
    </Drawer>
  );
}

// ── Overview ──────────────────────────────────────────────────────────────────

function OverviewTab({ vuln }: { vuln: EnrichedVuln }) {
  const scope = findingWorkloadScope(vuln);
  const summary = vuln.attack_vector_summary ?? vuln.summary ?? vuln.description ?? "No advisory summary available.";
  const fixCandidates = vuln.remediation_items.filter((item) => item.fixed_version || item.command || item.verify_command);
  const packageLabel = vuln.packages.join(", ") || "Affected asset";
  const fixValue = vuln.current_version && vuln.fixed_version
    ? `${vuln.current_version} → ${vuln.fixed_version}`
    : vuln.fixed_version ? `Upgrade to ${vuln.fixed_version}` : null;
  const impact = [
    scope.agents.length ? `${scope.agents.length} agent${scope.agents.length === 1 ? "" : "s"}` : null,
    scope.servers.length ? `${scope.servers.length} MCP server${scope.servers.length === 1 ? "" : "s"}` : null,
    vuln.exposed_credentials.length ? `${vuln.exposed_credentials.length} credential reference${vuln.exposed_credentials.length === 1 ? "" : "s"}` : null,
    vuln.reachable_tools.length ? `${vuln.reachable_tools.length} linked tool${vuln.reachable_tools.length === 1 ? "" : "s"}` : null,
  ].filter(Boolean);

  return (
    <div className="space-y-4">
      <div>
        <p className="break-words text-base font-semibold text-foreground">{packageLabel}</p>
        <p className="mt-1 text-sm leading-6 text-ink-secondary">{summary}</p>
      </div>

      <Section title="Next action" accent>
        <p className="text-sm font-medium text-foreground">
          {fixValue ?? "Review the evidence and determine the appropriate fix."}
        </p>
        {fixValue ? <p className="mt-1 text-xs text-ink-secondary">Apply the fix, then rescan the affected asset to verify the result.</p> : null}
        <div className="mt-3 flex flex-wrap gap-3">
          {fixValue || fixCandidates.length ? (
            <Link href={remediationHref({ q: vuln.id })} className="rounded-lg bg-accent-mint px-3 py-2 text-sm font-medium text-black">
              Review remediation
            </Link>
          ) : null}
          <Link href={buildFindingInvestigationHref(vuln)} data-testid="finding-investigate-estate" className="inline-flex items-center gap-1.5 py-2 text-sm font-medium text-accent-mint hover:underline">
            Open in investigation <ExternalLink className="h-3.5 w-3.5" />
          </Link>
        </div>
      </Section>

      {impact.length || scope.sbomSources.length ? (
        <Section title="Affected scope">
          {scope.sbomSources.length > 0 && scope.agents.length === 0 && scope.servers.length === 0 ? <p className="text-sm text-ink-secondary">SBOM evidence; workload not identified</p> : null}
          {impact.length ? <p className="text-sm text-ink-secondary">{impact.join(" · ")}</p> : null}
          {scope.sbomSources.map((source) => <p key={source} className="mt-1 break-words text-xs text-ink-secondary">SBOM source: {sbomSourceName(source)}</p>)}
        </Section>
      ) : null}

      {fixCandidates.length > 0 ? (
        <details className="border-t border-outline pt-3">
          <summary className="cursor-pointer text-sm font-medium text-foreground">Apply and verify commands</summary>
          <div className="mt-3 space-y-4">
            {fixCandidates.map((item) => (
              <div key={`${item.package}:${item.current_version}`}>
                <p className="text-sm font-medium text-foreground">{item.package} · {item.current_version} → {item.fixed_version ?? "fix version unavailable"}</p>
                {item.action ? <p className="mt-1 text-xs text-ink-secondary">{item.action}</p> : null}
                {item.command ? <CodeLine label="Apply" value={item.command} /> : null}
                {item.verify_command ? <CodeLine label="Verify" value={item.verify_command} /> : null}
              </div>
            ))}
          </div>
        </details>
      ) : null}
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
      className={`border-t border-outline pt-3 ${
        accent ? "border-l-2 border-l-[color:var(--accent-mint)] pl-3" : ""
      }`}
    >
      <h4 className="text-[11px] font-semibold uppercase tracking-wide text-ink-tertiary">{title}</h4>
      <div className="mt-2">{children}</div>
    </section>
  );
}

/** Typed estate node → evidence: primary investigation entry from a finding. */
function EstateNodeSection({ vuln }: { vuln: EnrichedVuln }) {
  const href = buildFindingInvestigationHref(vuln);
  const entityType = vuln.entity_type || vuln.asset_type || "asset";
  const estateLabel = vuln.node_id || vuln.packages[0] || vuln.agents[0] || "estate node";
  const findingNode = vuln.finding_node_id;

  return (
    <Section title="Estate node" accent>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
        <Chip mono>{entityType}</Chip>
        {vuln.node_id ? <Chip mono>{vuln.node_id}</Chip> : <Chip>{estateLabel}</Chip>}
        {findingNode ? <Chip mono>{findingNode}</Chip> : null}
        {vuln.finding_id ? (
          <span className="font-mono text-[10px] text-ink-tertiary">finding {vuln.finding_id}</span>
        ) : null}
      </div>
      <div className="mt-3">
        <Link
          href={href}
          className="inline-flex items-center gap-1.5 text-sm font-medium text-accent-mint hover:underline"
          data-testid="finding-investigate-estate"
        >
          Open in investigation
          <ExternalLink className="h-3.5 w-3.5" />
        </Link>
      </div>
    </Section>
  );
}

// ── Evidence ──────────────────────────────────────────────────────────────────

function EvidenceTab({ vuln }: { vuln: EnrichedVuln }) {
  const scope = findingWorkloadScope(vuln);
  const references = officialAdvisoryLinks(vuln.references);
  const whyItMatters = buildWhyItMatters(vuln);
  const cweIds = uniqueStrings(vuln.cwe_ids ?? []);
  const investigationSources = uniqueStrings([...vuln.sources, ...vuln.advisory_sources]);
  const complianceControls = uniqueStrings([
    ...(vuln.framework_tags ?? []),
    ...(vuln.controls ?? []).map(controlLabel),
  ]);

  return (
    <div className="space-y-4">
      <EstateNodeSection vuln={vuln} />
      <IntelligencePanel vuln={vuln} />
      <ReachBadges vuln={vuln} />
      <Panel title="Affected scope">
        <TagList label="Packages" values={vuln.packages} />
        <TagList label="Agents" values={scope.agents} />
        <TagList label="MCP servers" values={scope.servers} />
        <TagList label="SBOM sources" values={scope.sbomSources} />
        <TagList label="Credential references" values={vuln.exposed_credentials} />
        <TagList label="Linked tools" values={vuln.reachable_tools} />
        {whyItMatters ? <div className="mt-3 space-y-2 text-xs leading-5 text-ink-secondary">
          {whyItMatters.paragraphs.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
          {whyItMatters.links.map((link) => <Link key={link.href} href={link.href} className="mr-3 inline-block text-accent-mint hover:underline">{link.label}</Link>)}
        </div> : null}
      </Panel>
      <Panel title="Investigation sources">
        <div className="space-y-3">
          <TagList label="Signals" values={investigationSources} />
          <TagList label="Aliases" values={vuln.aliases ?? []} mono />
          <TagList label="Weaknesses" values={cweIds} mono />
          {references.length > 0 ? (
            <div className="space-y-2">
              <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">Advisories</div>
              <div className="flex flex-col gap-2">
                {references.map((ref) => (
                  <a
                    key={ref.href}
                    href={ref.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-2 text-xs text-ink-secondary transition-colors hover:border-outline-strong hover:text-foreground"
                  >
                    <FileSearch className="h-3.5 w-3.5 text-ink-tertiary" />
                    <span className="font-medium text-foreground">{ref.label}</span>
                    <span className="truncate text-ink-tertiary">{ref.href}</span>
                    <ExternalLink className="ml-auto h-3 w-3 shrink-0" />
                  </a>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </Panel>

      <Panel title="Provenance">
        <div className="grid gap-x-5 gap-y-1.5 text-xs text-ink-secondary sm:grid-cols-2">
          <KeyVal label="Finding sources" value={investigationSources.join(", ") || "Unavailable"} />
          <KeyVal label="Scan" value={vuln.scan_id ?? "Unavailable"} />
          <KeyVal label="Evidence provenance" value={formatProvenance(vuln.provenance)} />
          <KeyVal label="Match confidence" value={vuln.match_confidence_tier ?? "Unavailable"} />
          <KeyVal
            label="Data confidence"
            value={typeof vuln.confidence === "number" ? `${(vuln.confidence * 100).toFixed(0)}%` : "Unavailable"}
          />
        </div>
      </Panel>

      {complianceControls.length > 0 ? (
        <Panel title="Compliance controls">
          <details>
            <summary className="cursor-pointer text-sm text-ink-secondary">View {complianceControls.length} mapped controls</summary>
            <div className="mt-3 flex flex-wrap gap-1">
              {complianceControls.map((tag) => <Chip key={tag} mono>{tag}</Chip>)}
            </div>
          </details>
        </Panel>
      ) : null}

      {vuln.first_seen || vuln.last_observed || vuln.last_seen || vuln.resolved_at || vuln.reopened_at || typeof vuln.occurrence_count === "number" || typeof vuln.scan_count === "number" ? (
        <Panel title="Lifecycle">
          <div className="space-y-2 text-sm text-ink-secondary">
            {vuln.first_seen ? <KeyVal label="First seen" value={formatFindingTimestamp(vuln.first_seen)} /> : null}
            {vuln.last_observed || vuln.last_seen ? <KeyVal label="Last observed" value={formatFindingTimestamp(vuln.last_observed ?? vuln.last_seen)} /> : null}
            {vuln.resolved_at ? <KeyVal label="Resolved" value={formatFindingTimestamp(vuln.resolved_at)} /> : null}
            {vuln.reopened_at ? <KeyVal label="Reopened" value={formatFindingTimestamp(vuln.reopened_at)} /> : null}
            {typeof (vuln.occurrence_count ?? vuln.scan_count) === "number" ? <KeyVal label="Observed occurrences" value={String(vuln.occurrence_count ?? vuln.scan_count)} /> : null}
          </div>
        </Panel>
      ) : null}

      {vuln.remediation_items.some((item) => item.risk_narrative) ? <Panel title="Remediation context">
        {vuln.remediation_items.filter((item) => item.risk_narrative).map((item) => <p key={`${item.package}:${item.current_version}`} className="text-sm leading-6 text-ink-secondary">{item.risk_narrative}</p>)}
      </Panel> : null}
      <WorkloadRuntimeEvidencePanel evidence={vuln.workload_runtime_evidence} />
    </div>
  );
}

function WorkloadRuntimeEvidencePanel({
  evidence,
}: {
  evidence: EnrichedVuln["workload_runtime_evidence"];
}) {
  if (!evidence?.state) return null;
  const state = evidence.state;
  const label =
    state === "runtime_ioc_observed"
      ? "IOC observed"
      : state === "runtime_alert_observed"
        ? "Alert observed"
        : state === "runtime_activity_observed"
          ? "Activity observed"
          : state === "no_runtime_signal"
            ? "No runtime signal"
            : state.replaceAll("_", " ");
  const tone =
    state === "runtime_ioc_observed"
      ? "border-rose-500/30 dark:border-rose-800/60 bg-rose-500/10 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300"
      : state === "runtime_alert_observed"
        ? "border-amber-500/30 dark:border-amber-800/60 bg-amber-500/10 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300"
        : state === "runtime_activity_observed"
          ? "border-sky-500/30 dark:border-sky-800/60 bg-sky-500/10 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300"
          : "border-outline bg-surface text-ink-secondary";
  const sourceKinds = Array.isArray(evidence.source_kinds) ? evidence.source_kinds.filter(Boolean) : [];
  return (
    <Panel title="Workload runtime evidence">
      <div className="space-y-3 text-sm text-ink-secondary">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${tone}`}>
            {label}
          </span>
          {typeof evidence.signal_count === "number" ? (
            <span className="text-xs text-ink-tertiary">{evidence.signal_count} signal{evidence.signal_count === 1 ? "" : "s"}</span>
          ) : null}
        </div>
        {evidence.latest_observed_at ? (
          <KeyVal label="Latest observed" value={formatFindingTimestamp(evidence.latest_observed_at)} />
        ) : null}
        {sourceKinds.length > 0 ? <TagList label="Sources" values={sourceKinds} /> : null}
        <p className="text-xs leading-5 text-ink-tertiary">
          Additive CWPP/EDR metadata only — absence of a signal is not a clean-workload assertion
          {evidence.clean_workload_assertion === false ? " (clean_workload_assertion: false)" : ""}.
          Distinct from proxy/gateway runtime evidence on the Overview reach badges.
        </p>
      </div>
    </Panel>
  );
}

// ── Triage ────────────────────────────────────────────────────────────────────

function TriageTab({
  vuln,
  triage,
  triageBusy,
  onTriageDecision,
  lens,
  canTriage,
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
  canTriage: boolean;
}) {
  return (
    <div className="space-y-4">
      <Panel title={findingsTriageTitle(lens)}>
        <p className="text-xs leading-5 text-ink-tertiary">{findingsTriageDetail(lens)}</p>
        <div className="mt-3 space-y-1.5 text-xs text-ink-secondary">
          {vuln.lifecycle_status ? <KeyVal label="Status" value={findingStatusLabel(vuln.lifecycle_status)} /> : null}
          {vuln.owner ? <KeyVal label="Owner" value={vuln.owner} /> : null}
          {vuln.sla_due_at ? <KeyVal label="SLA" value={formatFindingTimestamp(vuln.sla_due_at)} /> : null}
        </div>
        {triage ? (
          <div className="mt-3 grid gap-2 text-xs text-ink-secondary sm:grid-cols-2">
            <KeyVal label="Queue state" value={triage.queue_state} />
            <KeyVal label="Decision" value={triage.decision} />
            <KeyVal label="Assignee" value={triage.assignee || "unassigned"} />
            <KeyVal label="Created" value={formatFindingTimestamp(triage.created_at)} />
            <KeyVal label="Reviewed" value={triage.reviewed_at ? formatFindingTimestamp(triage.reviewed_at) : "Unavailable"} />
            <KeyVal label="Expires" value={triage.expires_at ? formatFindingTimestamp(triage.expires_at) : "Unavailable"} />
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
          <p className="mt-3 text-xs text-ink-tertiary">No triage item recorded for this finding/package pair.</p>
        )}
        <div className="mt-4 flex flex-wrap gap-2">
          <TriageButton label="Investigate" busy={triageBusy} disabled={!canTriage || Boolean(triage)} onClick={() => onTriageDecision(vuln, "under_investigation")} />
          <TriageButton label="Affected" busy={triageBusy} disabled={!canTriage} onClick={() => onTriageDecision(vuln, "affected")} />
          <TriageButton label="Not affected" busy={triageBusy} disabled={!canTriage} tone="green" onClick={() => onTriageDecision(vuln, "not_affected", "vulnerable_code_not_in_execute_path")} />
        </div>
        {!canTriage ? (
          <p className="mt-2 text-xs text-ink-tertiary">Contributor role required to update triage.</p>
        ) : null}
      </Panel>

      <div className="flex flex-wrap gap-2">
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
        <Link
          href="/traces"
          className="text-xs text-emerald-700 hover:underline dark:text-emerald-300"
        >
          Open trace explorer
        </Link>
      ) : null}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-outline bg-surface-muted p-4">
      <h4 className="text-[11px] font-semibold uppercase tracking-wide text-ink-tertiary">{title}</h4>
      <div className="mt-2.5">{children}</div>
    </div>
  );
}

function KeyVal({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 break-words" aria-label={`${label}: ${value}`}>
      <span className="text-ink-tertiary">{label}:</span> <span>{value}</span>
    </div>
  );
}

function Chip({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return (
    <span className={`rounded border border-outline bg-surface px-2 py-0.5 text-[11px] text-ink-secondary ${mono ? "font-mono" : ""}`}>
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
      : "border-outline bg-surface text-ink-secondary hover:border-outline-strong hover:text-foreground";
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

function formatDateOnly(value: string): string {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value;
  return new Date(parsed).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function controlLabel(control: Record<string, unknown>): string | undefined {
  for (const key of ["control_id", "id", "name", "title"] as const) {
    const value = control[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function formatProvenance(value: EnrichedVuln["provenance"]): string {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (!value || typeof value !== "object") return "Unavailable";
  const parts: string[] = [];
  for (const key of ["source", "collector", "basis", "method"] as const) {
    const field = value[key];
    if (typeof field === "string" && field.trim()) parts.push(field.trim());
  }
  return uniqueStrings(parts).join(" · ") || "Available in raw evidence";
}

function IntelligencePanel({ vuln }: { vuln: EnrichedVuln }) {
  const version = cvssVersion(vuln.cvss_vector);
  const published = vuln.published_at ?? vuln.published ?? vuln.nvd_published;
  return (
    <Panel title="Security intelligence">
      <div className="space-y-2 break-words text-xs text-ink-secondary">
        {typeof vuln.cvss_score === "number" ? <div><KeyVal label="CVSS" value={vuln.cvss_score.toFixed(1)} /><span>{[version ? `v${version}` : null, vuln.cvss_severity].filter(Boolean).join(" · ")}</span></div> : null}
        {typeof vuln.epss_score === "number" ? <KeyVal label="EPSS" value={`${(vuln.epss_score * 100).toFixed(1)}%`} /> : null}
        {typeof vuln.epss_percentile === "number" ? <p>{vuln.epss_percentile.toFixed(1)}th percentile</p> : null}
        {typeof vuln.is_kev === "boolean" ? <KeyVal label="CISA KEV" value={vuln.is_kev ? "Known exploited" : "Not listed"} /> : null}
        {vuln.kev_date_added ? <KeyVal label="KEV added" value={formatDateOnly(vuln.kev_date_added)} /> : null}
        {vuln.cvss_vector ? <KeyVal label="CVSS vector" value={vuln.cvss_vector} /> : null}
        {vuln.severity_source ? <KeyVal label="Severity source" value={vuln.severity_source} /> : null}
        {published ? <KeyVal label="Published" value={formatDateOnly(published)} /> : null}
        {vuln.modified_at ? <KeyVal label="Modified" value={formatDateOnly(vuln.modified_at)} /> : null}
      </div>
    </Panel>
  );
}

function TagList({ label, values, mono = false }: { label: string; values: string[]; mono?: boolean }) {
  if (values.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">{label}</div>
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
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">{label}</div>
      <code className="mt-1 block overflow-x-auto rounded bg-surface px-2 py-1.5 text-[11px] text-foreground">{value}</code>
    </div>
  );
}
