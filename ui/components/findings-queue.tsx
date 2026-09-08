"use client";

import { ChevronDown, ChevronRight, ChevronUp, ExternalLink } from "lucide-react";
import { Fragment, useLayoutEffect, useState, type ReactNode } from "react";
import { FINDING_COLUMN_LABELS, defaultFindingColumns, readFindingColumns, writeFindingColumns, type FindingColumnKey, type FindingColumnPreferences } from "@/lib/finding-columns";

import { useAuthState } from "@/components/auth-provider";
import { severityColor, severityDot, type FindingTriageItem } from "@/lib/api";
import type { FindingsLens } from "@/lib/findings-lens";
import type { EnrichedVuln, SortKey } from "@/lib/findings-view";
import {
  findingSecondaryText,
  findingStatusClass,
  formatFindingTimestamp,
  formatSlaDue,
  vulnRowKey,
} from "@/lib/findings-view";
import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";
import { controlLabels, triageForFinding } from "@/lib/findings-workspace";

function ReachabilityBadge({
  reachable,
  hops,
}: {
  reachable: boolean | null | undefined;
  hops: number | null | undefined;
}) {
  if (reachable === true) {
    const hopLabel = typeof hops === "number" && hops > 0 ? ` · ${hops} hop${hops === 1 ? "" : "s"}` : "";
    return (
      <span
        title="An agent's USES/DEPENDS_ON closure reaches this package"
        className="text-xs font-mono bg-amber-950 border border-amber-800 text-amber-300 rounded px-1.5 py-0.5"
      >
        Reachable{hopLabel}
      </span>
    );
  }
  if (reachable === false) {
    return (
      <span
        title="Package is in inventory but no agent traversal reaches it"
        className="text-xs font-mono bg-surface border border-outline text-ink-tertiary rounded px-1.5 py-0.5"
      >
        Unreachable
      </span>
    );
  }
  return null;
}

function CisaKevBadge() {
  return (
    <span className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-1.5 py-0.5">
      KEV
    </span>
  );
}

function SortButton({
  label,
  field,
  current,
  dir,
  onClick,
}: {
  label: string;
  field: SortKey;
  current: SortKey;
  dir: "asc" | "desc";
  onClick: (f: SortKey) => void;
}) {
  const active = current === field;
  return (
    <button
      onClick={() => onClick(field)}
      className={`flex items-center gap-0.5 text-xs font-medium uppercase tracking-wide transition-colors ${
        active ? "text-foreground" : "text-ink-tertiary hover:text-ink-secondary"
      }`}
    >
      {label}
      {active ? (
        dir === "desc" ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
      ) : null}
    </button>
  );
}

function ariaSort(field: SortKey, current: SortKey, dir: "asc" | "desc"): "ascending" | "descending" | "none" {
  if (field !== current) return "none";
  return dir === "asc" ? "ascending" : "descending";
}

function renderScoreValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toFixed(1);
  }
  return (
    <span className="rounded bg-surface px-1.5 py-0.5 text-ink-tertiary" title={missingLabel}>
      N/A
    </span>
  );
}

function renderPercentValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `${(value * 100).toFixed(1)}%`;
  }
  return (
    <span className="rounded bg-surface px-1.5 py-0.5 text-ink-tertiary" title={missingLabel}>
      N/A
    </span>
  );
}

export function FindingsQueueTable({
  vulns,
  sortKey,
  sortDir,
  handleSort,
  suppressed,
  onMarkFP,
  selectedId,
  onSelect,
  triageByKey = new Map(),
}: {
  vulns: EnrichedVuln[];
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  handleSort: (f: SortKey) => void;
  suppressed: Set<string>;
  onMarkFP: (vulnId: string, packageName: string) => void;
  selectedId: string | null;
  onSelect: (vulnId: string | null) => void;
  /** Retained for caller compatibility. The queue uses one column model. */
  showLifecycle?: boolean;
  lens?: FindingsLens;
  triageByKey?: ReadonlyMap<string, FindingTriageItem>;
}) {
  const { hasCapability } = useAuthState();
  const canManageExceptions = hasCapability("exceptions.manage");
  const compactLayout = useCompactFindingsLayout();
  const [preferences, setPreferences] = useState<FindingColumnPreferences>(defaultFindingColumns);
  useLayoutEffect(() => { setPreferences(readFindingColumns()); }, []);
  const columns = preferences.order.filter((key) => !preferences.hidden.includes(key));
  const updateColumns = (next: FindingColumnPreferences) => { setPreferences(next); writeFindingColumns(next); };
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const toggleOccurrences = (rowKey: string) => {
    setExpandedGroups((current) => {
      const next = new Set(current);
      if (next.has(rowKey)) next.delete(rowKey);
      else next.add(rowKey);
      return next;
    });
  };
  const emptyLabel = "No findings match the selected filters.";

  return (
    <div className="overflow-hidden rounded-xl border border-outline">
      <FindingColumnsChooser preferences={preferences} onChange={updateColumns} />
      {compactLayout ? (
      <div className="divide-y divide-outline bg-background">
        {vulns.map((vuln) => {
          const rowKey = vulnRowKey(vuln);
          return (
            <MobileFindingCard
              key={rowKey}
              vuln={vuln}
              columns={columns}
              triage={triageForFinding(vuln, triageByKey)}
              selected={selectedId === rowKey || selectedId === vuln.id}
              suppressed={suppressed.has(vuln.id)}
              onSelect={() => onSelect(rowKey)}
              onMarkFP={() => onMarkFP(vuln.id, vuln.packages[0] ?? "")}
              canMarkFalsePositive={canManageExceptions}
              occurrencesExpanded={expandedGroups.has(rowKey)}
              onToggleOccurrences={() => toggleOccurrences(rowKey)}
            />
          );
        })}
      </div>
      ) : (
      <div className="overflow-x-auto">
      <table className="w-full table-fixed text-sm [&_td]:align-top" style={{ minWidth: `${23 + columns.reduce((total, key) => total + COLUMN_WIDTH_REM[key], 0)}rem` }}>
        <colgroup>
          <col />
          {columns.map((key) => <col key={key} style={{ width: `${COLUMN_WIDTH_REM[key]}rem` }} />)}
          <col style={{ width: "7rem" }} />
        </colgroup>
        <caption className="sr-only">Findings and supporting evidence</caption>
        <thead className="bg-surface border-b border-outline">
          <tr>
            <ColumnHeader>Finding</ColumnHeader>
            {columns.map((key) => key === "priority" ? (
              <th key={key} scope="col" aria-sort={ariaSort("severity", sortKey, sortDir)} className="text-left px-3 py-3">
                <SortButton label="Priority" field="severity" current={sortKey} dir={sortDir} onClick={handleSort} />
              </th>
            ) : <ColumnHeader key={key}>{FINDING_COLUMN_LABELS[key]}</ColumnHeader>)}
            <ColumnHeader>Action</ColumnHeader>
          </tr>
        </thead>
        <tbody className="divide-y divide-outline bg-background">
          {vulns?.map((v) => {
            const rowKey = vulnRowKey(v);
            const isSelected = selectedId === rowKey || selectedId === v.id;
            const triage = triageForFinding(v, triageByKey);
            const occurrencesExpanded = expandedGroups.has(rowKey);
            return (
              <Fragment key={rowKey}>
                <tr
                  className={`cursor-pointer transition-colors ${isSelected ? "bg-surface/90 ring-1 ring-inset ring-emerald-900/60" : "hover:bg-surface"}`}
                  onClick={() => onSelect(rowKey)}
                >
                  <FindingIdentity
                    vuln={v}
                    rowKey={rowKey}
                    onSelect={onSelect}
                    occurrencesExpanded={occurrencesExpanded}
                    onToggleOccurrences={() => toggleOccurrences(rowKey)}
                  />
                  <EngineeringCells
                    vuln={v} triage={triage} columns={columns}
                    suppressed={suppressed.has(v.id)} onSelect={() => onSelect(rowKey)}
                    onMarkFP={() => onMarkFP(v.id, v.packages[0] ?? "")}
                    canMarkFalsePositive={canManageExceptions}
                  />
                </tr>
                {occurrencesExpanded ? (
                  <tr className="bg-surface/45">
                    <td colSpan={columns.length + 2} className="px-10 py-3">
                      <OccurrenceList vuln={v} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </tbody>
      </table>
      </div>
      )}

      {vulns.length === 0 && (
        <div className="px-4 py-8 text-center text-ink-tertiary text-sm">
          {emptyLabel}
        </div>
      )}
    </div>
  );
}

const COLUMN_WIDTH_REM: Record<FindingColumnKey, number> = {
  priority: 5.5, asset: 10, detection: 8, observed: 9.5, remediation: 10,
  reach: 10, owner: 10, controls: 11, disposition: 12, scope: 12,
};

function useCompactFindingsLayout() {
  const [compact, setCompact] = useState(false);

  useLayoutEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(max-width: 767px)");
    const update = () => setCompact(query.matches);
    update();
    query.addEventListener?.("change", update);
    return () => query.removeEventListener?.("change", update);
  }, []);

  return compact;
}

function MobileFindingCard({
  vuln,
  columns,
  triage,
  selected,
  suppressed,
  onSelect,
  onMarkFP,
  canMarkFalsePositive,
  occurrencesExpanded,
  onToggleOccurrences,
}: {
  vuln: EnrichedVuln;
  columns: FindingColumnKey[];
  triage: FindingTriageItem | undefined;
  selected: boolean;
  suppressed: boolean;
  onSelect: () => void;
  onMarkFP: () => void;
  canMarkFalsePositive: boolean;
  occurrencesExpanded: boolean;
  onToggleOccurrences: () => void;
}) {
  const affectedScope = [...vuln.packages, ...vuln.agents, ...vuln.affected_servers];
  const exploit = vuln.is_kev ?? vuln.cisa_kev
    ? "CISA KEV"
    : typeof vuln.epss_score === "number"
      ? `EPSS ${(vuln.epss_score * 100).toFixed(1)}%`
      : typeof vuln.cvss_score === "number"
        ? `CVSS ${vuln.cvss_score.toFixed(1)}`
        : "Unavailable";

  const controls = controlLabels(vuln);
  const due = formatSlaDue(vuln.sla_due_at);
  const fields: Record<FindingColumnKey, ReactNode> = {
    priority: <span className={`inline-block rounded border px-1.5 py-0.5 text-xs ${severityColor(vuln.severity)}`}>{vuln.severity}</span>,
    asset: affectedScope.slice(0, 2).join(", ") || "Unavailable",
    detection: <DetectionEvidence vuln={vuln} />,
    observed: <ObservedEvidence vuln={vuln} />,
    remediation: `${vuln.fixed_version ? `Upgrade ${vuln.fixed_version}` : "Fix not provided"} · ${remediationLifecycle(vuln)}`,
    reach: vuln.graph_reachable === true ? `Reachable · ${exploit}` : vuln.graph_reachable === false ? `Unreachable · ${exploit}` : exploit,
    owner: `${vuln.owner || triage?.assignee || "Unassigned"} · ${due?.label ?? "SLA unavailable"}`,
    controls: controls.join(", ") || "Unavailable",
    disposition: `${triage?.decision?.replaceAll("_", " ") || "Not reviewed"} · ${triage?.vex_eligible ? "OpenVEX ready" : "Attestation unavailable"}`,
    scope: affectedScope.join(", ") || "Unavailable",
  };

  return (
    <article
      className={`p-3 ${selected ? "bg-surface ring-1 ring-inset ring-emerald-900/60" : ""}`}
    >
      <button
        type="button"
        onClick={onSelect}
        className="flex w-full min-w-0 items-start justify-between gap-3 text-left"
        aria-label={`Open details for ${vuln.id}`}
      >
        <span className="min-w-0">
          <span className="flex min-w-0 items-center gap-2">
            <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${severityDot(vuln.severity)}`} />
            <span className="truncate font-mono text-xs text-foreground">{vuln.id}</span>
          </span>
          {findingSecondaryText(vuln) ? (
            <span className="mt-1 block line-clamp-2 text-xs text-ink-tertiary">
              {findingSecondaryText(vuln)}
            </span>
          ) : null}
        </span>
      </button>

      <OccurrenceDisclosure
        vuln={vuln}
        expanded={occurrencesExpanded}
        onToggle={onToggleOccurrences}
      />

      <dl className="mt-3 grid min-w-0 grid-cols-2 gap-x-3 gap-y-2 text-xs">
        {columns.map((key) => <MobileDetail key={key} label={FINDING_COLUMN_LABELS[key]} value={fields[key]} />)}
      </dl>

      <div className="mt-3 flex min-w-0 flex-wrap items-center gap-2 border-t border-outline pt-3">
        <button
          type="button"
          onClick={onSelect}
          className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-300"
        >
          Investigate
        </button>
        {
          suppressed ? (
            <span className="rounded border border-outline bg-surface-elevated px-2 py-1 text-xs text-ink-secondary">
              Suppressed
            </span>
          ) : (
            <button
              type="button"
              onClick={onMarkFP}
              disabled={!canMarkFalsePositive}
              title={!canMarkFalsePositive ? "Contributor role required to mark false positives" : undefined}
              className="rounded-md border border-outline px-2.5 py-1.5 text-xs text-ink-secondary"
            >
              Mark false positive
            </button>
          )
        }
      </div>
    </article>
  );
}

function MobileDetail({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] font-medium uppercase tracking-wide text-ink-tertiary">{label}</dt>
      <dd className="mt-0.5 break-words text-ink-secondary">{value}</dd>
    </div>
  );
}

function ColumnHeader({ children }: { children: React.ReactNode }) {
  return (
    <th scope="col" className="text-left px-3 py-3 text-xs font-medium text-ink-tertiary uppercase tracking-wide">
      {children}
    </th>
  );
}

function FindingIdentity({
  vuln,
  rowKey,
  onSelect,
  occurrencesExpanded,
  onToggleOccurrences,
}: {
  vuln: EnrichedVuln;
  rowKey: string;
  onSelect: (vulnId: string | null) => void;
  occurrencesExpanded: boolean;
  onToggleOccurrences: () => void;
}) {
  const secondary = findingSecondaryText(vuln);
  return (
    <td className="px-3 py-3">
      <div className="flex items-start gap-2">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onSelect(rowKey);
          }}
          className="mt-0.5 rounded p-0.5 text-ink-tertiary transition-colors hover:bg-surface-elevated hover:text-ink-secondary"
          aria-label={`Open details for ${vuln.id}`}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(vuln.severity)}`} />
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onSelect(rowKey);
              }}
              title={vuln.id}
              className="min-w-0 line-clamp-2 text-left text-xs font-medium text-foreground [overflow-wrap:anywhere] transition-colors hover:text-emerald-700 dark:hover:text-emerald-300"
            >
              {vuln.id}
            </button>
            {getOsvVulnerabilityUrl(vuln.id) ? (
              <a
                href={getOsvVulnerabilityUrl(vuln.id) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(event) => event.stopPropagation()}
                className="inline-flex items-center gap-1 rounded-full border border-outline px-2 py-0.5 text-[11px] font-medium text-ink-secondary transition-colors hover:border-outline-strong hover:text-foreground"
              >
                OSV
                <ExternalLink className="h-3 w-3" />
              </a>
            ) : null}
          </div>
          {secondary ? (
            <p className="text-xs text-ink-tertiary mt-0.5 ml-3.5 line-clamp-1 max-w-xs">
              {secondary}
            </p>
          ) : null}
          <OccurrenceDisclosure
            vuln={vuln}
            expanded={occurrencesExpanded}
            onToggle={onToggleOccurrences}
            showDetails={false}
          />
        </div>
      </div>
    </td>
  );
}

function OccurrenceDisclosure({
  vuln,
  expanded,
  onToggle,
  showDetails = true,
}: {
  vuln: EnrichedVuln;
  expanded: boolean;
  onToggle: () => void;
  showDetails?: boolean;
}) {
  const count = vuln.occurrence_count ?? 1;
  if (count <= 1) return null;
  const label = `${expanded ? "Hide" : "Show"} ${count} affected asset occurrences`;
  return (
    <div className="mt-2">
      <button
        type="button"
        aria-label={label}
        aria-expanded={expanded}
        onClick={(event) => {
          event.stopPropagation();
          onToggle();
        }}
        className="inline-flex items-center gap-1 rounded border border-outline px-2 py-1 text-[11px] font-medium text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
      >
        {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {count} occurrences
      </button>
      {expanded && showDetails ? <OccurrenceList vuln={vuln} /> : null}
    </div>
  );
}

function OccurrenceList({ vuln }: { vuln: EnrichedVuln }) {
  const visible = (vuln.occurrences ?? []).slice(0, 8);
  const remaining = Math.max(0, (vuln.occurrence_count ?? visible.length) - visible.length);
  return (
    <div className="rounded-lg border border-outline bg-background p-3">
      <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-ink-tertiary">
        Asset-scoped occurrences
      </p>
      <ul className="grid gap-2 text-[11px] text-ink-secondary sm:grid-cols-2 xl:grid-cols-4">
        {visible.map((occurrence, index) => {
          const asset = occurrence.asset;
          const key = occurrence.finding_id ?? occurrence.occurrence_id ?? asset?.stable_id ?? String(index);
          return (
            <li key={key} className="min-w-0 rounded border border-outline bg-surface px-2.5 py-2">
              <span className="block truncate font-mono text-foreground" title={asset?.name || asset?.stable_id || undefined}>
                {asset?.name || asset?.stable_id || "Asset unavailable"}
              </span>
              <span className="mt-0.5 block truncate text-ink-tertiary">
                {[asset?.asset_type, occurrence.package_version, occurrence.owner]
                  .filter((value): value is string => Boolean(value))
                  .join(" · ") || "Evidence retained"}
              </span>
            </li>
          );
        })}
      </ul>
      {remaining > 0 || vuln.occurrences_truncated ? (
        <p className="mt-2 text-[11px] text-ink-tertiary">
          {remaining > 0 ? `${remaining} more occurrences retained.` : "Additional occurrences are retained."} Narrow the query to inspect a specific asset.
        </p>
      ) : null}
    </div>
  );
}

function EngineeringCells({
  vuln,
  columns,
  triage,
  suppressed,
  onSelect,
  onMarkFP,
  canMarkFalsePositive,
}: {
  vuln: EnrichedVuln;
  columns: FindingColumnKey[];
  triage: FindingTriageItem | undefined;
  suppressed: boolean;
  onSelect: () => void;
  onMarkFP: () => void;
  canMarkFalsePositive: boolean;
}) {
  const verifyCommand = vuln.remediation_items.find((item) => item.verify_command)?.verify_command;
  const sla = formatSlaDue(vuln.sla_due_at);
  const packageName = vuln.packages[0];
  const visibleAgents = vuln.agents.slice(0, 2);
  const controlTags = controlLabels(vuln);
  const disposition = triage?.decision?.replaceAll("_", " ");
  const affectedScope = [...vuln.packages, ...vuln.agents, ...vuln.affected_servers];
  const cells: Record<FindingColumnKey | "action", ReactNode> = {
    reach: (<td className="px-3 py-3">
        <div className="flex flex-col items-start gap-1">
          <div className="flex flex-wrap items-center gap-1">
            <ReachabilityBadge reachable={vuln.graph_reachable} hops={vuln.graph_min_hop_distance} />
            {(vuln.is_kev ?? vuln.cisa_kev) ? <CisaKevBadge /> : null}
          </div>
          {typeof vuln.epss_score === "number" ? (
            <span className="text-[11px] font-mono text-ink-secondary">
              EPSS {renderPercentValue(vuln.epss_score, "EPSS not available")}
            </span>
          ) : typeof vuln.cvss_score === "number" ? (
            <span className="text-[11px] font-mono text-ink-secondary">
              CVSS {renderScoreValue(vuln.cvss_score, "CVSS not available")}
            </span>
          ) : vuln.graph_reachable == null ? (
            <span className="text-xs text-ink-tertiary">Unavailable</span>
          ) : null}
        </div>
      </td>),
    asset: (<td className="px-3 py-3">
        <div className="flex flex-col gap-1 text-xs">
          {packageName ? (
            <a
              href={`/findings?q=${encodeURIComponent(packageName)}`}
              onClick={(event) => event.stopPropagation()}
              title={packageName}
              className="line-clamp-2 font-mono text-ink-secondary underline decoration-dotted underline-offset-2 [overflow-wrap:anywhere] transition hover:text-foreground"
            >
              {packageName}
            </a>
          ) : (
            <span className="font-mono text-ink-tertiary">Unavailable</span>
          )}
          {visibleAgents.length > 0 ? (
            <span className="flex flex-wrap gap-x-1 text-ink-tertiary">
              {visibleAgents.map((agent, index) => (
                <span key={agent}>
                  {index > 0 ? ", " : null}
                  <a
                    href={`/findings?q=${encodeURIComponent(agent)}`}
                    onClick={(event) => event.stopPropagation()}
                    className="underline decoration-dotted underline-offset-2 transition hover:text-foreground"
                  >
                    {agent}
                  </a>
                </span>
              ))}
            </span>
          ) : (
            <span className="text-ink-tertiary">Agent unavailable</span>
          )}
        </div>
      </td>),
    remediation: (<td className="px-3 py-3">
        <div className="flex flex-col gap-1 text-xs">
          <span className={vuln.fixed_version ? "font-mono text-emerald-700 dark:text-emerald-300" : "text-ink-tertiary"}>
            {vuln.fixed_version ? `Upgrade ${vuln.fixed_version}` : "Fix not provided"}
          </span>
          <span className="text-ink-secondary">{remediationLifecycle(vuln)}</span>
          <span className="max-w-[14rem] truncate font-mono text-[11px] text-ink-tertiary" title={verifyCommand ?? "No scanner-provided verification command"}>
            {verifyCommand ? `Verify: ${verifyCommand}` : "No scanner-provided verification command"}
          </span>
        </div>
      </td>),
    owner: (<td className="px-3 py-3">
        <div className="flex flex-col gap-1 text-xs">
          <span className="text-ink-secondary">{vuln.owner || triage?.assignee || "Unassigned"}</span>
          {sla ? (
            <span
              className={sla.overdue ? "font-medium text-[color:var(--status-danger)]" : "text-ink-tertiary"}
              title={`SLA due ${sla.absolute}`}
            >
              {sla.label}
            </span>
          ) : (
            <span className="text-ink-tertiary">SLA unavailable</span>
          )}
        </div>
      </td>),
    observed: (<td className="px-3 py-3 text-xs text-ink-secondary"><ObservedEvidence vuln={vuln} /></td>),
    action: (<td className="px-3 py-3">
        {suppressed ? (
          <span className="text-xs font-medium px-2 py-0.5 rounded border bg-surface-elevated border-outline text-ink-secondary">
            Suppressed
          </span>
        ) : (
          <div className="flex flex-col items-start gap-1">
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onSelect();
              }}
              className="rounded-md border border-outline bg-surface-muted px-2.5 py-1 text-xs font-medium text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
            >
              Investigate
            </button>
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onMarkFP();
              }}
              disabled={!canMarkFalsePositive}
              title={!canMarkFalsePositive ? "Contributor role required to mark false positives" : undefined}
              className="px-1 text-[11px] text-ink-tertiary hover:text-ink-secondary disabled:cursor-not-allowed disabled:opacity-50"
            >
              Mark false positive
            </button>
          </div>
        )}
      </td>),
    detection: (<td className="px-3 py-3 text-xs text-ink-secondary"><DetectionEvidence vuln={vuln} /></td>),
    priority: (<td className="px-3 py-3"><span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(vuln.severity)}`}>{vuln.severity}</span></td>),
    controls: (<td className="px-3 py-3">
        {controlTags.length > 0 ? (
          <div className="flex max-w-[16rem] flex-wrap gap-1">
            {controlTags.slice(0, 2).map((tag) => (
              <span key={tag} className="rounded border border-outline bg-surface-elevated px-1.5 py-0.5 text-[11px] text-ink-secondary">
                {tag}
              </span>
            ))}
            {controlTags.length > 2 ? (
              <span className="text-[11px] text-ink-tertiary">+{controlTags.length - 2}</span>
            ) : null}
          </div>
        ) : (
          <a
            href="/compliance"
            onClick={(event) => event.stopPropagation()}
            className="text-xs text-ink-tertiary underline decoration-dotted underline-offset-2 hover:text-ink-secondary"
          >
            Unavailable · open Compliance
          </a>
        )}
      </td>),
    disposition: (<td className="px-3 py-3">
        <div className="flex flex-col items-start gap-1">
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${findingStatusClass(triage?.queue_state)}`}>
            {disposition || "Not reviewed"}
          </span>
          {triage?.vex_eligible ? (
            <span className="text-[11px] text-emerald-600 dark:text-emerald-400">OpenVEX ready</span>
          ) : <span className="text-[11px] text-ink-tertiary">Attestation unavailable</span>}
        </div>
      </td>),
    scope: (<td className="px-3 py-3 text-xs text-ink-secondary">
        {affectedScope.length > 0 ? (
          <span className="block max-w-[14rem] truncate" title={affectedScope.join(", ")}>
            {affectedScope.slice(0, 2).join(", ")}{affectedScope.length > 2 ? ` +${affectedScope.length - 2}` : ""}
          </span>
        ) : "Unavailable"}
      </td>),
  };
  return <>{[...columns, "action" as const].map((key) => <Fragment key={key}>{cells[key]}</Fragment>)}</>;
}

function remediationLifecycle(vuln: EnrichedVuln): string {
  switch (vuln.lifecycle_status) {
    case "open": return "Open";
    case "reopened": return "Reopened";
    case "resolved": return "Reported resolved · verification not provided";
    case "suppressed": return "Suppressed · not verified fixed";
    default: return "Status unavailable";
  }
}
function ObservedEvidence({ vuln }: { vuln: EnrichedVuln }) {
  const last = vuln.last_observed ?? vuln.last_seen;
  return <span className="flex flex-col gap-1"><ObservationDate label="First" value={vuln.first_seen} /><ObservationDate label="Last" value={last} /></span>;
}
function ObservationDate({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value || Number.isNaN(Date.parse(value))) return <span>{label}: Unavailable</span>;
  const exact = formatFindingTimestamp(value);
  const date = new Date(value).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  return <time dateTime={value} title={exact} aria-label={`${label}: ${exact}`} className="whitespace-nowrap">{label}: {date}</time>;
}
function DetectionEvidence({ vuln }: { vuln: EnrichedVuln }) {
  return <span className="flex flex-col gap-1 break-words"><span>Source: {vuln.detection_source || "Unavailable"}</span><span>Type: {vuln.finding_type || "Unavailable"}</span></span>;
}
function FindingColumnsChooser({ preferences, onChange }: { preferences: FindingColumnPreferences; onChange: (next: FindingColumnPreferences) => void }) {
  const move = (key: FindingColumnKey, delta: number) => {
    const order = [...preferences.order];
    const index = order.indexOf(key);
    const target = index + delta;
    if (target < 0 || target >= order.length) return;
    [order[index], order[target]] = [order[target]!, order[index]!];
    onChange({ ...preferences, order });
  };
  return <details className="border-b border-outline p-3">
    <summary className="w-fit cursor-pointer rounded text-sm font-medium text-ink-secondary focus-visible:outline-2 focus-visible:outline-emerald-600">Columns</summary>
    <div className="mt-3 max-w-lg space-y-2" aria-label="Column preferences">
      <p className="text-xs text-ink-secondary">Finding and Action stay visible. Preferences apply to both the table and mobile cards.</p>
      <ul className="space-y-1">
        {preferences.order.map((key, index) => <li key={key} className="flex items-center gap-2">
          <label className="flex flex-1 items-center gap-2 text-sm text-ink-secondary"><input type="checkbox" checked={!preferences.hidden.includes(key)} onChange={() => onChange({ ...preferences, hidden: preferences.hidden.includes(key) ? preferences.hidden.filter(item => item !== key) : [...preferences.hidden, key] })} />{FINDING_COLUMN_LABELS[key]}</label>
          <button type="button" aria-label={`Move ${FINDING_COLUMN_LABELS[key]} up`} disabled={index === 0} onClick={() => move(key, -1)} className="rounded border border-outline p-1 text-ink-secondary disabled:opacity-40"><ChevronUp className="h-4 w-4" /></button>
          <button type="button" aria-label={`Move ${FINDING_COLUMN_LABELS[key]} down`} disabled={index === preferences.order.length - 1} onClick={() => move(key, 1)} className="rounded border border-outline p-1 text-ink-secondary disabled:opacity-40"><ChevronDown className="h-4 w-4" /></button>
        </li>)}
      </ul>
      <button type="button" onClick={() => onChange(defaultFindingColumns())} className="rounded border border-outline px-3 py-1.5 text-sm text-ink-secondary">Reset view</button>
    </div>
  </details>;
}
