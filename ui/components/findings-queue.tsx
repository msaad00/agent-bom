"use client";

import { ChevronDown, ChevronRight, ChevronUp, ExternalLink } from "lucide-react";

import { severityColor, severityDot, type FindingTriageItem } from "@/lib/api";
import type { FindingsLens } from "@/lib/findings-lens";
import type { EnrichedVuln, SortKey } from "@/lib/findings-view";
import {
  findingSecondaryText,
  findingStatusClass,
  formatFindingTimestamp,
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
        className="text-xs font-mono bg-[var(--surface)] border border-[var(--border-subtle)] text-[var(--text-tertiary)] rounded px-1.5 py-0.5"
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
        active ? "text-[var(--foreground)]" : "text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
      }`}
    >
      {label}
      {active ? (
        dir === "desc" ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
      ) : null}
    </button>
  );
}

function renderScoreValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toFixed(1);
  }
  return (
    <span className="rounded bg-[var(--surface)] px-1.5 py-0.5 text-[var(--text-tertiary)]" title={missingLabel}>
      N/A
    </span>
  );
}

function renderPercentValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `${(value * 100).toFixed(1)}%`;
  }
  return (
    <span className="rounded bg-[var(--surface)] px-1.5 py-0.5 text-[var(--text-tertiary)]" title={missingLabel}>
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
  lens = "ops",
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
  /** Retained for story/caller compatibility; persona columns own timestamp visibility. */
  showLifecycle?: boolean;
  lens?: FindingsLens;
  triageByKey?: ReadonlyMap<string, FindingTriageItem>;
}) {
  const emptyLabel =
    lens === "trust"
      ? "No findings match the selected compliance query."
      : "No findings match the selected engineering filters.";

  return (
    <div className="border border-[var(--border-subtle)] rounded-xl overflow-hidden overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-[var(--surface)] border-b border-[var(--border-subtle)]">
          {lens === "trust" ? (
            <tr>
              <th className="text-left px-4 py-3">
                <SortButton label="Finding" field="id" current={sortKey} dir={sortDir} onClick={handleSort} />
              </th>
              <ColumnHeader>Control mapping</ColumnHeader>
              <ColumnHeader>Evidence freshness</ColumnHeader>
              <ColumnHeader>Disposition / attestation</ColumnHeader>
              <ColumnHeader>Affected scope</ColumnHeader>
              <ColumnHeader>Action</ColumnHeader>
            </tr>
          ) : (
            <tr>
              <th className="text-left px-4 py-3">
                <SortButton label="Finding" field="id" current={sortKey} dir={sortDir} onClick={handleSort} />
              </th>
              <th className="text-left px-4 py-3">
                <SortButton label="Priority" field="severity" current={sortKey} dir={sortDir} onClick={handleSort} />
              </th>
              <ColumnHeader>Reach / exploit</ColumnHeader>
              <ColumnHeader>Affected asset</ColumnHeader>
              <ColumnHeader>Fix &amp; verify</ColumnHeader>
              <ColumnHeader>Owner / SLA</ColumnHeader>
              <ColumnHeader>Last observed</ColumnHeader>
              <ColumnHeader>Action</ColumnHeader>
            </tr>
          )}
        </thead>
        <tbody className="divide-y divide-[var(--border-subtle)] bg-[var(--background)]">
          {vulns?.map((v) => {
            const rowKey = vulnRowKey(v);
            const isSelected = selectedId === rowKey || selectedId === v.id;
            const triage = triageForFinding(v, triageByKey);
            return (
              <tr
                key={rowKey}
                className={`cursor-pointer transition-colors ${isSelected ? "bg-[var(--surface)]/90 ring-1 ring-inset ring-emerald-900/60" : "hover:bg-[var(--surface)]"}`}
                onClick={() => onSelect(rowKey)}
              >
                <FindingIdentity vuln={v} rowKey={rowKey} onSelect={onSelect} />
                {lens === "trust" ? (
                  <ComplianceCells vuln={v} triage={triage} onSelect={() => onSelect(rowKey)} />
                ) : (
                  <>
                    <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(v.severity)}`}>
                      {v.severity}
                    </span>
                    </td>
                    <EngineeringCells
                      vuln={v}
                      triage={triage}
                      suppressed={suppressed.has(v.id)}
                      onSelect={() => onSelect(rowKey)}
                      onMarkFP={() => onMarkFP(v.id, v.packages[0] ?? "")}
                    />
                  </>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>

      {vulns.length === 0 && (
        <div className="px-4 py-8 text-center text-[var(--text-tertiary)] text-sm">
          {emptyLabel}
        </div>
      )}
    </div>
  );
}

function ColumnHeader({ children }: { children: React.ReactNode }) {
  return (
    <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">
      {children}
    </th>
  );
}

function FindingIdentity({
  vuln,
  rowKey,
  onSelect,
}: {
  vuln: EnrichedVuln;
  rowKey: string;
  onSelect: (vulnId: string | null) => void;
}) {
  const secondary = findingSecondaryText(vuln);
  return (
    <td className="px-4 py-3">
      <div className="flex items-start gap-2">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onSelect(rowKey);
          }}
          className="mt-0.5 rounded p-0.5 text-[var(--text-tertiary)] transition-colors hover:bg-[var(--surface-elevated)] hover:text-[var(--text-secondary)]"
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
              className="font-mono text-xs text-[var(--foreground)] transition-colors hover:text-emerald-400"
            >
              {vuln.id}
            </button>
            {getOsvVulnerabilityUrl(vuln.id) ? (
              <a
                href={getOsvVulnerabilityUrl(vuln.id) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(event) => event.stopPropagation()}
                className="inline-flex items-center gap-1 rounded-full border border-[var(--border-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
              >
                OSV
                <ExternalLink className="h-3 w-3" />
              </a>
            ) : null}
          </div>
          {secondary ? (
            <p className="text-xs text-[var(--text-tertiary)] mt-0.5 ml-3.5 line-clamp-1 max-w-xs">
              {secondary}
            </p>
          ) : null}
        </div>
      </div>
    </td>
  );
}

function EngineeringCells({
  vuln,
  triage,
  suppressed,
  onSelect,
  onMarkFP,
}: {
  vuln: EnrichedVuln;
  triage: FindingTriageItem | undefined;
  suppressed: boolean;
  onSelect: () => void;
  onMarkFP: () => void;
}) {
  const verifyCommand = vuln.remediation_items.find((item) => item.verify_command)?.verify_command;
  return (
    <>
      <td className="px-4 py-3">
        <div className="flex flex-col items-start gap-1">
          <div className="flex flex-wrap items-center gap-1">
            <ReachabilityBadge reachable={vuln.graph_reachable} hops={vuln.graph_min_hop_distance} />
            {(vuln.is_kev ?? vuln.cisa_kev) ? <CisaKevBadge /> : null}
          </div>
          {typeof vuln.epss_score === "number" ? (
            <span className="text-[11px] font-mono text-[var(--text-secondary)]">
              EPSS {renderPercentValue(vuln.epss_score, "EPSS not available")}
            </span>
          ) : typeof vuln.cvss_score === "number" ? (
            <span className="text-[11px] font-mono text-[var(--text-secondary)]">
              CVSS {renderScoreValue(vuln.cvss_score, "CVSS not available")}
            </span>
          ) : vuln.graph_reachable == null ? (
            <span className="text-xs text-[var(--text-tertiary)]">Unavailable</span>
          ) : null}
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col gap-1 text-xs">
          <span className="font-mono text-[var(--text-secondary)]">
            {vuln.packages[0] ?? "Unavailable"}
          </span>
          <span className="text-[var(--text-tertiary)]">
            {vuln.agents.length > 0 ? vuln.agents.slice(0, 2).join(", ") : "Agent unavailable"}
          </span>
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col gap-1 text-xs">
          <span className={vuln.fixed_version ? "font-mono text-emerald-500" : "text-[var(--text-tertiary)]"}>
            {vuln.fixed_version ? `Upgrade ${vuln.fixed_version}` : "Fix unavailable"}
          </span>
          <span className="max-w-[14rem] truncate font-mono text-[11px] text-[var(--text-tertiary)]" title={verifyCommand ?? undefined}>
            {verifyCommand ? `Verify: ${verifyCommand}` : "Verify unavailable"}
          </span>
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col gap-1 text-xs">
          <span className="text-[var(--text-secondary)]">{vuln.owner || triage?.assignee || "Unassigned"}</span>
          <span className="text-[var(--text-tertiary)]">
            {vuln.sla_due_at ? `SLA ${formatFindingTimestamp(vuln.sla_due_at)}` : "SLA unavailable"}
          </span>
        </div>
      </td>
      <td className="px-4 py-3 text-xs font-mono text-[var(--text-secondary)]">
        {vuln.last_observed || vuln.last_seen
          ? formatFindingTimestamp(vuln.last_observed ?? vuln.last_seen)
          : "Unavailable"}
      </td>
      <td className="px-4 py-3">
        {suppressed ? (
          <span className="text-xs font-medium px-2 py-0.5 rounded border bg-[var(--surface-elevated)] border-[var(--border-subtle)] text-[var(--text-secondary)]">
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
              className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-muted)] px-2.5 py-1 text-xs font-medium text-[var(--text-secondary)] transition hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
            >
              Investigate
            </button>
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                onMarkFP();
              }}
              className="px-1 text-[11px] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
            >
              Mark false positive
            </button>
          </div>
        )}
      </td>
    </>
  );
}

function ComplianceCells({
  vuln,
  triage,
  onSelect,
}: {
  vuln: EnrichedVuln;
  triage: FindingTriageItem | undefined;
  onSelect: () => void;
}) {
  const controlTags = controlLabels(vuln);
  const evidenceSources = vuln.sources.filter((source) => source !== "finding");
  const disposition = triage?.decision?.replaceAll("_", " ");
  const affectedScope = [...vuln.packages, ...vuln.agents, ...vuln.affected_servers];
  return (
    <>
      <td className="px-4 py-3">
        {controlTags.length > 0 ? (
          <div className="flex max-w-[16rem] flex-wrap gap-1">
            {controlTags.slice(0, 2).map((tag) => (
              <span key={tag} className="rounded border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">
                {tag}
              </span>
            ))}
            {controlTags.length > 2 ? (
              <span className="text-[11px] text-[var(--text-tertiary)]">+{controlTags.length - 2}</span>
            ) : null}
          </div>
        ) : (
          <a
            href="/compliance"
            onClick={(event) => event.stopPropagation()}
            className="text-xs text-[var(--text-tertiary)] underline decoration-dotted underline-offset-2 hover:text-[var(--text-secondary)]"
          >
            Unavailable · open Compliance
          </a>
        )}
      </td>
      <td className="px-4 py-3">
        {evidenceSources.length > 0 || vuln.last_observed || vuln.last_seen ? (
          <div className="flex flex-col gap-1 text-xs">
            <span className="text-[var(--text-secondary)]">
              {vuln.last_observed || vuln.last_seen
                ? formatFindingTimestamp(vuln.last_observed ?? vuln.last_seen)
                : "Freshness unavailable"}
            </span>
            <span className="max-w-[12rem] truncate text-[var(--text-tertiary)]" title={evidenceSources.join(", ")}>
              {evidenceSources.length > 0
                ? `${evidenceSources.length} source${evidenceSources.length === 1 ? "" : "s"} · ${evidenceSources.join(", ")}`
                : "Source unavailable"}
            </span>
          </div>
        ) : (
          <span className="text-xs text-[var(--text-tertiary)]">Unavailable</span>
        )}
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col items-start gap-1">
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${findingStatusClass(triage?.queue_state)}`}>
            {disposition || "Not reviewed"}
          </span>
          {triage?.vex_eligible ? (
            <span className="text-[11px] text-emerald-600 dark:text-emerald-400">OpenVEX ready</span>
          ) : <span className="text-[11px] text-[var(--text-tertiary)]">Attestation unavailable</span>}
        </div>
      </td>
      <td className="px-4 py-3 text-xs text-[var(--text-secondary)]">
        {affectedScope.length > 0 ? (
          <span className="block max-w-[14rem] truncate" title={affectedScope.join(", ")}>
            {affectedScope.slice(0, 2).join(", ")}{affectedScope.length > 2 ? ` +${affectedScope.length - 2}` : ""}
          </span>
        ) : "Unavailable"}
      </td>
      <td className="px-4 py-3">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onSelect();
          }}
          className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-700 transition hover:bg-emerald-500/15 dark:text-emerald-300"
        >
          Review evidence
        </button>
      </td>
    </>
  );
}
