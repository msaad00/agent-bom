"use client";

import { ChevronDown, ChevronRight, ChevronUp, ExternalLink, ShieldOff } from "lucide-react";

import { severityColor, severityDot } from "@/lib/api";
import type { EnrichedVuln, FindingColumnVisibility, SortKey } from "@/lib/findings-view";
import {
  findingSecondaryText,
  findingStatusClass,
  findingStatusLabel,
  formatFindingTimestamp,
  vulnRowKey,
} from "@/lib/findings-view";
import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";

const ALL_COLUMNS_VISIBLE: FindingColumnVisibility = {
  cvss: true,
  epss: true,
  packages: true,
  agents: true,
  fix: true,
};

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
  showLifecycle = false,
  columns = ALL_COLUMNS_VISIBLE,
}: {
  vulns: EnrichedVuln[];
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  handleSort: (f: SortKey) => void;
  suppressed: Set<string>;
  onMarkFP: (vulnId: string, packageName: string) => void;
  selectedId: string | null;
  onSelect: (vulnId: string | null) => void;
  showLifecycle?: boolean;
  columns?: FindingColumnVisibility;
}) {
  return (
    <div className="border border-[var(--border-subtle)] rounded-xl overflow-hidden overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-[var(--surface)] border-b border-[var(--border-subtle)]">
          <tr>
            <th className="text-left px-4 py-3">
              <SortButton label="CVE" field="id" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="Severity" field="severity" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            {showLifecycle ? (
              <>
                <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">Last seen</th>
              </>
            ) : null}
            {columns.cvss ? (
              <th className="text-left px-4 py-3">
                <SortButton label="CVSS" field="cvss" current={sortKey} dir={sortDir} onClick={handleSort} />
              </th>
            ) : null}
            {columns.epss ? (
              <th className="text-left px-4 py-3">
                <SortButton label="EPSS" field="epss" current={sortKey} dir={sortDir} onClick={handleSort} />
              </th>
            ) : null}
            {columns.packages ? (
              <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">Packages</th>
            ) : null}
            {columns.agents ? (
              <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">Agents</th>
            ) : null}
            {columns.fix ? (
              <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">Fix</th>
            ) : null}
            <th className="text-left px-4 py-3 text-xs font-medium text-[var(--text-tertiary)] uppercase tracking-wide">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border-subtle)] bg-[var(--background)]">
          {vulns?.map((v) => {
            const rowKey = vulnRowKey(v);
            const isSelected = selectedId === rowKey || selectedId === v.id;
            const secondary = findingSecondaryText(v);
            return (
              <tr
                key={rowKey}
                className={`cursor-pointer transition-colors ${isSelected ? "bg-[var(--surface)]/90 ring-1 ring-inset ring-emerald-900/60" : "hover:bg-[var(--surface)]"}`}
                onClick={() => onSelect(rowKey)}
              >
                <td className="px-4 py-3">
                  <div className="flex items-start gap-2">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect(rowKey);
                      }}
                      className="mt-0.5 rounded p-0.5 text-[var(--text-tertiary)] transition-colors hover:bg-[var(--surface-elevated)] hover:text-[var(--text-secondary)]"
                      aria-label={`Open details for ${v.id}`}
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(v.severity)}`} />
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              onSelect(rowKey);
                            }}
                            className="font-mono text-xs text-[var(--foreground)] transition-colors hover:text-emerald-400"
                          >
                            {v.id}
                          </button>
                          {getOsvVulnerabilityUrl(v.id) ? (
                            <a
                              href={getOsvVulnerabilityUrl(v.id) ?? undefined}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(event) => event.stopPropagation()}
                              className="inline-flex items-center gap-1 rounded-full border border-[var(--border-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
                            >
                              OSV
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : null}
                          {(v.is_kev ?? v.cisa_kev) && <CisaKevBadge />}
                          <ReachabilityBadge
                            reachable={v.graph_reachable}
                            hops={v.graph_min_hop_distance}
                          />
                        </div>
                        {secondary && (
                          <p className="text-xs text-[var(--text-tertiary)] mt-0.5 ml-3.5 line-clamp-1 max-w-xs">
                            {secondary}
                          </p>
                        )}
                      </div>
                    </div>
                  </td>
                <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(v.severity)}`}>
                      {v.severity}
                    </span>
                  </td>
                  {showLifecycle ? (
                    <>
                      <td className="px-4 py-3">
                        <span
                          className={`text-xs font-medium px-2 py-0.5 rounded border ${findingStatusClass(v.lifecycle_status)}`}
                        >
                          {findingStatusLabel(v.lifecycle_status)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-[var(--text-secondary)]">
                        {formatFindingTimestamp(v.last_seen ?? v.first_seen)}
                      </td>
                    </>
                  ) : null}
                  {columns.cvss ? (
                    <td className="px-4 py-3 text-xs font-mono text-[var(--text-secondary)]">
                      {renderScoreValue(v.cvss_score, "CVSS not published by the current advisory")}
                    </td>
                  ) : null}
                  {columns.epss ? (
                    <td className="px-4 py-3 text-xs font-mono text-[var(--text-secondary)]">
                      {renderPercentValue(v.epss_score, "EPSS not available for this advisory")}
                    </td>
                  ) : null}
                  {columns.packages ? (
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {v.packages.slice(0, 3).map((p) => (
                          <span key={p} className="text-xs font-mono bg-[var(--surface-elevated)] border border-[var(--border-subtle)] rounded px-1.5 py-0.5 text-[var(--text-secondary)]">
                            {p}
                          </span>
                        ))}
                        {v.packages.length > 3 && (
                          <span className="text-xs text-[var(--text-tertiary)]">+{v.packages.length - 3}</span>
                        )}
                      </div>
                    </td>
                  ) : null}
                  {columns.agents ? (
                    <td className="px-4 py-3 text-xs text-[var(--text-tertiary)]">
                      {v.agents.slice(0, 2).join(", ")}
                      {v.agents.length > 2 && <span className="text-[var(--text-tertiary)]"> +{v.agents.length - 2}</span>}
                    </td>
                  ) : null}
                  {columns.fix ? (
                    <td className="px-4 py-3 text-xs font-mono text-emerald-500">
                      {v.fixed_version ?? "N/A"}
                    </td>
                  ) : null}
                  <td className="px-4 py-3">
                    {suppressed.has(v.id) ? (
                      <span className="text-xs font-medium px-2 py-0.5 rounded border bg-[var(--surface-elevated)] border-[var(--border-subtle)] text-[var(--text-secondary)]">
                        Suppressed
                      </span>
                    ) : (
                      <button
                        onClick={(event) => {
                          event.stopPropagation();
                          onMarkFP(v.id, v.packages[0] ?? "");
                        }}
                        className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-[var(--surface-muted)] hover:bg-[var(--surface-muted)] text-[var(--text-secondary)] transition-colors"
                      >
                        <ShieldOff className="w-3 h-3" />
                        Mark FP
                      </button>
                    )}
                  </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {vulns.length === 0 && (
        <div className="px-4 py-8 text-center text-[var(--text-tertiary)] text-sm">
          No vulnerabilities match your filters.
        </div>
      )}
    </div>
  );
}
