"use client";

import type { InvestigationPresetFilters } from "@/components/graph-preset-controls";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const LAYERS = [
  { key: "orchestration", label: "Orchestration" },
  { key: "mcp_server", label: "MCP" },
  { key: "package", label: "Package" },
  { key: "finding", label: "Finding" },
  { key: "identity", label: "Identity" },
  { key: "infra", label: "Infra" },
] as const;
const EVIDENCE_TIERS = [
  { key: "static_scan", label: "Static" },
  { key: "runtime_observed", label: "Observed" },
  { key: "runtime_blocked", label: "Blocked" },
] as const;

function Chip({
  active,
  label,
  onClick,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`rounded-lg border px-2.5 py-1 text-[11px] font-medium transition ${
        active
          ? "border-sky-600/50 bg-sky-500/10 text-sky-800 dark:text-sky-200"
          : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-tertiary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
      }`}
    >
      {label}
    </button>
  );
}

/**
 * Compact severity · layer · evidence_tier · environment chips for the
 * investigation portfolio (path queue), reusing filter-algebra concepts
 * without pulling the full lineage FilterPanel.
 */
export function InvestigationFilterChips({
  filters,
  onChange,
  environments = [],
}: {
  filters: InvestigationPresetFilters;
  onChange: (next: InvestigationPresetFilters) => void;
  environments?: string[];
}) {
  return (
    <div className="space-y-2" data-testid="investigation-filter-chips">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
          Severity
        </span>
        {SEVERITIES.map((severity) => (
          <Chip
            key={severity}
            label={severity}
            active={filters.severity === severity}
            onClick={() =>
              onChange({
                ...filters,
                severity: filters.severity === severity ? null : severity,
              })
            }
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
          Layer
        </span>
        {LAYERS.map((layer) => (
          <Chip
            key={layer.key}
            label={layer.label}
            active={filters.layer === layer.key}
            onClick={() =>
              onChange({
                ...filters,
                layer: filters.layer === layer.key ? null : layer.key,
              })
            }
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
          Evidence
        </span>
        {EVIDENCE_TIERS.map((tier) => (
          <Chip
            key={tier.key}
            label={tier.label}
            active={filters.evidenceTier === tier.key}
            onClick={() =>
              onChange({
                ...filters,
                evidenceTier: filters.evidenceTier === tier.key ? null : tier.key,
              })
            }
          />
        ))}
      </div>
      {environments.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            Environment
          </span>
          {environments.map((environment) => (
            <Chip
              key={environment}
              label={environment}
              active={filters.environment === environment}
              onClick={() =>
                onChange({
                  ...filters,
                  environment:
                    filters.environment === environment ? null : environment,
                })
              }
            />
          ))}
        </div>
      ) : null}
    </div>
  );
}
