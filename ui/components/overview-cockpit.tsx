"use client";

import Link from "next/link";
import type { ElementType } from "react";
import {
  ArrowRight,
  Bug,
  Fingerprint,
  UserRound,
  Flame,
  KeyRound,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";

import type { OverviewResponse } from "@/lib/api";
import { sbomSourceName } from "@/lib/findings-view";
import type {
  ExecScoreDriver,
  OverviewCoverageLane,
  OverviewDomainStatus,
  ServiceEntry,
  ServiceId,
} from "@/lib/api-types";
import { Collapsible } from "@/components/collapsible";
import { isNotEvaluated } from "@/components/compliance-status";
import { FrameworkIcon } from "@/components/framework-icon";
import type { SeverityCounts } from "@/lib/dashboard-data";
import {
  ISSUE_TYPE_SHORT,
  emptyIssueSeverityMatrix,
  findingsHref,
  type IssueSeverityMatrix,
  type IssueType,
  type SeverityBand,
} from "@/lib/finding-issue-type";

export interface ExposurePathView {
  nodes: { type: "cve" | "package" | "server" | "agent" | "credential"; label: string; severity?: string }[];
  riskScore: number;
  href: string;
  key: string;
}

export type OverviewComplianceFramework = {
  id: string;
  label: string;
  pass: number;
  warn: number;
  fail: number;
  total: number;
  kind: "scored" | "applicability";
  applicable?: number;
  notApplicable?: number;
};

export type OverviewComplianceSnapshot = {
  /** Percentage of EVALUATED controls passing — always render it next to
   *  `evaluatedControls` / `totalControls` so a small denominator is visible. */
  overallScore: number;
  overallStatus: "pass" | "warning" | "fail" | "no_data";
  evaluatedControls: number;
  totalControls: number;
  frameworks: OverviewComplianceFramework[];
};

/** Controls a framework actually scored (pass/warn/fail) — NOT its catalogue
 *  size. A framework with 10 bundled controls but 0 mapped findings has
 *  `total` 10 yet `evaluated` 0, and must never read as a green PASS (#3889). */
function frameworkEvaluated(framework: OverviewComplianceFramework): number {
  if (framework.kind === "applicability") return 0;
  return framework.pass + framework.warn + framework.fail;
}

/** Is `overallScore` a number worth rendering?
 *
 *  Framework pass/warn/fail counts alone are NOT the answer. A completed scan
 *  over an estate with nothing gradeable passes only its DETECTIVE controls
 *  ("we scan") — real pass counts that make this predicate true — while the
 *  backend correctly reports `overallStatus: "no_data"`. Reading the counts and
 *  ignoring the status rendered "Compliance 100%" over an unmeasured estate.
 *  The status is the backend's own verdict on whether the score means anything,
 *  so it is authoritative here, and `isNotEvaluated` is the SAME predicate the
 *  Trust Center uses — one implementation, not two. */
function hasEvaluatedCompliance(compliance: OverviewComplianceSnapshot | null | undefined): boolean {
  if (!compliance || isNotEvaluated(compliance.overallStatus)) return false;
  return compliance.frameworks.some((framework) => frameworkEvaluated(framework) > 0);
}

// Shared class for the collapsible section headers (Command center, Cross-lane
// coverage, Open issues, Compliance) — larger + normal-case so exec section
// titles read as headings, not micro-labels (issue #3940 / #3931 item G).
const SECTION_TITLE_CLASS =
  "text-sm font-semibold normal-case tracking-normal text-foreground";

/**
 * How the posture score is rendered. Display-only groundwork for a future
 * user-configurable weighting/mapping (that deeper config is a backend
 * follow-up — see #3940). "percent" treats the 0–100 score as a percentage,
 * "points" shows the raw score, "grade" leans on the letter grade alone.
 */
export type PostureScoreFormat = "percent" | "points" | "grade";

function formatPostureScore(
  score: number | undefined,
  grade: string,
  format: PostureScoreFormat,
): string | null {
  if (typeof score !== "number") return null;
  const rounded = Math.round(score);
  switch (format) {
    case "grade":
      return `Grade ${grade}`;
    case "points":
      return `${rounded} / 100`;
    case "percent":
    default:
      return `${rounded}%`;
  }
}

/**
 * Honest, self-consistent posture blurb. Never asserts "no vulnerabilities"
 * while the open-CVE / severity counts on the same screen are > 0: those counts
 * are the estate-wide rollup, whereas a backend `summary` is derived from only
 * the latest single scan's scorecard (see #3940 — 78 open CVEs vs a clean
 * latest-scan "no vulnerabilities" summary). When anything is open we derive the
 * blurb from the visible counts and ignore a contradicting summary.
 */
function derivePostureBlurb({
  summary,
  critical,
  high,
  cves,
  graded,
}: {
  summary?: string | undefined;
  critical: number;
  high: number;
  cves: number | null;
  graded: boolean;
}): string {
  if (!graded) return "Connect a surface or run a scan to grade posture.";
  const openCves = cves ?? 0;
  const hasOpen = critical > 0 || high > 0 || openCves > 0;

  if (hasOpen) {
    const sevBits = [
      critical > 0
        ? `${critical.toLocaleString("en-US")} critical finding${critical === 1 ? "" : "s"}`
        : null,
      high > 0
        ? `${high.toLocaleString("en-US")} high finding${high === 1 ? "" : "s"}`
        : null,
    ].filter(Boolean);
    const sev = sevBits.join(" · ");
    if (openCves > 0) {
      return `${openCves.toLocaleString("en-US")} unique open CVE${openCves === 1 ? "" : "s"}${sev ? ` · ${sev}` : ""} across connected surfaces.`;
    }
    return `${sev} in the current snapshot.`;
  }

  // Nothing open: a backend summary can only be trusted here (it can't now
  // contradict the counts). Strip a trailing "(A, 95%)" that duplicates the
  // grade/score already shown beside it.
  const cleaned = summary?.replace(/\s*\([A-F][+-]?,\s*[\d.]+%\)\s*$/i, "").trim();
  return cleaned && cleaned.length > 0
    ? cleaned
    : "No open vulnerabilities across connected surfaces.";
}

export interface OverviewCockpitProps {
  /** True until the posture and cross-domain overview requests settle. */
  loading?: boolean | undefined;
  grade: string;
  score?: number | undefined;
  /** Display-only score presentation. Defaults to a percentage. */
  scoreFormat?: PostureScoreFormat | undefined;
  /** Weighted inputs behind the score, for the "what influences this" panel. */
  scoreBreakdown?: ExecScoreDriver[] | null | undefined;
  scoreFloored?: boolean | undefined;
  /** Called when the user picks a display format; parent persists it (#3940). */
  onScoreFormatChange?: ((format: PostureScoreFormat) => void) | undefined;
  postureSummary?: string | undefined;
  postureTrend?: {
    direction: "improved" | "worsened" | "unchanged";
    delta: number;
    previousScore: number;
    points: number;
  } | null | undefined;
  critical: number;
  high: number;
  kev: number | null;
  credentials: number | null;
  agents: number | null;
  cves: number | null;
  scans: number | null;
  latestScan: string | null;
  mode: string;
  summaryReady: boolean;
  /** Honest scope shared by the headline and its finding drill-downs. */
  findingsScopeLabel?: string | undefined;
  severity: SeverityCounts;
  /** Severity × issue-type matrix (CVEs, misconfigs, secrets, identity). */
  issueMatrix?: IssueSeverityMatrix | null | undefined;
  domains: OverviewResponse["domains"] | null;
  /** Five security-posture coverage lanes (CSPM / Vuln / ASPM / DSPM /
   *  AISPM) with reconciled, non-overlapping counts (issue #3946). */
  coverage?: OverviewCoverageLane[] | null | undefined;
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  signals: {
    tools: number | null;
    packages: number | null;
    activeServices: number;
    connected: boolean;
  };
  compliance?: OverviewComplianceSnapshot | null | undefined;
  services?: Partial<Record<ServiceId, ServiceEntry>> | null | undefined;
}

export function OverviewCockpit({
  loading = false,
  grade,
  score,
  scoreFormat = "percent",
  scoreBreakdown = null,
  scoreFloored,
  onScoreFormatChange,
  postureSummary,
  postureTrend = null,
  critical,
  high,
  kev,
  credentials,
  agents,
  cves,
  scans,
  latestScan,
  summaryReady,
  findingsScopeLabel,
  severity,
  issueMatrix = null,
  domains,
  coverage = null,
  topPath,
  exposurePaths,
  compliance = null,
  services = null,
}: OverviewCockpitProps) {
  const hasScanEvidence = Boolean(summaryReady && scans && scans > 0);
  // Once scans exist the chip always renders, but an unevidenced score reads as
  // an em dash — the SAME treatment the Trust Center gives this status. Hiding
  // the chip instead would leave the reader unable to tell "not measured" from
  // "not loaded"; printing the raw percentage claimed compliance we never
  // evidenced.
  const complianceEvaluated = hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance);
  const complianceScore = complianceEvaluated
    ? `${Math.round(compliance.overallScore)}%`
    : hasScanEvidence && compliance != null
      ? "—"
      : undefined;

  return (
    <div className="space-y-4">
      <div className="grid items-start gap-4 xl:grid-cols-2">
      <section aria-label="Command center" className="min-w-0 rounded-2xl border border-outline bg-surface p-4 lg:p-5">
        <Collapsible
          bare
          title="Command center"
          titleClassName={SECTION_TITLE_CLASS}
          subtitle="Current posture and open findings"
          defaultOpen
        >
          <FreshnessStatus latestScan={latestScan} scans={scans} loading={loading} />

          <div className="mt-3 grid gap-4">
            <PostureHero
              loading={loading}
              grade={grade}
              score={score}
              scoreFormat={scoreFormat}
              onScoreFormatChange={onScoreFormatChange}
              summary={postureSummary}
              trend={postureTrend}
              critical={critical}
              high={high}
              cves={cves}
            />
            <SeverityIssueStrip
              summaryReady={summaryReady}
              critical={critical}
              high={high}
              kev={kev}
              credentials={credentials}
              complianceScore={complianceScore}
              severity={severity}
              matrix={issueMatrix}
              scopeLabel={findingsScopeLabel}
            />
          </div>

          {/* 1b — What influences the score: read-only weighted-input breakdown
              so the grade is legible, not opaque (#3940). */}
          <ScoreExplainer breakdown={scoreBreakdown} grade={grade} floored={scoreFloored} />
        </Collapsible>
      </section>

      <section aria-label="Coverage & controls" className="min-w-0 rounded-2xl border border-outline bg-surface p-4 lg:p-5">
        <h2 className={SECTION_TITLE_CLASS}>Coverage &amp; controls</h2>
        <CoverageOperationsSection coverage={coverage} domains={domains} services={services} />
        <ComplianceSnapshotPanel compliance={compliance} hasScanEvidence={hasScanEvidence} />
      </section>
      </div>
      <section aria-label="Top risks" className="min-w-0">
        <TopRisksPanel
          topPath={topPath}
          exposurePaths={exposurePaths}
          agentMeshHref={agents != null && agents > 0 ? "/agents/topology" : null}
        />
      </section>

    </div>
  );
}

function FreshnessStatus({
  latestScan,
  scans,
  loading,
}: {
  latestScan: string | null;
  scans: number | null;
  loading: boolean;
}) {
  const label = loading
    ? "Loading scan evidence"
    : latestScan
    ? "Last successful scan"
    : scans === 0
      ? "No completed scan evidence"
      : "Last successful scan unavailable";

  return (
    <div
      data-testid="overview-freshness"
      role="status"
      className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1"
    >
      <div className="flex items-center gap-2">
        <span
          className={`h-2 w-2 rounded-full ${latestScan ? "bg-emerald-500" : "bg-ink-tertiary"}`}
          aria-hidden="true"
        />
        <span className="text-xs font-semibold text-foreground">{label}</span>
      </div>
      {loading ? (
        <span className="text-[11px] text-ink-tertiary">
          Refreshing current evidence.
        </span>
      ) : latestScan ? (
        <time className="text-xs font-medium tabular-nums text-ink-secondary">
          {latestScan}
        </time>
      ) : (
        <span className="text-[11px] text-ink-tertiary">
          {scans === 0 ? "Run a scan to establish freshness." : "The current evidence has no observed scan timestamp."}
        </span>
      )}
    </div>
  );
}

function CoverageOperationsSection({
  coverage,
  domains,
  services,
}: {
  coverage: OverviewCoverageLane[] | null | undefined;
  domains: OverviewResponse["domains"] | null;
  services: Partial<Record<ServiceId, ServiceEntry>> | null | undefined;
}) {
  const operationalTiles = buildOperationalTiles(domains);
  if ((!coverage || coverage.length === 0) && operationalTiles.length === 0) return null;

  const dataSources = services?.data_sources;
  const dataSourceCount =
    dataSources && (dataSources.state === "live" || dataSources.state === "connected")
      ? dataSources.count
      : 0;

  return (
    <div className="mt-3" data-testid="overview-coverage-operations">
      <EstateOpsStrip tiles={operationalTiles} />
      <Link href="/connections" className="mt-2 inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
        {dataSourceCount > 0 ? `${dataSourceCount} connected · ` : ""}
        Connections <ArrowRight className="h-3 w-3" />
      </Link>
      {coverage && coverage.length > 0 ? (
        <Collapsible bare className="mt-3 border-t border-outline"
          title="Findings by discipline" titleClassName={SECTION_TITLE_CLASS}
          subtitle="Overlapping finding counts, not collection coverage" defaultOpen={false}>
          <SecurityCoverageLanes coverage={coverage} />
        </Collapsible>
      ) : null}
    </div>
  );
}

// Severity bands shown in a coverage lane's strip, in descending order, plus
// ``unrated`` for findings whose severity is unknown/unscored (issue #3946).
const COVERAGE_SEVERITY_BANDS: { key: keyof OverviewCoverageLane["severity"]; label: string; token: string }[] = [
  { key: "critical", label: "Critical", token: "--severity-critical" },
  { key: "high", label: "High", token: "--severity-high" },
  { key: "medium", label: "Medium", token: "--severity-medium" },
  { key: "low", label: "Low", token: "--severity-low" },
  { key: "unrated", label: "Unrated", token: "--severity-unrated" },
];

/**
 * The security-posture coverage lanes rendered 1:1 (CSPM / Vuln mgmt / ASPM /
 * DSPM / AISPM). These are overlapping posture *disciplines* (lenses), not a
 * partition: one finding can count in several lanes (a repo CVE is both Vuln
 * mgmt and ASPM; an IaC misconfig is both CSPM and ASPM), so the lanes are not
 * additive — the caption above says so, and nothing here presents a lane total.
 * Each lane's count is the sum of its own severity strip, so the metric can
 * never contradict the strip. An ``unrated`` chip is surfaced only when
 * unknown-severity findings are present. All colors come from design tokens (no
 * hardcoded palette) so light + dark both read correctly.
 */
function SecurityCoverageLanes({ coverage }: { coverage?: OverviewCoverageLane[] | null | undefined }) {
  if (!coverage || coverage.length === 0) return null;
  return (
    <div className="pt-1" data-testid="overview-security-coverage">
      <h3 className="mb-1 text-xs font-semibold text-foreground">Security disciplines</h3>
      <p className="mb-2 text-[11px] leading-4 text-ink-tertiary">
        Open findings per posture discipline — not assets or accounts. Lenses overlap, so one repo CVE counts under both Vuln mgmt and ASPM; lanes are not additive and will not sum to the total. Zero open findings does not establish assessment coverage.
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {coverage.map((lane) => {
          const known = lane.evidence_status !== undefined;
          const exact = lane.evidence_status === "complete" && lane.count_exact !== false;
          const statusLabel = lane.evidence_status === "partial" ? "Partial count" : "Count unavailable";
          const total = COVERAGE_SEVERITY_BANDS.reduce((sum, band) => sum + (lane.severity[band.key] || 0), 0);
          const bands = COVERAGE_SEVERITY_BANDS.filter((band) => (lane.severity[band.key] || 0) > 0);
          return (
            <Link
              key={lane.domain}
              href={lane.href}
              data-testid={`coverage-lane-${lane.domain}`}
              className="flex flex-col gap-2 rounded-xl border border-outline bg-surface-elevated p-3 transition-colors hover:border-outline-strong"
            >
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-xs font-semibold text-foreground">{lane.label}</span>
                {/* The unit is not decoration. A bare "1610" under a heading
                    called CSPM reads as assets, accounts, VMs or data stores
                    depending on the reader — every one of which is wrong. These
                    are FINDINGS in that posture lane, which is also what the
                    severity chips below sum to. */}
                <span className="flex items-baseline gap-1">
                  <span className="text-lg font-bold tabular-nums text-foreground">
                    {known && total > 0 ? `${exact ? "" : "≥"}${lane.count.toLocaleString()}` : "—"}
                  </span>
                  {known && total > 0 ? (
                    <span className="text-[10px] font-medium uppercase tracking-[0.08em] text-ink-tertiary">
                      {lane.count === 1 ? "finding" : "findings"}
                    </span>
                  ) : null}
                </span>
              </div>
              {!exact && known && total > 0 ? (
                <span className="text-[11px] text-ink-tertiary">{statusLabel} · at least this many</span>
              ) : null}
              {/* Stacked severity strip — widths reflect share of the lane count. */}
              <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-surface-muted">
                {known && total > 0 &&
                  bands.map((band) => (
                    <span
                      key={band.key}
                      className="h-full"
                      style={{
                        width: `${((lane.severity[band.key] || 0) / total) * 100}%`,
                        backgroundColor: `var(${band.token})`,
                      }}
                    />
                  ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {!known || total === 0 ? (
                  <span className="text-[11px] text-ink-tertiary">{exact ? "No open findings" : statusLabel}</span>
                ) : (
                  bands.map((band) => (
                    <span
                      key={band.key}
                      className="rounded px-1.5 py-0.5 text-[11px] font-medium tabular-nums"
                      style={{
                        color: `var(${band.token})`,
                        backgroundColor: `var(${band.token}-bg)`,
                        border: `1px solid var(${band.token}-border)`,
                      }}
                    >
                      {band.label} {lane.severity[band.key]}
                    </span>
                  ))
                )}
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

// The genuinely-operational estate lanes — cloud / vuln / code are deliberately
// excluded because the five security-coverage lanes above already own CSPM,
// Vuln mgmt, and ASPM. Rendering them here too would double-count.
const OPERATIONAL_DOMAIN_KEYS = ["runtime", "cost", "identity", "ops"] as const;
type OperationalDomainKey = (typeof OPERATIONAL_DOMAIN_KEYS)[number];

type OpsTile = {
  key: OperationalDomainKey;
  label: string;
  metric: number;
  metricLabel: string;
  status: OverviewDomainStatus;
  href: string;
  /** One-line scope clarifier surfaced as a tooltip so the tile can stay a
   *  terse name + count + dot instead of an always-visible sentence. */
  hint?: string | undefined;
};

function buildOperationalTiles(domains: OverviewResponse["domains"] | null): OpsTile[] {
  if (!domains) return [];
  return OPERATIONAL_DOMAIN_KEYS.flatMap((key) => {
    const domain = domains[key];
    if (!domain) return [];
    return [{
      key,
      label: domain.label,
      metric: domain.metric,
      metricLabel: domain.metric_label,
      status: domain.status,
      href: domain.graph_href ?? domain.href,
      hint: LANE_HINTS[key],
    }];
  });
}

// Scope clarifiers keyed by the operational domain key, shown as tooltips only.
const LANE_HINTS: Record<OperationalDomainKey, string> = {
  runtime: "Live runtime surfaces — gateway, proxy, traces, and agent mesh.",
  cost: "LLM spend tracked across agents and providers.",
  identity: "Non-human identities and agents under governance.",
  ops: "Completed scan jobs feeding the estate rollup.",
};

/** A lane is "active" once it is reporting (status !== idle) or carries a
 *  non-zero metric — otherwise it's applicable-but-not-connected. */
function opsLaneActive(tile: OpsTile): boolean {
  return tile.status !== "idle" || tile.metric > 0;
}

/**
 * Estate / operations strip — the genuinely-operational lanes (runtime, cost,
 * identity, ops) shown by activation. Active lanes get a full tile with their
 * number + status dot; applicable-but-not-connected lanes de-emphasize into a
 * muted "Connect …" prompt so the strip never fabricates a wall of zero tiles.
 * Verbose scope copy lives in tooltips, not always-visible sentences. This is a
 * lighter-weight companion to the five security-coverage lanes above.
 */
function EstateOpsStrip({
  tiles,
}: {
  tiles: OpsTile[];
}) {
  if (tiles.length === 0) return null;

  const active = tiles.filter(opsLaneActive).length;

  return (
    <div data-testid="overview-estate-ops">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold text-foreground">Operational signals</h3>
        <span className="text-[11px] text-ink-tertiary">
          {active} of {tiles.length} active
        </span>
      </div>
      <div className="mt-1 grid gap-2 sm:grid-cols-2">
        {tiles.map((tile) => (
          <OpsTileCard key={tile.key} tile={tile} />
        ))}
      </div>
    </div>
  );
}

function OpsTileCard({ tile }: { tile: OpsTile }) {
  // Applicable-but-not-connected lane: de-emphasize into a muted, available
  // "Connect …" affordance instead of a loud zero tile.
  if (!opsLaneActive(tile)) {
    return (
      <Link
        href={tile.href}
        title={tile.hint ?? tile.label}
        className="flex items-center justify-between gap-2 rounded-lg border border-dashed border-outline bg-transparent px-3 py-2 text-ink-tertiary transition hover:border-outline-strong hover:text-foreground"
      >
        <span className="truncate text-[11px] font-medium">{tile.label}</span>
        <span className="inline-flex shrink-0 items-center gap-1 text-[10px] font-medium">
          Connect <ArrowRight className="h-3 w-3" />
        </span>
      </Link>
    );
  }

  const tone = domainStatusTone(tile.status);
  return (
    <Link
      href={tile.href}
      title={tile.hint ?? tile.label}
      className="flex items-center justify-between gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-2 transition hover:border-outline-strong"
    >
      <div className="flex min-w-0 items-center gap-2">
        <span className={`h-2 w-2 shrink-0 rounded-full ${tone.dot}`} aria-hidden="true" />
        <span className="truncate text-[11px] font-medium text-foreground">{tile.label}</span>
      </div>
      <div className="flex min-w-0 flex-wrap items-baseline justify-end gap-x-1">
        <span className={`font-mono text-base font-semibold ${tone.text}`}>{tile.metric}</span>
        <span className="text-right text-[10px] text-ink-tertiary" title={tile.metricLabel}>
          {tile.metricLabel}
        </span>
      </div>
    </Link>
  );
}

function ComplianceSnapshotPanel({
  compliance,
  hasScanEvidence = false,
  defaultOpen = true,
}: {
  compliance: OverviewComplianceSnapshot | null | undefined;
  hasScanEvidence?: boolean | undefined;
  defaultOpen?: boolean | undefined;
}) {
  const allFrameworks = compliance?.frameworks ?? [];
  const frameworks = allFrameworks.slice(0, 8);
  const evidenceReady = hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance);
  const failing = evidenceReady ? allFrameworks.filter((item) => item.kind === "scored" && item.fail > 0).length : 0;


  return (
    <Collapsible
      bare
      className="mt-4 border-t border-outline"
      title="Evaluated compliance"
      titleClassName={SECTION_TITLE_CLASS}
      defaultOpen={defaultOpen}
      subtitle={<span className="block whitespace-normal">{
        evidenceReady
          ? `${Math.round(compliance.overallScore)}% of ${compliance.evaluatedControls} evaluated control${compliance.evaluatedControls === 1 ? "" : "s"} · ${failing} framework${failing === 1 ? " needs" : "s need"} attention`
          : hasScanEvidence
            ? "No evaluated framework coverage is available for completed scans"
            : "Framework coverage appears after the first completed scan"
      }</span>}
      count={evidenceReady && allFrameworks.length > 0 ? allFrameworks.length : undefined}
      scrollMaxHeight="16rem"
      data-testid="overview-compliance-snapshot"
      actions={
        <div className="flex items-center gap-3">
          <Link href="/compliance" className="inline-flex items-center gap-1 text-xs text-emerald-500 hover:text-emerald-400">
            Trust center <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      }
    >
      {evidenceReady && frameworks.length > 0 ? (
        <div className="grid gap-2 sm:grid-cols-2">
          {frameworks.map((framework) => {
            const evaluated = frameworkEvaluated(framework);
            const isApplicability = framework.kind === "applicability";
            // 0 evaluated controls is NOT a pass — surface a neutral
            // "not evaluated" state so an unscored framework never reads green.
            const tone =
              isApplicability
                ? (framework.applicable ?? 0) > 0 ? "applicability" : "not_applicable"
                : evaluated === 0
                ? "not_evaluated"
                : framework.fail > 0
                  ? "fail"
                  : framework.warn > 0
                    ? "warn"
                    : "pass";
            return (
              <Link
                key={framework.id}
                href="/compliance"
                className="grid min-h-[3.25rem] grid-cols-[2rem_minmax(0,1fr)_auto] items-center gap-2.5 rounded-xl border border-outline bg-surface-muted px-2.5 py-2 transition hover:border-outline-strong"
              >
                <FrameworkIcon frameworkId={framework.id} size={32} />
                <div className="min-w-0">
                  <p className="text-[11px] font-semibold leading-tight text-foreground">
                    {framework.label}
                  </p>
                  <p className="mt-0.5 text-[10px] leading-tight text-ink-tertiary">
                    {isApplicability
                      ? `${framework.applicable ?? 0}/${framework.total} risks applicable`
                      : evaluated === 0
                      ? `Not evaluated · 0/${framework.total} controls`
                      : `${framework.pass}/${evaluated} pass${framework.fail > 0 ? ` · ${framework.fail} fail` : ""}`}
                  </p>
                </div>
                <span
                  className={`justify-self-end rounded-full px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${
                    tone === "applicability"
                      ? "bg-sky-500/15 text-sky-700 dark:text-sky-300"
                      : tone === "fail"
                      ? "bg-red-500/15 text-red-700 dark:text-red-300"
                      : tone === "warn"
                        ? "bg-yellow-500/15 text-yellow-700 dark:text-yellow-200"
                        : tone === "pass"
                          ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : "border border-outline bg-surface text-ink-tertiary"
                  }`}
                >
                  {tone === "applicability" ? "Risks mapped" : tone === "not_applicable" ? "none" : tone === "not_evaluated" ? "n/a" : tone}
                </span>
              </Link>
            );
          })}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-outline bg-surface-muted px-4 py-5 text-center text-xs text-ink-tertiary">
          {hasScanEvidence
            ? "Completed scans have not produced mapped framework evidence. Review scan scope before drawing a compliance conclusion."
            : "Run a scan to light up OWASP, NIST, CIS, and related framework coverage. Empty estates do not show pass tiles."}
        </div>
      )}
    </Collapsible>
  );
}

function TopRisksPanel({
  topPath,
  exposurePaths,
  agentMeshHref = null,
}: {
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  agentMeshHref?: string | null;
}) {
  const allPaths = exposurePaths.length > 0 ? exposurePaths : topPath ? [topPath] : [];
  const ranked = [...allPaths].sort((a, b) => b.riskScore - a.riskScore);
  const shown = ranked.slice(0, 3);
  const moreCount = ranked.length - shown.length;

  return (
    <Collapsible title="Top risks" subtitle="Prioritized findings and affected workloads"
      count={ranked.length || undefined} defaultOpen>
      {shown.length > 0 ? (
        <div className="space-y-2">
          {shown.map((path, index) => <RiskChainRow key={path.key} path={path} rank={index + 1} />)}
        </div>
      ) : (
        <p className="text-sm text-ink-secondary">
          Run a scan to correlate CVEs, packages, agents, and credentials into ranked exposure paths.
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
        <Link href="/security-graph" className="text-emerald-600 dark:text-emerald-400">
          {moreCount > 0 ? `Security graph · ${moreCount} more risk paths` : "Security graph"}
        </Link>
        {agentMeshHref ? <Link href={agentMeshHref} className="text-emerald-600 dark:text-emerald-400">Agent mesh</Link> : null}
        <Link href="/findings?scope=all&severity=critical" className="text-ink-secondary">Critical findings</Link>
        <Link href="/compliance" className="text-ink-secondary">Compliance evidence</Link>
      </div>
    </Collapsible>
  );
}

function RiskChainRow({ path, rank }: { path: ExposurePathView; rank: number }) {
  const finding = path.nodes.find((node) => node.type === "cve");
  const pkg = path.nodes.find((node) => node.type === "package");
  const workload = path.nodes.find((node) => node.type === "agent") ?? path.nodes.find((node) => node.type === "server");
  const sbomSource = workload ? sbomSourceName(workload.label) : null;
  const findingLabel = finding && /^(CVE-\d{4}-\d+|GHSA-[\w-]+)$/i.test(finding.label) ? finding.label : "Finding";
  const severity = finding?.severity?.toLowerCase();
  const knownSeverity = severity && ["critical", "high", "medium", "low"].includes(severity) ? severity : null;

  const severityTone = knownSeverity === "critical"
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : knownSeverity === "high"
      ? "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300"
      : "border-outline bg-surface-muted text-ink-secondary";

  return (
    <article className={`rounded-lg border ${rank === 1 ? "border-outline-strong bg-surface-muted/40" : "border-outline"}`}>
      <Link href={path.href} className="group block rounded-lg p-3 transition hover:bg-surface-muted">
        <div className="flex items-start gap-2">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-outline font-mono text-xs text-ink-secondary">{rank}</span>
          <div className="grid min-w-0 flex-1 gap-x-4 xl:grid-cols-[minmax(0,1fr)_auto]">
            <p className="text-base font-semibold leading-snug text-foreground [overflow-wrap:anywhere]">
              <span>{findingLabel}</span>{pkg ? <> in <span>{pkg.label}</span></> : null}
            </p>
            <p className="mt-1 text-xs text-ink-secondary [overflow-wrap:anywhere] xl:col-start-1">
              {sbomSource ? `SBOM source: ${sbomSource}` : workload ? `Affected workload: ${workload.label}` : "Workload not identified"}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-secondary xl:col-start-2 xl:row-start-1 xl:row-span-2 xl:mt-0">
              <span className={`rounded-md border px-2 py-0.5 font-semibold capitalize ${severityTone}`}>{knownSeverity ? `${knownSeverity} severity` : "Severity unavailable"}</span>
              <span>Path priority <strong className="font-semibold tabular-nums text-foreground">{Number.isFinite(path.riskScore) ? path.riskScore.toFixed(1) : "unavailable"}</strong></span>
              <span className="inline-flex items-center gap-1 font-medium text-emerald-600 dark:text-emerald-400">Inspect finding <ArrowRight className="h-3 w-3" aria-hidden="true" /></span>
            </div>
          </div>
        </div>
      </Link>
      <details className="border-t border-outline px-3 py-2 text-xs">
        <summary className="cursor-pointer text-ink-tertiary">Technical details</summary>
        <dl className="mt-2 space-y-2">
          {path.nodes.map((node, index) => (
            <div key={`${node.type}-${index}`} className="grid grid-cols-[5rem_minmax(0,1fr)] gap-2">
              <dt className="capitalize text-ink-tertiary">{node.type === "cve" ? "Finding" : (node.type === "agent" || node.type === "server") && sbomSourceName(node.label) !== null ? "SBOM source" : node.type}</dt>
              <dd className="text-ink-secondary [overflow-wrap:anywhere]">{node.label}</dd>
            </div>
          ))}
        </dl>
      </details>
    </article>
  );
}

/**
 * Read-only "what influences this score" panel. Lists the weighted inputs
 * (severity buckets, KEV, exposure, compliance, unrated) with each driver's
 * count × weight = relative pressure, so the grade is legible instead of an
 * opaque number (#3940). Only inputs with finite positive pressure are shown.
 * A full weight/threshold editor is a documented follow-up.
 */
function ScoreExplainer({
  breakdown,
  grade,
  floored,
}: {
  floored?: boolean | undefined;
  breakdown?: ExecScoreDriver[] | null | undefined;
  grade: string;
}) {
  const ungraded = grade === "N/A" || grade === "—";
  const rows = (breakdown ?? [])
    .filter((row) => Number.isFinite(row.contribution) && row.contribution > 0 && Number.isFinite(row.count) && Number.isFinite(row.weight))
    .sort((a, b) => b.contribution - a.contribution);
  if (ungraded || rows.length === 0) return null;
  const totalPressure = rows.reduce((sum, row) => sum + row.contribution, 0);

  return (
    <Collapsible
      bare
      className="mt-4 border-t border-outline"
      title="What influences this score"
      titleClassName={SECTION_TITLE_CLASS}
      subtitle="Relative weighted inputs and scoring method"
      defaultOpen={false}
      data-testid="overview-score-explainer"
    >
      <div className="mt-2 space-y-1.5">
        {rows.map((row) => {
          return (
            <div key={row.driver} className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3" data-testid={`score-driver-${row.driver}`}>
              <span className="text-[11px] text-ink-secondary" title={row.label}>
                {row.label}
              </span>
              <span className="text-right font-mono text-[11px] tabular-nums text-ink-tertiary">
                {row.count} × {row.weight}
              </span>
              <span className="w-14 shrink-0 text-right font-mono text-[11px] font-semibold tabular-nums text-foreground">
                {row.contribution.toFixed(1)}
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-xs font-medium text-ink-secondary">Total weighted pressure: {totalPressure.toFixed(1)}</p>
      <p className="mt-2 text-xs leading-relaxed text-ink-tertiary">
        Each input is count × weight. The server converts combined pressure to a score using a nonlinear curve;
        these values are not points deducted from 100.
        {floored === true ? " The worse recorded scan posture limits the displayed score." : ""}
        {floored === undefined ? " Whether a recorded scan limits this score is unavailable." : ""}
      </p>
    </Collapsible>
  );
}

const SCORE_FORMAT_OPTIONS: { value: PostureScoreFormat; label: string }[] = [
  { value: "grade", label: "Grade" },
  { value: "percent", label: "%" },
  { value: "points", label: "Points" },
];

function ScoreFormatToggle({
  value,
  onChange,
}: {
  value: PostureScoreFormat;
  onChange: (format: PostureScoreFormat) => void;
}) {
  return (
    <div
      className="inline-flex overflow-hidden rounded-md border border-outline"
      role="group"
      aria-label="Score display format"
      data-testid="score-format-toggle"
    >
      {SCORE_FORMAT_OPTIONS.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            aria-pressed={active}
            className={`px-1.5 py-0.5 text-[10px] font-semibold transition ${
              active
                ? "bg-surface-elevated text-foreground"
                : "bg-surface-muted text-ink-tertiary hover:text-foreground"
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

function PostureHero({
  loading,
  grade,
  score,
  scoreFormat = "percent",
  onScoreFormatChange,
  summary,
  trend,
  critical,
  high,
  cves,
}: {
  loading: boolean;
  grade: string;
  score?: number | undefined;
  scoreFormat?: PostureScoreFormat | undefined;
  onScoreFormatChange?: ((format: PostureScoreFormat) => void) | undefined;
  summary?: string | undefined;
  trend?: OverviewCockpitProps["postureTrend"];
  critical: number;
  high: number;
  cves: number | null;
}) {
  const ungraded = grade === "N/A" || grade === "—";
  const graded = typeof score === "number" && !ungraded;
  const scoreDisplay = graded ? formatPostureScore(score, grade, scoreFormat) : null;
  const scoreTone = graded && ["D", "F"].includes(grade)
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : graded && grade === "C"
      ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200"
      : "border-outline-strong bg-surface-muted text-foreground";
  const blurb = loading
    ? "Refreshing the current posture and evidence summary."
    : derivePostureBlurb({ summary, critical, high, cves, graded });

  return (
    <div className="flex items-center gap-4">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-tertiary">
            Risk posture
          </p>
          {graded && onScoreFormatChange ? (
            <ScoreFormatToggle value={scoreFormat} onChange={onScoreFormatChange} />
          ) : null}
        </div>
        <p className={`mt-2 inline-flex flex-wrap items-baseline gap-3 rounded-xl border px-4 py-3 font-semibold ${scoreTone}`} data-testid="overview-posture-score">
          {loading ? (
            "Loading posture…"
          ) : graded ? (
            <>
              {/* Always show BOTH the letter grade and the %/points, whatever the
                  chosen primary format, so the number is never ambiguous. */}
              <span className="text-4xl leading-none tracking-tight tabular-nums">{scoreDisplay}</span>
              {scoreFormat !== "grade" ? (
                <span className="text-xs font-medium text-ink-tertiary">Grade {grade}</span>
              ) : typeof score === "number" ? (
                <span className="text-xs font-medium text-ink-tertiary">{Math.round(score)}%</span>
              ) : null}
            </>
          ) : (
            "Awaiting scan"
          )}
        </p>
        {graded ? (
          trend && trend.points >= 2 ? (
            <p
              className="mt-1 text-[10px] text-ink-tertiary"
              data-testid="overview-posture-trend"
              title={`Previous posture score: ${Math.round(trend.previousScore)}%`}
            >
              {trend.direction === "unchanged"
                ? "Unchanged since the previous scan"
                : `${trend.direction === "improved" ? "Improved" : "Worsened"} ${Math.abs(Math.round(trend.delta))} points since the previous scan`}
            </p>
          ) : (
            <p className="mt-1 text-[10px] text-ink-tertiary">
              Current evidence snapshot · ranked exposure paths below show what to fix first
            </p>
          )
        ) : null}
        <p className="mt-1 text-xs text-ink-secondary">{blurb}</p>
      </div>
    </div>
  );
}

// One distinct glyph per issue type so a category reads by shape, not by a
// severity hue it doesn't own (KEV/Secrets/Misconfig/Identity all go neutral).
const ISSUE_TYPE_GLYPH: Record<IssueType, ElementType> = {
  vulnerability: Bug,
  misconfiguration: SlidersHorizontal,
  secret: KeyRound,
  pii: UserRound,
  identity: Fingerprint,
  unclassified: Bug,
};

// Neutral grayscale fills for the in-tile issue-type mini bar — segments stay
// distinguishable by lightness (theme-safe text tokens), never by severity hue.
const ISSUE_TYPE_BAR: Record<IssueType, string> = {
  vulnerability: "bg-ink-secondary",
  misconfiguration: "bg-ink-tertiary",
  secret: "bg-ink-secondary opacity-60",
  pii: "bg-ink-secondary opacity-45",
  identity: "bg-ink-tertiary opacity-50",
  unclassified: "bg-ink-tertiary opacity-35",
};

/**
 * A neutral, iconified category chip for the Open-issues header (KEV / Secrets /
 * Compliance). Uses only surface/border/text tokens so it never mimics a
 * severity band; the glyph carries the category meaning. Works in both themes.
 */
function CategoryChip({
  href,
  icon: Icon,
  label,
  value,
  title,
}: {
  href: string;
  icon: ElementType;
  label: string;
  value: number | string;
  title?: string | undefined;
}) {
  return (
    <Link
      href={href}
      title={title}
      className="inline-flex items-center gap-1 rounded-full border border-outline bg-surface-muted px-2 py-0.5 text-[10px] font-semibold text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
    >
      <Icon className="h-3 w-3 text-ink-tertiary" aria-hidden="true" />
      {label} {value}
    </Link>
  );
}

function SeverityIssueStrip({
  summaryReady,
  critical,
  high,
  kev,
  credentials,
  complianceScore,
  severity,
  matrix,
  scopeLabel,
}: {
  summaryReady: boolean;
  critical: number;
  high: number;
  kev: number | null;
  credentials: number | null;
  complianceScore?: string | undefined;
  severity: SeverityCounts;
  matrix: IssueSeverityMatrix | null | undefined;
  scopeLabel?: string | undefined;
}) {
  const resolved = matrix ?? emptyIssueSeverityMatrix();
  const hasTyped = resolved.openTotal > 0;
  const bands: { key: SeverityBand; label: string; tone: string; tint: string; value: number }[] = [
    {
      key: "critical",
      label: "Critical",
      tone: "text-[color:var(--severity-critical)]",
      tint: "border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] hover:border-[color:var(--severity-critical)]",
      value: summaryReady ? (hasTyped ? resolved.totals.critical : critical) : 0,
    },
    {
      key: "high",
      label: "High",
      tone: "text-[color:var(--severity-high)]",
      tint: "border-[color:var(--severity-high-border)] bg-[color:var(--severity-high-bg)] hover:border-[color:var(--severity-high)]",
      value: summaryReady ? (hasTyped ? resolved.totals.high : high) : 0,
    },
    {
      key: "medium",
      label: "Medium",
      tone: "text-[color:var(--severity-medium)]",
      tint: "border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] hover:border-[color:var(--severity-medium)]",
      value: summaryReady ? (hasTyped ? resolved.totals.medium : severity.medium) : 0,
    },
    {
      key: "low",
      label: "Low",
      tone: "text-[color:var(--severity-low)]",
      tint: "border-[color:var(--severity-low-border)] bg-[color:var(--severity-low-bg)] hover:border-[color:var(--severity-low)]",
      value: summaryReady ? (hasTyped ? resolved.totals.low : severity.low) : 0,
    },
  ];
  const stackedTotal = bands.reduce((sum, band) => sum + band.value, 0);
  const issueTypes: IssueType[] = ["vulnerability", "misconfiguration", "secret", "pii", "identity", "unclassified"];

  return (
    <div
      className="min-w-0 rounded-xl border border-outline bg-surface-muted px-3 py-1"
      data-testid="overview-severity-issue-strip"
    >
      <Collapsible
        bare
        title="Open issues"
        titleClassName={SECTION_TITLE_CLASS}
        subtitle={scopeLabel ?? "By severity and issue class"}
        defaultOpen
      >
          <div className="mb-3 flex flex-wrap items-center gap-1.5">
            {/* Category chips are neutral + iconified: hue is reserved for
                severity alone, so a category never mimics a severity band
                (KEV is not amber, Secrets is not red, Compliance is not a
                green pass). The glyph carries the distinction. */}
            {summaryReady && kev != null ? (
              <CategoryChip
                href={findingsHref({ scope: "all", kev: true })}
                icon={Flame}
                label="KEV"
                value={kev}
                title="Known-exploited vulnerabilities (CISA KEV)"
              />
            ) : null}
            {summaryReady && credentials != null ? (
              <CategoryChip
                href={findingsHref({ scope: "all", issue: "secret" })}
                icon={KeyRound}
                label="Secrets"
                value={credentials}
                title="Findings that expose credentials or secrets"
              />
            ) : null}
            {complianceScore ? (
              <CategoryChip
                href="/compliance"
                icon={ShieldCheck}
                label="Compliance"
                value={complianceScore}
                title={
                  complianceScore === "—"
                    ? "No framework was substantively evaluated — nothing to score"
                    : "Overall compliance score across evaluated frameworks"
                }
              />
            ) : null}
          </div>
      <div className="mb-3 mt-1 flex h-2.5 overflow-hidden rounded-full bg-surface">
        {summaryReady && stackedTotal > 0 ? (
          bands.map((band) =>
            band.value > 0 ? (
              <div
                key={band.key}
                className={
                  band.key === "critical"
                    ? "bg-[color:var(--severity-critical)]"
                    : band.key === "high"
                      ? "bg-[color:var(--severity-high)]"
                      : band.key === "medium"
                        ? "bg-[color:var(--severity-medium)]"
                        : "bg-[color:var(--severity-low)]"
                }
                style={{ width: `${(band.value / stackedTotal) * 100}%` }}
                title={`${band.label}: ${band.value}`}
              />
            ) : null,
          )
        ) : (
          <div className="w-full bg-[color:var(--status-success)]/35" />
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {bands.map((band) => (
          <Link
            key={band.key}
            href={findingsHref({ scope: "all", severity: band.key })}
            className={`rounded-lg border px-2.5 py-2 transition ${band.tint}`}
          >
            <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-ink-secondary">
              {band.label}
            </p>
            <p className={`mt-1 font-mono text-xl font-semibold ${band.tone}`}>
              {summaryReady ? band.value : "—"}
            </p>
            {hasTyped && summaryReady ? (
              <div className="mt-2 space-y-1">
                <div className="flex h-1.5 overflow-hidden rounded-full bg-surface-muted">
                  {issueTypes.map((issue) => {
                    const count = resolved[issue][band.key];
                    if (count <= 0 || band.value <= 0) return null;
                    return (
                      <div
                        key={issue}
                        className={ISSUE_TYPE_BAR[issue]}
                        style={{ width: `${(count / band.value) * 100}%` }}
                        title={`${ISSUE_TYPE_SHORT[issue]}: ${count}`}
                      />
                    );
                  })}
                </div>
                <div className="flex flex-wrap gap-x-1.5 gap-y-0.5 text-[9px] text-ink-tertiary">
                  {issueTypes.map((issue) => {
                    const count = resolved[issue][band.key];
                    if (count <= 0) return null;
                    const Glyph = ISSUE_TYPE_GLYPH[issue];
                    return (
                      <span key={issue} className="inline-flex items-center gap-0.5">
                        <Glyph className="h-2.5 w-2.5" aria-hidden="true" />
                        {ISSUE_TYPE_SHORT[issue]} {count}
                      </span>
                    );
                  })}
                </div>
              </div>
            ) : (
              <p className="mt-2 text-[9px] text-ink-tertiary">All issue types</p>
            )}
          </Link>
        ))}
      </div>

      {hasTyped && summaryReady ? (
        <div className="mt-3 flex flex-wrap gap-2 border-t border-outline pt-2.5">
          {issueTypes.map((issue) => {
            const total = resolved.byType[issue];
            if (total <= 0) return null;
            const Glyph = ISSUE_TYPE_GLYPH[issue];
            return (
              <Link
                key={issue}
                href={findingsHref({ scope: "all", issue })}
                className="inline-flex items-center gap-1.5 rounded-full border border-outline bg-surface px-2 py-0.5 text-[10px] text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
              >
                <Glyph className="h-3 w-3 text-ink-tertiary" aria-hidden="true" />
                {ISSUE_TYPE_SHORT[issue]} {total}
              </Link>
            );
          })}
        </div>
      ) : null}
      </Collapsible>
    </div>
  );
}

function domainStatusTone(status: OverviewDomainStatus): { dot: string; text: string } {
  switch (status) {
    case "critical":
      return { dot: "bg-red-500", text: "text-red-400" };
    case "warn":
      return { dot: "bg-amber-500", text: "text-amber-400" };
    case "ok":
      return { dot: "bg-emerald-500", text: "text-emerald-400" };
    default:
      return { dot: "bg-ink-tertiary", text: "text-ink-tertiary" };
  }
}
