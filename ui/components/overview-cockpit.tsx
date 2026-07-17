"use client";

import Link from "next/link";
import type { ElementType } from "react";
import {
  ArrowRight,
  Bug,
  ChevronRight,
  Fingerprint,
  Flame,
  KeyRound,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";

import type { OverviewResponse } from "@/lib/api";
import type {
  ExecScoreDriver,
  OverviewCoverageLane,
  OverviewDomainStatus,
  ServiceEntry,
  ServiceId,
} from "@/lib/api-types";
import { Collapsible } from "@/components/collapsible";
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
};

export type OverviewComplianceSnapshot = {
  overallScore: number;
  overallStatus: "pass" | "warning" | "fail";
  frameworks: OverviewComplianceFramework[];
};

/** Controls a framework actually scored (pass/warn/fail) — NOT its catalogue
 *  size. A framework with 10 bundled controls but 0 mapped findings has
 *  `total` 10 yet `evaluated` 0, and must never read as a green PASS (#3889). */
function frameworkEvaluated(framework: OverviewComplianceFramework): number {
  return framework.pass + framework.warn + framework.fail;
}

function hasEvaluatedCompliance(compliance: OverviewComplianceSnapshot | null | undefined): boolean {
  return Boolean(compliance?.frameworks.some((framework) => frameworkEvaluated(framework) > 0));
}

// Shared class for the collapsible section headers (Command center, Cross-lane
// coverage, Open issues, Compliance) — larger + normal-case so exec section
// titles read as headings, not micro-labels (issue #3940 / #3931 item G).
const SECTION_TITLE_CLASS =
  "text-sm font-semibold normal-case tracking-normal text-[color:var(--foreground)]";

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
      critical > 0 ? `${critical} critical` : null,
      high > 0 ? `${high} high` : null,
    ].filter(Boolean);
    const sev = sevBits.join(" · ");
    if (openCves > 0) {
      return `${openCves} open CVE${openCves === 1 ? "" : "s"}${sev ? ` · ${sev}` : ""} across connected surfaces.`;
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
  grade: string;
  score?: number | undefined;
  /** Display-only score presentation. Defaults to a percentage. */
  scoreFormat?: PostureScoreFormat | undefined;
  /** Weighted inputs behind the score, for the "what influences this" panel. */
  scoreBreakdown?: ExecScoreDriver[] | null | undefined;
  /** Delta from authoritative posture history. null means no comparable history. */
  scoreTrend?: { delta: number; previousScore: number; timestamp: string } | null | undefined;
  /** Called when the user picks a display format; parent persists it (#3940). */
  onScoreFormatChange?: ((format: PostureScoreFormat) => void) | undefined;
  postureSummary?: string | undefined;
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
  grade,
  score,
  scoreFormat = "percent",
  scoreBreakdown = null,
  scoreTrend,
  onScoreFormatChange,
  postureSummary,
  critical,
  high,
  kev,
  credentials,
  agents,
  cves,
  scans,
  latestScan,
  summaryReady,
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
  const complianceScore =
    hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance)
      ? `${Math.round(compliance.overallScore)}%`
      : undefined;

  return (
    <div className="space-y-4">
      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 lg:p-5">
        <Collapsible
          bare
          title="Command center"
          titleClassName={SECTION_TITLE_CLASS}
          subtitle="Posture and open issues across every lane — one exec read."
          defaultOpen
        >
          {/* 1 — Posture headline + open issues by severity.
              Posture track is capped (minmax) so a long summary can't grow it
              unbounded and squeeze the open-issues severity tiles into an
              unreadable sliver. */}
          <div className="mt-1 grid gap-5 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)] lg:items-start">
            <PostureHero
              grade={grade}
              score={score}
              scoreFormat={scoreFormat}
              onScoreFormatChange={onScoreFormatChange}
              summary={postureSummary}
              critical={critical}
              high={high}
              cves={cves}
              latestScan={latestScan}
              scoreTrend={scoreTrend}
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
            />
          </div>

          {/* 1b — What influences the score: read-only weighted-input breakdown
              so the grade is legible, not opaque (#3940). */}
          <ScoreExplainer breakdown={scoreBreakdown} grade={grade} />

          {/* 2 — Security coverage: the five posture domains 1:1, each with a
              reconciled severity strip (sum === count, unrated shown). This is
              the lead coverage block — the exec security posture. */}
          <SecurityCoverageLanes coverage={coverage} />

          {/* 2b — Estate / operations: the genuinely-operational lanes
              (runtime, cost, identity, ops) shown by activation. The security
              lanes above already cover cloud posture, vuln mgmt, and application posture. */}
          <EstateOpsStrip domains={domains} services={services} />

          {/* 3 — Compliance: one honest strip, coverage after first scan */}
          <ComplianceSnapshotPanel compliance={compliance} hasScanEvidence={hasScanEvidence} />
        </Collapsible>
      </section>

      {/* 4 — Top risks: the hero exposure path */}
      <section className="min-h-0">
        <TopRisksPanel
          topPath={topPath}
          exposurePaths={exposurePaths}
          critical={critical}
          high={high}
          credentials={credentials}
          summaryReady={summaryReady}
          agentMeshHref={agents != null && agents > 0 ? "/agents/topology" : null}
        />
      </section>
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
    <div className="mt-4" data-testid="overview-security-coverage">
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-[color:var(--text-tertiary)]">Security coverage</h3>
      <p className="mb-2 text-[11px] leading-4 text-[color:var(--text-tertiary)]">
        Coverage by discipline — lenses can overlap, so a repo CVE counts under both Vuln mgmt and ASPM. Lanes are not additive.
      </p>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        {coverage.map((lane) => {
          const total = COVERAGE_SEVERITY_BANDS.reduce((sum, band) => sum + (lane.severity[band.key] || 0), 0);
          const bands = COVERAGE_SEVERITY_BANDS.filter((band) => (lane.severity[band.key] || 0) > 0);
          return (
            <Link
              key={lane.domain}
              href={lane.href}
              data-testid={`coverage-lane-${lane.domain}`}
              className="flex flex-col gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 transition-colors hover:border-[color:var(--border-strong)]"
            >
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-xs font-semibold text-[color:var(--foreground)]">{lane.label}</span>
                <span className="text-lg font-bold tabular-nums text-[color:var(--foreground)]">{lane.count}</span>
              </div>
              {/* Stacked severity strip — widths reflect share of the lane count. */}
              <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
                {total > 0 &&
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
                {total === 0 ? (
                  <span className="text-[11px] text-[color:var(--text-tertiary)]">No findings</span>
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
  domains,
  services,
}: {
  domains: OverviewResponse["domains"] | null;
  services: Partial<Record<ServiceId, ServiceEntry>> | null | undefined;
}) {
  if (!domains) return null;
  const tiles: OpsTile[] = OPERATIONAL_DOMAIN_KEYS.flatMap((key) => {
    const domain = domains[key];
    if (!domain) return [];
    return [
      {
        key,
        label: domain.label,
        metric: domain.metric,
        metricLabel: domain.metric_label,
        status: domain.status,
        href: domain.graph_href ?? domain.href,
        hint: LANE_HINTS[key],
      },
    ];
  });
  if (tiles.length === 0) return null;

  // Data sources / connections are operational plumbing — surfaced as a small
  // connected count next to the Connections link, not as an equal-weight lane.
  const dataSources = services?.data_sources;
  const dataSourceCount =
    dataSources &&
    (dataSources.state === "live" || dataSources.state === "connected")
      ? dataSources.count
      : 0;

  const active = tiles.filter(opsLaneActive).length;

  return (
    <Collapsible
      bare
      className="mt-5 border-t border-[color:var(--border-subtle)] pt-1"
      data-testid="overview-estate-ops"
      title="Estate / operations"
      titleClassName={SECTION_TITLE_CLASS}
      subtitle={`${active} of ${tiles.length} operational lanes active · runtime, cost, identity, ops`}
      count={tiles.length}
      defaultOpen
      actions={
        <Link
          href="/connections"
          className="inline-flex items-center gap-1 text-xs text-emerald-500 hover:text-emerald-400"
        >
          {dataSourceCount > 0 ? (
            <span className="text-[color:var(--text-tertiary)]">{dataSourceCount} connected · </span>
          ) : null}
          Connections <ArrowRight className="h-3 w-3" />
        </Link>
      }
    >
      <div className="mt-1 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {tiles.map((tile) => (
          <OpsTileCard key={tile.key} tile={tile} />
        ))}
      </div>
    </Collapsible>
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
        className="flex items-center justify-between gap-2 rounded-lg border border-dashed border-[color:var(--border-subtle)] bg-transparent px-3 py-2 text-[color:var(--text-tertiary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
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
      className="flex items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 transition hover:border-[color:var(--border-strong)]"
    >
      <div className="flex min-w-0 items-center gap-2">
        <span className={`h-2 w-2 shrink-0 rounded-full ${tone.dot}`} aria-hidden="true" />
        <span className="truncate text-[11px] font-medium text-[color:var(--foreground)]">{tile.label}</span>
      </div>
      <div className="flex shrink-0 items-baseline gap-1">
        <span className={`font-mono text-base font-semibold ${tone.text}`}>{tile.metric}</span>
        <span className="truncate text-[10px] text-[color:var(--text-tertiary)]" title={tile.metricLabel}>
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
  const frameworks = (compliance?.frameworks ?? []).slice(0, 8);
  const evidenceReady = hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance);
  const failing = evidenceReady ? frameworks.filter((item) => item.fail > 0).length : 0;
  const statusTone =
    !evidenceReady
      ? "text-[color:var(--text-tertiary)]"
      : compliance?.overallStatus === "pass"
        ? "text-emerald-400"
        : compliance?.overallStatus === "warning"
          ? "text-amber-300"
          : compliance?.overallStatus === "fail"
            ? "text-red-400"
            : "text-[color:var(--text-tertiary)]";

  return (
    <Collapsible
      bare
      className="mt-4 border-t border-[color:var(--border-subtle)]"
      title="Compliance"
      titleClassName={SECTION_TITLE_CLASS}
      defaultOpen={defaultOpen}
      subtitle={
        evidenceReady
          ? `${Math.round(compliance.overallScore)}% overall · ${failing} framework${failing === 1 ? "" : "s"} need attention`
          : "Framework coverage appears after the first completed scan"
      }
      count={evidenceReady && frameworks.length > 0 ? frameworks.length : undefined}
      scrollMaxHeight="16rem"
      data-testid="overview-compliance-snapshot"
      actions={
        <div className="flex items-center gap-3">
          {evidenceReady ? (
            <span className={`text-sm font-semibold tabular-nums ${statusTone}`}>
              {Math.round(compliance.overallScore)}%
            </span>
          ) : null}
          <Link href="/compliance" className="inline-flex items-center gap-1 text-xs text-emerald-500 hover:text-emerald-400">
            Trust center <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      }
    >
      {evidenceReady && frameworks.length > 0 ? (
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {frameworks.map((framework) => {
            const evaluated = frameworkEvaluated(framework);
            // 0 evaluated controls is NOT a pass — surface a neutral
            // "not evaluated" state so an unscored framework never reads green.
            const tone =
              evaluated === 0
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
                className="grid min-h-[3.25rem] grid-cols-[2rem_minmax(0,1fr)_auto] items-center gap-2.5 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2 transition hover:border-[color:var(--border-strong)]"
              >
                <FrameworkIcon frameworkId={framework.id} size={32} />
                <div className="min-w-0">
                  <p className="truncate text-[11px] font-semibold leading-tight text-[color:var(--foreground)]">
                    {framework.label}
                  </p>
                  <p className="mt-0.5 truncate text-[10px] leading-tight text-[color:var(--text-tertiary)]">
                    {evaluated === 0
                      ? `Not evaluated · 0/${framework.total} controls`
                      : `${framework.pass}/${evaluated} pass${framework.fail > 0 ? ` · ${framework.fail} fail` : ""}`}
                  </p>
                </div>
                <span
                  className={`justify-self-end rounded-full px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${
                    tone === "fail"
                      ? "bg-red-500/15 text-red-700 dark:text-red-300"
                      : tone === "warn"
                        ? "bg-yellow-500/15 text-yellow-700 dark:text-yellow-200"
                        : tone === "pass"
                          ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : "border border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-tertiary)]"
                  }`}
                >
                  {tone === "not_evaluated" ? "n/a" : tone}
                </span>
              </Link>
            );
          })}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-5 text-center text-xs text-[color:var(--text-tertiary)]">
          Run a scan to light up OWASP, NIST, CIS, and related framework coverage. Empty estates do not show pass tiles.
        </div>
      )}
    </Collapsible>
  );
}

function TopRisksPanel({
  topPath,
  exposurePaths,
  critical,
  high,
  credentials,
  summaryReady,
  agentMeshHref = null,
}: {
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  critical: number;
  high: number;
  credentials: number | null;
  summaryReady: boolean;
  agentMeshHref?: string | null;
}) {
  const headline =
    summaryReady && critical > 0
      ? `${critical} critical finding${critical === 1 ? "" : "s"} need attention`
      : summaryReady && high > 0
        ? `${high} high-severity finding${high === 1 ? "" : "s"} in the latest scan`
        : "No prioritized risk themes yet";

  // Rank the correlated exposure paths by composite risk so the exec view leads
  // with the worst chain. Each row shows the whole path in one glance:
  // CVE → package → MCP/runtime → agent → credential. Fall back to the single
  // top path when the full list hasn't been computed yet.
  const allPaths = exposurePaths.length > 0 ? exposurePaths : topPath ? [topPath] : [];
  const ranked = [...allPaths].sort((a, b) => b.riskScore - a.riskScore);
  const MAX_ROWS = 5;
  const shown = ranked.slice(0, MAX_ROWS);
  const moreCount = ranked.length - shown.length;
  const metaBits = [
    summaryReady && critical > 0 ? `${critical} critical` : null,
    summaryReady && high > 0 ? `${high} high` : null,
    summaryReady && credentials != null && credentials > 0
      ? `${credentials} touch secrets`
      : null,
  ].filter(Boolean);

  return (
    <Collapsible
      title="Top risks"
      subtitle="Highest-risk exposure paths — correlated CVE → package → agent → credential"
      count={ranked.length || undefined}
      defaultOpen
      scrollMaxHeight="28rem"
      actions={
        <div className="flex flex-wrap items-center gap-3">
          {agentMeshHref ? (
            <Link href={agentMeshHref} className="text-xs text-emerald-500 hover:text-emerald-400">
              Agent mesh
            </Link>
          ) : null}
          <Link href="/security-graph" className="text-xs text-emerald-500 hover:text-emerald-400">
            Security graph
          </Link>
        </div>
      }
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <p className="text-sm font-semibold text-[color:var(--foreground)]">{headline}</p>
        {metaBits.length > 0 ? (
          <p className="text-[11px] text-[color:var(--text-tertiary)]">{metaBits.join(" · ")}</p>
        ) : null}
      </div>

      {shown.length > 0 ? (
        <div className="mt-3 space-y-2">
          {shown.map((path, index) => (
            <RiskChainRow key={path.key} path={path} rank={index + 1} />
          ))}
        </div>
      ) : (
        <p className="mt-3 text-sm text-[color:var(--text-secondary)]">
          Run a scan to correlate CVEs, packages, agents, and credentials into ranked exposure paths.
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {moreCount > 0 ? (
          <Link
            href="/security-graph"
            className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
          >
            +{moreCount} more risk path{moreCount === 1 ? "" : "s"} <ArrowRight className="h-3 w-3" />
          </Link>
        ) : null}
        <Link
          href="/findings?severity=critical"
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)]"
        >
          Critical findings
        </Link>
        <Link
          href="/compliance"
          className="rounded-lg border border-emerald-700/50 bg-emerald-500/10 dark:bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200"
        >
          Compliance evidence
        </Link>
      </div>
    </Collapsible>
  );
}

const RISK_NODE_META: Record<
  ExposurePathView["nodes"][number]["type"],
  { dot: string }
> = {
  cve: { dot: "bg-red-500" },
  package: { dot: "bg-violet-500" },
  server: { dot: "bg-sky-500" },
  agent: { dot: "bg-emerald-500" },
  credential: { dot: "bg-amber-500" },
};
const RISK_NODE_ORDER: ExposurePathView["nodes"][number]["type"][] = [
  "cve",
  "package",
  "server",
  "agent",
  "credential",
];

function riskScoreTone(score: number): string {
  if (score >= 9) return "border-red-500/45 bg-red-500/10 text-red-700 dark:text-red-300";
  if (score >= 7) return "border-orange-500/45 bg-orange-500/10 text-orange-700 dark:text-orange-300";
  if (score >= 4) return "border-yellow-500/45 bg-yellow-500/10 text-yellow-700 dark:text-yellow-200";
  return "border-sky-500/45 bg-sky-500/10 text-sky-700 dark:text-sky-300";
}

function RiskChainRow({ path, rank }: { path: ExposurePathView; rank: number }) {
  // Order the chain into the readable attack narrative regardless of the raw
  // node order: CVE → package → MCP/runtime → agent → credential.
  const ordered = RISK_NODE_ORDER.flatMap((type) =>
    path.nodes.filter((node) => node.type === type),
  );
  const hasCredential = path.nodes.some((node) => node.type === "credential");

  return (
    <Link
      href={path.href}
      className="group flex items-center gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5 transition hover:border-[color:var(--border-strong)]"
    >
      <span className="w-4 shrink-0 text-center font-mono text-xs text-[color:var(--text-tertiary)]">
        {rank}
      </span>
      <span
        className={`shrink-0 rounded-md border px-2 py-1 font-mono text-xs font-semibold ${riskScoreTone(path.riskScore)}`}
        title={`Composite risk ${path.riskScore.toFixed(1)}`}
      >
        {path.riskScore.toFixed(1)}
      </span>
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-y-1">
        {ordered.map((node, index) => (
          <span key={`${node.type}-${index}`} className="inline-flex items-center">
            {index > 0 ? (
              <ChevronRight className="mx-0.5 h-3 w-3 shrink-0 text-[color:var(--text-tertiary)]" />
            ) : null}
            <span className="inline-flex items-center gap-1 rounded-md bg-[color:var(--surface)] px-1.5 py-0.5 text-[11px]">
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${RISK_NODE_META[node.type].dot}`}
                aria-hidden="true"
              />
              <span
                className="max-w-[18ch] truncate text-[color:var(--text-secondary)]"
                title={node.label}
              >
                {node.label}
              </span>
            </span>
          </span>
        ))}
      </div>
      {hasCredential ? (
        <span className="hidden shrink-0 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-200 sm:inline">
          credential
        </span>
      ) : null}
      <ArrowRight className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)] transition group-hover:text-[color:var(--foreground)]" />
    </Link>
  );
}

/**
 * Read-only "what influences this score" panel. Lists the weighted inputs
 * (severity buckets, KEV, exposure, compliance, unrated) with each driver's
 * count × weight = penalty contribution, so the grade is legible instead of an
 * opaque number (#3940). Only drivers that actually moved the score are shown.
 * A full weight/threshold editor is a documented follow-up.
 */
function ScoreExplainer({
  breakdown,
  grade,
}: {
  breakdown?: ExecScoreDriver[] | null | undefined;
  grade: string;
}) {
  const ungraded = grade === "N/A" || grade === "—";
  const rows = (breakdown ?? [])
    .filter((row) => row.count > 0 || row.contribution > 0)
    .sort((a, b) => b.contribution - a.contribution);
  if (ungraded || rows.length === 0) return null;
  const totalPenalty = rows.reduce((sum, row) => sum + row.contribution, 0);

  return (
    <Collapsible
      bare
      className="mt-4 border-t border-[color:var(--border-subtle)]"
      title="What influences this score"
      titleClassName={SECTION_TITLE_CLASS}
      subtitle="Weighted risk inputs behind the grade · each shown as count × weight = points off 100"
      defaultOpen={false}
      data-testid="overview-score-explainer"
    >
      <div className="mt-2 space-y-1.5">
        {rows.map((row) => {
          const share = totalPenalty > 0 ? (row.contribution / totalPenalty) * 100 : 0;
          return (
            <div key={row.driver} className="flex items-center gap-3" data-testid={`score-driver-${row.driver}`}>
              <span className="w-40 shrink-0 truncate text-[11px] text-[color:var(--text-secondary)]" title={row.label}>
                {row.label}
              </span>
              <span className="w-24 shrink-0 text-right font-mono text-[11px] tabular-nums text-[color:var(--text-tertiary)]">
                {row.count} × {row.weight}
              </span>
              <div className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
                <span
                  className="block h-full rounded-full bg-[color:var(--severity-high)]"
                  style={{ width: `${Math.min(100, share)}%` }}
                />
              </div>
              <span className="w-14 shrink-0 text-right font-mono text-[11px] font-semibold tabular-nums text-[color:var(--foreground)]">
                −{row.contribution.toFixed(1)}
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-2 text-[10px] leading-tight text-[color:var(--text-tertiary)]">
        Score = 100 − total points off (capped at 100). Weights, grade thresholds, and the display format are
        configurable per tenant via the score-config API. A full in-UI weight editor is a follow-up.
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
      className="inline-flex overflow-hidden rounded-md border border-[color:var(--border-subtle)]"
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
                ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                : "bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
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
  grade,
  score,
  scoreFormat = "percent",
  onScoreFormatChange,
  summary,
  critical,
  high,
  cves,
  latestScan,
  scoreTrend,
}: {
  grade: string;
  score?: number | undefined;
  scoreFormat?: PostureScoreFormat | undefined;
  onScoreFormatChange?: ((format: PostureScoreFormat) => void) | undefined;
  summary?: string | undefined;
  critical: number;
  high: number;
  cves: number | null;
  latestScan: string | null;
  scoreTrend?: { delta: number; previousScore: number; timestamp: string } | null | undefined;
}) {
  const ungraded = grade === "N/A" || grade === "—";
  const badgeTone = ungraded
    ? "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]"
    : grade === "A" || grade === "B"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
      : grade === "C" || grade === "D"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
        : "border-red-500/40 bg-red-500/10 text-red-400";
  const graded = typeof score === "number" && !ungraded;
  const scoreDisplay = graded ? formatPostureScore(score, grade, scoreFormat) : null;
  const blurb = derivePostureBlurb({ summary, critical, high, cves, graded });

  return (
    <div className="flex items-center gap-4">
      <div
        className={`flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-2xl border ${badgeTone}`}
        title={graded ? `Grade ${grade}${scoreDisplay ? ` · ${scoreDisplay}` : ""}` : "Awaiting scan"}
      >
        <span className="text-3xl font-bold leading-none">{grade}</span>
        {graded && scoreFormat !== "grade" && scoreDisplay ? (
          <span className="mt-0.5 text-[10px] font-semibold leading-none opacity-80">{scoreDisplay}</span>
        ) : null}
      </div>
      <div className="min-w-0">
        <div className="flex items-center justify-between gap-2">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
            Risk posture
          </p>
          {graded && onScoreFormatChange ? (
            <ScoreFormatToggle value={scoreFormat} onChange={onScoreFormatChange} />
          ) : null}
        </div>
        <p className="mt-1 flex items-baseline gap-2 text-lg font-semibold text-[color:var(--foreground)]">
          {graded ? (
            <>
              {/* Always show BOTH the letter grade and the %/points, whatever the
                  chosen primary format, so the number is never ambiguous. */}
              <span>{scoreDisplay}</span>
              {scoreFormat !== "grade" ? (
                <span className="text-xs font-medium text-[color:var(--text-tertiary)]">Grade {grade}</span>
              ) : typeof score === "number" ? (
                <span className="text-xs font-medium text-[color:var(--text-tertiary)]">{Math.round(score)}%</span>
              ) : null}
            </>
          ) : (
            "Awaiting scan"
          )}
        </p>
        <p className="mt-0.5 text-[10px] text-[color:var(--text-tertiary)]">
          {latestScan ? `Last scan · ${latestScan}` : graded ? "Scan complete" : "No completed scans"}
        </p>
        {graded && scoreTrend !== undefined ? (
          scoreTrend === null ? (
            <p className="mt-1 text-[10px] text-[color:var(--text-tertiary)]">Trend unavailable · fewer than two posture snapshots</p>
          ) : (
            <p
              className={`mt-1 text-[10px] font-medium ${
                scoreTrend.delta > 0
                  ? "text-emerald-700 dark:text-emerald-300"
                  : scoreTrend.delta < 0
                    ? "text-red-700 dark:text-red-300"
                    : "text-[color:var(--text-tertiary)]"
              }`}
            >
              {scoreTrend.delta > 0
                ? `Improved ${Math.abs(scoreTrend.delta).toFixed(1)} points`
                : scoreTrend.delta < 0
                  ? `Declined ${Math.abs(scoreTrend.delta).toFixed(1)} points`
                  : "No score change"}
              {` · previous ${Math.round(scoreTrend.previousScore)}`}
            </p>
          )
        ) : null}
        <p className="mt-0.5 line-clamp-2 text-xs text-[color:var(--text-secondary)]">{blurb}</p>
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
  identity: Fingerprint,
};

// Neutral grayscale fills for the in-tile issue-type mini bar — segments stay
// distinguishable by lightness (theme-safe text tokens), never by severity hue.
const ISSUE_TYPE_BAR: Record<IssueType, string> = {
  vulnerability: "bg-[color:var(--text-secondary)]",
  misconfiguration: "bg-[color:var(--text-tertiary)]",
  secret: "bg-[color:var(--text-secondary)] opacity-60",
  identity: "bg-[color:var(--text-tertiary)] opacity-50",
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
      className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 text-[10px] font-semibold text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
    >
      <Icon className="h-3 w-3 text-[color:var(--text-tertiary)]" aria-hidden="true" />
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
}: {
  summaryReady: boolean;
  critical: number;
  high: number;
  kev: number | null;
  credentials: number | null;
  complianceScore?: string | undefined;
  severity: SeverityCounts;
  matrix: IssueSeverityMatrix | null | undefined;
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
  const issueTypes: IssueType[] = ["vulnerability", "misconfiguration", "secret", "identity"];

  return (
    <div
      className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1"
      data-testid="overview-severity-issue-strip"
    >
      <Collapsible
        bare
        title="Open issues"
        titleClassName={SECTION_TITLE_CLASS}
        subtitle="By severity · CVE, misconfig, secret, identity"
        defaultOpen
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            {/* Category chips are neutral + iconified: hue is reserved for
                severity alone, so a category never mimics a severity band
                (KEV is not amber, Secrets is not red, Compliance is not a
                green pass). The glyph carries the distinction. */}
            {summaryReady && kev != null ? (
              <CategoryChip
                href={findingsHref({ kev: true })}
                icon={Flame}
                label="KEV"
                value={kev}
                title="Known-exploited vulnerabilities (CISA KEV)"
              />
            ) : null}
            {summaryReady && credentials != null ? (
              <CategoryChip
                href={findingsHref({ issue: "secret" })}
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
                title="Overall compliance score across evaluated frameworks"
              />
            ) : null}
          </div>
        }
      >
      <div className="mb-3 mt-1 flex h-2.5 overflow-hidden rounded-full bg-[color:var(--surface)]">
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
            href={findingsHref({ severity: band.key })}
            className={`rounded-lg border px-2.5 py-2 transition ${band.tint}`}
          >
            <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-secondary)]">
              {band.label}
            </p>
            <p className={`mt-1 font-mono text-xl font-semibold ${band.tone}`}>
              {summaryReady ? band.value : "—"}
            </p>
            {hasTyped && summaryReady ? (
              <div className="mt-2 space-y-1">
                <div className="flex h-1.5 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
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
                <div className="flex flex-wrap gap-x-1.5 gap-y-0.5 text-[9px] text-[color:var(--text-tertiary)]">
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
              <p className="mt-2 text-[9px] text-[color:var(--text-tertiary)]">All issue types</p>
            )}
          </Link>
        ))}
      </div>

      {hasTyped && summaryReady ? (
        <div className="mt-3 flex flex-wrap gap-2 border-t border-[color:var(--border-subtle)] pt-2.5">
          {issueTypes.map((issue) => {
            const total = resolved.byType[issue];
            if (total <= 0) return null;
            const Glyph = ISSUE_TYPE_GLYPH[issue];
            return (
              <Link
                key={issue}
                href={findingsHref({ issue })}
                className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
              >
                <Glyph className="h-3 w-3 text-[color:var(--text-tertiary)]" aria-hidden="true" />
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
      return { dot: "bg-[color:var(--text-tertiary)]", text: "text-[color:var(--text-tertiary)]" };
  }
}
