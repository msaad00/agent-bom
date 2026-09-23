"use client";

import Link from "next/link";
import { useEffect, useId, useRef, useState, type ElementType, type ComponentProps } from "react";
import {
  ArrowRight,
  Bug,
  Bot,
  Cloud,
  CodeXml,
  Database,
  Fingerprint,
  UserRound,
  Flame,
  KeyRound,
  ShieldCheck,
  CircleCheck,
  CircleX,
  SearchCheck,
  SlidersHorizontal,
} from "lucide-react";

import type { InventorySummaryResponse, OverviewResponse } from "@/lib/api";
import { sbomSourceName } from "@/lib/findings-view";
import type {
  ExecScoreDriver,
  OverviewCoverageLane,
  ServiceEntry,
  ServiceId,
} from "@/lib/api-types";
import { OverviewAssets } from "@/components/overview-assets";
import { Drawer } from "@/components/drawer";
import { DetailTabs } from "@/components/detail-tabs";
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
  impactCategory?: string;
  affectedWorkloads?: string[];
  affectedServices?: string[];
  fixedVersion?: string;
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
  "text-lg font-semibold normal-case tracking-normal text-foreground";

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
  localReport?: boolean | undefined;
  /** True until the posture and cross-domain overview requests settle. */
  loading?: boolean | undefined;
  overviewUnavailable?: boolean | undefined;
  inventorySummary?: InventorySummaryResponse | null | undefined;
  inventoryLoading?: boolean | undefined;
  inventoryUnavailable?: boolean | undefined;
  inventoryUnavailableHref?: string | undefined;
  complianceLoading?: boolean | undefined;
  scanScopeLoading?: boolean | undefined;
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
   *  AISPM) with evidence-qualified, overlapping counts (issue #3946). */
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
  localReport = false,
  loading = false,
  overviewUnavailable = false,
  inventorySummary = null,
  inventoryLoading = false,
  inventoryUnavailable = false,
  inventoryUnavailableHref = "/inventory",
  complianceLoading = false,
  scanScopeLoading = false,
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
}: OverviewCockpitProps) {
  const [riskTab, setRiskTab] = useState<"risks" | "posture" | "assets">("posture");
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

  const coverageSummary = coverage?.length
    ? `${coverage.length} security disciplines`
    : "Security findings and operational context";

  return (
    <div className="space-y-7">
      {localReport && <p className="text-sm text-ink-secondary">Local report only. Findings are not linked to tenant investigations or live coverage.</p>}
      <section aria-label="Risk overview" className="@container min-w-0 rounded-2xl border border-outline-strong bg-surface p-4 sm:p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className={SECTION_TITLE_CLASS}>Risk overview</h2>
          <FreshnessStatus latestScan={latestScan} scans={scans} loading={loading} />
        </div>
        <DetailTabs ariaLabel="Risk overview views" value={riskTab} onChange={setRiskTab}
          tabs={[{ key: "posture", label: "Posture" }, { key: "risks", label: "Top risks" }, { key: "assets", label: "Assets & coverage" }]} />
        <div role="tabpanel" aria-label="Top risks" hidden={riskTab !== "risks"}>
          <TopRisksPanel localReport={localReport} loading={loading} unavailable={overviewUnavailable} scans={scans}
            topPath={topPath} exposurePaths={exposurePaths}
            agentMeshHref={agents != null && agents > 0 ? "/agents/topology" : null} />
        </div>
        <div role="tabpanel" aria-label="Assets & coverage" hidden={riskTab !== "assets"}>{localReport ? <p className="mt-4 text-sm text-ink-secondary">This report is not linked to a live inventory snapshot.</p> : <OverviewAssets summary={inventorySummary} loading={inventoryLoading} unavailable={inventoryUnavailable} unavailableHref={inventoryUnavailableHref} />}</div>
        <div role="tabpanel" aria-label="Posture" hidden={riskTab !== "posture"}>
            <div className="mt-4 grid items-start gap-5 @min-[56rem]:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] @min-[56rem]:gap-6">
              <PostureHero
                localReport={localReport}
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
                localReport={localReport}
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
        </div>
      </section>
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <section aria-label="Compliance & frameworks" className="min-w-0 rounded-2xl border border-outline bg-surface p-5 sm:p-6">
          <Collapsible bare title="Compliance & frameworks" titleClassName={SECTION_TITLE_CLASS} defaultOpen
            actions={localReport ? undefined : <Link href="/compliance" aria-label="View all frameworks" title="View all frameworks" className="inline-flex min-h-8 min-w-8 items-center justify-center gap-1 text-xs text-emerald-700 dark:text-emerald-300"><span className="hidden sm:inline">View all frameworks</span><ArrowRight className="h-4 w-4" aria-hidden="true" /></Link>}>
            {localReport ? <p className="text-sm text-ink-secondary">Tenant compliance assessment is unavailable for this local report.</p> : <ComplianceSnapshotPanel compliance={compliance} hasScanEvidence={hasScanEvidence}
              loading={loading || complianceLoading || scanScopeLoading} scanScopeKnown={scans !== null} />}
          </Collapsible>
        </section>
        <section aria-label="Findings by discipline" className="min-w-0 rounded-2xl border border-outline bg-surface p-5 sm:p-6">
          <Collapsible bare title="Findings by discipline" subtitle={coverageSummary} titleClassName={SECTION_TITLE_CLASS} defaultOpen>
            {loading && !domains ? (
              <p role="status" className="mt-3 text-sm text-ink-secondary">Loading coverage…</p>
            ) : overviewUnavailable && !domains ? (
              <p role="status" className="mt-3 text-sm text-ink-secondary">Coverage unavailable.</p>
            ) : <SecurityCoverageLanes coverage={coverage} />}
          </Collapsible>
        </section>
      </div>
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
        <span className="text-xs text-ink-secondary">
          Refreshing current evidence.
        </span>
      ) : latestScan ? (
        <time className="text-xs font-medium tabular-nums text-ink-secondary">
          {latestScan}
        </time>
      ) : (
        <span className="text-xs text-ink-secondary">
          {scans === 0 ? "Run a scan to establish freshness." : "The current evidence has no observed scan timestamp."}
        </span>
      )}
    </div>
  );
}

// Severity counts shown in each discipline, in descending order, plus
// ``unrated`` for findings whose severity is unknown/unscored (issue #3946).
const COVERAGE_SEVERITY_BANDS: { key: keyof OverviewCoverageLane["severity"]; label: string }[] = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "unrated", label: "Unrated" },
];

/**
 * The security-posture coverage lanes rendered 1:1 (CSPM / Vuln mgmt / ASPM /
 * DSPM / AISPM). These are overlapping posture *disciplines* (lenses), not a
 * partition: one finding can count in several lanes (a repo CVE is both Vuln
 * mgmt and ASPM; an IaC misconfig is both CSPM and ASPM), so the lanes are not
 * additive — the caption above says so, and nothing here presents a lane total.
 * Each lane retains its finding total and labeled severity counts. Unrated is
 * shown only when unknown-severity findings are present.
 */
const SECURITY_DISCIPLINES: Record<string, { label: string; icon: ElementType; order: number; accent: string; tile: string }> = {
  cspm: { label: "Cloud security (CSPM)", icon: Cloud, order: 0, accent: "text-sky-700 dark:text-sky-300", tile: "border-sky-600/35 bg-sky-500/5 dark:border-sky-400/35" },
  aspm: { label: "Application security (ASPM)", icon: CodeXml, order: 1, accent: "text-violet-700 dark:text-violet-300", tile: "border-violet-600/35 bg-violet-500/5 dark:border-violet-400/35" },
  vuln: { label: "Vulnerability management", icon: Bug, order: 2, accent: "text-orange-700 dark:text-orange-300", tile: "border-orange-600/35 bg-orange-500/5 dark:border-orange-400/35" },
  dspm: { label: "Data security (DSPM)", icon: Database, order: 3, accent: "text-cyan-700 dark:text-cyan-300", tile: "border-cyan-600/35 bg-cyan-500/5 dark:border-cyan-400/35" },
  aispm: { label: "AI security (AISPM)", icon: Bot, order: 4, accent: "text-teal-700 dark:text-teal-300", tile: "border-teal-600/35 bg-teal-500/5 dark:border-teal-400/35" },
};

function SecurityCoverageLanes({ coverage }: { coverage?: OverviewCoverageLane[] | null | undefined }) {
  const [showSeverity, setShowSeverity] = useState(false);
  const lanesId = useId();
  if (!coverage || coverage.length === 0) return null;
  return (
    <div className="@container pt-1" data-testid="overview-security-coverage">
      <p className="mb-3 text-xs leading-relaxed text-ink-secondary">
        Overlapping finding counts, not additive. Zero findings does not establish assessment coverage.
      </p>
      <button type="button" aria-expanded={showSeverity} aria-controls={lanesId} onClick={() => setShowSeverity(!showSeverity)} className="mb-2 rounded-md py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300">
        {showSeverity ? "Hide severity breakdown" : "Show severity breakdown"}
      </button>
      <div id={lanesId} className="grid grid-cols-1 gap-x-3 @min-[30rem]:grid-cols-2">
        {[...coverage].sort((left, right) => (SECURITY_DISCIPLINES[left.domain]?.order ?? 5) - (SECURITY_DISCIPLINES[right.domain]?.order ?? 5)).map((lane) => {
          const discipline = SECURITY_DISCIPLINES[lane.domain];
          const Icon = discipline?.icon ?? ShieldCheck;
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
              className="min-w-0 rounded-md border-b border-outline px-1 py-2.5 transition-colors hover:bg-surface-muted"
            >
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <span className="flex items-start gap-2 text-sm font-semibold text-foreground"><Icon className={`mt-0.5 h-4 w-4 shrink-0 ${discipline?.accent ?? "text-ink-secondary"}`} aria-hidden="true" /><span>{discipline?.label ?? lane.label}</span></span>
                {/* The unit is not decoration. A bare "1610" under a heading
                    called CSPM reads as assets, accounts, VMs or data stores
                    depending on the reader — every one of which is wrong. These
                    are FINDINGS in that posture lane, which is also what the
                    severity chips below sum to. */}
                {known && total > 0 ? <span className="ml-6 flex items-baseline gap-1">
                  <span className="text-sm font-semibold tabular-nums text-foreground">
                    {known && total > 0 ? `${exact ? "" : "≥"}${lane.count.toLocaleString()}` : "—"}
                  </span>
                  {known && total > 0 ? (
                    <span className="text-[10px] font-medium uppercase tracking-[0.08em] text-ink-secondary">
                      {lane.count === 1 ? "finding" : "findings"}
                    </span>
                  ) : null}
                </span> : null}
              </div>
              <div className="ml-6 mt-1 min-w-0">
                {!exact && known && total > 0 ? (
                  <p className="mb-1 text-xs text-ink-secondary">{statusLabel} · at least this many</p>
                ) : null}
              <div className="flex flex-wrap gap-1">
                {!known || total === 0 ? (
                  <span className="text-xs text-ink-secondary">{exact ? "No open findings" : statusLabel}</span>
                ) : (
                  bands.map((band) => (
                    <span
                      key={band.key}
                      className="text-xs font-medium tabular-nums text-ink-secondary"
                      hidden={!showSeverity}
                    >
                      {band.label} {lane.severity[band.key]}
                    </span>
                  ))
                )}
              </div>
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
function ComplianceSnapshotPanel({
  compliance,
  hasScanEvidence = false,
  loading = false,
  scanScopeKnown = true,
}: {
  compliance: OverviewComplianceSnapshot | null | undefined;
  hasScanEvidence?: boolean | undefined;
  loading?: boolean | undefined;
  scanScopeKnown?: boolean | undefined;
}) {
  const [showAllFrameworks, setShowAllFrameworks] = useState(false);
  const allFrameworks = compliance?.frameworks ?? [];
  // Show the largest observed control gaps first; never infer certification status.
  const scored = allFrameworks.filter((item) => item.kind === "scored")
    .sort((a, b) => (b.fail + b.warn) - (a.fail + a.warn));
  const mappings = allFrameworks.filter((item) => item.kind === "applicability");
  const evidenceReady = hasScanEvidence && compliance != null && hasEvaluatedCompliance(compliance);
  const attention = scored.filter((item) => item.fail > 0 || item.warn > 0).length;
  const passed = scored.reduce((total, item) => total + item.pass, 0);
  const unassessed = scored.filter((item) => frameworkEvaluated(item) === 0).length;
  const assessmentCoverage = evidenceReady
    && Number.isInteger(compliance.evaluatedControls) && compliance.evaluatedControls >= 0
    && Number.isInteger(compliance.totalControls) && compliance.totalControls > 0
    && compliance.evaluatedControls <= compliance.totalControls
    ? Math.round(100 * compliance.evaluatedControls / compliance.totalControls)
    : null;

  return (
    <div data-testid="overview-compliance-snapshot">
      {loading ? (
        <p role="status" className="mt-2 text-xs text-ink-secondary">Loading control evaluation…</p>
      ) : evidenceReady ? (
        <>
          <dl className="mt-3 grid grid-cols-3 gap-2" aria-label="Evaluated control results">
            {[
              { label: "Controls passed", value: passed, tone: "text-emerald-700 dark:text-emerald-200", Icon: CircleCheck },
              { label: "Controls failed", value: scored.reduce((n, f) => n + f.fail, 0), tone: "text-red-700 dark:text-red-200", Icon: CircleX },
              { label: "Controls need review", value: scored.reduce((n, f) => n + f.warn, 0), tone: "text-amber-800 dark:text-amber-200", Icon: SearchCheck },
            ].map(({ label, value, tone, Icon }) => (
              <div key={label} className="compliance-metric min-w-0 rounded-lg border border-outline p-3">
                <dt className="text-xs leading-snug text-ink-secondary">{label}</dt>
                <dd className={`mt-2 flex flex-wrap items-center gap-2 text-2xl font-semibold tabular-nums ${tone}`}>
                  <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />{value}
                </dd>
              </div>
            ))}
          </dl>
          <div className="mt-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 text-xs text-ink-secondary">
            <p>{passed}/{compliance.evaluatedControls} evaluated controls pass</p>
            <p className="font-medium">{Math.round(compliance.overallScore)}% pass rate</p>
          </div>

        </>
      ) : (
        <p className="mt-2 text-xs text-ink-secondary">
          {!scanScopeKnown
            ? "Control evaluation unavailable. Scan scope could not be established."
            : hasScanEvidence
            ? "Control evaluation unavailable for completed scans. Review scan scope and evaluation status before drawing a compliance conclusion."
            : "Framework coverage appears after the first completed scan. Empty estates do not show pass tiles."}
        </p>
      )}
      {!loading && hasScanEvidence && compliance ? (
        <details className="mt-2 text-xs text-ink-secondary">
          <summary className="cursor-pointer rounded-sm focus-visible:outline-2 focus-visible:outline-emerald-500">
            {assessmentCoverage == null ? "Assessment coverage unavailable" : `Assessment: ${compliance.evaluatedControls}/${compliance.totalControls} framework control entries evaluated (${assessmentCoverage}%)`}
          </summary>
          <p className="mt-2 leading-relaxed">Entries are counted per framework and may overlap. Recorded evaluations can include check errors. Coverage is limited to the framework entries returned for this assessment.</p>
        </details>
      ) : null}
      {!loading && hasScanEvidence && scored.length > 0 ? (
        <div className="mt-3 border-t border-outline pt-3">
          {evidenceReady ? <p className="mb-2 text-xs text-ink-secondary">{attention} framework{attention === 1 ? " needs" : "s need"} attention{unassessed > 0 ? ` · ${unassessed} not evaluated` : ""}</p> : null}
          <Collapsible bare title="Control frameworks" subtitle={`${scored.length} frameworks · ordered by failing and warning checks`} defaultOpen data-testid="overview-evaluated-frameworks">
            <div role="region" aria-label="Control framework list" tabIndex={showAllFrameworks ? 0 : undefined}
              className="max-h-[min(50vh,22rem)] overflow-y-auto overscroll-contain rounded-md focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500">
              <FrameworkCards frameworks={showAllFrameworks ? scored : scored.slice(0, 4)} />
            </div>
            {scored.length > 4 ? (
              <button type="button" className="mt-2 text-xs text-emerald-700 dark:text-emerald-300"
                aria-expanded={showAllFrameworks} onClick={() => setShowAllFrameworks(!showAllFrameworks)}>
                {showAllFrameworks ? "Show priority frameworks" : `Show all ${scored.length} control frameworks`}
              </button>
            ) : null}
          </Collapsible>
        </div>
      ) : null}
      {hasScanEvidence && mappings.length > 0 ? (
        <Collapsible bare title="Risk mappings" count={mappings.length} subtitle="Applicability, separate from control pass/fail" defaultOpen={!evidenceReady} data-testid="overview-risk-mappings">
          <div className="grid gap-2 sm:grid-cols-2">
            {mappings.slice(0, 4).map((framework) => (
              <Link key={framework.id} href={`/compliance?framework=${encodeURIComponent(framework.id)}`} className="flex min-w-0 items-center gap-2 rounded-md py-2 hover:bg-surface-muted">
                <span aria-hidden="true"><FrameworkIcon frameworkId={framework.id} size={24} /></span>
                <span className="min-w-0 text-sm font-semibold text-foreground">{framework.label}
                  <span className="mt-1 block font-normal text-ink-secondary">{framework.applicable ?? 0}/{framework.total} risks applicable</span>
                </span>
              </Link>
            ))}
          </div>
          {mappings.length > 4 ? <Collapsible bare title={`More risk mappings (${mappings.length - 4})`} defaultOpen={false}><FrameworkCards frameworks={mappings.slice(4)} /></Collapsible> : null}
        </Collapsible>
      ) : null}
    </div>
  );
}

function FrameworkCards({ frameworks }: { frameworks: OverviewComplianceSnapshot["frameworks"] }) {
  return (
        <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2" data-testid="overview-framework-cards">
          {frameworks.map((framework) => {
            const evaluated = frameworkEvaluated(framework);
            const isApplicability = framework.kind === "applicability";
            // 0 evaluated controls is NOT a pass — surface a neutral
            // "not evaluated" state so an unscored framework never reads green.
            return (
              <Link
                key={framework.id}
                href={`/compliance?framework=${encodeURIComponent(framework.id)}`}
                className="grid min-h-12 grid-cols-[1.75rem_minmax(0,1fr)] items-center gap-2 border-b border-outline px-1.5 py-2 transition hover:bg-surface-muted"
              >
                <span aria-hidden="true" className="flex h-7 w-7 items-center justify-center">
                  <FrameworkIcon frameworkId={framework.id} size={28} />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold leading-snug text-foreground">
                    {framework.label}
                  </p>
                  <p className="mt-0.5 text-sm leading-snug text-ink-secondary">
                    {isApplicability
                      ? `${framework.applicable ?? 0}/${framework.total} risks applicable`
                      : evaluated === 0
                      ? `Not evaluated · 0/${framework.total} controls`
                      : `${framework.pass}/${evaluated} evaluated controls pass${framework.fail > 0 ? ` · ${framework.fail} failed` : ""}${framework.warn > 0 ? ` · ${framework.warn} need review` : ""}`}
                  </p>
                </div>

              </Link>
            );
          })}
        </div>
  );
}

function TopRisksPanel({
  localReport = false,
  loading,
  unavailable,
  scans,
  topPath,
  exposurePaths,
  agentMeshHref = null,
}: {
  localReport?: boolean | undefined;
  loading: boolean;
  unavailable: boolean;
  scans: number | null;
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  agentMeshHref?: string | null;
}) {
  const allPaths = exposurePaths.length > 0 ? exposurePaths : topPath ? [topPath] : [];
  const ranked = [...allPaths].sort((a, b) => b.riskScore - a.riskScore);
  const shown = ranked.slice(0, 5);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [wide, setWide] = useState(false);
  const container = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!container.current || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const sideBySide = (entry?.contentRect.width ?? 0) >= 960;
      setWide(sideBySide);
      if (sideBySide) setDrawerOpen(false);
    });
    observer.observe(container.current);
    return () => observer.disconnect();
  }, []);
  const selected = shown.find((path) => path.key === selectedKey) ?? shown[0];
  const detail = selected ? <RiskChainRow localReport={localReport} path={selected} rank={shown.indexOf(selected) + 1} /> : null;
  return (
    <section ref={container} aria-label="Prioritized findings" className="@container">
      <p className="mb-3 text-xs text-ink-secondary">Review these findings first · {ranked.length} prioritized risks</p>
      {loading ? <p role="status" className="text-sm text-ink-secondary">Loading prioritized findings…</p>
        : shown.length > 0 ? <div className="grid items-start gap-4 @min-[960px]:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <div role="group" aria-label="Select a risk" className="divide-y divide-outline">
            {shown.map((path, index) => {
              const workload = path.affectedWorkloads?.[0] ?? path.nodes.find((node) => node.type === "agent" || node.type === "server")?.label;
              const finding = path.nodes.find((node) => node.type === "cve");
              return <button key={path.key} type="button" aria-pressed={selected?.key === path.key}
                onClick={() => { setSelectedKey(path.key); if (!wide) setDrawerOpen(true); }}
                className={`flex w-full items-start gap-2 rounded-md px-2 py-3 text-left ${selected?.key === path.key ? "bg-emerald-500/10" : "hover:bg-surface-muted"}`}>
                <span className="text-xs tabular-nums text-ink-secondary">{index + 1}</span>
                <span className="min-w-0 flex-1"><span className="block break-words text-sm font-semibold">{workload ? (sbomSourceName(workload) ? `SBOM source: ${sbomSourceName(workload)}` : workload) : "Workload not identified"}</span>
                  <span className="block break-words text-xs text-ink-secondary">{finding?.label ?? "Finding"} · {finding?.severity ?? "Severity unavailable"}</span></span>
                <ArrowRight className="mt-1 h-4 w-4 shrink-0 text-ink-secondary" aria-hidden="true" />
              </button>;
            })}
          </div>
          {wide ? <div role="region" aria-label="Selected risk" className="min-w-0 max-h-[28rem] overflow-y-auto rounded-lg border border-outline p-3">{detail}</div> : null}
          <Drawer open={!wide && drawerOpen} onClose={() => setDrawerOpen(false)} title="Selected risk" ariaLabel="Selected risk" size="lg">{detail}</Drawer>
        </div>
        : <p className="text-sm text-ink-secondary">{unavailable ? "Prioritized findings unavailable." : scans === 0 ? "No completed scans. Run a scan to assess findings." : "No prioritized findings in the current overview."}</p>}
      {!localReport && <div className="mt-3 flex flex-wrap gap-3 text-sm">
        <ReportEvidenceLink localReport={localReport} href="/security-graph" className="text-emerald-700 dark:text-emerald-300">Open investigation →</ReportEvidenceLink>
        {agentMeshHref ? <ReportEvidenceLink localReport={localReport} href={agentMeshHref} className="text-ink-secondary">Agent mesh</ReportEvidenceLink> : null}
      </div>}
    </section>
  );
}

function RiskChainRow({ path, rank, localReport = false }: { path: ExposurePathView; rank: number; localReport?: boolean }) {
  const finding = path.nodes.find((node) => node.type === "cve");
  const workload = path.nodes.find((node) => node.type === "agent") ?? path.nodes.find((node) => node.type === "server");
  const sbomSource = workload ? sbomSourceName(workload.label) : null;
  const workloads = [...new Set(path.affectedWorkloads?.length ? path.affectedWorkloads : workload ? [workload.label] : [])];
  const impact = {
    "code-execution": "Could allow attacker-controlled code to run if the vulnerable feature processes untrusted input.",
    "credential-access": "Could allow unauthorized access if the affected authentication feature is exposed.",
    "file-access": "Could expose files if an attacker can reach the vulnerable feature.",
    injection: "Could let untrusted input alter commands or data operations.",
    ssrf: "Could let an attacker make requests to services reachable by this workload.",
    "data-leak": "Could disclose sensitive information through the affected feature.",
    availability: "Could interrupt service when the vulnerable feature handles malicious input.",
    "client-side": "Could affect users of the application through a vulnerable browser-facing feature.",
  }[path.impactCategory ?? ""];
  const subject = sbomSource ? `SBOM source: ${sbomSource}` : workloads.length
    ? `Affected workload: ${workloads[0]}${workloads.length > 1 ? ` and ${workloads.length - 1} more` : ""}`
    : "Affected workload not identified";
  const severity = finding?.severity?.toLowerCase();
  const knownSeverity = severity && ["critical", "high", "medium", "low"].includes(severity) ? severity : null;

  const severityTone = knownSeverity === "critical"
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : knownSeverity === "high"
      ? "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300"
      : "border-outline bg-surface-muted text-ink-secondary";

  return (
    <article className="@container border-b border-outline py-1 last:border-b-0">
      <ReportEvidenceLink localReport={localReport} href={path.href} className="group block rounded-md px-1 py-3 transition hover:bg-surface-muted">
        <div className="flex items-start gap-2">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-outline font-mono text-xs text-ink-secondary">{rank}</span>
          <div className="grid min-w-0 flex-1 gap-x-4 @min-[42rem]:grid-cols-[minmax(0,1fr)_auto]">
            <p className="text-base font-semibold leading-snug text-foreground [overflow-wrap:anywhere]">
              {subject}
            </p>
            <p className="mt-1 text-xs text-ink-secondary [overflow-wrap:anywhere] @min-[42rem]:col-start-1">
              {impact ?? "A vulnerable dependency was found. Its effect on this workload needs review."}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-secondary @min-[42rem]:col-start-2 @min-[42rem]:row-start-1 @min-[42rem]:row-span-2 @min-[42rem]:mt-0">
              <span className={`rounded-md border px-2 py-0.5 font-semibold capitalize ${severityTone}`}>{knownSeverity ? `${knownSeverity} severity` : "Severity unavailable"}</span>
              <span className="inline-flex items-center gap-1 font-medium text-emerald-600 dark:text-emerald-400">Review impact <ArrowRight className="h-3 w-3" aria-hidden="true" /></span>
            </div>
          </div>
        </div>
      </ReportEvidenceLink>
      <details className="pb-3 pl-9 text-xs">
        <summary className="cursor-pointer text-ink-secondary">Technical details</summary>
        <p className="mt-2 text-ink-secondary">Dependency evidence; exploitation of this workload is not established.</p>
        <dl className="mt-2 space-y-2">
          <div><dt className="text-ink-secondary">Path priority</dt><dd>{Number.isFinite(path.riskScore) ? path.riskScore.toFixed(1) : "Unavailable"}</dd></div>
          {path.fixedVersion ? <div><dt className="text-ink-secondary">Advisory fix version</dt><dd>{path.fixedVersion}</dd></div> : null}
          {workloads.length > 1 ? <div><dt className="text-ink-secondary">Affected workloads</dt><dd>{workloads.join(", ")}</dd></div> : null}
          {path.affectedServices?.length ? <div><dt className="text-ink-secondary">Affected services</dt><dd>{path.affectedServices.join(", ")}</dd></div> : null}
          {path.nodes.map((node, index) => (
            <div key={`${node.type}-${index}`} className="grid grid-cols-[5rem_minmax(0,1fr)] gap-2">
              <dt className="capitalize text-ink-secondary">{node.type === "cve" ? "Finding" : (node.type === "agent" || node.type === "server") && sbomSourceName(node.label) !== null ? "SBOM source" : node.type}</dt>
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
      titleClassName="text-sm font-medium text-foreground"
      defaultOpen={false}
      data-testid="overview-score-explainer"
    >
      <div className="mt-2 space-y-1.5">
        {rows.map((row) => {
          return (
            <div key={row.driver} className="space-y-1" data-testid={`score-driver-${row.driver}`}>
              <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-0.5">
                <span className="min-w-0 text-xs leading-4 text-ink-secondary [overflow-wrap:anywhere]">
                  {row.label}
                </span>
                <span className="text-right font-mono text-xs font-semibold tabular-nums text-foreground">
                  {row.contribution.toFixed(1)}
                </span>
                <span className="col-span-2 font-mono text-xs tabular-nums text-ink-secondary">
                  {row.count} × {row.weight}
                </span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-surface-muted" aria-hidden="true">
                <div
                  data-testid={`score-pressure-${row.driver}`}
                  className="h-full rounded-full bg-accent-mint"
                  style={{ width: `${(row.contribution / totalPressure) * 100}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-xs font-medium text-ink-secondary">Total weighted pressure: {totalPressure.toFixed(1)}</p>
      <p className="mt-2 text-xs leading-relaxed text-ink-secondary">
        Bars show each input’s share of weighted pressure (count × weight). The server converts combined pressure to a score using a nonlinear curve;
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
            className={`px-2 py-1 text-xs font-semibold transition ${
              active
                ? "bg-surface-elevated text-foreground"
                : "bg-surface-muted text-ink-secondary hover:text-foreground"
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
  localReport = false,
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
  localReport?: boolean | undefined;
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
  const graded = !loading && typeof score === "number" && !ungraded;
  const scoreDisplay = graded ? formatPostureScore(score, grade, scoreFormat) : null;
  const scoreTone = graded && ["D", "F"].includes(grade)
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : graded && grade === "C"
      ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200"
      : "border-outline-strong bg-surface-muted text-foreground";
  const blurb = loading
    ? "Refreshing the current posture and evidence summary."
    : localReport ? "Tenant posture cannot be assessed from an imported report. Review its findings below." : derivePostureBlurb({ summary, critical, high, cves, graded });

  return (
    <div className="flex items-center gap-4">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-ink-secondary">
            Risk posture
          </p>
          {graded && onScoreFormatChange ? (
            <ScoreFormatToggle value={scoreFormat} onChange={onScoreFormatChange} />
          ) : null}
        </div>
        <p className={`mt-2 inline-flex flex-wrap items-baseline gap-3 rounded-xl border px-3 py-2 font-semibold ${scoreTone}`} data-testid="overview-posture-score">
          {loading ? (
            "Loading posture…"
          ) : graded ? (
            <>
              {/* Always show BOTH the letter grade and the %/points, whatever the
                  chosen primary format, so the number is never ambiguous. */}
              <span className="text-4xl leading-none tracking-tight tabular-nums">{scoreDisplay}</span>
              {scoreFormat !== "grade" ? (
                <span className="text-xs font-medium text-ink-secondary">Grade {grade}</span>
              ) : typeof score === "number" ? (
                <span className="text-xs font-medium text-ink-secondary">{Math.round(score)}%</span>
              ) : null}
            </>
          ) : (
            localReport ? "Posture unavailable" : "Awaiting scan"
          )}
        </p>
        {graded && <p className="mt-2 text-sm font-medium text-foreground">Posture score · 0–100, higher is better</p>}
        {graded ? (
          trend && trend.points >= 2 ? (
            <p
              className="mt-1 text-xs text-ink-secondary"
              data-testid="overview-posture-trend"
              title={`Previous posture score: ${Math.round(trend.previousScore)}%`}
            >
              {trend.direction === "unchanged"
                ? "Unchanged since the previous scan"
                : `${trend.direction === "improved" ? "Improved" : "Worsened"} ${Math.abs(Math.round(trend.delta))} points since the previous scan`}
            </p>
          ) : (
            <p className="mt-1 text-xs text-ink-secondary">
              Current evidence snapshot · use Top risks to prioritize remediation
            </p>
          )
        ) : null}
        <p className="mt-2 text-sm leading-relaxed text-ink-secondary">{blurb}</p>
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
  localReport = false,
  href,
  icon: Icon,
  label,
  value,
  title,
}: {
  localReport?: boolean | undefined;
  href: string;
  icon: ElementType;
  label: string;
  value: number | string;
  title?: string | undefined;
}) {
  return (
    <ReportEvidenceLink localReport={localReport}
      href={href}
      title={title}
      className="inline-flex items-center gap-1 rounded-full border border-outline bg-surface-muted px-2 py-0.5 text-[10px] font-semibold text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
    >
      <Icon className="h-3 w-3 text-ink-secondary" aria-hidden="true" />
      {label} {value}
    </ReportEvidenceLink>
  );
}

function SeverityIssueStrip({
  localReport = false,
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
  localReport?: boolean | undefined;
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
      tone: "text-red-800 dark:text-red-200",
      tint: "border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] hover:border-[color:var(--severity-critical)]",
      value: summaryReady ? (hasTyped ? resolved.totals.critical : critical) : 0,
    },
    {
      key: "high",
      label: "High",
      tone: "text-orange-800 dark:text-orange-200",
      tint: "border-[color:var(--severity-high-border)] bg-[color:var(--severity-high-bg)] hover:border-[color:var(--severity-high)]",
      value: summaryReady ? (hasTyped ? resolved.totals.high : high) : 0,
    },
    {
      key: "medium",
      label: "Medium",
      tone: "text-amber-800 dark:text-amber-200",
      tint: "border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] hover:border-[color:var(--severity-medium)]",
      value: summaryReady ? (hasTyped ? resolved.totals.medium : severity.medium) : 0,
    },
    {
      key: "low",
      label: "Low",
      tone: "text-blue-800 dark:text-blue-200",
      tint: "border-[color:var(--severity-low-border)] bg-[color:var(--severity-low-bg)] hover:border-[color:var(--severity-low)]",
      value: summaryReady ? (hasTyped ? resolved.totals.low : severity.low) : 0,
    },
  ];
  const stackedTotal = bands.reduce((sum, band) => sum + band.value, 0);
  const issueTypes: IssueType[] = ["vulnerability", "misconfiguration", "secret", "pii", "identity", "unclassified"];

  return (
    <div
      className="@container min-w-0 border-t border-outline pt-3 @min-[56rem]:border-t-0 @min-[56rem]:border-l @min-[56rem]:pt-0 @min-[56rem]:pl-6"
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
                localReport={localReport}
                href={findingsHref({ scope: "all", kev: true })}
                icon={Flame}
                label="KEV"
                value={kev}
                title="Known-exploited vulnerabilities (CISA KEV)"
              />
            ) : null}
            {summaryReady && credentials != null ? (
              <CategoryChip
                localReport={localReport}
                href={findingsHref({ scope: "all", issue: "secret" })}
                icon={KeyRound}
                label="Secrets"
                value={credentials}
                title="Findings that expose credentials or secrets"
              />
            ) : null}
            {complianceScore ? (
              <CategoryChip
                localReport={localReport}
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

      <div className="grid grid-cols-2 gap-2 @min-[36rem]:grid-cols-4">
        {bands.map((band) => (
          <ReportEvidenceLink localReport={localReport}
            key={band.key}
            href={findingsHref({ scope: "all", severity: band.key })}
            className={`grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2 rounded-lg border px-2.5 py-2 transition ${band.tint}`}
          >
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-ink-secondary">
              {band.label}
            </p>
            <p className={`font-mono text-xl font-semibold ${band.tone}`}>
              {summaryReady ? band.value : "—"}
            </p>
            {hasTyped && summaryReady ? (
              <div className="col-span-2 mt-2 space-y-1">
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
                <div className="flex flex-wrap gap-x-1.5 gap-y-0.5 text-[9px] text-ink-secondary">
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
            ) : null}
          </ReportEvidenceLink>
        ))}
      </div>

      {hasTyped && summaryReady ? (
        <div className="mt-3 flex flex-wrap gap-2 border-t border-outline pt-2.5">
          {issueTypes.map((issue) => {
            const total = resolved.byType[issue];
            if (total <= 0) return null;
            const Glyph = ISSUE_TYPE_GLYPH[issue];
            return (
              <ReportEvidenceLink localReport={localReport}
                key={issue}
                href={findingsHref({ scope: "all", issue })}
                className="inline-flex items-center gap-1.5 rounded-full border border-outline bg-surface px-2 py-0.5 text-[10px] text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
              >
                <Glyph className="h-3 w-3 text-ink-secondary" aria-hidden="true" />
                {ISSUE_TYPE_SHORT[issue]} {total}
              </ReportEvidenceLink>
            );
          })}
        </div>
      ) : null}
      </Collapsible>
    </div>
  );
}

function ReportEvidenceLink({ localReport, children, className, title, ...props }: ComponentProps<typeof Link> & { localReport: boolean }) {
  return localReport ? <div className={className} title={title}>{children}</div> : <Link {...props} className={className} title={title}>{children}</Link>;
}
