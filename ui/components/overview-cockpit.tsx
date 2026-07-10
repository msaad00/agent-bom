"use client";

import Link from "next/link";
import {
  ArrowRight,
  Bot,
  GitBranch,
  Shield,
  ShieldAlert,
  Workflow,
} from "lucide-react";

import type { OverviewDomain, OverviewResponse } from "@/lib/api";
import type { ServiceEntry, ServiceId } from "@/lib/api-types";
import { AttackPathCard } from "@/components/attack-path-card";
import { Collapsible } from "@/components/collapsible";
import { FrameworkIcon } from "@/components/framework-icon";
import type { SeverityCounts } from "@/lib/dashboard-data";
import {
  ISSUE_TYPE_SHORT,
  SEVERITY_BANDS,
  emptyIssueSeverityMatrix,
  findingsHref,
  type IssueSeverityMatrix,
  type IssueType,
  type SeverityBand,
} from "@/lib/finding-issue-type";
import {
  OVERVIEW_PERSONAS,
  overviewPersonaDrillDown,
  overviewPersonaHint,
  overviewPersonaLabel,
  overviewPersonaZoomOut,
  type OverviewPersona,
} from "@/lib/overview-persona";
import { SERVICE_META, serviceStateLabel } from "@/lib/service-registry";

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

export interface OverviewCockpitProps {
  grade: string;
  score?: number | undefined;
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
  persona: OverviewPersona;
  onPersonaChange: (persona: OverviewPersona) => void;
}

export function OverviewCockpit({
  grade,
  score,
  postureSummary,
  critical,
  high,
  kev,
  credentials,
  agents,
  cves,
  scans,
  latestScan,
  mode,
  summaryReady,
  severity,
  issueMatrix = null,
  domains,
  topPath,
  exposurePaths,
  signals,
  compliance = null,
  services = null,
  persona,
  onPersonaChange,
}: OverviewCockpitProps) {
  const isCiso = persona === "ciso";
  const isTrust = persona === "trust";
  const isEngineer = persona === "engineer";
  const drillDown = overviewPersonaDrillDown(persona);
  const zoomOut = overviewPersonaZoomOut(persona);
  const domainList = domains ? Object.values(domains) : [];
  const activeDomains = domainList.filter((domain) => domain.status !== "idle").length;
  const coverage = domainList.length > 0 ? Math.round((activeDomains / domainList.length) * 100) : null;
  const complianceScore =
    compliance != null ? `${Math.round(compliance.overallScore)}%` : coverage != null ? `${coverage}%` : undefined;

  return (
    <div className="space-y-4">
      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 lg:p-5">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
              Command center
            </p>
            <p className="mt-1 max-w-xl text-xs text-[color:var(--text-secondary)]">
              {overviewPersonaHint(persona)} Same estate — change altitude to go deeper or zoom out.
            </p>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <div
              className="flex rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5"
              role="group"
              aria-label="Overview altitude"
            >
              {OVERVIEW_PERSONAS.map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => onPersonaChange(value)}
                  className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition ${
                    persona === value
                      ? "bg-[color:var(--surface)] text-[color:var(--foreground)] shadow-sm"
                      : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
                  }`}
                >
                  {overviewPersonaLabel(value)}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap justify-end gap-2 text-[10px]">
              {zoomOut ? (
                <button
                  type="button"
                  onClick={() => onPersonaChange(zoomOut)}
                  className="text-[color:var(--text-tertiary)] hover:text-emerald-400"
                >
                  ↑ {overviewPersonaLabel(zoomOut)}
                </button>
              ) : null}
              {drillDown ? (
                <button
                  type="button"
                  onClick={() => onPersonaChange(drillDown)}
                  className="text-[color:var(--text-tertiary)] hover:text-emerald-400"
                >
                  ↓ {overviewPersonaLabel(drillDown)}
                </button>
              ) : null}
            </div>
          </div>
        </div>

        <div className="grid gap-5 lg:grid-cols-[auto_minmax(0,1fr)_auto] lg:items-start">
          <PostureHero
            grade={grade}
            score={score}
            summary={postureSummary}
            persona={persona}
            critical={critical}
            high={high}
          />
          <SeverityIssueStrip
            summaryReady={summaryReady}
            critical={critical}
            high={high}
            kev={kev}
            credentials={credentials}
            complianceScore={complianceScore}
            showComplianceCallout={isCiso || isTrust}
            showSecretsCallout={isEngineer}
            severity={severity}
            matrix={issueMatrix}
          />
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs lg:grid-cols-1">
            <MetaLine label="Agents" value={summaryReady && agents != null ? String(agents) : "—"} href="/agents" />
            <MetaLine label="CVEs" value={summaryReady && cves != null ? String(cves) : "—"} href={findingsHref({ issue: "vulnerability" })} />
            <MetaLine label="Scans" value={summaryReady && scans != null ? String(scans) : "—"} href="/jobs" />
            <MetaLine label="Last scan" value={latestScan ?? "—"} />
            <MetaLine label="Mode" value={mode} />
          </div>
        </div>

        <ComplianceSnapshotPanel compliance={compliance} defaultOpen={isTrust || isCiso} />
        <ActivatedServicesPanel
          services={services}
          activeCount={signals.activeServices}
          defaultOpen={isEngineer}
        />

        {domainList.length > 0 ? (
          <Collapsible
            bare
            className="mt-4 border-t border-[color:var(--border-subtle)]"
            title="Domain coverage"
            subtitle={
              coverage != null ? `${coverage}% domains reporting signal` : "Cross-domain posture roll-up"
            }
            count={domainList.length}
            scrollMaxHeight="14rem"
            defaultOpen={!isTrust}
            actions={
              <div className="flex flex-wrap justify-end gap-1.5 text-[10px]">
                {isEngineer ? (
                  <>
                    <SignalChip label="Tools" value={summaryReady && signals.tools != null ? String(signals.tools) : "—"} />
                    <SignalChip label="Packages" value={summaryReady && signals.packages != null ? String(signals.packages) : "—"} />
                  </>
                ) : (
                  <SignalChip
                    label="Cred exposure"
                    value={summaryReady && credentials != null ? String(credentials) : "—"}
                  />
                )}
                <SignalChip label="Services" value={summaryReady ? String(signals.activeServices) : "—"} />
                <SignalChip label="Connect" value={signals.connected ? "Live" : "Setup"} highlight={signals.connected} />
              </div>
            }
          >
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              {domainList.map((domain) => (
                <DomainCard key={domain.href} domain={domain} />
              ))}
            </div>
          </Collapsible>
        ) : null}
      </section>

      <div className="grid gap-4 lg:grid-cols-12">
        <section className="min-h-0 space-y-3 lg:col-span-8">
          {isCiso ? (
            <CisoRiskPanel
              topPath={topPath}
              exposurePaths={exposurePaths}
              critical={critical}
              high={high}
              credentials={credentials}
              summaryReady={summaryReady}
              onDrillDown={drillDown ? () => onPersonaChange(drillDown) : undefined}
            />
          ) : null}
          {isTrust ? (
            <TrustEvidencePanel
              compliance={compliance}
              critical={critical}
              summaryReady={summaryReady}
              onZoomOut={zoomOut ? () => onPersonaChange(zoomOut) : undefined}
              onDrillDown={drillDown ? () => onPersonaChange(drillDown) : undefined}
            />
          ) : null}
          {isEngineer ? (
            <EngineerExposurePanel
              topPath={topPath}
              exposurePaths={exposurePaths}
              onZoomOut={zoomOut ? () => onPersonaChange(zoomOut) : undefined}
            />
          ) : null}
        </section>

        <aside className="min-h-0 space-y-3 lg:col-span-4">
          <Collapsible
            title="Severity roll-up"
            subtitle={
              isTrust
                ? "Issue severity for control evidence and attestations"
                : isCiso
                  ? "Open issues by severity across CVEs, misconfigs, and secrets"
                  : "Finding backlog by severity and issue type"
            }
            defaultOpen
          >
            <SeverityRollup
              severity={severity}
              summaryReady={summaryReady}
              matrix={issueMatrix}
            />
          </Collapsible>

          <Collapsible
            title={isCiso ? "Leadership actions" : isTrust ? "Trust & GRC" : "Investigate"}
            defaultOpen
            scrollMaxHeight="18rem"
          >
            <div className="grid gap-2">
              {isCiso ? (
                <>
                  <QuickLink href="/compliance" icon={Shield} label="Compliance posture" detail="Framework coverage & trust center" />
                  <QuickLink href="/findings?severity=critical" icon={ShieldAlert} label="Critical findings" detail={`${critical} open`} />
                  <QuickLink href="/governance" icon={Shield} label="Governance" detail="Policy and control evidence" />
                  <QuickLink href="/audit" icon={Shield} label="Audit trail" detail="Signed operator events" />
                  <QuickLink href="/connections" icon={Workflow} label="Integrations" detail={signals.connected ? "Live connectors" : "Connect cloud & SIEM"} />
                </>
              ) : null}
              {isTrust ? (
                <>
                  <QuickLink href="/compliance" icon={Shield} label="Trust center" detail="Framework packs & control status" />
                  <QuickLink href="/audit" icon={Shield} label="Audit evidence" detail="Signed operator events" />
                  <QuickLink href="/governance" icon={Shield} label="Control mapping" detail="Policy and ownership" />
                  <QuickLink href="/findings?severity=critical" icon={ShieldAlert} label="Open control gaps" detail={`${critical} critical`} />
                  <QuickLink href="/jobs" icon={Workflow} label="Evidence runs" detail="Scans that feed attestations" />
                </>
              ) : null}
              {isEngineer ? (
                <>
                  <QuickLink href="/findings?severity=critical" icon={ShieldAlert} label="Critical findings" detail={`${critical} open`} />
                  <QuickLink href="/security-graph" icon={GitBranch} label="Security graph" detail="Lineage & attack paths" />
                  <QuickLink href="/mesh" icon={Workflow} label="Agent mesh" detail={`${agents ?? "—"} agents`} />
                  <QuickLink href="/agents" icon={Bot} label="Fleet inventory" detail="Runtime & MCP evidence" />
                  <QuickLink href="/remediation" icon={ShieldAlert} label="Remediation queue" detail="Actionable fixes" />
                </>
              ) : null}
            </div>
          </Collapsible>
        </aside>
      </div>
    </div>
  );
}

function ComplianceSnapshotPanel({
  compliance,
  defaultOpen = true,
}: {
  compliance: OverviewComplianceSnapshot | null | undefined;
  defaultOpen?: boolean | undefined;
}) {
  const frameworks = (compliance?.frameworks ?? []).slice(0, 8);
  const failing = frameworks.filter((item) => item.fail > 0).length;
  const statusTone =
    compliance?.overallStatus === "pass"
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
      defaultOpen={defaultOpen}
      subtitle={
        compliance
          ? `${Math.round(compliance.overallScore)}% overall · ${failing} framework${failing === 1 ? "" : "s"} need attention`
          : "Framework coverage appears after the first scan"
      }
      count={frameworks.length > 0 ? frameworks.length : undefined}
      scrollMaxHeight="16rem"
      data-testid="overview-compliance-snapshot"
      actions={
        <div className="flex items-center gap-3">
          {compliance ? (
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
      {frameworks.length > 0 ? (
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {frameworks.map((framework) => {
            const tone =
              framework.fail > 0 ? "fail" : framework.warn > 0 ? "warn" : "pass";
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
                    {framework.pass}/{framework.total} pass
                    {framework.fail > 0 ? ` · ${framework.fail} fail` : ""}
                  </p>
                </div>
                <span
                  className={`justify-self-end rounded-full px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${
                    tone === "fail"
                      ? "bg-red-500/15 text-red-300"
                      : tone === "warn"
                        ? "bg-yellow-500/15 text-yellow-200"
                        : "bg-emerald-500/15 text-emerald-300"
                  }`}
                >
                  {tone}
                </span>
              </Link>
            );
          })}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-5 text-center text-xs text-[color:var(--text-tertiary)]">
          Run a scan to light up OWASP, NIST, CIS, and related framework coverage.
        </div>
      )}
    </Collapsible>
  );
}

function ActivatedServicesPanel({
  services,
  activeCount,
  defaultOpen = true,
}: {
  services: Partial<Record<ServiceId, ServiceEntry>> | null | undefined;
  activeCount: number;
  defaultOpen?: boolean | undefined;
}) {
  const rows = (Object.entries(SERVICE_META) as [ServiceId, (typeof SERVICE_META)[ServiceId]][]).map(
    ([id, meta]) => {
      const entry = services?.[id] ?? { state: "locked" as const, count: 0 };
      return { id, entry, meta };
    },
  );

  return (
    <Collapsible
      bare
      className="mt-4 border-t border-[color:var(--border-subtle)]"
      title="Activated services"
      defaultOpen={defaultOpen}
      subtitle={
        activeCount > 0
          ? `${activeCount} live or connected · tools, data, runtime, and governance surfaces`
          : "Connect accounts, sync fleet, or enable runtime to activate surfaces"
      }
      count={rows.length}
      scrollMaxHeight="14rem"
      data-testid="overview-activated-services"
      actions={
        <Link href="/connections" className="inline-flex items-center gap-1 text-xs text-emerald-500 hover:text-emerald-400">
          Manage <ArrowRight className="h-3 w-3" />
        </Link>
      }
    >
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {rows.map(({ id, entry, meta }) => {
          const live = entry.state === "live" || entry.state === "connected";
          return (
            <Link
              key={id}
              href={meta.unlockHref}
              className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-2.5 transition ${
                live
                  ? "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] hover:border-[color:var(--border-strong)]"
                  : "border-dashed border-[color:var(--border-subtle)] bg-transparent text-[color:var(--text-tertiary)] hover:border-[color:var(--border-strong)]"
              }`}
            >
              <div className="min-w-0">
                <p className={`truncate text-xs font-medium ${live ? "text-[color:var(--foreground)]" : ""}`}>
                  {meta.label}
                </p>
                <p className="mt-0.5 text-[10px] text-[color:var(--text-tertiary)]">
                  {live && entry.count > 0 ? `${entry.count} · ${serviceStateLabel(entry.state)}` : serviceStateLabel(entry.state)}
                </p>
              </div>
              <span
                className={`h-2 w-2 shrink-0 rounded-full ${
                  entry.state === "live"
                    ? "bg-emerald-400"
                    : entry.state === "connected"
                      ? "bg-sky-400"
                      : "bg-[color:var(--border-strong)]"
                }`}
                aria-hidden="true"
              />
            </Link>
          );
        })}
      </div>
    </Collapsible>
  );
}

function EngineerExposurePanel({
  topPath,
  exposurePaths,
  onZoomOut,
}: {
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  onZoomOut?: (() => void) | undefined;
}) {
  return (
    <Collapsible
      title="Priority exposure path"
      subtitle="Highest-scored blast-radius chain for engineering triage"
      defaultOpen
      scrollMaxHeight="28rem"
      actions={
        <div className="flex items-center gap-3">
          {onZoomOut ? (
            <button type="button" onClick={onZoomOut} className="text-xs text-[color:var(--text-tertiary)] hover:text-emerald-400">
              ← Trust
            </button>
          ) : null}
          <Link href="/security-graph" className="text-xs text-emerald-500 hover:text-emerald-400">
            Open graph
          </Link>
        </div>
      }
    >
      {topPath ? (
        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
          <AttackPathCard nodes={topPath.nodes} riskScore={topPath.riskScore} href={topPath.href} captureMode compact />
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">
          No scored exposure path yet. Run a scan to populate attack-path evidence.
        </div>
      )}

      {exposurePaths.length > 1 ? (
        <div className="mt-3 space-y-2">
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
            Next paths
          </p>
          {exposurePaths.slice(1, 5).map((path) => (
            <Link
              key={path.key}
              href={path.href}
              className="flex items-center justify-between gap-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 transition hover:border-[color:var(--border-strong)]"
            >
              <div className="min-w-0 truncate font-mono text-xs text-[color:var(--text-secondary)]">
                {path.nodes.map((node) => node.label).join(" → ")}
              </div>
              <span className="shrink-0 font-mono text-[11px] text-[color:var(--text-tertiary)]">
                {path.riskScore.toFixed(1)}
              </span>
            </Link>
          ))}
        </div>
      ) : null}
    </Collapsible>
  );
}

function CisoRiskPanel({
  topPath,
  exposurePaths,
  critical,
  high,
  credentials,
  summaryReady,
  onDrillDown,
}: {
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  critical: number;
  high: number;
  credentials: number | null;
  summaryReady: boolean;
  onDrillDown?: (() => void) | undefined;
}) {
  const headline =
    summaryReady && critical > 0
      ? `${critical} critical finding${critical === 1 ? "" : "s"} need leadership attention`
      : summaryReady && high > 0
        ? `${high} high-severity finding${high === 1 ? "" : "s"} in the latest scan`
        : "No prioritized risk themes yet";

  const cveNode = topPath?.nodes.find((node) => node.type === "cve");
  const agentNode = topPath?.nodes.find((node) => node.type === "agent");
  const serverNode = topPath?.nodes.find((node) => node.type === "server");
  const hasCredentialPath = topPath?.nodes.some((node) => node.type === "credential");

  return (
    <Collapsible
      title="Top risks"
      subtitle="Business-readable priorities — drill into Trust for evidence, Engineer for paths"
      defaultOpen
      scrollMaxHeight="28rem"
      actions={
        onDrillDown ? (
          <button type="button" onClick={onDrillDown} className="text-xs text-emerald-500 hover:text-emerald-400">
            Trust →
          </button>
        ) : null
      }
    >
      <p className="text-base font-semibold text-[color:var(--foreground)]">{headline}</p>
      {topPath ? (
        <ul className="mt-3 space-y-2 text-sm text-[color:var(--text-secondary)]">
          {cveNode ? <li>Known exploit exposure: {cveNode.label}</li> : null}
          {serverNode ? <li>MCP / runtime surface: {serverNode.label}</li> : null}
          {agentNode ? <li>Production agent scope: {agentNode.label}</li> : null}
          {hasCredentialPath ? <li>Credential-aware blast radius detected in evidence chain</li> : null}
          {summaryReady && credentials != null && credentials > 0 ? (
            <li>{credentials} finding{credentials === 1 ? "" : "s"} touch exposed credentials or secrets</li>
          ) : null}
        </ul>
      ) : (
        <p className="mt-3 text-sm text-[color:var(--text-secondary)]">
          Run a scan to populate compliance, findings, and domain coverage evidence.
        </p>
      )}
      <div className="mt-4 flex flex-wrap gap-2">
        <Link
          href="/compliance"
          className="rounded-lg border border-emerald-700/50 bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-200"
        >
          Compliance evidence
        </Link>
        <Link
          href="/findings?severity=critical"
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)]"
        >
          Critical findings
        </Link>
      </div>

      {exposurePaths.length > 1 ? (
        <div className="mt-4 border-t border-[color:var(--border-subtle)] pt-3">
          <p className="text-xs font-medium text-[color:var(--foreground)]">
            {exposurePaths.length - 1} additional risk theme{exposurePaths.length - 1 === 1 ? "" : "s"}
          </p>
          <ul className="mt-2 space-y-2 text-xs text-[color:var(--text-secondary)]">
            {exposurePaths.slice(1, 4).map((path) => (
              <li key={path.key}>
                {path.nodes.find((node) => node.type === "cve")?.label ?? "Risk chain"} affecting{" "}
                {path.nodes.find((node) => node.type === "agent")?.label ?? "agent runtime"} · score{" "}
                {path.riskScore.toFixed(1)}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Collapsible>
  );
}

function TrustEvidencePanel({
  compliance,
  critical,
  summaryReady,
  onZoomOut,
  onDrillDown,
}: {
  compliance: OverviewComplianceSnapshot | null | undefined;
  critical: number;
  summaryReady: boolean;
  onZoomOut?: (() => void) | undefined;
  onDrillDown?: (() => void) | undefined;
}) {
  const frameworks = compliance?.frameworks ?? [];
  const failing = frameworks.filter((item) => item.fail > 0);
  const warning = frameworks.filter((item) => item.fail === 0 && item.warn > 0);

  return (
    <Collapsible
      title="Trust evidence"
      subtitle="GRC altitude — frameworks and control gaps that feed CISO reporting"
      defaultOpen
      scrollMaxHeight="28rem"
      actions={
        <div className="flex items-center gap-3">
          {onZoomOut ? (
            <button type="button" onClick={onZoomOut} className="text-xs text-[color:var(--text-tertiary)] hover:text-emerald-400">
              ← CISO
            </button>
          ) : null}
          {onDrillDown ? (
            <button type="button" onClick={onDrillDown} className="text-xs text-emerald-500 hover:text-emerald-400">
              Engineer →
            </button>
          ) : null}
        </div>
      }
    >
      <p className="text-base font-semibold text-[color:var(--foreground)]">
        {compliance
          ? `${Math.round(compliance.overallScore)}% framework coverage · ${failing.length} gap${failing.length === 1 ? "" : "s"}`
          : "No framework evidence yet"}
      </p>
      <p className="mt-2 text-sm text-[color:var(--text-secondary)]">
        {summaryReady && critical > 0
          ? `${critical} critical finding${critical === 1 ? "" : "s"} may block attestations until remediated.`
          : "Same findings and scans as leadership and engineering — packaged for audit and trust reviews."}
      </p>

      {failing.length > 0 || warning.length > 0 ? (
        <ul className="mt-3 space-y-2 text-sm text-[color:var(--text-secondary)]">
          {failing.slice(0, 4).map((item) => (
            <li key={item.id}>
              <span className="font-medium text-red-300">{item.label}</span> — {item.fail} fail / {item.total} controls
            </li>
          ))}
          {warning.slice(0, 3).map((item) => (
            <li key={item.id}>
              <span className="font-medium text-amber-200">{item.label}</span> — {item.warn} warn / {item.total} controls
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-sm text-[color:var(--text-secondary)]">
          {frameworks.length > 0
            ? "Mapped frameworks are currently passing — export packs from the trust center."
            : "Run a scan to light up OWASP, NIST, CIS, and related framework coverage."}
        </p>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <Link
          href="/compliance"
          className="rounded-lg border border-emerald-700/50 bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-200"
        >
          Open trust center
        </Link>
        <Link
          href="/audit"
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)]"
        >
          Audit trail
        </Link>
      </div>
    </Collapsible>
  );
}

function PostureHero({
  grade,
  score,
  summary,
  persona,
  critical,
  high,
}: {
  grade: string;
  score?: number | undefined;
  summary?: string | undefined;
  persona: OverviewPersona;
  critical: number;
  high: number;
}) {
  const tone =
    grade === "A" || grade === "B"
      ? "text-emerald-500"
      : grade === "C" || grade === "D"
        ? "text-amber-500"
        : "text-red-500";

  const altitudeLabel =
    persona === "ciso" ? "Risk posture" : persona === "trust" ? "Trust posture" : "Operator posture";

  return (
    <div className="flex items-center gap-4">
      <div className={`flex h-16 w-16 items-center justify-center rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] ${tone}`}>
        <span className="text-2xl font-bold">{grade}</span>
      </div>
      <div className="min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
          {altitudeLabel}
        </p>
        <p className="mt-1 text-lg font-semibold text-[color:var(--foreground)]">
          {typeof score === "number" ? `Score ${score}` : "Awaiting scan"}
        </p>
        <p className="mt-0.5 line-clamp-2 text-xs text-[color:var(--text-secondary)]">
          {summary ??
            (persona === "ciso"
              ? critical > 0
                ? `${critical} critical and ${high} high findings across the AI supply chain.`
                : "Single-pane roll-up across compliance, cloud, runtime, and identity domains."
              : persona === "trust"
                ? "Framework coverage and control evidence for GRC and audit reviews."
                : "Blast-radius paths, MCP topology, and remediation evidence for engineering triage.")}
        </p>
      </div>
    </div>
  );
}

function SeverityIssueStrip({
  summaryReady,
  critical,
  high,
  kev,
  credentials,
  complianceScore,
  showComplianceCallout,
  showSecretsCallout,
  severity,
  matrix,
}: {
  summaryReady: boolean;
  critical: number;
  high: number;
  kev: number | null;
  credentials: number | null;
  complianceScore?: string | undefined;
  showComplianceCallout: boolean;
  showSecretsCallout: boolean;
  severity: SeverityCounts;
  matrix: IssueSeverityMatrix | null | undefined;
}) {
  const resolved = matrix ?? emptyIssueSeverityMatrix();
  const hasTyped = resolved.openTotal > 0;
  const bands: { key: SeverityBand; label: string; tone: string; value: number }[] = [
    {
      key: "critical",
      label: "Critical",
      tone: "text-red-500 dark:text-red-400",
      value: summaryReady ? (hasTyped ? resolved.totals.critical : critical) : 0,
    },
    {
      key: "high",
      label: "High",
      tone: "text-orange-500 dark:text-orange-400",
      value: summaryReady ? (hasTyped ? resolved.totals.high : high) : 0,
    },
    {
      key: "medium",
      label: "Medium",
      tone: "text-yellow-500 dark:text-yellow-300",
      value: summaryReady ? (hasTyped ? resolved.totals.medium : severity.medium) : 0,
    },
    {
      key: "low",
      label: "Low",
      tone: "text-sky-500 dark:text-sky-300",
      value: summaryReady ? (hasTyped ? resolved.totals.low : severity.low) : 0,
    },
  ];
  const stackedTotal = bands.reduce((sum, band) => sum + band.value, 0);
  const issueTypes: IssueType[] = ["vulnerability", "misconfiguration", "secret", "identity"];
  const issueTone: Record<IssueType, string> = {
    vulnerability: "bg-violet-500",
    misconfiguration: "bg-orange-500",
    secret: "bg-rose-500",
    identity: "bg-cyan-500",
  };

  return (
    <div
      className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3"
      data-testid="overview-severity-issue-strip"
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            Open issues
          </p>
          <p className="mt-0.5 text-[11px] text-[color:var(--text-secondary)]">
            Severity across CVEs, misconfigs, secrets, and identity
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {summaryReady && kev != null ? (
            <Link
              href={findingsHref({ kev: true })}
              className="rounded-full border border-amber-500/35 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-200"
            >
              KEV {kev}
            </Link>
          ) : null}
          {!showComplianceCallout && showSecretsCallout && summaryReady && credentials != null ? (
            <Link
              href={findingsHref({ issue: "secret" })}
              className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-semibold text-rose-200"
            >
              Secrets {credentials}
            </Link>
          ) : null}
          {showComplianceCallout && complianceScore ? (
            <Link
              href="/compliance"
              className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-200"
            >
              Compliance {complianceScore}
            </Link>
          ) : null}
        </div>
      </div>

      <div className="mb-3 flex h-2.5 overflow-hidden rounded-full bg-[color:var(--surface)]">
        {summaryReady && stackedTotal > 0 ? (
          bands.map((band) =>
            band.value > 0 ? (
              <div
                key={band.key}
                className={
                  band.key === "critical"
                    ? "bg-red-500"
                    : band.key === "high"
                      ? "bg-orange-500"
                      : band.key === "medium"
                        ? "bg-yellow-500"
                        : "bg-sky-500"
                }
                style={{ width: `${(band.value / stackedTotal) * 100}%` }}
                title={`${band.label}: ${band.value}`}
              />
            ) : null,
          )
        ) : (
          <div className="w-full bg-emerald-500/35" />
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {bands.map((band) => (
          <Link
            key={band.key}
            href={findingsHref({ severity: band.key })}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-2 transition hover:border-[color:var(--border-strong)]"
          >
            <p className="text-[10px] font-medium uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
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
                        className={issueTone[issue]}
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
                    return (
                      <span key={issue}>
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
            return (
              <Link
                key={issue}
                href={findingsHref({ issue })}
                className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)]"
              >
                <span className={`h-1.5 w-1.5 rounded-full ${issueTone[issue]}`} aria-hidden="true" />
                {ISSUE_TYPE_SHORT[issue]} {total}
              </Link>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function MetaLine({ label, value, href }: { label: string; value: string; href?: string | undefined }) {
  const content = (
    <div className="flex items-center justify-between gap-2">
      <span className="text-[color:var(--text-tertiary)]">{label}</span>
      <span className="font-medium text-[color:var(--foreground)]">{value}</span>
    </div>
  );
  return href ? <Link href={href} className="block rounded hover:bg-[color:var(--surface-muted)]">{content}</Link> : content;
}

function SignalChip({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string;
  highlight?: boolean | undefined;
}) {
  return (
    <span
      className={`rounded-full border px-2.5 py-1 ${
        highlight
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
          : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
      }`}
    >
      <span className="text-[color:var(--text-tertiary)]">{label}</span> {value}
    </span>
  );
}

function DomainCard({ domain }: { domain: OverviewDomain }) {
  const tone = domainStatusTone(domain.status);
  return (
    <Link
      href={domain.graph_href ?? domain.href}
      className="flex items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5 transition hover:border-[color:var(--border-strong)]"
    >
      <div className="min-w-0">
        <p className="truncate text-xs font-medium text-[color:var(--foreground)]">{domain.label}</p>
        <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{domain.metric_label}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <span className={`font-mono text-sm font-semibold ${tone.text}`}>{domain.metric}</span>
        <span className={`h-2 w-2 rounded-full ${tone.dot}`} />
      </div>
    </Link>
  );
}

function SeverityRollup({
  severity,
  summaryReady,
  matrix,
}: {
  severity: SeverityCounts;
  summaryReady: boolean;
  matrix: IssueSeverityMatrix | null | undefined;
}) {
  const resolved = matrix ?? emptyIssueSeverityMatrix();
  const hasTyped = resolved.openTotal > 0;
  const rows = SEVERITY_BANDS.map((key) => ({
    key,
    label: key.charAt(0).toUpperCase() + key.slice(1),
    tone:
      key === "critical"
        ? "bg-red-500"
        : key === "high"
          ? "bg-orange-500"
          : key === "medium"
            ? "bg-yellow-500"
            : "bg-sky-500",
    href: findingsHref({ severity: key }),
    count: hasTyped ? resolved.totals[key] : severity[key],
  }));
  const max = Math.max(...rows.map((row) => row.count), 1);
  const issueTypes: IssueType[] = ["vulnerability", "misconfiguration", "secret", "identity"];

  return (
    <div className="space-y-2.5">
      {rows.map((row) => {
        const width = summaryReady ? Math.max(8, (row.count / max) * 100) : 0;
        return (
          <div key={row.key} className="space-y-1">
            <Link href={row.href} className="block group">
              <div className="mb-1 flex items-center justify-between text-xs">
                <span className="text-[color:var(--text-secondary)] group-hover:text-[color:var(--foreground)]">
                  {row.label}
                </span>
                <span className="font-mono text-[color:var(--text-tertiary)]">
                  {summaryReady ? row.count : "—"}
                </span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
                <div className={`h-full rounded-full ${row.tone}`} style={{ width: `${width}%` }} />
              </div>
            </Link>
            {hasTyped && summaryReady && row.count > 0 ? (
              <div className="flex flex-wrap gap-1 pl-0.5">
                {issueTypes.map((issue) => {
                  const count = resolved[issue][row.key];
                  if (count <= 0) return null;
                  return (
                    <Link
                      key={issue}
                      href={findingsHref({ severity: row.key, issue })}
                      className="rounded border border-[color:var(--border-subtle)] px-1.5 py-0.5 text-[9px] text-[color:var(--text-tertiary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--text-secondary)]"
                    >
                      {ISSUE_TYPE_SHORT[issue]} {count}
                    </Link>
                  );
                })}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function QuickLink({
  href,
  icon: Icon,
  label,
  detail,
}: {
  href: string;
  icon: typeof Shield;
  label: string;
  detail: string;
}) {
  return (
    <Link
      href={href}
      className="flex items-center justify-between gap-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 transition hover:border-[color:var(--border-strong)]"
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <Icon className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)]" />
        <div className="min-w-0">
          <p className="text-xs font-medium text-[color:var(--foreground)]">{label}</p>
          <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{detail}</p>
        </div>
      </div>
      <ArrowRight className="h-3.5 w-3.5 shrink-0 text-[color:var(--text-tertiary)]" />
    </Link>
  );
}

function domainStatusTone(status: OverviewDomain["status"]): { dot: string; text: string } {
  switch (status) {
    case "critical":
      return { dot: "bg-red-500", text: "text-red-400" };
    case "warn":
      return { dot: "bg-amber-500", text: "text-amber-400" };
    case "ok":
      return { dot: "bg-emerald-500", text: "text-emerald-400" };
    default:
      return { dot: "bg-zinc-600", text: "text-zinc-500" };
  }
}
