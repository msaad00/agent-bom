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
import { AttackPathCard } from "@/components/attack-path-card";
import type { SeverityCounts } from "@/lib/dashboard-data";
import {
  overviewPersonaHint,
  overviewPersonaLabel,
  type OverviewPersona,
} from "@/lib/overview-persona";

export interface ExposurePathView {
  nodes: { type: "cve" | "package" | "server" | "agent" | "credential"; label: string; severity?: string }[];
  riskScore: number;
  href: string;
  key: string;
}

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
  domains: OverviewResponse["domains"] | null;
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  signals: {
    tools: number | null;
    packages: number | null;
    activeServices: number;
    connected: boolean;
  };
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
  domains,
  topPath,
  exposurePaths,
  signals,
  persona,
  onPersonaChange,
}: OverviewCockpitProps) {
  const isExecutive = persona === "executive";
  const domainList = domains ? Object.values(domains) : [];
  const activeDomains = domainList.filter((domain) => domain.status !== "idle").length;
  const coverage = domainList.length > 0 ? Math.round((activeDomains / domainList.length) * 100) : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-xs text-[color:var(--text-secondary)]">{overviewPersonaHint(persona)}</p>
        <div className="flex rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-0.5">
          {(["executive", "engineer"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => onPersonaChange(value)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition ${
                persona === value
                  ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                  : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
              }`}
            >
              {overviewPersonaLabel(value)}
            </button>
          ))}
        </div>
      </div>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 lg:p-5">
        <div className="grid gap-5 lg:grid-cols-[auto_1fr_auto] lg:items-center">
          <PostureHero
            grade={grade}
            score={score}
            summary={postureSummary}
            persona={persona}
            critical={critical}
            high={high}
          />
          <div className={`grid grid-cols-2 gap-3 ${isExecutive ? "sm:grid-cols-3" : "sm:grid-cols-4"}`}>
            <PriorityKpi label="Critical" value={summaryReady ? critical : null} href="/findings?severity=critical" tone="critical" />
            <PriorityKpi label="High" value={summaryReady ? high : null} href="/findings?severity=high" tone="high" />
            {isExecutive ? (
              <PriorityKpi
                label="Compliance"
                value={null}
                textValue={coverage != null ? `${coverage}%` : undefined}
                href="/compliance"
              />
            ) : (
              <PriorityKpi label="KEV" value={summaryReady ? kev : null} href="/findings?kev=1" />
            )}
            {!isExecutive ? (
              <PriorityKpi label="Cred exposure" value={summaryReady ? credentials : null} href="/findings?q=credential" tone="warn" />
            ) : (
              <PriorityKpi label="KEV" value={summaryReady ? kev : null} href="/findings?kev=1" tone="warn" />
            )}
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs lg:grid-cols-1">
            <MetaLine label="Agents" value={summaryReady && agents != null ? String(agents) : "—"} href="/agents" />
            <MetaLine label="CVEs" value={summaryReady && cves != null ? String(cves) : "—"} href="/findings" />
            <MetaLine label="Scans" value={summaryReady && scans != null ? String(scans) : "—"} href="/jobs" />
            <MetaLine label="Last scan" value={latestScan ?? "—"} />
            <MetaLine label="Mode" value={mode} />
          </div>
        </div>

        {domainList.length > 0 ? (
          <div className="mt-5 border-t border-[color:var(--border-subtle)] pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  Domain coverage
                </p>
                <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">
                  {coverage != null ? `${coverage}% domains reporting signal` : "Cross-domain posture roll-up"}
                </p>
              </div>
              <div className="flex flex-wrap gap-2 text-[10px]">
                {!isExecutive ? (
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
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              {domainList.map((domain) => (
                <DomainCard key={domain.href} domain={domain} />
              ))}
            </div>
          </div>
        ) : null}
      </section>

      <div className="grid gap-4 lg:grid-cols-12">
        <section className="space-y-3 lg:col-span-8">
          {isExecutive ? (
            <ExecutiveRiskPanel
              topPath={topPath}
              exposurePaths={exposurePaths}
              critical={critical}
              high={high}
              credentials={credentials}
              summaryReady={summaryReady}
            />
          ) : (
            <EngineerExposurePanel topPath={topPath} exposurePaths={exposurePaths} />
          )}
        </section>

        <aside className="space-y-4 lg:col-span-4">
          <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Severity roll-up</h2>
            <p className="mt-0.5 text-xs text-[color:var(--text-tertiary)]">
              {isExecutive ? "Open findings by severity band" : "Finding backlog by severity"}
            </p>
            <SeverityRollup severity={severity} summaryReady={summaryReady} />
          </section>

          <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <h2 className="text-sm font-semibold text-[color:var(--foreground)]">
              {isExecutive ? "Governance actions" : "Investigate"}
            </h2>
            <div className="mt-3 grid gap-2">
              {isExecutive ? (
                <>
                  <QuickLink href="/compliance" icon={Shield} label="Compliance posture" detail="Framework coverage & trust center" />
                  <QuickLink href="/findings?severity=critical" icon={ShieldAlert} label="Critical findings" detail={`${critical} open`} />
                  <QuickLink href="/governance" icon={Shield} label="Governance" detail="Policy and control evidence" />
                  <QuickLink href="/audit" icon={Shield} label="Audit trail" detail="Signed operator events" />
                  <QuickLink href="/connections" icon={Workflow} label="Integrations" detail={signals.connected ? "Live connectors" : "Connect cloud & SIEM"} />
                </>
              ) : (
                <>
                  <QuickLink href="/findings?severity=critical" icon={ShieldAlert} label="Critical findings" detail={`${critical} open`} />
                  <QuickLink href="/security-graph" icon={GitBranch} label="Security graph" detail="Lineage & attack paths" />
                  <QuickLink href="/mesh" icon={Workflow} label="Agent mesh" detail={`${agents ?? "—"} agents`} />
                  <QuickLink href="/agents" icon={Bot} label="Fleet inventory" detail="Runtime & MCP evidence" />
                  <QuickLink href="/remediation" icon={ShieldAlert} label="Remediation queue" detail="Actionable fixes" />
                </>
              )}
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

function EngineerExposurePanel({
  topPath,
  exposurePaths,
}: {
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
}) {
  return (
    <>
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Priority exposure path</h2>
          <p className="text-xs text-[color:var(--text-tertiary)]">Highest-scored blast-radius chain for engineering triage</p>
        </div>
        <Link href="/security-graph" className="text-xs text-emerald-500 hover:text-emerald-400">
          Open graph
        </Link>
      </div>
      {topPath ? (
        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <AttackPathCard nodes={topPath.nodes} riskScore={topPath.riskScore} href={topPath.href} captureMode compact />
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">
          No scored exposure path yet. Run a scan to populate attack-path evidence.
        </div>
      )}

      {exposurePaths.length > 1 ? (
        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
            Next paths
          </p>
          <div className="space-y-2">
            {exposurePaths.slice(1, 5).map((path) => (
              <Link
                key={path.key}
                href={path.href}
                className="flex items-center justify-between gap-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 transition hover:border-[color:var(--border-strong)]"
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
        </div>
      ) : null}
    </>
  );
}

function ExecutiveRiskPanel({
  topPath,
  exposurePaths,
  critical,
  high,
  credentials,
  summaryReady,
}: {
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  critical: number;
  high: number;
  credentials: number | null;
  summaryReady: boolean;
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
    <>
      <div>
        <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Top risks</h2>
        <p className="text-xs text-[color:var(--text-tertiary)]">
          Business-readable priorities — no attack-path chains on this lens
        </p>
      </div>
      <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
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
      </div>

      {exposurePaths.length > 1 ? (
        <details className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
          <summary className="cursor-pointer text-xs font-medium text-[color:var(--foreground)]">
            {exposurePaths.length - 1} additional risk theme{exposurePaths.length - 1 === 1 ? "" : "s"}
          </summary>
          <ul className="mt-3 space-y-2 text-xs text-[color:var(--text-secondary)]">
            {exposurePaths.slice(1, 4).map((path) => (
              <li key={path.key}>
                {path.nodes.find((node) => node.type === "cve")?.label ?? "Risk chain"} affecting{" "}
                {path.nodes.find((node) => node.type === "agent")?.label ?? "agent runtime"} · score{" "}
                {path.riskScore.toFixed(1)}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </>
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
  const isExecutive = persona === "executive";

  return (
    <div className="flex items-center gap-4">
      <div className={`flex h-16 w-16 items-center justify-center rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] ${tone}`}>
        <span className="text-2xl font-bold">{grade}</span>
      </div>
      <div className="min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
          {isExecutive ? "Risk posture" : "Operator posture"}
        </p>
        <p className="mt-1 text-lg font-semibold text-[color:var(--foreground)]">
          {typeof score === "number" ? `Score ${score}` : "Awaiting scan"}
        </p>
        <p className="mt-0.5 line-clamp-2 text-xs text-[color:var(--text-secondary)]">
          {summary ??
            (isExecutive
              ? critical > 0
                ? `${critical} critical and ${high} high findings across the AI supply chain.`
                : "Single-pane roll-up across compliance, cloud, runtime, and identity domains."
              : "Blast-radius paths, MCP topology, and remediation evidence for engineering triage.")}
        </p>
      </div>
    </div>
  );
}

function PriorityKpi({
  label,
  value,
  textValue,
  href,
  tone,
}: {
  label: string;
  value: number | null;
  textValue?: string | undefined;
  href?: string | undefined;
  tone?: "critical" | "high" | "warn" | undefined;
}) {
  const valueClass =
    tone === "critical"
      ? "text-red-500 dark:text-red-400"
      : tone === "high"
        ? "text-orange-500 dark:text-orange-400"
        : tone === "warn"
          ? "text-amber-500 dark:text-amber-400"
          : "text-[color:var(--foreground)]";

  const display = textValue ?? (value != null ? String(value) : "—");

  const inner = (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5">
      <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</p>
      <p className={`mt-1 font-mono text-xl font-semibold ${valueClass}`}>{display}</p>
    </div>
  );

  return href ? <Link href={href}>{inner}</Link> : inner;
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

function SeverityRollup({ severity, summaryReady }: { severity: SeverityCounts; summaryReady: boolean }) {
  const rows = [
    { key: "critical", label: "Critical", tone: "bg-red-500", href: "/findings?severity=critical" },
    { key: "high", label: "High", tone: "bg-orange-500", href: "/findings?severity=high" },
    { key: "medium", label: "Medium", tone: "bg-yellow-500", href: "/findings?severity=medium" },
    { key: "low", label: "Low", tone: "bg-blue-500", href: "/findings?severity=low" },
  ] as const;
  const max = Math.max(severity.critical, severity.high, severity.medium, severity.low, 1);

  return (
    <div className="mt-4 space-y-2.5">
      {rows.map((row) => {
        const count = severity[row.key];
        const width = summaryReady ? Math.max(8, (count / max) * 100) : 0;
        return (
          <Link key={row.key} href={row.href} className="block group">
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="text-[color:var(--text-secondary)] group-hover:text-[color:var(--foreground)]">{row.label}</span>
              <span className="font-mono text-[color:var(--text-tertiary)]">{summaryReady ? count : "—"}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
              <div className={`h-full rounded-full ${row.tone}`} style={{ width: `${width}%` }} />
            </div>
          </Link>
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
