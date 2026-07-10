"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  Bot,
  Cloud,
  Layers,
  Package,
  Server,
  Shield,
  Wrench,
} from "lucide-react";

import {
  api,
  type CloudConnectionRecord,
  type OverviewDomain,
  type OverviewResponse,
  type PostureCountsResponse,
} from "@/lib/api";
import { deploymentModeLabel } from "@/lib/deployment-context";
import { providerDisplayName } from "@/lib/scan-scope";
import { PostureGrade } from "@/components/posture-grade";

type OverviewTab = "environments" | "domains" | "services" | "inventory";

export type OverviewCommandCenterProps = {
  postureGrade: string;
  postureScore?: number | undefined;
  postureSummary?: string | undefined;
  critical: number;
  high: number;
  medium: number;
  low: number;
  agents: number | null;
  cves: number | null;
  scans: number | null;
  kev: number | null;
  credentials: number | null;
  tools: number | null;
  packages: number | null;
  latestScan: string | null;
  mode: string;
  summaryReady: boolean;
  counts: PostureCountsResponse | null;
  overview: OverviewResponse | null;
  scanCount: number | null;
  latestScanLabel: string | null;
};

const SERVICE_META = {
  cloud_accounts: { label: "Cloud accounts", href: "/connections" },
  data_sources: { label: "Data sources", href: "/sources" },
  local_agents: { label: "Local agents", href: "/agents" },
  fleet: { label: "Fleet sync", href: "/fleet" },
  runtime_proxy: { label: "Runtime proxy", href: "/runtime?tab=proxy" },
  runtime_gateway: { label: "Gateway", href: "/runtime?tab=gateway" },
  runtime_traces: { label: "Traces", href: "/runtime?tab=traces" },
  ai_spend: { label: "AI spend", href: "/cost" },
  compliance: { label: "Compliance", href: "/compliance" },
} as const;

type OverviewServiceId = keyof typeof SERVICE_META;

function severityTotal(critical: number, high: number, medium: number, low: number): number {
  return critical + high + medium + low;
}

function MiniStackedBar({
  critical,
  high,
  medium,
  low,
}: {
  critical: number;
  high: number;
  medium: number;
  low: number;
}) {
  const total = severityTotal(critical, high, medium, low);
  const pct = (value: number) => (total > 0 ? (value / total) * 100 : 0);

  return (
    <div className="space-y-2">
      <div className="flex h-2.5 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
        {critical > 0 ? <div className="bg-red-500" style={{ width: `${pct(critical)}%` }} /> : null}
        {high > 0 ? <div className="bg-orange-500" style={{ width: `${pct(high)}%` }} /> : null}
        {medium > 0 ? <div className="bg-yellow-500" style={{ width: `${pct(medium)}%` }} /> : null}
        {low > 0 ? <div className="bg-zinc-500" style={{ width: `${pct(low)}%` }} /> : null}
        {total === 0 ? <div className="w-full bg-emerald-500/40" /> : null}
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-4">
        <SeverityLegend label="Critical" value={critical} tone="text-red-400" href="/findings?severity=critical" />
        <SeverityLegend label="High" value={high} tone="text-orange-400" href="/findings?severity=high" />
        <SeverityLegend label="Medium" value={medium} tone="text-yellow-300" href="/findings?severity=medium" />
        <SeverityLegend label="Low" value={low} tone="text-zinc-400" href="/findings?severity=low" />
      </div>
    </div>
  );
}

function SeverityLegend({
  label,
  value,
  tone,
  href,
}: {
  label: string;
  value: number;
  tone: string;
  href: string;
}) {
  return (
    <Link href={href} className="flex items-center justify-between gap-2 rounded-md px-1 py-0.5 transition hover:bg-[color:var(--surface-muted)]">
      <span className="text-[color:var(--text-tertiary)]">{label}</span>
      <span className={`font-mono font-semibold ${tone}`}>{value}</span>
    </Link>
  );
}

function KpiTile({
  label,
  value,
  href,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  href: string;
  icon: typeof Bot;
  tone?: "critical" | "high" | undefined;
}) {
  const valueClass =
    tone === "critical"
      ? "text-red-400"
      : tone === "high"
        ? "text-orange-400"
        : "text-[color:var(--foreground)]";

  return (
    <Link
      href={href}
      className="group flex flex-col rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3 transition hover:border-[color:var(--border-strong)]"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">{label}</span>
        <Icon className="h-3.5 w-3.5 text-[color:var(--text-tertiary)] group-hover:text-emerald-400" />
      </div>
      <p className={`mt-1 font-mono text-xl font-semibold ${valueClass}`}>{value}</p>
    </Link>
  );
}

function domainTone(status: OverviewDomain["status"]): { dot: string; text: string; badge: string } {
  switch (status) {
    case "critical":
      return { dot: "bg-red-500", text: "text-red-300", badge: "bg-red-500/15 text-red-300" };
    case "warn":
      return { dot: "bg-amber-500", text: "text-amber-300", badge: "bg-amber-500/15 text-amber-300" };
    case "ok":
      return { dot: "bg-emerald-500", text: "text-emerald-300", badge: "bg-emerald-500/15 text-emerald-300" };
    default:
      return { dot: "bg-zinc-600", text: "text-zinc-500", badge: "bg-zinc-500/15 text-zinc-400" };
  }
}

function serviceStateBadge(state: string): string {
  if (state === "live" || state === "connected") return "bg-emerald-500/15 text-emerald-300";
  if (state === "degraded" || state === "stale") return "bg-amber-500/15 text-amber-200";
  return "bg-zinc-500/15 text-zinc-400";
}

export function OverviewCommandCenter({
  postureGrade,
  postureScore,
  postureSummary,
  critical,
  high,
  medium,
  low,
  agents,
  cves,
  scans,
  kev,
  credentials,
  tools,
  packages,
  latestScan,
  mode,
  summaryReady,
  counts,
  overview,
  scanCount,
  latestScanLabel,
}: OverviewCommandCenterProps) {
  const [tab, setTab] = useState<OverviewTab>("environments");
  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api
      .listCloudConnections()
      .then((response) => {
        if (!mounted) return;
        setConnections(response.connections ?? []);
        setConnectionsLoading(false);
      })
      .catch(() => {
        if (!mounted) return;
        setConnectionsLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const domains = overview ? Object.values(overview.domains) : [];
  const activeDomains = domains.filter((domain) => domain.status !== "idle").length;
  const domainCoverage = domains.length > 0 ? Math.round((activeDomains / domains.length) * 100) : null;

  const services = counts?.services ?? {};
  const serviceIds = (Object.keys(SERVICE_META) as OverviewServiceId[]).filter((id) => services[id]);
  const liveServices = serviceIds.filter((id) => {
    const entry = services[id];
    return entry && (entry.state === "live" || entry.state === "connected");
  }).length;

  const activeConnections = connections.filter((connection) => connection.status === "active").length;
  const providers = useMemo(() => {
    const unique = new Set(connections.map((connection) => providerDisplayName(connection.provider)));
    return [...unique];
  }, [connections]);

  const scanSources = counts?.scan_sources ?? [];
  const deploymentMode = counts?.deployment_mode ?? "local";
  const deploymentLabel = deploymentModeLabel(deploymentMode);

  const display = (value: number | null | undefined) =>
    summaryReady && value != null ? String(value) : "—";

  const tabs: { id: OverviewTab; label: string; hint: string }[] = [
    { id: "environments", label: "Environments", hint: `${connections.length} accounts` },
    { id: "domains", label: "Domains", hint: domainCoverage != null ? `${domainCoverage}% active` : "signals" },
    { id: "services", label: "Services", hint: `${liveServices} live` },
    { id: "inventory", label: "Inventory", hint: display(agents) },
  ];

  return (
    <section data-testid="overview-command-center" className="space-y-4">
      <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
        <div className="grid gap-6 xl:grid-cols-[minmax(0,200px)_1fr_minmax(0,240px)]">
          <Link href="/compliance" className="flex flex-col items-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 transition hover:border-[color:var(--border-strong)]">
            <PostureGrade
              grade={postureGrade}
              score={typeof postureScore === "number" ? postureScore : 0}
              variant="compact"
            />
            <p className="mt-2 text-center text-xs text-[color:var(--text-tertiary)]">
              {postureSummary ?? "Unified posture grade"}
            </p>
            <span className="mt-2 inline-flex items-center gap-1 text-[11px] text-cyan-400">
              View compliance <ArrowRight className="h-3 w-3" />
            </span>
          </Link>

          <div className="space-y-4">
            <div>
              <div className="mb-2 flex items-center justify-between gap-2">
                <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Findings breakdown</h2>
                <Link href="/findings" className="text-xs text-cyan-400 hover:text-cyan-300">
                  Open findings
                </Link>
              </div>
              <MiniStackedBar critical={critical} high={high} medium={medium} low={low} />
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              <KpiTile label="Agents" value={display(agents)} href="/agents" icon={Bot} />
              <KpiTile label="CVEs" value={display(cves)} href="/findings" icon={Shield} />
              <KpiTile label="Critical" value={display(critical)} href="/findings?severity=critical" icon={Shield} tone="critical" />
              <KpiTile label="High" value={display(high)} href="/findings?severity=high" icon={Shield} tone="high" />
              <KpiTile label="KEV" value={display(kev)} href="/findings?kev=true" icon={Shield} />
              <KpiTile label="Scans" value={display(scans)} href="/jobs" icon={Layers} />
            </div>
          </div>

          <div className="space-y-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
            <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Scan coverage</h2>
            <dl className="space-y-2 text-xs">
              <div className="flex items-center justify-between gap-2">
                <dt className="text-[color:var(--text-tertiary)]">Last scan</dt>
                <dd className="font-medium text-[color:var(--foreground)]">{latestScan ?? "—"}</dd>
              </div>
              <div className="flex items-center justify-between gap-2">
                <dt className="text-[color:var(--text-tertiary)]">Completed jobs</dt>
                <dd className="font-mono font-semibold text-[color:var(--foreground)]">{display(scanCount)}</dd>
              </div>
              <div className="flex items-center justify-between gap-2">
                <dt className="text-[color:var(--text-tertiary)]">Deployment</dt>
                <dd className="font-medium text-[color:var(--foreground)]">{mode}</dd>
              </div>
            </dl>
            {scanSources.length > 0 ? (
              <div className="pt-1">
                <p className="mb-1.5 text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">Evidence sources</p>
                <div className="flex flex-wrap gap-1">
                  {scanSources.map((source) => (
                    <span
                      key={source}
                      className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] text-[color:var(--text-secondary)]"
                    >
                      {source}
                    </span>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-[color:var(--text-tertiary)]">
                No scan evidence yet. Connect an account or run a workstation scan.
              </p>
            )}
            <Link
              href="/scan"
              className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-medium text-white hover:bg-emerald-500"
            >
              Run scan <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <div className="flex flex-wrap items-center gap-1 border-b border-[color:var(--border-subtle)] p-2">
          {tabs.map((entry) => (
            <button
              key={entry.id}
              type="button"
              onClick={() => setTab(entry.id)}
              className={`rounded-lg px-3 py-2 text-left transition ${
                tab === entry.id
                  ? "bg-[color:var(--surface-muted)] text-[color:var(--foreground)]"
                  : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
              }`}
            >
              <span className="block text-xs font-medium">{entry.label}</span>
              <span className="block text-[10px] text-[color:var(--text-tertiary)]">{entry.hint}</span>
            </button>
          ))}
        </div>

        <div className="p-4">
          {tab === "environments" ? (
            <div className="grid gap-3 lg:grid-cols-3">
              <EnvironmentTile
                icon={Server}
                title="Deployment"
                metric={deploymentLabel}
                status={counts?.has_local_scan || counts?.has_fleet_ingest ? "Connected" : "Setup"}
                href="/help"
                chips={
                  [
                    counts?.has_local_scan ? "Workstation" : null,
                    counts?.has_fleet_ingest ? "Fleet" : null,
                    counts?.has_cluster_scan ? "Kubernetes" : null,
                    counts?.has_ci_cd_scan ? "CI/CD" : null,
                  ].filter((chip): chip is string => Boolean(chip))
                }
                detail={
                  deploymentMode === "local"
                    ? "Local control plane — ad-hoc scans and MCP discovery."
                    : `${deploymentLabel} mode — hybrid evidence from cloud and workstation runs.`
                }
              />
              <EnvironmentTile
                icon={Cloud}
                title="Cloud accounts"
                metric={connectionsLoading ? "…" : String(connections.length)}
                status={`${activeConnections} active`}
                href="/connections"
                chips={providers.length > 0 ? providers : ["None connected"]}
                detail={
                  connections.length === 0
                    ? "Onboard AWS, Azure, GCP, or Snowflake for brokered inventory."
                    : `${connections.length} connected · ${activeConnections} active`
                }
                actionHref={connections[0] ? `/scan?connection=${connections[0].id}` : "/connections"}
                actionLabel={connections.length > 0 ? "Scan account" : "Connect"}
              />
              <EnvironmentTile
                icon={Layers}
                title="Scans"
                metric={display(scanCount)}
                status={latestScanLabel ? `Latest ${latestScanLabel}` : "No runs"}
                href="/jobs"
                chips={
                  [
                    counts?.has_local_scan ? "Workstation" : null,
                    scanSources.length ? `${scanSources.length} source types` : null,
                  ].filter((chip): chip is string => Boolean(chip))
                }
                detail="Completed jobs feed findings, graph, and compliance posture."
                actionHref="/scan"
                actionLabel="New scan"
              />
            </div>
          ) : null}

          {tab === "domains" ? (
            domains.length > 0 ? (
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
                {domains.map((domain) => {
                  const tone = domainTone(domain.status);
                  return (
                    <Link
                      key={domain.href}
                      href={domain.graph_href ?? domain.href}
                      className="flex flex-col rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3 transition hover:border-[color:var(--border-strong)]"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-xs font-medium text-[color:var(--foreground)]">{domain.label}</span>
                        <span className={`h-2 w-2 shrink-0 rounded-full ${tone.dot}`} />
                      </div>
                      <p className="mt-1 font-mono text-lg font-semibold text-[color:var(--foreground)]">{domain.metric}</p>
                      <p className="text-[10px] text-[color:var(--text-tertiary)]">{domain.metric_label}</p>
                      <span className={`mt-2 self-start rounded-full px-2 py-0.5 text-[10px] uppercase ${tone.badge}`}>
                        {domain.status}
                      </span>
                    </Link>
                  );
                })}
              </div>
            ) : (
              <EmptyTab message="Domain signals appear after the first completed scan." actionHref="/scan" actionLabel="Run scan" />
            )
          ) : null}

          {tab === "services" ? (
            serviceIds.length > 0 ? (
              <ul className="divide-y divide-[color:var(--border-subtle)] rounded-xl border border-[color:var(--border-subtle)]">
                {serviceIds.map((id) => {
                  const entry = services[id];
                  if (!entry) return null;
                  const meta = SERVICE_META[id];
                  return (
                    <li key={id}>
                      <Link
                        href={meta.href}
                        className="flex items-center justify-between gap-3 px-4 py-3 transition hover:bg-[color:var(--surface-muted)]"
                      >
                        <div>
                          <p className="text-sm font-medium text-[color:var(--foreground)]">{meta.label}</p>
                          {entry.detail ? (
                            <p className="text-xs text-[color:var(--text-tertiary)]">{entry.detail}</p>
                          ) : null}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-[color:var(--foreground)]">{entry.count}</span>
                          <span className={`rounded-full px-2 py-0.5 text-[10px] uppercase ${serviceStateBadge(entry.state)}`}>
                            {entry.state}
                          </span>
                        </div>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <EmptyTab message="Connect cloud accounts or enable runtime surfaces to populate services." actionHref="/connections" actionLabel="Cloud accounts" />
            )
          ) : null}

          {tab === "inventory" ? (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <InventoryTile label="Agents" value={display(agents)} href="/agents" icon={Bot} />
              <InventoryTile label="Packages" value={display(packages)} href="/findings" icon={Package} />
              <InventoryTile label="Tools" value={display(tools)} href="/mesh" icon={Wrench} />
              <InventoryTile label="Credentials exposed" value={display(credentials)} href="/identity" icon={Shield} />
              <InventoryTile label="KEV matches" value={display(kev)} href="/findings?kev=true" icon={Shield} />
              <InventoryTile label="CVEs" value={display(cves)} href="/findings" icon={Shield} />
              <InventoryTile label="Completed scans" value={display(scanCount)} href="/jobs" icon={Layers} />
              <InventoryTile label="Cloud accounts" value={connectionsLoading ? "—" : String(connections.length)} href="/connections" icon={Cloud} />
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function EnvironmentTile({
  icon: Icon,
  title,
  metric,
  status,
  href,
  chips,
  detail,
  actionHref,
  actionLabel,
}: {
  icon: typeof Server;
  title: string;
  metric: string;
  status: string;
  href: string;
  chips: string[];
  detail: string;
  actionHref?: string | undefined;
  actionLabel?: string | undefined;
}) {
  const [open, setOpen] = useState(false);

  return (
    <article className="flex flex-col rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
      <div className="p-4">
        <div className="flex items-start gap-3">
          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2 text-emerald-400">
            <Icon className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <Link href={href} className="text-sm font-semibold text-[color:var(--foreground)] hover:text-emerald-400">
              {title}
            </Link>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="font-mono text-xl font-semibold text-[color:var(--foreground)]">{metric}</span>
              <span className="text-[10px] text-[color:var(--text-tertiary)]">{status}</span>
            </div>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-1">
          {(chips.length > 0 ? chips : ["No signals"]).map((chip) => (
            <span
              key={chip}
              className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] text-[color:var(--text-secondary)]"
            >
              {chip}
            </span>
          ))}
        </div>
      </div>
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className="border-t border-[color:var(--border-subtle)] px-4 py-2 text-left text-[11px] text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
      >
        {open ? "Hide details" : "Show details"}
      </button>
      {open ? (
        <div className="space-y-2 border-t border-[color:var(--border-subtle)] px-4 py-3">
          <p className="text-xs leading-5 text-[color:var(--text-tertiary)]">{detail}</p>
          {actionHref && actionLabel ? (
            <Link
              href={actionHref}
              className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
            >
              {actionLabel} <ArrowRight className="h-3 w-3" />
            </Link>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}

function InventoryTile({
  label,
  value,
  href,
  icon: Icon,
}: {
  label: string;
  value: string;
  href: string;
  icon: typeof Bot;
}) {
  return (
    <Link
      href={href}
      className="flex items-center gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 transition hover:border-[color:var(--border-strong)]"
    >
      <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2 text-emerald-400">
        <Icon className="h-4 w-4" />
      </div>
      <div>
        <p className="text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">{label}</p>
        <p className="font-mono text-lg font-semibold text-[color:var(--foreground)]">{value}</p>
      </div>
    </Link>
  );
}

function EmptyTab({
  message,
  actionHref,
  actionLabel,
}: {
  message: string;
  actionHref: string;
  actionLabel: string;
}) {
  return (
    <div className="rounded-xl border border-dashed border-[color:var(--border-subtle)] px-4 py-10 text-center">
      <p className="text-sm text-[color:var(--text-secondary)]">{message}</p>
      <Link href={actionHref} className="mt-3 inline-flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
        {actionLabel} <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}
