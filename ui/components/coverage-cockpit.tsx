"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowRight, Cloud, Layers, Server } from "lucide-react";

import {
  api,
  type CloudConnectionRecord,
  type PostureCountsResponse,
} from "@/lib/api";
import { deploymentModeLabel } from "@/lib/deployment-context";
import { providerDisplayName } from "@/lib/scan-scope";

type CoverageCockpitProps = {
  counts: PostureCountsResponse | null;
  scanCount: number | null;
  latestScanLabel: string | null;
  /** When provided (e.g. Connections page), skip a second listCloudConnections fetch. */
  connections?: CloudConnectionRecord[] | undefined;
};

function deploymentSignals(counts: PostureCountsResponse | null): string[] {
  if (!counts) return [];
  const signals: string[] = [];
  if (counts.has_local_scan) signals.push("Workstation");
  if (counts.has_fleet_ingest) signals.push("Fleet sync");
  if (counts.has_cluster_scan) signals.push("Kubernetes");
  if (counts.has_ci_cd_scan) signals.push("CI/CD");
  if (counts.has_mesh) signals.push("Agent mesh");
  return signals;
}

function formatWhen(value: string | null | undefined): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function CoverageCockpit({
  counts,
  scanCount,
  latestScanLabel,
  connections: connectionsProp,
}: CoverageCockpitProps) {
  const [fetchedConnections, setFetchedConnections] = useState<CloudConnectionRecord[]>([]);
  const [loading, setLoading] = useState(connectionsProp === undefined);

  useEffect(() => {
    if (connectionsProp !== undefined) {
      setLoading(false);
      return;
    }
    let mounted = true;
    api
      .listCloudConnections()
      .then((response) => {
        if (!mounted) return;
        setFetchedConnections(response.connections ?? []);
        setLoading(false);
      })
      .catch(() => {
        if (!mounted) return;
        setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [connectionsProp]);

  const connections = connectionsProp ?? fetchedConnections;

  const deploymentMode = counts?.deployment_mode ?? "local";
  const deploymentLabel = deploymentModeLabel(deploymentMode);
  const signals = useMemo(() => deploymentSignals(counts), [counts]);

  const activeConnections = connections.filter((connection) => connection.status === "active").length;
  const scheduledConnections = connections.filter((connection) => connection.scan_interval_minutes).length;
  const providers = useMemo(() => {
    const unique = new Set(connections.map((connection) => providerDisplayName(connection.provider)));
    return [...unique];
  }, [connections]);

  const lastAccountScan = useMemo(() => {
    const timestamps = connections
      .map((connection) => connection.last_scan_at)
      .filter((value): value is string => Boolean(value));
    if (timestamps.length === 0) return null;
    return timestamps.sort((a, b) => b.localeCompare(a))[0] ?? null;
  }, [connections]);

  return (
    <section
      aria-labelledby="coverage-cockpit-heading"
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4"
    >
      <div className="mb-4">
        <h2 id="coverage-cockpit-heading" className="text-sm font-semibold text-[color:var(--foreground)]">
          Onboard & coverage
        </h2>
        <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
          Deployment is your control plane. Accounts are onboarded cloud boundaries. Scans are the evidence runs that feed Overview posture.
        </p>
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <CoverageCard
          icon={Server}
          title="Deployment"
          subtitle={`${deploymentLabel} control plane`}
          href="/help"
          chips={signals.length > 0 ? signals : ["No ingest signals yet"]}
          footer={
            deploymentMode === "local"
              ? "Self-hosted on this host — ad-hoc scans and local MCP discovery run here."
              : deploymentMode === "fleet"
                ? "Fleet ingest is active — endpoint sync populates inventory between scans."
                : deploymentMode === "cluster"
                  ? "Cluster evidence is present — prioritize Kubernetes and connected accounts."
                  : "Hybrid — cloud connectors, fleet, and workstation scans share one graph."
          }
        />

        <CoverageCard
          icon={Cloud}
          title="Cloud accounts"
          subtitle={loading ? "Loading accounts…" : `${connections.length} connected · ${activeConnections} active`}
          href="/connections"
          chips={
            providers.length > 0
              ? providers
              : ["No accounts connected"]
          }
          footer={
            connections.length === 0
              ? "Onboard AWS, Azure, GCP, or Snowflake for brokered inventory + CIS per account."
              : `${scheduledConnections} scheduled · last account scan ${formatWhen(lastAccountScan)}`
          }
          actionHref={connections[0] ? `/scan?connection=${encodeURIComponent(connections[0].id)}` : "/connections"}
          actionLabel={connections.length > 0 ? "Scan account" : "Connect account"}
        />

        <CoverageCard
          icon={Layers}
          title="Scans"
          subtitle={scanCount != null ? `${scanCount} completed job${scanCount === 1 ? "" : "s"}` : "Scan jobs"}
          href="/jobs"
          chips={[
            counts?.has_local_scan ? "Workstation" : null,
            scheduledConnections > 0 ? `${scheduledConnections} scheduled cloud` : null,
            counts?.scan_sources?.length ? `${counts.scan_sources.length} source types` : null,
          ].filter((chip): chip is string => Boolean(chip))}
          footer={
            latestScanLabel
              ? `Latest evidence ${latestScanLabel}. Ad-hoc, connected-account, and source runs all land in Jobs.`
              : "No completed scans yet. Start with a connected account or an ad-hoc workstation scan."
          }
          actionHref="/jobs"
          actionLabel="View jobs"
          secondaryHref="/sources"
          secondaryLabel="Data sources"
        />
      </div>
    </section>
  );
}

function CoverageCard({
  icon: Icon,
  title,
  subtitle,
  href,
  chips,
  footer,
  actionHref,
  actionLabel,
  secondaryHref,
  secondaryLabel,
}: {
  icon: typeof Cloud;
  title: string;
  subtitle: string;
  href: string;
  chips: string[];
  footer: string;
  actionHref?: string | undefined;
  actionLabel?: string | undefined;
  secondaryHref?: string | undefined;
  secondaryLabel?: string | undefined;
}) {
  return (
    <article className="flex min-h-full flex-col rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
      <div className="flex items-start gap-3">
        <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2 text-emerald-400">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <Link href={href} className="text-sm font-semibold text-[color:var(--foreground)] hover:text-emerald-400">
            {title}
          </Link>
          <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">{subtitle}</p>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {chips.map((chip) => (
          <span
            key={chip}
            className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] font-medium text-[color:var(--text-secondary)]"
          >
            {chip}
          </span>
        ))}
      </div>

      <p className="mt-3 flex-1 text-xs leading-5 text-[color:var(--text-tertiary)]">{footer}</p>

      {(actionHref || secondaryHref) && (
        <div className="mt-3 flex flex-wrap gap-2">
          {actionHref && actionLabel ? (
            <Link
              href={actionHref}
              className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 dark:border-emerald-800/50 bg-emerald-500/10 dark:bg-emerald-950/20 px-2.5 py-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-300 transition hover:border-emerald-600"
            >
              {actionLabel}
              <ArrowRight className="h-3 w-3" />
            </Link>
          ) : null}
          {secondaryHref && secondaryLabel ? (
            <Link
              href={secondaryHref}
              className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] px-2.5 py-1 text-[11px] text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)]"
            >
              {secondaryLabel}
            </Link>
          ) : null}
        </div>
      )}
    </article>
  );
}
