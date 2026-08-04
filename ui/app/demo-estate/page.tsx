"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  Database,
  ExternalLink,
  Fingerprint,
  GitBranch,
  Network,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

import { StatStrip } from "@/components/stat-strip";
import { PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { api, type EnterpriseDemoStory } from "@/lib/api";

const FIRST_COMMAND = "agent-bom serve --demo-estate --allow-insecure-no-auth";
const DISPLAY_LABELS: Record<string, string> = {
  aws_cloudtrail: "AWS CloudTrail",
  azure_activity: "Azure Activity",
  entra_signin: "Microsoft Entra sign-in",
  gcp_audit: "GCP Audit Logs",
  github_actions: "GitHub Actions",
  kubernetes_audit: "Kubernetes Audit",
  mcp_gateway: "MCP Gateway",
  otel_llm: "OpenTelemetry GenAI",
  snowflake_access_history: "Snowflake Access History",
};

function words(value: string): string {
  return DISPLAY_LABELS[value] ?? value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function shortId(value: string): string {
  return value.length > 28 ? `${value.slice(0, 12)}…${value.slice(-10)}` : value;
}

function displayTime(value: string): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

export default function DemoEstatePage() {
  const [story, setStory] = useState<EnterpriseDemoStory | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api
      .getEnterpriseDemoStory()
      .then((result) => {
        if (active) setStory(result);
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Demo estate is unavailable");
      });
    return () => {
      active = false;
    };
  }, []);

  const orderedEvents = useMemo(
    () => [...(story?.events ?? [])].sort((a, b) => a.observed_at.localeCompare(b.observed_at)),
    [story],
  );

  if (error) {
    return (
      <PageErrorState
        title="Enterprise demo is not enabled"
        detail="This read-only story is served only when the explicitly labeled synthetic estate is enabled. No production data is substituted when it is absent."
        command={FIRST_COMMAND}
        suggestions={[error, "Use authenticated mode for any shared or persistent deployment."]}
        action={{ label: "Review live findings", href: "/findings", variant: "secondary" }}
        data-testid="demo-estate-error"
      />
    );
  }

  if (!story) {
    return (
      <PageLoadingState
        title="Verifying enterprise evidence"
        detail="Checking fixture hashes, normalizing provider observations, and rebuilding correlations."
        data-testid="demo-estate-loading"
      />
    );
  }

  const primary = story.primary_correlation;

  return (
    <div className="space-y-6" data-testid="demo-estate-page">
      <header className="overflow-hidden rounded-3xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] elev-2">
        <div className="grid gap-6 p-6 lg:grid-cols-[1.35fr_0.65fr] lg:p-8">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-emerald-700 dark:text-emerald-200">
                Synthetic enterprise evidence
              </span>
              <span className="rounded-full border border-[color:var(--border-subtle)] px-3 py-1 font-mono text-[11px] text-[color:var(--text-tertiary)]">
                {story.schema_version}
              </span>
            </div>
            <h1 className="mt-4 text-3xl font-semibold tracking-tight text-[color:var(--foreground)] sm:text-4xl">
              {story.estate_name}
            </h1>
            <p className="mt-3 max-w-4xl text-sm leading-7 text-[color:var(--text-secondary)]">
              {story.scenario}
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Link className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500" href="/security-graph">
                Open security graph <ExternalLink className="h-3.5 w-3.5" />
              </Link>
              <Link className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]" href="/traces">
                Inspect runtime traces
              </Link>
              <Link className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]" href="/findings">
                Review findings
              </Link>
            </div>
          </div>
          <aside className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-amber-800 dark:text-amber-200">
              <TriangleAlert className="h-4 w-4" /> Fictional data boundary
            </div>
            <p className="mt-3 text-sm leading-6 text-[color:var(--text-secondary)]">{story.disclosure}</p>
            <dl className="mt-4 space-y-2 border-t border-amber-500/20 pt-4 text-xs">
              <div className="flex justify-between gap-3"><dt className="text-[color:var(--text-tertiary)]">Tenant</dt><dd className="font-mono text-[color:var(--foreground)]">{story.tenant_id}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-[color:var(--text-tertiary)]">Estate</dt><dd className="font-mono text-[color:var(--foreground)]">{story.estate_id}</dd></div>
            </dl>
          </aside>
        </div>
      </header>

      <StatStrip
        data-testid="demo-estate-summary"
        items={[
          { label: "Assets", value: story.summary.assets, icon: Database },
          { label: "Observations", value: story.summary.observations, icon: Clock3 },
          { label: "Evidence sources", value: story.summary.evidence_sources, hint: `${story.summary.complete_sources} complete` },
          { label: "Correlations", value: story.summary.correlations, icon: Network },
          { label: "Snapshots", value: story.summary.snapshots, icon: GitBranch },
          { label: "Partial sources", value: story.summary.partial_sources, accent: "warn", icon: TriangleAlert },
        ]}
      />

      <section className="rounded-2xl border border-[color:var(--status-danger-border)] bg-[color:var(--surface)] p-5 elev-1">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--severity-high)]">Primary correlated incident</p>
            <h2 className="mt-2 text-xl font-semibold text-[color:var(--foreground)]">Sensitive-data path stopped before model egress</h2>
            <p className="mt-2 text-sm text-[color:var(--text-secondary)]">
              {primary.event_ids.length} normalized events across {primary.sources.length} provider records produced one <strong className="text-[color:var(--foreground)]">{primary.outcome}</strong> outcome.
            </p>
          </div>
          <span className="inline-flex w-fit items-center gap-2 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-emerald-700 dark:text-emerald-200">
            <ShieldCheck className="h-4 w-4" /> {primary.outcome}
          </span>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-2" aria-label="Correlated asset path">
          {primary.asset_path.map((asset, index) => (
            <div className="contents" key={asset}>
              {index > 0 ? <ArrowRight className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)]" aria-hidden="true" /> : null}
              <span className="max-w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 font-mono text-xs text-[color:var(--foreground)]" title={asset}>
                {asset}
              </span>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap gap-2 text-xs">
          {primary.sources.map((source) => <span key={source} className="rounded-full bg-[color:var(--surface-elevated)] px-2.5 py-1 text-[color:var(--text-secondary)]">{words(source)}</span>)}
          {primary.data_classifications.map((classification) => <span key={classification} className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 font-semibold uppercase text-rose-700 dark:text-rose-200">{classification}</span>)}
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_0.6fr]">
        <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 elev-1">
          <div className="flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-emerald-600 dark:text-emerald-300" />
            <h2 className="text-base font-semibold text-[color:var(--foreground)]">Normalized evidence timeline</h2>
          </div>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">Every row retains its source run and evidence hash; raw provider payloads are not returned.</p>
          <ol className="mt-5 space-y-3">
            {orderedEvents.map((event) => (
              <li key={event.event_id} className="grid gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 sm:grid-cols-[8rem_1fr]">
                <div>
                  <div className="font-mono text-[11px] text-[color:var(--text-tertiary)]">{displayTime(event.observed_at)}</div>
                  <div className="mt-1 text-xs font-semibold text-emerald-700 dark:text-emerald-200">{words(event.source)}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-[color:var(--foreground)]">{event.event_type}</div>
                  <div className="mt-1 truncate font-mono text-xs text-[color:var(--text-secondary)]" title={event.actor_id}>{event.actor_id}</div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {event.resource_ids.map((resource) => <span key={resource} title={resource} className="rounded bg-[color:var(--surface-elevated)] px-2 py-1 font-mono text-[10px] text-[color:var(--text-tertiary)]">{shortId(resource)}</span>)}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <div className="space-y-6">
          <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 elev-1">
            <h2 className="text-base font-semibold text-[color:var(--foreground)]">Collection truth</h2>
            <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">Incomplete collection stays incomplete throughout correlation.</p>
            <div className="mt-4 space-y-2">
              {story.collection_health.map((source) => (
                <div key={source.source} className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-sm font-medium text-[color:var(--foreground)]">{words(source.source)}</span>
                    <span className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase ${source.status === "complete" ? "text-emerald-700 dark:text-emerald-200" : "text-amber-700 dark:text-amber-200"}`}>
                      {source.status === "complete" ? <CheckCircle2 className="h-3.5 w-3.5" /> : <TriangleAlert className="h-3.5 w-3.5" />}
                      {source.status}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-[color:var(--text-tertiary)]">{source.records_read} {source.records_read === 1 ? "record" : "records"} · {source.source_schema}</div>
                  {source.failure_code ? <div className="mt-2 rounded bg-amber-500/10 px-2 py-1 font-mono text-[10px] text-amber-800 dark:text-amber-200">{source.failure_code}</div> : null}
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 elev-1">
            <div className="flex items-center gap-2"><Fingerprint className="h-4 w-4 text-[color:var(--text-secondary)]" /><h2 className="text-base font-semibold text-[color:var(--foreground)]">Verified provenance</h2></div>
            <dl className="mt-4 space-y-4 text-xs">
              <div><dt className="text-[color:var(--text-tertiary)]">Estate content hash</dt><dd className="mt-1 break-all font-mono text-[color:var(--foreground)]">{story.estate_content_hash}</dd></div>
              <div><dt className="text-[color:var(--text-tertiary)]">Normalized story hash</dt><dd className="mt-1 break-all font-mono text-[color:var(--foreground)]">{story.story_content_hash}</dd></div>
              <div><dt className="text-[color:var(--text-tertiary)]">Evidence quality</dt><dd className="mt-1 font-semibold text-[color:var(--foreground)]">{words(primary.evidence_quality)}</dd></div>
            </dl>
          </section>
        </div>
      </div>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 elev-1">
        <h2 className="text-base font-semibold text-[color:var(--foreground)]">Cross-vendor correlations</h2>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {story.correlations.map((correlation) => (
            <article key={correlation.correlation_id} className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
              <div className="flex items-start justify-between gap-3">
                <div><div className="text-sm font-semibold text-[color:var(--foreground)]">{words(correlation.kind)}</div><div className="mt-1 font-mono text-[10px] text-[color:var(--text-tertiary)]">{shortId(correlation.trace_id)}</div></div>
                <span className="rounded-full bg-[color:var(--surface-elevated)] px-2 py-1 text-[10px] font-semibold uppercase text-[color:var(--text-secondary)]">{correlation.outcome}</span>
              </div>
              <p className="mt-3 text-xs leading-5 text-[color:var(--text-secondary)]">{correlation.event_ids.length} events · {correlation.sources.map(words).join(" · ")}</p>
              {correlation.incomplete_sources.length ? <p className="mt-2 text-xs text-amber-700 dark:text-amber-200">Partial evidence: {correlation.incomplete_sources.map(words).join(", ")}</p> : null}
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
