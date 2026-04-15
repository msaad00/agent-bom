"use client";

import Link from "next/link";
import {
  Activity,
  ArrowRight,
  Cloud,
  Database,
  Radio,
  ScanSearch,
  Shield,
  Workflow,
} from "lucide-react";

type SourceMode = "Direct scan" | "Read-only integration" | "Pushed ingest" | "Imported artifact";

interface SourceCard {
  title: string;
  mode: SourceMode;
  description: string;
  href?: string;
  action?: string;
  status: string;
}

const SOURCE_GROUPS: Array<{
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  summary: string;
  cards: SourceCard[];
}> = [
  {
    label: "Direct scans",
    icon: ScanSearch,
    summary: "Agentless or local scan jobs that agent-bom launches directly.",
    cards: [
      {
        title: "Local inventory and MCP discovery",
        mode: "Direct scan",
        description: "Scan local MCP configs, Python agent projects, GitHub Actions, inventories, container images, and Terraform from the New Scan flow.",
        href: "/scan",
        action: "Open New Scan",
        status: "Shipping now",
      },
      {
        title: "Kubernetes and image analysis",
        mode: "Direct scan",
        description: "Use the same scan flow for cluster inventory and container/image package analysis where you can point agent-bom at the runtime or artifact directly.",
        href: "/scan",
        action: "Launch direct scan",
        status: "Shipping now",
      },
    ],
  },
  {
    label: "Connected sources",
    icon: Cloud,
    summary: "Read-only sources where the customer points us at a cloud or SaaS system that already contains the data.",
    cards: [
      {
        title: "Governance and cloud activity",
        mode: "Read-only integration",
        description: "Snowflake-backed governance, access history, and activity pages already consume cloud-side telemetry without forcing everything through the local scan form.",
        href: "/governance",
        action: "Open Governance",
        status: "Shipping now",
      },
      {
        title: "Connector-backed discovery",
        mode: "Read-only integration",
        description: "The backend exposes connector and SIEM connector routes today. The product still needs a first-class setup wizard in the UI.",
        status: "API first today",
      },
    ],
  },
  {
    label: "Ingested evidence",
    icon: Radio,
    summary: "Evidence pushed into agent-bom from an existing collector, exporter, or security data lake workflow.",
    cards: [
      {
        title: "OTLP traces and runtime events",
        mode: "Pushed ingest",
        description: "The traces surface and POST /v1/traces route accept OTLP JSON so teams can correlate runtime calls against known vulnerable assets.",
        href: "/traces",
        action: "Open Traces",
        status: "Shipping now",
      },
      {
        title: "Security lake and warehouse feeds",
        mode: "Pushed ingest",
        description: "If customers already centralize evidence in Snowflake or another data platform, agent-bom should consume that source of truth instead of duplicating collection.",
        href: "/activity",
        action: "Open Activity",
        status: "Partial today",
      },
    ],
  },
  {
    label: "Imported artifacts",
    icon: Database,
    summary: "Customer-exported files that agent-bom can analyze without managing the source system.",
    cards: [
      {
        title: "SBOM and custom inventory inputs",
        mode: "Imported artifact",
        description: "SBOMs, custom inventory JSON, and similar exported artifacts remain valid entry points when direct access is not available or not desired.",
        href: "/scan",
        action: "Use scan inputs",
        status: "Shipping now",
      },
    ],
  },
];

const OPERATING_SURFACES: Array<{
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  href: string;
  summary: string;
  status: string;
}> = [
  {
    title: "Security graph and path analysis",
    icon: Workflow,
    href: "/security-graph",
    summary: "Persisted graph snapshots, attack-path focus, and blast-radius analysis across agents, servers, packages, tools, and credentials.",
    status: "Analyze",
  },
  {
    title: "Fleet management",
    icon: Activity,
    href: "/fleet",
    summary: "Persisted agent inventory, lifecycle state, trust score, and operational review state for the agent fleet.",
    status: "Operate",
  },
  {
    title: "Runtime proxy and alerts",
    icon: Radio,
    href: "/proxy",
    summary: "Live runtime enforcement, detector alerts, drift protection, and audit review for MCP and tool-call activity.",
    status: "Runtime",
  },
  {
    title: "Gateway and policy enforcement",
    icon: Shield,
    href: "/gateway",
    summary: "Policy evaluation, review, and enforcement surfaces for controlling high-impact tool usage and approval workflows.",
    status: "Protect",
  },
];

function modeTone(mode: SourceMode): string {
  switch (mode) {
    case "Direct scan":
      return "text-emerald-400 border-emerald-900/60 bg-emerald-950/30";
    case "Read-only integration":
      return "text-sky-400 border-sky-900/60 bg-sky-950/30";
    case "Pushed ingest":
      return "text-amber-400 border-amber-900/60 bg-amber-950/30";
    case "Imported artifact":
      return "text-fuchsia-400 border-fuchsia-900/60 bg-fuchsia-950/30";
  }
}

export default function SourcesPage() {
  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[linear-gradient(135deg,var(--surface),var(--surface-elevated))] p-6 shadow-2xl shadow-black/10">
        <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-400">Data sources</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--foreground)]">Data sources and operating surfaces</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-[var(--text-secondary)]">
          The product should support three honest modes: launch direct scans, connect to a read-only source, or ingest evidence that the customer already
          centralizes elsewhere. This page makes those boundaries explicit and also shows where runtime, fleet, graph, and policy surfaces fit once the data
          is in the system.
        </p>
        <div className="mt-5 flex flex-wrap gap-3 text-xs text-[var(--text-secondary)]">
          <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5">Canonical model first</span>
          <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5">Read-only where possible</span>
          <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5">Bring your data when collection already exists</span>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        {SOURCE_GROUPS.map((group) => {
          const Icon = group.icon;
          return (
            <section
              key={group.label}
              className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5"
            >
              <div className="flex items-start gap-3">
                <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
                  <Icon className="h-5 w-5 text-emerald-400" />
                </span>
                <div>
                  <h2 className="text-base font-semibold text-[var(--foreground)]">{group.label}</h2>
                  <p className="mt-1 text-sm text-[var(--text-secondary)]">{group.summary}</p>
                </div>
              </div>

              <div className="mt-5 space-y-3">
                {group.cards.map((card) => {
                  const content = (
                    <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition-colors hover:border-[color:var(--border-strong)]">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium ${modeTone(card.mode)}`}>
                            {card.mode}
                          </div>
                          <h3 className="mt-3 text-sm font-semibold text-[var(--foreground)]">{card.title}</h3>
                        </div>
                        {card.href ? <ArrowRight className="mt-1 h-4 w-4 text-[var(--text-tertiary)]" /> : null}
                      </div>
                      <p className="mt-2 text-xs leading-5 text-[var(--text-secondary)]">{card.description}</p>
                      <div className="mt-4 flex items-center justify-between gap-3">
                        <span className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{card.status}</span>
                        {card.href && card.action ? (
                          <span className="text-xs font-medium text-emerald-400">{card.action}</span>
                        ) : null}
                      </div>
                    </div>
                  );

                  return card.href ? (
                    <Link key={card.title} href={card.href}>
                      {content}
                    </Link>
                  ) : (
                    <div key={card.title}>{content}</div>
                  );
                })}
              </div>
            </section>
          );
        })}
      </div>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
        <div className="flex items-start gap-3">
          <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
            <Activity className="h-5 w-5 text-emerald-400" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-[var(--foreground)]">Operating surfaces after ingest</h2>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              Discovery and ingest are only the front door. Agent-bom also needs clear surfaces for runtime review, fleet operations, policy enforcement,
              and graph analysis after the data lands.
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-3 xl:grid-cols-2">
          {OPERATING_SURFACES.map((surface) => {
            const Icon = surface.icon;
            return (
              <Link key={surface.title} href={surface.href}>
                <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition-colors hover:border-[color:var(--border-strong)]">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2">
                        <Icon className="h-4 w-4 text-emerald-400" />
                      </span>
                      <div>
                        <p className="text-sm font-semibold text-[var(--foreground)]">{surface.title}</p>
                        <p className="mt-1 text-xs leading-5 text-[var(--text-secondary)]">{surface.summary}</p>
                      </div>
                    </div>
                    <ArrowRight className="mt-1 h-4 w-4 text-[var(--text-tertiary)]" />
                  </div>
                  <div className="mt-4 text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{surface.status}</div>
                </div>
              </Link>
            );
          })}
        </div>
      </section>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
        <div className="flex items-start gap-3">
          <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
            <Shield className="h-5 w-5 text-emerald-400" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-[var(--foreground)]">Guardrail principle</h2>
            <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
              Prefer agentless read-only discovery when the product can safely gather the data itself. When the customer already owns the collection path,
              use imported artifacts or pushed ingest instead of rebuilding their telemetry pipeline inside agent-bom.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
