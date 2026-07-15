"use client";

import Link from "next/link";
import { ArrowRight, CheckCircle2, Circle, Plug, ScanSearch, Sparkles } from "lucide-react";

import type { AuthMeResponse } from "@/lib/api";
import { PermissionDeniedNotice } from "@/components/role-access";

type StepStatus = "done" | "current" | "todo";

interface JourneyStep {
  id: "connect" | "scan" | "results";
  title: string;
  detail: string;
  icon: typeof Plug;
  status: StepStatus;
}

function statusOf(done: boolean, isCurrent: boolean): StepStatus {
  if (done) return "done";
  return isCurrent ? "current" : "todo";
}

/**
 * Guided connect → scan → see-results path for a fresh instance. Honest: a step
 * is "done" only when the real estate says so (a connection exists, a scan has
 * run, findings landed). No fabricated progress. Renders nothing once the whole
 * journey is complete so it never clutters a populated instance.
 */
export function FirstRunJourney({
  connectionsCount,
  scanCount,
  findingsCount,
  canManage,
  session,
  onConnect,
}: {
  connectionsCount: number;
  scanCount: number;
  findingsCount: number;
  canManage: boolean;
  session: AuthMeResponse | null;
  onConnect: () => void;
}) {
  const connected = connectionsCount > 0;
  const scanned = scanCount > 0;
  const hasResults = findingsCount > 0;

  if (connected && scanned && hasResults) return null;

  // The current step is the first incomplete one.
  const currentId: JourneyStep["id"] = !connected
    ? "connect"
    : !scanned
      ? "scan"
      : "results";

  const steps: JourneyStep[] = [
    {
      id: "connect",
      title: "Connect a source",
      detail:
        "Add a read-only cloud account, or register a repo, image, IaC, or MCP source. Secrets are encrypted at rest.",
      icon: Plug,
      status: statusOf(connected, currentId === "connect"),
    },
    {
      id: "scan",
      title: "Run a scan",
      detail:
        "Launch a read-only inventory + CIS scan on the connection, or run a local scan for repo / image / IaC evidence.",
      icon: ScanSearch,
      status: statusOf(scanned, currentId === "scan"),
    },
    {
      id: "results",
      title: "See results",
      detail:
        "Findings, the security graph, and compliance populate from your first scan — each one links straight to its evidence.",
      icon: Sparkles,
      status: statusOf(hasResults, currentId === "results"),
    },
  ];

  const completed = steps.filter((s) => s.status === "done").length;

  return (
    <section
      data-testid="first-run-journey"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[linear-gradient(160deg,var(--surface-elevated),var(--surface))] p-5"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-[var(--foreground)]">
            Get to your first findings
          </h2>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Three steps from an empty instance to correlated evidence. We only
            check a step off once it has actually happened.
          </p>
        </div>
        <span className="shrink-0 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]">
          {completed} of {steps.length} done
        </span>
      </div>

      <ol className="mt-4 space-y-3">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const isCurrent = step.status === "current";
          return (
            <li
              key={step.id}
              data-testid={`journey-step-${step.id}`}
              data-status={step.status}
              className={`rounded-xl border p-4 transition ${
                isCurrent
                  ? "border-emerald-500/50 bg-emerald-500/10"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface)]"
              }`}
            >
              <div className="flex items-start gap-3">
                <span className="mt-0.5 shrink-0">
                  {step.status === "done" ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  ) : isCurrent ? (
                    <span className="flex h-5 w-5 items-center justify-center rounded-full border border-emerald-500 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                      {index + 1}
                    </span>
                  ) : (
                    <Circle className="h-5 w-5 text-[var(--text-tertiary)]" />
                  )}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="inline-flex items-center gap-2 text-sm font-semibold text-[var(--foreground)]">
                    <Icon className="h-4 w-4 text-emerald-400" />
                    {step.title}
                    {step.status === "done" ? (
                      <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-200">
                        Done
                      </span>
                    ) : null}
                  </p>
                  <p className="mt-1 text-[13px] leading-6 text-[var(--text-secondary)]">
                    {step.detail}
                  </p>

                  {isCurrent ? (
                    <JourneyAction
                      step={step.id}
                      canManage={canManage}
                      session={session}
                      onConnect={onConnect}
                    />
                  ) : null}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function JourneyAction({
  step,
  canManage,
  session,
  onConnect,
}: {
  step: JourneyStep["id"];
  canManage: boolean;
  session: AuthMeResponse | null;
  onConnect: () => void;
}) {
  // Connect and scan both require the analyst/contributor role. A viewer sees
  // the concrete elevation path instead of a dead button.
  if (!canManage && (step === "connect" || step === "scan")) {
    return (
      <PermissionDeniedNotice
        session={session}
        needed="analyst"
        action={step === "connect" ? "connect a source" : "run a scan"}
        className="mt-3"
      />
    );
  }

  if (step === "connect") {
    return (
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onConnect}
          className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400"
        >
          <Plug className="h-3.5 w-3.5" />
          Connect cloud account
        </button>
        <Link
          href="/sources"
          className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
        >
          Register a source
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    );
  }

  if (step === "scan") {
    return (
      <div className="mt-3 flex flex-wrap gap-2">
        <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200">
          <ScanSearch className="h-3.5 w-3.5" />
          Use “Run scan” on your connection below
        </span>
        <Link
          href="/scan"
          className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
        >
          New local scan
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    );
  }

  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <Link
        href="/findings"
        className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400"
      >
        Open findings
        <ArrowRight className="h-3.5 w-3.5" />
      </Link>
      <Link
        href="/security-graph"
        className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
      >
        Open graph
        <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}
