"use client";

import Link from "next/link";
import { ArrowRight, CheckCircle2, Circle, Plug, ScanSearch, ShieldCheck } from "lucide-react";

import type { AuthMeResponse } from "@/lib/api";
import { PermissionDeniedNotice } from "@/components/role-access";

type StepStatus = "done" | "current" | "todo";
type JourneyStepId = "connect" | "verify" | "scan";

interface JourneyStep {
  id: JourneyStepId;
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
 * Compact cloud onboarding rail backed only by connection evidence: a stored
 * connection, an API-verified active status, and a recorded connection scan.
 * Global scans and findings may belong to another source, so they never advance
 * this journey. The rail disappears once the selected path is complete.
 */
export function FirstRunJourney({
  connectionsCount,
  verifiedConnectionsCount,
  scannedConnectionsCount,
  canManage,
  session,
  onConnect,
}: {
  connectionsCount: number;
  verifiedConnectionsCount: number;
  scannedConnectionsCount: number;
  canManage: boolean;
  session: AuthMeResponse | null;
  onConnect: () => void;
}) {
  const connected = connectionsCount > 0;
  const verified = verifiedConnectionsCount > 0;
  const scanned = scannedConnectionsCount > 0;

  if (connected && verified && scanned) return null;

  const currentId: JourneyStepId = !connected ? "connect" : !verified ? "verify" : "scan";
  const steps: JourneyStep[] = [
    {
      id: "connect",
      title: "Connect",
      detail: "Store one read-only cloud account.",
      icon: Plug,
      status: statusOf(connected, currentId === "connect"),
    },
    {
      id: "verify",
      title: "Verify",
      detail: "Confirm the least-privilege credential works.",
      icon: ShieldCheck,
      status: statusOf(verified, currentId === "verify"),
    },
    {
      id: "scan",
      title: "Scan",
      detail: "Queue read-only inventory and posture collection.",
      icon: ScanSearch,
      status: statusOf(scanned, currentId === "scan"),
    },
  ];
  const completed = steps.filter((step) => step.status === "done").length;
  const currentStep = steps.find((step) => step.status === "current") ?? steps[0]!;

  return (
    <section
      data-testid="first-run-journey"
      aria-labelledby="first-run-journey-title"
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-4 py-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <h2 id="first-run-journey-title" className="text-sm font-semibold text-[var(--foreground)]">
            Connect → verify → scan
          </h2>
          <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
            Progress reflects this cloud connection path, not unrelated scans.
          </p>
        </div>
        <span
          role="status"
          aria-live="polite"
          className="shrink-0 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]"
        >
          {completed} of {steps.length} complete
        </span>
      </div>

      <ol aria-label="Cloud connection setup progress" className="mt-3 grid gap-2 sm:grid-cols-3">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const isCurrent = step.status === "current";
          return (
            <li
              key={step.id}
              data-testid={`journey-step-${step.id}`}
              data-status={step.status}
              aria-current={isCurrent ? "step" : undefined}
              className={`flex min-w-0 items-center gap-2 rounded-lg border px-3 py-2 ${
                isCurrent
                  ? "border-emerald-500/50 bg-emerald-500/10"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]"
              }`}
            >
              {step.status === "done" ? (
                <CheckCircle2 aria-hidden="true" className="h-4 w-4 shrink-0 text-emerald-400" />
              ) : isCurrent ? (
                <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-emerald-500 text-[9px] font-semibold text-emerald-300">
                  {index + 1}
                </span>
              ) : (
                <Circle aria-hidden="true" className="h-4 w-4 shrink-0 text-[var(--text-tertiary)]" />
              )}
              <Icon aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span className="truncate text-xs font-medium text-[var(--foreground)]">{step.title}</span>
              <span className="ml-auto text-[10px] text-[var(--text-tertiary)]">
                {step.status === "done" ? "Done" : isCurrent ? "Current" : "Next"}
              </span>
            </li>
          );
        })}
      </ol>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-[color:var(--border-subtle)] pt-3">
        <p className="text-xs text-[var(--text-secondary)]">{currentStep.detail}</p>
        <JourneyAction
          step={currentStep.id}
          canManage={canManage}
          session={session}
          onConnect={onConnect}
        />
      </div>
    </section>
  );
}

function JourneyAction({
  step,
  canManage,
  session,
  onConnect,
}: {
  step: JourneyStepId;
  canManage: boolean;
  session: AuthMeResponse | null;
  onConnect: () => void;
}) {
  if (!canManage) {
    return (
      <PermissionDeniedNotice
        session={session}
        needed="analyst"
        action={step === "connect" ? "connect a cloud account" : step === "verify" ? "verify a cloud connection" : "run a cloud scan"}
        className="w-full sm:max-w-lg"
      />
    );
  }

  if (step === "connect") {
    return (
      <button
        type="button"
        onClick={onConnect}
        className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400"
      >
        <Plug className="h-3.5 w-3.5" />
        Connect cloud account
      </button>
    );
  }

  return (
    <Link
      href="/connections?tab=sources"
      className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400"
    >
      {step === "verify" ? "Open connection to verify" : "Open connection to run scan"}
      <ArrowRight className="h-3.5 w-3.5" />
    </Link>
  );
}
