"use client";

import { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  XCircle,
} from "lucide-react";

import { api } from "@/lib/api";
import type {
  SelfPostureCheck,
  SelfPostureOverall,
  SelfPostureReport,
  SelfPostureStatus,
} from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { Collapsible } from "@/components/collapsible";
import { PageErrorState, PageLoadingState } from "@/components/states/page-state";

// Headless equivalent for agents/CI — the panel is the human surface, this is
// the same posture from the CLI/API (§11 human + headless parity).
const HEADLESS_CLI = "agent-bom self-audit";
const HEADLESS_API = "GET /v1/self-posture";

type Verdict = {
  label: string;
  detail: string;
  icon: typeof ShieldCheck;
  container: string;
  badge: string;
  accent: string;
};

// Headline verdict derives from the SAME overall_status the API returns
// (fail > warn > unknown > pass precedence lives in the backend) — never a
// re-computation on the client.
const OVERALL_VERDICTS: Record<SelfPostureOverall, Verdict> = {
  hardened: {
    label: "Control plane hardened",
    detail: "Every evaluated control is in its hardened configuration.",
    icon: ShieldCheck,
    container: "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)]",
    badge:
      "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
    accent: "text-[color:var(--status-success)]",
  },
  action_advised: {
    label: "Action advised",
    detail: "A weakened setting is in effect — acknowledged or dev-scoped, but worth tightening.",
    icon: ShieldAlert,
    container: "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)]",
    badge:
      "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
    accent: "text-[color:var(--status-warn)]",
  },
  needs_review: {
    label: "Needs review",
    detail: "One or more controls could not be evaluated from configuration alone — verify them directly.",
    icon: ShieldQuestion,
    container: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]",
    badge:
      "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]",
    accent: "text-[color:var(--text-secondary)]",
  },
  at_risk: {
    label: "At risk",
    detail: "A control is misconfigured for this deployment mode and weakens posture — fix before relying on it.",
    icon: ShieldX,
    container: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)]",
    badge:
      "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
    accent: "text-[color:var(--status-danger)]",
  },
};

type ChipMeta = {
  label: string;
  icon: typeof CheckCircle2;
  chip: string;
};

// Four-way, theme-safe chips. `unknown` is an explicit neutral "not evaluated"
// state — never rendered as an implied pass.
const STATUS_CHIPS: Record<SelfPostureStatus, ChipMeta> = {
  pass: {
    label: "Pass",
    icon: CheckCircle2,
    chip: "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
  },
  fail: {
    label: "Fail",
    icon: XCircle,
    chip: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
  },
  warn: {
    label: "Warn",
    icon: ShieldAlert,
    chip: "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
  },
  unknown: {
    label: "Not evaluated",
    icon: HelpCircle,
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]",
  },
};

const COUNT_ORDER: Array<{ status: SelfPostureStatus }> = [
  { status: "fail" },
  { status: "warn" },
  { status: "unknown" },
  { status: "pass" },
];

function StatusChip({ status }: { status: SelfPostureStatus }) {
  const meta = STATUS_CHIPS[status];
  const Icon = meta.icon;
  return (
    <span
      data-testid="posture-check-status"
      data-status={status}
      className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${meta.chip}`}
    >
      <Icon className="h-3 w-3" aria-hidden="true" />
      {meta.label}
    </span>
  );
}

function CheckRow({ check }: { check: SelfPostureCheck }) {
  const hasRemediation = Boolean(check.remediation && check.remediation.trim());
  return (
    <Collapsible
      data-testid={`posture-check-${check.id}`}
      title={check.title}
      defaultOpen={false}
      actions={<StatusChip status={check.status} />}
      className="bg-[color:var(--surface)]"
    >
      <p className="text-xs leading-5 text-[color:var(--text-secondary)] [overflow-wrap:anywhere]">
        {check.detail}
      </p>
      {hasRemediation && (
        <div className="mt-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
            Remediation
          </div>
          <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)] [overflow-wrap:anywhere]">
            {check.remediation}
          </p>
        </div>
      )}
      <p className="mt-3 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
        {check.category} · {check.id}
      </p>
    </Collapsible>
  );
}

export default function SelfPosturePage() {
  const [report, setReport] = useState<SelfPostureReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .getSelfPosture()
      .then(setReport)
      .catch((e) => setError(userFacingApiErrorMessage(e, "Self-posture could not be evaluated")))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <PageLoadingState
        data-testid="self-posture-loading"
        title="Evaluating control-plane posture…"
        detail="Reading this instance's own security and governance configuration."
      />
    );
  }

  if (error || !report) {
    return (
      <PageErrorState
        data-testid="self-posture-error"
        title="Self-posture could not be evaluated"
        detail={error ?? "No self-posture report was returned by the control plane."}
        suggestions={[
          "Confirm you are signed in with read access to this control plane.",
          "The same posture is available headless for agents and CI.",
        ]}
        command={`${HEADLESS_CLI}   # or ${HEADLESS_API}`}
        action={{ label: "Retry", onClick: load }}
      />
    );
  }

  const verdict = OVERALL_VERDICTS[report.overall_status];
  const VerdictIcon = verdict.icon;

  return (
    <div className="space-y-6">
      <div className="min-w-0">
        <h1 className="flex items-center gap-2 text-2xl font-bold text-[color:var(--foreground)]">
          <ShieldCheck className="h-6 w-6 text-[color:var(--accent)]" aria-hidden="true" />
          Self-Audit
        </h1>
        <p className="mt-1 text-sm text-[color:var(--text-tertiary)]">
          agent-bom&apos;s honest posture of its OWN control plane — read-only, configuration only,
          never a secret value.
        </p>
      </div>

      {/* Overall verdict — derived from the API's overall_status, reconciled
          with the per-check counts below (§11 one source of truth). */}
      <section
        aria-label="Overall self-posture"
        data-testid="self-posture-headline"
        data-overall={report.overall_status}
        className={`rounded-2xl border p-4 ${verdict.container}`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <VerdictIcon className={`h-7 w-7 shrink-0 ${verdict.accent}`} aria-hidden="true" />
            <div className="min-w-0">
              <div
                className={`inline-flex items-center rounded-full border px-3 py-0.5 text-sm font-bold tracking-[0.06em] ${verdict.badge}`}
              >
                {verdict.label}
              </div>
              <p className="mt-1 max-w-xl text-xs text-[color:var(--text-secondary)]">{verdict.detail}</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
              Deployment
            </div>
            <div className="font-mono text-sm font-semibold text-[color:var(--foreground)]">
              {report.deployment_env}
            </div>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2 border-t border-[color:var(--border-subtle)] pt-3">
          {COUNT_ORDER.map(({ status }) => (
            <span
              key={status}
              className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-0.5 text-[11px] text-[color:var(--text-secondary)]"
            >
              <span className="tabular-nums font-semibold text-[color:var(--foreground)]">
                {report.counts[status]}
              </span>
              {STATUS_CHIPS[status].label}
            </span>
          ))}
        </div>
      </section>

      {/* Individual checks — chip + title always visible; evidence + remediation
          in collapsible detail (§11 concise, one primary read). */}
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-[color:var(--foreground)]">
          Checks ({report.checks.length})
        </h2>
        {report.checks.map((check) => (
          <CheckRow key={check.id} check={check} />
        ))}
      </div>

      <p className="text-[11px] text-[color:var(--text-tertiary)]">
        Headless equivalent: <code className="text-[color:var(--text-secondary)]">{HEADLESS_CLI}</code>{" "}
        · <code className="text-[color:var(--text-secondary)]">{HEADLESS_API}</code>
      </p>
    </div>
  );
}
