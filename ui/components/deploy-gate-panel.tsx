"use client";

import { useState } from "react";
import {
  Ban,
  CheckCircle2,
  Loader2,
  Rocket,
  ShieldAlert,
  ShieldQuestion,
} from "lucide-react";

import { api, type DeployDecision, type GraphDeployDecisionResponse } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";

type Verdict = {
  label: string;
  detail: string;
  icon: typeof CheckCircle2;
  container: string;
  badge: string;
  accent: string;
};

const VERDICTS: Record<DeployDecision, Verdict> = {
  allow: {
    label: "GO",
    detail: "No blocking exposure path reaches this candidate — safe to ship.",
    icon: CheckCircle2,
    container:
      "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)]",
    badge:
      "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
    accent: "text-[color:var(--status-success)]",
  },
  warn: {
    label: "REVIEW",
    detail: "A material exposure path was found — review the evidence before shipping.",
    icon: ShieldQuestion,
    container: "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)]",
    badge:
      "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
    accent: "text-[color:var(--status-warn)]",
  },
  block: {
    label: "BLOCK",
    detail: "A high-risk exposure path reaches this candidate — do not deploy.",
    icon: Ban,
    container:
      "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)]",
    badge:
      "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
    accent: "text-[color:var(--status-danger)]",
  },
};

function severityToken(severity: string): string {
  const value = severity.toLowerCase();
  if (value === "critical") return "text-[color:var(--severity-critical)]";
  if (value === "high") return "text-[color:var(--severity-high)]";
  if (value === "medium") return "text-[color:var(--severity-medium)]";
  if (value === "low") return "text-[color:var(--severity-low)]";
  return "text-[color:var(--text-secondary)]";
}

/**
 * "Should I deploy this agent/component?" gate — the exec answer over the
 * MCP-only /v1/graph/should-i-deploy surface. Renders GO / REVIEW / BLOCK from
 * the allow/warn/block decision with the reasons and exposure it found.
 */
export function DeployGatePanel({ scanId }: { scanId?: string | undefined }) {
  const [candidate, setCandidate] = useState("");
  const [result, setResult] = useState<GraphDeployDecisionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmed = candidate.trim();

  async function runGate() {
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      const response = await api.graphShouldIDeploy({
        candidate: trimmed,
        scanId: scanId || undefined,
      });
      setResult(response);
    } catch (err) {
      setResult(null);
      setError(userFacingApiErrorMessage(err, "Deploy gate could not be evaluated"));
    } finally {
      setLoading(false);
    }
  }

  const verdict = result ? VERDICTS[result.decision] : null;
  const VerdictIcon = verdict?.icon ?? Rocket;

  return (
    <section
      aria-label="Should I deploy gate"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Rocket className="h-4 w-4 text-[color:var(--accent)]" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Should I deploy?</h2>
          </div>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
            Check an agent, service, image, or package against this snapshot&apos;s exposure paths.
          </p>
        </div>
      </div>

      <form
        className="mt-3 flex flex-wrap items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          void runGate();
        }}
      >
        <label htmlFor="deploy-gate-candidate" className="sr-only">
          Deploy candidate
        </label>
        <input
          id="deploy-gate-candidate"
          value={candidate}
          onChange={(event) => setCandidate(event.target.value)}
          placeholder="agent:claude-desktop, service:payments-api, pkg@1.2.3…"
          className="min-w-0 flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--accent-border)] focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading || !trimmed}
          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-sm font-medium text-[color:var(--accent)] transition hover:bg-[color:var(--accent-soft-hover)] disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          ) : (
            <ShieldAlert className="h-4 w-4" aria-hidden="true" />
          )}
          Run gate
        </button>
      </form>

      {error && (
        <p
          role="alert"
          className="mt-3 rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-xs text-[color:var(--status-danger)]"
        >
          {error}
        </p>
      )}

      {result && verdict && (
        <div
          data-testid="deploy-gate-verdict"
          data-decision={result.decision}
          className={`mt-4 rounded-2xl border p-4 ${verdict.container}`}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <VerdictIcon className={`h-7 w-7 shrink-0 ${verdict.accent}`} aria-hidden="true" />
              <div className="min-w-0">
                <div
                  className={`inline-flex items-center rounded-full border px-3 py-0.5 text-sm font-bold tracking-[0.14em] ${verdict.badge}`}
                >
                  {verdict.label}
                </div>
                <p className="mt-1 max-w-xl text-xs text-[color:var(--text-secondary)]">{verdict.detail}</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                Max path risk
              </div>
              <div className={`font-mono text-2xl font-semibold ${verdict.accent}`}>
                {result.maxRisk.toFixed(1)}
              </div>
              <div className="text-[10px] text-[color:var(--text-tertiary)]">
                warn ≥ {result.thresholds.warnRisk} · block ≥ {result.thresholds.blockRisk}
              </div>
            </div>
          </div>

          {result.reasons.length > 0 && (
            <ul className="mt-3 space-y-1.5 border-t border-[color:var(--border-subtle)] pt-3 text-xs text-[color:var(--text-secondary)]">
              {result.reasons.map((reason) => (
                <li key={reason} className="flex items-start gap-2">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[color:var(--text-tertiary)]" />
                  <span className="[overflow-wrap:anywhere]">{reason}</span>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-3 border-t border-[color:var(--border-subtle)] pt-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
              Matched exposure paths ({result.matchedPathCount})
            </div>
            {result.matchedPaths.length === 0 ? (
              <p className="mt-2 text-xs text-[color:var(--text-secondary)]">
                No exposure path in this snapshot reaches the candidate.
              </p>
            ) : (
              <ul className="mt-2 space-y-2">
                {result.matchedPaths.slice(0, 5).map((path) => (
                  <li
                    key={path.id}
                    className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 truncate text-xs font-medium text-[color:var(--foreground)]">
                        {path.label || path.id}
                      </span>
                      <span className="shrink-0 font-mono text-xs text-[color:var(--text-secondary)]">
                        <span className={severityToken(path.severity)}>{path.severity}</span>{" "}
                        · {path.riskScore.toFixed(1)}
                      </span>
                    </div>
                    {path.findings.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {path.findings.slice(0, 4).map((finding) => (
                          <span
                            key={finding}
                            className="rounded border border-[color:var(--border-subtle)] px-1.5 py-0.5 font-mono text-[10px] text-[color:var(--text-tertiary)]"
                          >
                            {finding}
                          </span>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
