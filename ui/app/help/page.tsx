"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { AlertCircle, ArrowUpRight, Bug, CheckCircle2, Copy, MessageSquareQuote } from "lucide-react";

import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { api, type AuthDebugResponse, type VersionInfo } from "@/lib/api";
import { buildIssueUrl, buildSupportBundle } from "@/lib/feedback";

export default function HelpPage() {
  const searchParams = useSearchParams();
  const from = searchParams.get("from") || "/";
  const { counts, loading: deploymentLoading } = useDeploymentContext();
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [authDebug, setAuthDebug] = useState<AuthDebugResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    Promise.allSettled([api.version(), api.getAuthDebug()])
      .then(([versionResult, authResult]) => {
        if (!mounted) return;
        if (versionResult.status === "fulfilled") setVersion(versionResult.value);
        if (authResult.status === "fulfilled") setAuthDebug(authResult.value);
      })
      .finally(() => {
        if (!mounted) return;
        setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const supportBundle = useMemo(() => {
    return buildSupportBundle({
      from,
      currentUrl: typeof window !== "undefined" ? window.location.href : "/help",
      userAgent: typeof navigator !== "undefined" ? navigator.userAgent : "unknown",
      version,
      authDebug,
      counts,
    });
  }, [authDebug, counts, from, version]);

  async function copyBundle() {
    try {
      await navigator.clipboard.writeText(supportBundle);
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1500);
    } catch {
      setCopyState("error");
      window.setTimeout(() => setCopyState("idle"), 2000);
    }
  }

  const bugTitle = `bug(ui): issue from ${from}`;
  const feedbackTitle = `feedback(ui): ${counts?.deployment_mode ?? "self-hosted"} operator feedback`;

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-2">
            <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">
              Operator Help
            </p>
            <h1 className="text-2xl font-semibold text-[color:var(--foreground)]">Feedback and bug reporting</h1>
            <p className="max-w-3xl text-sm leading-6 text-[color:var(--text-secondary)]">
              This UI is the browser control-plane for the self-hosted <code>agent-bom</code> product. Use this page
              to share product feedback, report a bug, and copy a redaction-friendly support bundle without sending
              any hidden telemetry.
            </p>
          </div>
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3 text-xs text-[color:var(--text-secondary)]">
            <div>Opened from: <span className="font-mono text-[color:var(--foreground)]">{from}</span></div>
            <div>Deployment mode: <span className="font-mono text-[color:var(--foreground)]">{counts?.deployment_mode ?? "unknown"}</span></div>
            <div>Version: <span className="font-mono text-[color:var(--foreground)]">{version?.version ?? (loading ? "Loading…" : "unknown")}</span></div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
          <div className="mb-4 flex items-center gap-3">
            <div className="rounded-xl bg-emerald-500/10 p-2 text-emerald-400">
              <MessageSquareQuote className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-[color:var(--foreground)]">Share feedback</h2>
              <p className="text-sm text-[color:var(--text-secondary)]">
                Product UX, deployment friction, missing workflows, or integration requests.
              </p>
            </div>
          </div>
          <div className="space-y-3 text-sm text-[color:var(--text-secondary)]">
            <p>
              Opens the existing feature-request issue flow and gives you a copyable bundle for deployment, auth,
              and runtime context.
            </p>
            <div className="flex flex-wrap gap-2">
              <a
                href={buildIssueUrl("feature_request.yml", feedbackTitle)}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-2 text-sm font-medium text-black transition-opacity hover:opacity-90"
              >
                Open feature request
                <ArrowUpRight className="h-4 w-4" />
              </a>
              <button
                onClick={() => void copyBundle()}
                className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-muted)]"
              >
                <Copy className="h-4 w-4" />
                Copy support bundle
              </button>
            </div>
          </div>
        </article>

        <article className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
          <div className="mb-4 flex items-center gap-3">
            <div className="rounded-xl bg-rose-500/10 p-2 text-rose-400">
              <Bug className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-[color:var(--foreground)]">Report bug</h2>
              <p className="text-sm text-[color:var(--text-secondary)]">
                Broken UI flow, bad API response, deployment mismatch, or runtime behavior that regressed.
              </p>
            </div>
          </div>
          <div className="space-y-3 text-sm text-[color:var(--text-secondary)]">
            <p>
              Opens the existing bug-report issue template. The copied support bundle is redaction-friendly and avoids
              sending telemetry automatically.
            </p>
            <div className="flex flex-wrap gap-2">
              <a
                href={buildIssueUrl("bug_report.yml", bugTitle)}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-lg bg-rose-500 px-3 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Open bug report
                <ArrowUpRight className="h-4 w-4" />
              </a>
              <button
                onClick={() => void copyBundle()}
                className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-muted)]"
              >
                <Copy className="h-4 w-4" />
                Copy support bundle
              </button>
            </div>
          </div>
        </article>
      </section>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-[color:var(--foreground)]">Support bundle preview</h2>
            <p className="text-sm text-[color:var(--text-secondary)]">
              Review and redact if needed before sharing externally.
            </p>
          </div>
          <div className="text-xs">
            {copyState === "copied" && (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-1 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Copied
              </span>
            )}
            {copyState === "error" && (
              <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/10 px-2 py-1 text-rose-400">
                <AlertCircle className="h-3.5 w-3.5" />
                Copy failed
              </span>
            )}
          </div>
        </div>
        <textarea
          readOnly
          value={supportBundle}
          className="min-h-[340px] w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 font-mono text-xs leading-6 text-[color:var(--foreground)] outline-none"
        />
      </section>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 text-sm text-[color:var(--text-secondary)]">
        <h2 className="mb-2 text-lg font-semibold text-[color:var(--foreground)]">Support policy</h2>
        <ul className="space-y-2">
          <li>No hidden telemetry is sent from this page. It only prepares links and copyable text.</li>
          <li>Security issues should still go through the repository security policy, not the public bug form.</li>
          <li>
            The browser UI is part of the same <code>agent-bom</code> product, not a separate SaaS or separate
            collector.
          </li>
        </ul>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link
            href="https://github.com/msaad00/agent-bom/blob/main/SECURITY.md"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 text-sm font-medium text-emerald-400 hover:text-emerald-300"
          >
            Security policy
            <ArrowUpRight className="h-4 w-4" />
          </Link>
          <Link
            href="https://github.com/msaad00/agent-bom/discussions"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 text-sm font-medium text-emerald-400 hover:text-emerald-300"
          >
            Discussions
            <ArrowUpRight className="h-4 w-4" />
          </Link>
        </div>
      </section>

      {!deploymentLoading && counts?.deployment_mode == null && (
        <p className="text-xs text-[color:var(--text-tertiary)]">
          Deployment context is not fully detected yet. That usually means the control plane has not seen enough scan,
          fleet, or runtime state to infer a mode.
        </p>
      )}
    </div>
  );
}
