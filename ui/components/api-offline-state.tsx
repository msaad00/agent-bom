"use client";

import Link from "next/link";
import { AlertTriangle, FileText, PlayCircle, Server } from "lucide-react";

import type { ScanResult } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { getDisplayApiUrl } from "@/lib/runtime-config";
import { LocalReportImport } from "@/components/local-report-import";

// Distinguish "API is down" from "API rejected my request" so the splash
// stops shouting "Cannot connect" at users running `agent-bom serve` who
// just need to authenticate. Pages classify errors via the typed
// ApiError subclasses in lib/api-errors.ts and pass `kind` through.
export type ApiOfflineKind = "network" | "auth" | "forbidden";

interface ApiOfflineStateProps {
  title?: string | undefined;
  detail?: string | null | undefined;
  kind?: ApiOfflineKind | undefined;
  onImport?: ((data: ScanResult) => void) | undefined;
}

const KIND_TITLES: Record<ApiOfflineKind, string> = {
  network: "Cannot connect to the agent-bom API",
  auth: "Sign in to view the dashboard",
  forbidden: "This account doesn't have access to that view",
};

export function ApiOfflineState({
  title,
  detail,
  kind = "network",
  onImport,
}: ApiOfflineStateProps) {
  const apiUrl = getDisplayApiUrl();
  const resolvedTitle = title ?? KIND_TITLES[kind];
  const resolvedDetail = detail ? userFacingApiErrorMessage(detail, "The API request failed.") : null;

  return (
    <div className="py-10">
      <div className="mx-auto max-w-5xl rounded-3xl border border-[var(--border-subtle)] bg-[var(--background)]/70 p-6 shadow-2xl shadow-black/20 md:p-8">
        <div className="mx-auto max-w-3xl text-center">
          <AlertTriangle className="mx-auto mb-4 h-11 w-11 text-orange-400" />
          <h2 className="text-2xl font-semibold tracking-tight text-[var(--foreground)]">{resolvedTitle}</h2>
          {kind === "network" ? (
            <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
              Run the local stack at{" "}
              <code className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[var(--foreground)]">
                {apiUrl}
              </code>{" "}
              so the dashboard can load live scan data, graph views, and compliance surfaces.
            </p>
          ) : kind === "auth" ? (
            <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
              The API is reachable but rejected an unauthenticated request. Sign in via your IdP, set{" "}
              <code className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[var(--foreground)]">AGENT_BOM_API_KEY</code>{" "}
              when launching <code className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[var(--foreground)]">agent-bom serve</code>,
              or request access from your administrator.
            </p>
          ) : (
            <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
              Authenticated, but your role doesn&apos;t carry the permissions this view needs.
              Ask your administrator to grant a role with the relevant scope, or browse a
              tab that fits your current role.
            </p>
          )}
          {resolvedDetail ? (
            <p className="mt-3 text-xs text-[var(--text-tertiary)]">
              Current error: <span className="font-mono text-[var(--text-secondary)]">{resolvedDetail}</span>
            </p>
          ) : null}
        </div>

        {kind === "network" ? (
          <>
            <div className="mt-8 grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/20 p-5">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-emerald-800 dark:text-emerald-300">
                  <PlayCircle className="h-4 w-4" />
                  Recommended: start the full product surface
                </div>
                <p className="mb-4 text-sm text-[var(--text-secondary)]">
                  This starts the API and serves the bundled dashboard from one command path.
                </p>
                <code className="block rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3 font-mono text-sm leading-7 text-emerald-800 dark:text-emerald-400">
                  pip install &apos;agent-bom[ui]&apos;
                  <br />
                  agent-bom serve
                </code>
              </div>

              <div className="rounded-2xl border border-blue-900/60 bg-blue-950/20 p-5">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-blue-800 dark:text-blue-300">
                  <Server className="h-4 w-4" />
                  API only
                </div>
                <p className="mb-4 text-sm text-[var(--text-secondary)]">
                  Use this if the dashboard is already running separately and only the backend is missing.
                </p>
                <code className="block rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3 font-mono text-sm leading-7 text-blue-800 dark:text-blue-300">
                  pip install &apos;agent-bom[api]&apos;
                  <br />
                  agent-bom serve --no-ui
                </code>
              </div>
            </div>

            <div className="mt-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 p-4 text-sm text-[var(--text-secondary)]">
              If the API is already running and you still see this page, check the browser console for CORS errors and confirm{" "}
              <code className="rounded bg-[var(--background)] px-1.5 py-0.5 font-mono text-[var(--foreground)]">NEXT_PUBLIC_API_URL</code>{" "}
              points to{" "}
              <code className="rounded bg-[var(--background)] px-1.5 py-0.5 font-mono text-[var(--foreground)]">{apiUrl}</code>.
            </div>
          </>
        ) : null}

        {onImport ? (
          <LocalReportImport onImport={onImport} />
        ) : (
          <div className="mt-6 text-center">
            <Link
              href="/"
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]"
            >
              <FileText className="h-4 w-4" />
              Import a local report from the home page
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
