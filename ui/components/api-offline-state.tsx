"use client";

import { useState, type ChangeEvent } from "react";
import Link from "next/link";
import { AlertTriangle, FileText, PlayCircle, Server } from "lucide-react";

import type { ScanResult } from "@/lib/api";
import { getDisplayApiUrl } from "@/lib/runtime-config";
import { checkFileSize, validateScanReport } from "@/lib/validators";

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
  const [importError, setImportError] = useState<string | null>(null);
  const apiUrl = getDisplayApiUrl();
  const resolvedTitle = title ?? KIND_TITLES[kind];

  const handleFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError(null);

    const sizeCheck = checkFileSize(file);
    if (!sizeCheck.ok) {
      setImportError(sizeCheck.error);
      e.target.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => setImportError("Failed to read file.");
    reader.onload = (ev) => {
      const text = ev.target?.result;
      if (typeof text !== "string") {
        setImportError("Could not read file contents.");
        return;
      }
      const result = validateScanReport(text);
      if (!result.ok) {
        setImportError(result.error);
        return;
      }
      onImport?.(result.data as ScanResult);
    };
    reader.readAsText(file);
  };

  return (
    <div className="py-10">
      <div className="mx-auto max-w-5xl rounded-3xl border border-zinc-800 bg-zinc-950/70 p-6 shadow-2xl shadow-black/20 md:p-8">
        <div className="mx-auto max-w-3xl text-center">
          <AlertTriangle className="mx-auto mb-4 h-11 w-11 text-orange-400" />
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-100">{resolvedTitle}</h2>
          {kind === "network" ? (
            <p className="mt-3 text-sm leading-6 text-zinc-400">
              Run the local stack at{" "}
              <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-zinc-200">
                {apiUrl}
              </code>{" "}
              so the dashboard can load live scan data, graph views, and compliance surfaces.
            </p>
          ) : kind === "auth" ? (
            <p className="mt-3 text-sm leading-6 text-zinc-400">
              The API is reachable but rejected an unauthenticated request. Sign in via your IdP, set{" "}
              <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-zinc-200">AGENT_BOM_API_KEY</code>{" "}
              when launching <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-zinc-200">agent-bom serve</code>,
              or request access from your administrator.
            </p>
          ) : (
            <p className="mt-3 text-sm leading-6 text-zinc-400">
              Authenticated, but your role doesn&apos;t carry the permissions this view needs.
              Ask your administrator to grant a role with the relevant scope, or browse a
              tab that fits your current role.
            </p>
          )}
          {detail ? (
            <p className="mt-3 text-xs text-zinc-500">
              Current error: <span className="font-mono text-zinc-400">{detail}</span>
            </p>
          ) : null}
        </div>

        {kind === "network" ? (
          <>
            <div className="mt-8 grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/20 p-5">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-emerald-300">
                  <PlayCircle className="h-4 w-4" />
                  Recommended: start the full product surface
                </div>
                <p className="mb-4 text-sm text-zinc-400">
                  This starts the API and serves the bundled dashboard from one command path.
                </p>
                <code className="block rounded-xl border border-zinc-800 bg-zinc-950 px-4 py-3 font-mono text-sm leading-7 text-emerald-400">
                  pip install &apos;agent-bom[ui]&apos;
                  <br />
                  agent-bom serve
                </code>
              </div>

              <div className="rounded-2xl border border-blue-900/60 bg-blue-950/20 p-5">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-blue-300">
                  <Server className="h-4 w-4" />
                  API only
                </div>
                <p className="mb-4 text-sm text-zinc-400">
                  Use this if the dashboard is already running separately and only the backend is missing.
                </p>
                <code className="block rounded-xl border border-zinc-800 bg-zinc-950 px-4 py-3 font-mono text-sm leading-7 text-blue-300">
                  pip install &apos;agent-bom[api]&apos;
                  <br />
                  agent-bom api
                </code>
              </div>
            </div>

            <div className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-900/60 p-4 text-sm text-zinc-400">
              If the API is already running and you still see this page, check the browser console for CORS errors and confirm{" "}
              <code className="rounded bg-zinc-950 px-1.5 py-0.5 font-mono text-zinc-200">NEXT_PUBLIC_API_URL</code>{" "}
              points to{" "}
              <code className="rounded bg-zinc-950 px-1.5 py-0.5 font-mono text-zinc-200">{apiUrl}</code>.
            </div>
          </>
        ) : null}

        {onImport ? (
          <div className="mt-6 rounded-2xl border border-dashed border-zinc-700 bg-zinc-900/40 p-6 text-center">
            <FileText className="mx-auto mb-3 h-8 w-8 text-zinc-500" />
            <h3 className="text-sm font-semibold text-zinc-200">Or stay offline and import a real report</h3>
            <p className="mt-2 text-sm text-zinc-500">
              Use the built-in demo for a reproducible sample, or export a real project scan and load it here.
            </p>
            <code className="mt-4 block rounded-xl border border-zinc-800 bg-zinc-950 px-4 py-3 font-mono text-xs leading-7 text-zinc-300">
              agent-bom agents --demo --offline -f json -o report.json
              <br />
              agent-bom agents -p . -f json -o report.json
            </code>
            {importError ? (
              <div className="mx-auto mt-4 max-w-xl rounded-xl border border-red-800/50 bg-red-950/30 px-3 py-2 text-left">
                <p className="break-words text-xs font-mono text-red-400">{importError}</p>
              </div>
            ) : null}
            <label className="mt-5 inline-flex cursor-pointer items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-200 transition-colors hover:bg-zinc-700">
              <FileText className="h-4 w-4" />
              Choose report.json
              <input
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={handleFile}
              />
            </label>
            <p className="mt-3 text-xs text-zinc-600">Max 10 MB. Schema-validated before import.</p>
          </div>
        ) : (
          <div className="mt-6 text-center">
            <Link
              href="/"
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-200 transition-colors hover:bg-zinc-700"
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
