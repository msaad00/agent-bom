"use client";

import { isContinuousMode,isOrganizationScope,providerLabel } from "@/components/connections/catalog";
import { StatusPill } from "@/components/connections/display";
import { ConnectionEvidenceSummary,ScanHandoffLinks,ScanResultPanel } from "@/components/connections/evidence";
import { Drawer } from "@/components/drawer";
import {
  type CloudConnectionRecord,
  type CloudConnectionScanResponse,
  type CloudConnectionTestResponse
} from "@/lib/api";
import {
  CheckCircle2,
  ShieldCheck,
  Trash2
} from "lucide-react";


// ── Cloud connection detail drawer ────────────────────────────────────────────

export function ConnectionDetailDrawer({
  connection,
  result,
  testResult,
  scanError,
  scheduleError,
  isBusy,
  canManage,
  canDelete,
  scannable,
  onClose,
  onTest,
  onScan,
  onDelete,
}: {
  connection: CloudConnectionRecord | null;
  result: CloudConnectionScanResponse | undefined;
  testResult: CloudConnectionTestResponse | undefined;
  scanError: string | undefined;
  scheduleError: string | undefined;
  isBusy: boolean;
  canManage: boolean;
  canDelete: boolean;
  scannable: boolean;
  onClose: () => void;
  onTest: (connection: CloudConnectionRecord) => void;
  onScan: (connection: CloudConnectionRecord) => void;
  onDelete: (connection: CloudConnectionRecord) => void;
}) {
  if (!connection) return null;
  const handoffScanId = result?.job_id ?? connection.last_scan_id;
  const statusDetail = connection.status === "error" ? connection.status_detail : "";

  return (
    <Drawer
      open={Boolean(connection)}
      onClose={onClose}
      size="xl"
      eyebrow={providerLabel(connection.provider)}
      title={connection.display_name}
      subtitle={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="min-w-0 break-all font-mono text-[11px] text-ink-tertiary">{connection.role_ref}</span>
          {isOrganizationScope(connection) ? (
            <span
              className="inline-flex items-center rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-200"
              data-testid="connection-org-scope-chip"
            >
              Organization
            </span>
          ) : null}
          {isContinuousMode(connection) ? (
            <span
              className="inline-flex items-center rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium text-sky-700 dark:text-sky-200"
              data-testid="connection-continuous-chip"
            >
              Continuous
            </span>
          ) : null}
        </span>
      }
      headerAside={<StatusPill status={connection.status} />}
      footer={
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onTest(connection)}
            disabled={isBusy || !canManage || !scannable}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-800/70 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <CheckCircle2 className="h-3.5 w-3.5" /> {isBusy ? "Working…" : "Test"}
          </button>
          <button
            onClick={() => onScan(connection)}
            disabled={isBusy || !canManage || !scannable || connection.capability_probe_status !== "verified"}
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <ShieldCheck className="h-3.5 w-3.5" /> {isBusy ? "Working…" : "Run scan"}
          </button>
          <button
            onClick={() => onDelete(connection)}
            disabled={isBusy || !canDelete}
            className="ml-auto inline-flex items-center gap-1 rounded-lg border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 transition hover:bg-red-500/10 dark:hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      }
    >
      <div className="space-y-3">
        <ConnectionEvidenceSummary connection={connection} />
        {result ? <ScanResultPanel result={result} /> : null}
        {!result && testResult ? (
          <div className="rounded-xl border border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/20 p-3 text-xs text-emerald-700 dark:text-emerald-200">
            Provider read capability verified: {testResult.verified_capabilities.join(", ")}. No inventory, CIS,
            findings, or resource writes ran.
          </div>
        ) : null}
        {!result && handoffScanId ? <ScanHandoffLinks scanId={handoffScanId} /> : null}
        {scanError ? (
          <div className="rounded-xl border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 p-3 text-xs text-red-700 dark:text-red-300">
            {scanError}
          </div>
        ) : null}
        {scheduleError ? (
          <div className="rounded-xl border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 p-3 text-xs text-red-700 dark:text-red-300">
            {scheduleError}
          </div>
        ) : null}
        {statusDetail ? (
          <div className="rounded-xl border border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/20 p-3 text-xs text-amber-700 dark:text-amber-200">
            {statusDetail}
          </div>
        ) : null}
        {!result && !testResult && !handoffScanId && !scanError && !scheduleError && !statusDetail ? (
          <p className="text-sm text-ink-secondary">
            No scan has run for this account yet. Use “Run scan” below to populate inventory, CIS results, and
            evidence links.
          </p>
        ) : null}
      </div>
    </Drawer>
  );
}
