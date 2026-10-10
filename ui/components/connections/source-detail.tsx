"use client";

import { TextField } from "@/components/text-field";

import { formatShortId,formatWhen,kindOption,SCHEDULABLE_KINDS } from "@/components/connections/catalog";
import { sourceEvidenceHref,SourceStatusPill } from "@/components/connections/display";
import { Drawer } from "@/components/drawer";
import {
  type ScanSchedule,
  type SourceRecord
} from "@/lib/api";
import {
  sourceSupportsDirectRun
} from "@/lib/connections-sources";
import {
  CalendarClock,
  FileCheck2
} from "lucide-react";
import Link from "next/link";


// ── Source detail drawer ──────────────────────────────────────────────────────

export function SourceDrawer({
  source,
  open,
  onClose,
  schedules,
  busySourceId,
  busyScheduleId,
  canManageSources,
  canRunScans,
  canDeleteSources,
  onSourceAction,
  onScheduleAction,
  onCreateSchedule,
  submittingSchedule,
  scheduleName,
  scheduleCron,
  onScheduleNameChange,
  onScheduleCronChange,
}: {
  source: SourceRecord | null;
  open: boolean;
  onClose: () => void;
  schedules: ScanSchedule[];
  busySourceId: string | null;
  busyScheduleId: string | null;
  canManageSources: boolean;
  canRunScans: boolean;
  canDeleteSources: boolean;
  onSourceAction: (sourceId: string, action: "test" | "run" | "delete") => void;
  onScheduleAction: (scheduleId: string, action: "toggle" | "delete") => void;
  onCreateSchedule: (event: React.FormEvent<HTMLFormElement>, source: SourceRecord) => void;
  submittingSchedule: boolean;
  scheduleName: string;
  scheduleCron: string;
  onScheduleNameChange: (value: string) => void;
  onScheduleCronChange: (value: string) => void;
}) {
  if (!source) return null;
  const option = kindOption(source.kind);
  const mode = option?.mode ?? "Direct scan";
  const isBusy = busySourceId === source.source_id;
  const schedulable = SCHEDULABLE_KINDS.has(source.kind);
  const runnable = sourceSupportsDirectRun(source.kind);
  const credentialBlocksRun = runnable && source.credential_mode === "reference";
  const credentialContract =
    source.credential_mode === "reference"
      ? "Metadata only (not executable)"
      : "Server configured or not required";

  const meta: [string, React.ReactNode][] = [
    ["Owner", source.owner || "Unassigned"],
    ["Credential contract", credentialContract],
    ["Credential reference", source.credential_ref ? formatShortId(source.credential_ref) : "—"],
    ["Connector", source.connector_name || "—"],
    ["Enabled", source.enabled ? "Enabled" : "Disabled"],
    ["Last tested", formatWhen(source.last_tested_at)],
    ["Last run", formatWhen(source.last_run_at)],
  ];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      eyebrow={mode}
      title={source.display_name}
      subtitle={option?.label ?? source.kind}
      headerAside={<SourceStatusPill status={source.status} />}
      size="2xl"
      ariaLabel={`Source ${source.display_name}`}
      footer={
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSourceAction(source.source_id, "test")}
            disabled={isBusy || !canManageSources}
            className="rounded-lg border border-outline bg-surface-muted px-3 py-2 text-xs font-medium text-foreground transition hover:border-outline-strong disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isBusy ? "Working…" : "Test"}
          </button>
          <button
            onClick={() => onSourceAction(source.source_id, "run")}
            disabled={isBusy || !source.enabled || !canRunScans || !runnable || credentialBlocksRun}
            title={
              !runnable
                ? "Push and runtime sources receive evidence externally and cannot run directly."
                : credentialBlocksRun
                  ? "Credential references are governance metadata and cannot execute this source. Detach the reference first."
                : undefined
            }
            className="rounded-lg bg-[color:var(--accent)] px-3 py-2 text-xs font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Run now
          </button>
          <button
            onClick={() => onSourceAction(source.source_id, "delete")}
            disabled={isBusy || !canDeleteSources}
            title={!canDeleteSources ? "Deleting a source requires an Admin role." : undefined}
            className="rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-xs font-medium text-[color:var(--status-danger)] transition hover:border-[color:var(--status-danger)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Delete
          </button>
        </div>
      }
    >
      <div className="space-y-5" data-testid={`source-detail-${source.source_id}`}>
        {source.description ? (
          <p className="text-sm leading-6 text-ink-secondary">{source.description}</p>
        ) : null}

        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
          {meta.map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-[11px] uppercase tracking-[0.14em] text-ink-tertiary">{label}</dt>
              <dd className="mt-0.5 truncate text-ink-secondary">{value}</dd>
            </div>
          ))}
          <div className="col-span-2 min-w-0">
            <dt className="text-[11px] uppercase tracking-[0.14em] text-ink-tertiary">Last job</dt>
            <dd className="mt-0.5">
              {source.last_job_id ? (
                <Link
                  href={`/scan?id=${encodeURIComponent(source.last_job_id)}`}
                  className="inline-block max-w-full truncate font-mono text-[color:var(--accent)] hover:underline"
                  title={source.last_job_id}
                >
                  {formatShortId(source.last_job_id)}
                </Link>
              ) : (
                <span className="text-ink-secondary">—</span>
              )}
            </dd>
          </div>
        </dl>

        {source.last_test_message ? (
          <p className="rounded-lg border border-outline bg-surface-elevated p-3 text-xs leading-5 text-ink-secondary">
            {source.last_test_message}
          </p>
        ) : null}

        <div className="rounded-xl border border-outline bg-surface-elevated p-4">
          <div className="flex items-start gap-2">
            <FileCheck2 className="mt-0.5 h-4 w-4 text-[color:var(--accent)]" />
            <div>
              <p className="text-xs font-semibold text-foreground">Evidence workflow</p>
              <p className="mt-1 text-xs leading-5 text-ink-secondary">
                {source.last_job_id
                  ? "Open the completed job surfaces created from this source."
                  : "Run this source to create findings, graph, and compliance evidence."}
              </p>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {[
              { target: "jobs" as const, label: "Jobs" },
              { target: "findings" as const, label: "Findings" },
              { target: "graph" as const, label: "Graph" },
              { target: "compliance" as const, label: "Compliance" },
            ].map((link) => {
              const disabled = link.target !== "jobs" && !source.last_job_id;
              return (
                <Link
                  key={link.target}
                  href={sourceEvidenceHref(source, link.target)}
                  aria-disabled={disabled}
                  className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition ${
                    disabled
                      ? "pointer-events-none border-outline text-ink-tertiary opacity-60"
                      : "border-outline text-foreground hover:border-outline-strong"
                  }`}
                >
                  {link.label}
                </Link>
              );
            })}
          </div>
        </div>

        <div>
          <h3 className="text-sm font-semibold text-foreground">Schedules</h3>
          <div className="mt-3 space-y-2">
            {schedules.length === 0 ? (
              <p className="text-xs text-ink-secondary">No schedules bound to this source yet.</p>
            ) : (
              schedules.map((schedule) => {
                const isScheduleBusy = busyScheduleId === schedule.schedule_id;
                return (
                  <div
                    key={schedule.schedule_id}
                    className="rounded-lg border border-outline bg-surface-elevated p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-foreground">{schedule.name}</p>
                        <p className="mt-0.5 font-mono text-xs text-ink-secondary">
                          {schedule.cron_expression}
                        </p>
                      </div>
                      <SourceStatusPill status={schedule.enabled ? "active" : "paused"} />
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-ink-secondary">
                      <span>Next: {formatWhen(schedule.next_run)}</span>
                      <span>Last: {formatWhen(schedule.last_run)}</span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        onClick={() => onScheduleAction(schedule.schedule_id, "toggle")}
                        disabled={isScheduleBusy || !canManageSources}
                        className="rounded-lg border border-outline bg-surface-muted px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-outline-strong disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {isScheduleBusy ? "Working…" : schedule.enabled ? "Pause" : "Enable"}
                      </button>
                      <button
                        onClick={() => onScheduleAction(schedule.schedule_id, "delete")}
                        disabled={isScheduleBusy || !canManageSources}
                        className="rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-1.5 text-xs font-medium text-[color:var(--status-danger)] transition hover:border-[color:var(--status-danger)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })
            )}

            {schedulable ? (
              <form
                className="rounded-lg border border-dashed border-outline bg-surface-elevated p-3"
                onSubmit={(event) => onCreateSchedule(event, source)}
              >
                <div className="grid gap-3 sm:grid-cols-2">
                  <TextField label="Name"
                      aria-label="Schedule name"
                      value={scheduleName}
                      onChange={(event) => onScheduleNameChange(event.target.value)}
                      placeholder="Nightly posture" />
                  <TextField label="Cron"
                      aria-label="Schedule cron"
                      value={scheduleCron}
                      onChange={(event) => onScheduleCronChange(event.target.value)}
                      placeholder="0 * * * *" />
                </div>
                <button
                  type="submit"
                  disabled={submittingSchedule || !canManageSources}
                  className="mt-3 inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <CalendarClock className="h-4 w-4" />
                  {submittingSchedule ? "Creating…" : "Create schedule"}
                </button>
              </form>
            ) : null}
          </div>
        </div>
      </div>
    </Drawer>
  );
}
