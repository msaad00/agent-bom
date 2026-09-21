import type { FindingReconfirmation as Attempt } from "@/lib/api-types";

type Observation = {
  observation_status?: "observed" | "unreconfirmed" | undefined;
  reconfirmation?: Attempt | undefined;
  unreconfirmed_occurrence_count?: number | undefined;
};

const reasons: Record<Attempt["reason_codes"][number], string> = {
  scan_partial: "Partial scan",
  scan_failed: "Failed scan",
  scan_not_executed: "Scan did not execute",
  scope_partial: "Partial scope",
  scope_permission_denied: "Collection permission denied",
  scope_unavailable: "Scope unavailable",
  scope_unsupported: "Scope unsupported",
  scope_skipped: "Scope skipped",
  scope_incomplete: "Incomplete scope",
  coverage_issue: "Collection coverage issue",
};

export function ReconfirmationBadge({ finding }: { finding: Observation }) {
  const count = finding.unreconfirmed_occurrence_count ?? 0;
  if (finding.observation_status !== "unreconfirmed" && count === 0) return null;
  return <span className="mt-1 inline-flex rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-800 dark:text-amber-200">
    {count > 0 ? `${count} unreconfirmed` : "Unreconfirmed"}
  </span>;
}

export function FindingReconfirmation({ finding }: { finding: Observation }) {
  const count = finding.unreconfirmed_occurrence_count ?? 0;
  const retained = finding.observation_status === "unreconfirmed";
  if (!retained && count === 0) return null;
  const attempt = retained ? finding.reconfirmation : undefined;
  const labels = (attempt?.reason_codes ?? []).map((code) => reasons[code]).filter(Boolean);
  return <div role="note" aria-label="Unreconfirmed collection evidence" className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-5 text-ink-secondary">
    <p className="font-semibold text-foreground">Current presence unconfirmed</p>
    <p>{count > 0 ? `${count} occurrence${count === 1 ? " retains" : "s retain"} earlier evidence after incomplete collection.` : "This finding retains earlier evidence after an incomplete collection."} Restore collection coverage and rescan the same scope.</p>
    {attempt?.scan_id ? <p className="mt-1 break-words">Latest attempt: <span className="font-mono">{attempt.scan_id}</span></p> : null}
    {attempt?.attempted_at ? <p className="break-words">Attempted at: <time dateTime={attempt.attempted_at}>{attempt.attempted_at}</time></p> : null}
    {labels.length ? <p>{labels.join(" · ")}</p> : null}
  </div>;
}
