"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Network,
  RefreshCw,
  ShieldCheck,
  Ticket,
} from "lucide-react";

import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { api } from "@/lib/api";
import { ApiConflictError } from "@/lib/api-errors";
import type {
  RiskCampaign,
  RiskCampaignState,
  RiskCampaignVerificationResult,
  RiskCampaignVerificationQueueEntry,
  TicketingConnection,
} from "@/lib/api-types";

const STATE_LABELS: Record<RiskCampaignState, string> = {
  open: "Open",
  in_progress: "In progress",
  blocked: "Blocked",
  done: "Done",
};

const VERIFICATION_LABELS: Record<RiskCampaign["verification_status"], string> = {
  unverified: "Unverified",
  pending: "Pending verification",
  verified: "Verified",
  failed: "Verification failed",
};

function formatDate(value: string | null): string {
  if (!value) return "No SLA assigned";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "SLA date unavailable";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  }).format(date);
}

function resultMessage(
  successful: number,
  failed: number,
  verb: "created" | "synced",
  processed: number,
  total: number,
): string {
  if (failed > 0) {
    return `${successful} ticket${successful === 1 ? "" : "s"} ${verb}; ${failed} failed · ${processed}/${total} processed`;
  }
  return `${successful} ticket${successful === 1 ? "" : "s"} ${verb} · ${processed}/${total} processed`;
}

function factorValue(
  factor: keyof RiskCampaign["score_factors"],
  value: RiskCampaign["score_factors"][keyof RiskCampaign["score_factors"]]["value"],
): string {
  if (value === null) return "Unknown";
  if (factor === "reachability" && typeof value === "boolean") {
    return value ? "Reachable" : "Not reachable";
  }
  if (factor === "crown_jewel" && typeof value === "boolean") {
    return value ? "Crown jewel" : "Not a crown jewel";
  }
  return String(value).replaceAll("_", " ");
}

function hasExpectedReductionBasis(campaign: RiskCampaign): boolean {
  const reduction = campaign.expected_risk_reduction;
  return (
    Number.isFinite(reduction.modeled_window_percent) &&
    Number.isFinite(reduction.modeled_risk_points) &&
    reduction.assumption.trim().length > 0 &&
    reduction.method.trim().length > 0 &&
    reduction.scope.trim().length > 0
  );
}

type TicketProgress = {
  mode: "create" | "sync";
  successful: number;
  failed: number;
  processed: number;
  total: number;
  nextCursor: string | null;
  hasMore: boolean;
};

const ACTION_BATCH_LIMIT = 25;

function CampaignCard({
  campaign,
  onChanged,
  connections,
  onReload,
}: {
  campaign: RiskCampaign;
  onChanged: (campaign: RiskCampaign) => void;
  connections: TicketingConnection[];
  onReload: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionMessage, setActionMessage] = useState("");
  const [actionError, setActionError] = useState("");
  const [connectionId, setConnectionId] = useState(connections[0]?.id ?? "");
  const [editingAssignment, setEditingAssignment] = useState(false);
  const [owner, setOwner] = useState(campaign.owner ?? "");
  const [slaDate, setSlaDate] = useState(campaign.sla_due_at?.slice(0, 10) ?? "");
  const [versionConflict, setVersionConflict] = useState(false);
  const [ticketProgress, setTicketProgress] = useState<TicketProgress | null>(null);
  const [verificationResult, setVerificationResult] = useState<RiskCampaignVerificationResult | null>(null);
  const workflowActionable = campaign.membership_complete && !campaign.membership_provisional;
  const reductionAvailable = hasExpectedReductionBasis(campaign);

  useEffect(() => {
    if (!connectionId || !connections.some((connection) => connection.id === connectionId)) {
      setConnectionId(connections[0]?.id ?? "");
    }
  }, [connectionId, connections]);

  const updateState = useCallback(
    async (state: RiskCampaignState) => {
      setBusy(true);
      setActionError("");
      setVersionConflict(false);
      try {
        onChanged(await api.updateRiskCampaign(campaign.id, { version: campaign.version, state }));
      } catch (error: unknown) {
        setVersionConflict(error instanceof ApiConflictError);
        setActionError(error instanceof Error ? error.message : "Campaign update failed");
      } finally {
        setBusy(false);
      }
    },
    [campaign.id, campaign.version, onChanged],
  );

  const ticketAction = useCallback(
    async (mode: "create" | "sync") => {
      if (mode === "create" && !connectionId) {
        setActionError("Connect an active ticketing integration before creating campaign tickets");
        return;
      }
      setBusy(true);
      setActionError("");
      setActionMessage("");
      try {
        const continuing = ticketProgress?.mode === mode && ticketProgress.hasMore;
        const cursor = continuing ? ticketProgress.nextCursor : null;
        const result =
          mode === "create"
            ? await api.createRiskCampaignTickets(campaign.id, {
                connection_id: connectionId,
                ...(cursor ? { cursor } : {}),
                limit: ACTION_BATCH_LIMIT,
              })
            : await api.syncRiskCampaignTickets(campaign.id, {
                ...(cursor ? { cursor } : {}),
                limit: ACTION_BATCH_LIMIT,
              });
        if (result.per_action_credential !== false) {
          setActionError("Ticket action rejected: connect-once credential boundary was not confirmed");
          return;
        }
        const batchSuccessful = "created" in result ? result.created : result.synced;
        const successful = (continuing ? ticketProgress.successful : 0) + batchSuccessful;
        const failed = (continuing ? ticketProgress.failed : 0) + result.failed;
        const processed = (continuing ? ticketProgress.processed : 0) + result.processed;
        const nextProgress: TicketProgress = {
          mode,
          successful,
          failed,
          processed,
          total: result.total,
          nextCursor: result.next_cursor,
          hasMore: result.has_more,
        };
        setTicketProgress(nextProgress);
        setActionMessage(resultMessage(successful, failed, mode === "create" ? "created" : "synced", processed, result.total));
      } catch (error: unknown) {
        setActionError(error instanceof Error ? error.message : "Ticket action failed");
      } finally {
        setBusy(false);
      }
    },
    [campaign.id, connectionId, ticketProgress],
  );

  const saveAssignment = useCallback(async () => {
    setBusy(true);
    setActionError("");
    setVersionConflict(false);
    try {
      const updated = await api.updateRiskCampaign(campaign.id, {
        version: campaign.version,
        owner: owner.trim() || null,
        sla_due_at: slaDate ? new Date(`${slaDate}T00:00:00.000Z`).toISOString() : null,
      });
      onChanged(updated);
      setEditingAssignment(false);
    } catch (error: unknown) {
      setVersionConflict(error instanceof ApiConflictError);
      setActionError(error instanceof Error ? error.message : "Campaign assignment failed");
    } finally {
      setBusy(false);
    }
  }, [campaign.id, campaign.version, onChanged, owner, slaDate]);

  const verifyRemediation = useCallback(async () => {
    setBusy(true);
    setActionError("");
    setActionMessage("");
    setVersionConflict(false);
    setVerificationResult(null);
    try {
      const result = await api.verifyRiskCampaign(campaign.id, { version: campaign.version });
      setVerificationResult(result);
      onChanged({
        ...campaign,
        state: result.state,
        verification_status: result.verification_status,
        version: result.version,
        updated_at: result.verified_at,
      });
    } catch (error: unknown) {
      setVersionConflict(error instanceof ApiConflictError);
      setActionError(error instanceof Error ? error.message : "Campaign verification failed");
    } finally {
      setBusy(false);
    }
  }, [campaign, onChanged]);

  const factors = Object.entries(campaign.score_factors) as Array<
    [keyof RiskCampaign["score_factors"], RiskCampaign["score_factors"][keyof RiskCampaign["score_factors"]]]
  >;

  return (
    <details className="group risk-campaign-card">
      <summary className="risk-campaign-summary">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="risk-campaign-severity">{campaign.severity}</span>
            <h3 className="risk-card-title">{campaign.title}</h3>
          </div>
          <p className="risk-card-meta">
            {campaign.finding_count} finding{campaign.finding_count === 1 ? "" : "s"} · {campaign.owner || "Unassigned"} · {formatDate(campaign.sla_due_at)} · {VERIFICATION_LABELS[campaign.verification_status]}
          </p>
        </div>
        <span className="risk-campaign-priority">
          Priority <strong className="ml-1 tabular-nums text-[color:var(--foreground)]">{campaign.priority_score}</strong>
        </span>
        <span
          className="risk-campaign-reduction"
          data-testid={`campaign-reduction-${campaign.id}`}
        >
          {reductionAvailable ? (
            <>
              <span className="block">{campaign.expected_risk_reduction.modeled_window_percent}% modeled window risk</span>
              {!campaign.expected_risk_reduction.portfolio_complete ? (
                <span className="block text-[9px] font-normal text-[color:var(--status-warn)]">Bounded; not full portfolio</span>
              ) : null}
            </>
          ) : (
            <>
              <span className="block">Expected reduction </span>
              <span className="block text-[9px] font-normal text-[color:var(--text-tertiary)]">Unavailable</span>
            </>
          )}
        </span>
        <ChevronDown className="h-4 w-4 text-[color:var(--text-tertiary)] transition group-open:rotate-180" aria-hidden="true" />
      </summary>
      <div className="risk-campaign-body">
        <button
          type="button"
          onClick={() => setExpanded((current) => !current)}
          className="risk-priority-toggle"
          aria-expanded={expanded}
        >
          Why this priority {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        </button>

      {expanded ? (
        <div className="risk-campaign-explainer">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <p className="risk-campaign-evidence-label">
              Observed priority evidence
            </p>
            {factors.map(([factor, evidence]) => (
              <div key={factor} className="risk-campaign-factor">
                <div className="risk-campaign-factor-label">{factor.replace("_", " ")}</div>
                <div className="risk-campaign-factor-value">
                  {factorValue(factor, evidence.value)}
                </div>
                <div className="risk-campaign-factor-status">{evidence.status}</div>
              </div>
            ))}
            <p className="risk-campaign-evidence-note">
              Unknown evidence is neutral and adds no priority boost.
            </p>
          </div>
          <div className="risk-campaign-method">
            <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
              {Object.entries(campaign.priority_score_components).map(([component, value]) => (
                <div key={component} className="risk-campaign-method-cell">
                  <div className="risk-campaign-method-label">{component.replaceAll("_", " ")}</div>
                  <div className="risk-number">{value}</div>
                </div>
              ))}
            </div>
            {reductionAvailable ? (
              <>
                <p>{campaign.expected_risk_reduction.assumption}</p>
                <p className="mt-1 text-[color:var(--text-tertiary)]">{campaign.expected_risk_reduction.method}</p>
                <p className="mt-1 text-[color:var(--text-tertiary)]">Scope: {campaign.expected_risk_reduction.scope}</p>
              </>
            ) : (
              <p className="text-[color:var(--text-tertiary)]">
                Expected reduction unavailable because the server did not supply its assumption, method, and scope.
              </p>
            )}
            <p className="mt-1 text-[color:var(--text-tertiary)]">Priority method: {campaign.priority_score_method}</p>
          </div>
        </div>
      ) : null}

      <div className="risk-campaign-actions">
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs text-[color:var(--text-tertiary)]" htmlFor={`campaign-state-${campaign.id}`}>Campaign state</label>
          <select
            id={`campaign-state-${campaign.id}`}
            aria-label="Campaign state"
            value={campaign.state}
            disabled={busy || !workflowActionable}
            onChange={(event) => void updateState(event.target.value as RiskCampaignState)}
            className="risk-campaign-select"
          >
            {Object.entries(STATE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <span className="risk-campaign-status-pill">
            {VERIFICATION_LABELS[campaign.verification_status]}
          </span>
          <button
            type="button"
            disabled={busy || !workflowActionable}
            onClick={() => void verifyRemediation()}
            className="risk-campaign-link-action"
          >
            <ShieldCheck className="h-3.5 w-3.5" /> Re-verify remediation
          </button>
          <button type="button" disabled={!workflowActionable} onClick={() => setEditingAssignment((current) => !current)} className="risk-link-button">
            Edit owner and SLA
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {connections.length > 1 ? (
            <select aria-label="Ticketing connection" value={connectionId} onChange={(event) => setConnectionId(event.target.value)} className="risk-campaign-select">
              {connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.display_name || connection.provider}</option>)}
            </select>
          ) : null}
          <button type="button" disabled={busy || !workflowActionable || !connectionId} onClick={() => void ticketAction("create")} className="risk-campaign-ticket-primary">
            <Ticket className="h-3.5 w-3.5" /> {ticketProgress?.mode === "create" && ticketProgress.hasMore ? `Continue tickets (${ticketProgress.processed}/${ticketProgress.total})` : "Create campaign tickets"}
          </button>
          <button type="button" disabled={busy || !workflowActionable} onClick={() => void ticketAction("sync")} className="risk-campaign-ticket-secondary">
            <RefreshCw className={`h-3.5 w-3.5 ${busy ? "animate-spin" : ""}`} /> {ticketProgress?.mode === "sync" && ticketProgress.hasMore ? `Continue sync (${ticketProgress.processed}/${ticketProgress.total})` : "Sync tickets"}
          </button>
        </div>
      </div>
      {!workflowActionable ? (
        <p role="status" className="risk-campaign-warning">
          Workflow actions are paused until the complete campaign membership is available. No partial ticket or verification state will be written.
        </p>
      ) : null}
      {editingAssignment ? (
        <div className="risk-campaign-assignment">
          <label className="text-xs text-[color:var(--text-secondary)]">
            Campaign owner
            <input aria-label="Campaign owner" value={owner} onChange={(event) => setOwner(event.target.value)} className="risk-campaign-input" />
          </label>
          <label className="text-xs text-[color:var(--text-secondary)]">
            Campaign SLA
            <input aria-label="Campaign SLA" type="date" value={slaDate} onChange={(event) => setSlaDate(event.target.value)} className="risk-campaign-input" />
          </label>
          <button type="button" disabled={busy} onClick={() => void saveAssignment()} className="risk-campaign-save">Save owner and SLA</button>
        </div>
      ) : null}
      {actionMessage ? <p role="status" className="risk-status-copy">{actionMessage}</p> : null}
      {verificationResult ? (
        <div role="status" className="risk-campaign-verification-result">
          <strong className="text-[color:var(--foreground)]">
            {verificationResult.remaining_count === 0
              ? "No original findings remain."
              : `${verificationResult.remaining_count} of ${verificationResult.original_member_count} original findings remain.`}
          </strong>{" "}
          Evidence: {verificationResult.evidence_scope.source.replaceAll("_", " ")}, complete {verificationResult.evidence_scope.finding_window_days}-day window.
        </div>
      ) : null}
      {actionError ? <p role="alert" className="risk-error-copy">{actionError}</p> : null}
      {versionConflict ? (
        <button type="button" onClick={onReload} className="risk-campaign-reload">Reload campaigns</button>
      ) : null}
      {connections.length === 0 ? <p className="risk-empty-copy"><Link href="/connections">Connect ticketing</Link> to create new campaign tickets. Existing ticket links can still be synced.</p> : null}
      </div>
    </details>
  );
}

function VerificationQueue() {
  const [entries, setEntries] = useState<RiskCampaignVerificationQueueEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [retryCursor, setRetryCursor] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, RiskCampaignVerificationResult>>({});
  const [successMessage, setSuccessMessage] = useState("");

  const load = useCallback(async (cursor: string | null = null) => {
    const continuing = cursor !== null;
    if (continuing) setLoadingMore(true);
    else setLoading(true);
    setError("");
    try {
      const response = await api.listRiskCampaignVerificationQueue({ cursor, limit: 25 });
      setEntries((current) => {
        if (!continuing) return response.entries;
        const byId = new Map(current.map((entry) => [entry.campaign_id, entry]));
        for (const entry of response.entries) byId.set(entry.campaign_id, entry);
        return Array.from(byId.values());
      });
      setNextCursor(response.next_cursor);
      setHasMore(response.has_more);
      setRetryCursor(null);
    } catch (loadError: unknown) {
      setError(loadError instanceof Error ? loadError.message : "Verification queue could not be loaded");
      setRetryCursor(cursor);
    } finally {
      if (continuing) setLoadingMore(false);
      else setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const verify = useCallback(async (entry: RiskCampaignVerificationQueueEntry) => {
    setBusyId(entry.campaign_id);
    setError("");
    setSuccessMessage("");
    try {
      const result = await api.verifyRiskCampaign(entry.campaign_id, { version: entry.version });
      if (result.verification_status === "verified") {
        setSuccessMessage(`${entry.title} verified: no original findings remain in the complete canonical evidence window.`);
        setEntries((current) => current.filter((item) => item.campaign_id !== entry.campaign_id));
        setResults((current) => {
          const next = { ...current };
          delete next[entry.campaign_id];
          return next;
        });
      } else {
        setEntries((current) => current.map((item) => item.campaign_id === entry.campaign_id
          ? {
              ...item,
              state: result.state,
              verification_status: "failed",
              version: result.version,
              updated_at: result.verified_at,
            }
          : item));
        setResults((current) => ({ ...current, [entry.campaign_id]: result }));
      }
    } catch (verifyError: unknown) {
      setError(verifyError instanceof Error ? verifyError.message : "Campaign verification failed");
    } finally {
      setBusyId(null);
    }
  }, []);

  return (
    <details
      className="group risk-campaign-queue"
      open={entries.length > 0 || Boolean(error)}
    >
      <summary className="risk-campaign-queue-summary">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="risk-campaign-queue-label">Re-verification</span>
          <h3 id="verification-queue-title" className="risk-entry-title">Awaiting re-verification</h3>
          <span className="risk-campaign-count-pill">{entries.length} waiting</span>
        </div>
        {error ? (
          <button type="button" onClick={() => void load(retryCursor)} className="risk-campaign-reload">Retry verification queue</button>
        ) : <span className="risk-collapsed-label">show</span>}
      </summary>
      <div className="risk-queue-body">
      <p className="risk-helper-copy">Inactive campaigns stay here until canonical evidence confirms the original findings are gone.</p>
      {loading ? <p role="status" className="risk-empty-copy">Loading verification queue…</p> : null}
      {error ? <p role="alert" className="risk-error-copy">{error}</p> : null}
      {successMessage ? <p role="status" className="mt-3 text-xs text-[color:var(--status-success)]">{successMessage}</p> : null}
      {!loading && entries.length === 0 && !error ? (
        <p className="risk-empty-copy">No inactive campaigns await re-verification.</p>
      ) : null}
      {!loading && entries.length > 0 ? (
        <div className="mt-3 grid gap-2 lg:grid-cols-2">
          {entries.map((entry) => {
            const result = results[entry.campaign_id];
            return (
              <article key={entry.campaign_id} className="risk-campaign-queue-entry">
                <div className="risk-entry-layout">
                  <div className="min-w-0">
                    <h4 className="risk-entry-title">{entry.title}</h4>
                    <p className="risk-entry-copy">
                      {entry.original_member_count} original findings · Owner: {entry.owner || "Unassigned"} · {formatDate(entry.sla_due_at)}
                    </p>
                    <p className="risk-entry-meta">{VERIFICATION_LABELS[entry.verification_status]} · inactive snapshot</p>
                  </div>
                  <button
                    type="button"
                    disabled={busyId === entry.campaign_id}
                    onClick={() => void verify(entry)}
                    aria-label={`Re-verify ${entry.title}`}
                    className="risk-campaign-verify-button"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" /> {busyId === entry.campaign_id ? "Verifying…" : "Re-verify"}
                  </button>
                </div>
                {result ? (
                  <p role="status" className="mt-2 text-xs text-[color:var(--status-warn)]">
                    {result.remaining_count} of {result.original_member_count} original findings remain · canonical findings spine, complete {result.evidence_scope.finding_window_days}-day window.
                  </p>
                ) : null}
              </article>
            );
          })}
        </div>
      ) : null}
      {!loading && !error && hasMore ? (
        <button
          type="button"
          disabled={loadingMore || nextCursor === null}
          onClick={() => void load(nextCursor)}
          className="risk-campaign-load-more"
        >
          {loadingMore ? "Loading more…" : "Load more awaiting verification"}
        </button>
      ) : null}
      </div>
    </details>
  );
}

export function RiskCampaignCommandCenter() {
  const [campaigns, setCampaigns] = useState<RiskCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [windowDays, setWindowDays] = useState(90);
  const [connections, setConnections] = useState<TicketingConnection[]>([]);
  const [totalFindings, setTotalFindings] = useState<number | null>(null);
  const [totalApproximate, setTotalApproximate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.listRiskCampaigns();
      setCampaigns(response.campaigns);
      setTruncated(response.truncated);
      setWindowDays(response.finding_window_days);
      setTotalFindings(response.total_findings);
      setTotalApproximate(response.total_approximate);
      try {
        const ticketing = await api.listTicketingConnections();
        setConnections(ticketing.connections.filter((connection) => connection.status === "active"));
      } catch {
        setConnections([]);
      }
    } catch (loadError: unknown) {
      setError(loadError instanceof Error ? loadError.message : "Campaigns could not be loaded");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const campaignFindingCount = useMemo(() => campaigns.reduce((sum, campaign) => sum + campaign.finding_count, 0), [campaigns]);
  const updateCampaign = useCallback((updated: RiskCampaign) => {
    setCampaigns((current) => current.map((campaign) => campaign.id === updated.id ? updated : campaign));
  }, []);

  return (
    <section aria-labelledby="risk-campaigns-title" className="space-y-4">
      {loading ? (
        <PageLoadingState title="Loading prioritized campaigns" detail="Reading server-authored risk priorities and workflow state." />
      ) : error ? (
        <PageErrorState title={error} detail="No campaign status has been inferred. Retry the authoritative API." action={{ label: "Retry campaigns", onClick: () => void load() }} />
      ) : campaigns.length === 0 ? (
        <PageEmptyState title="No prioritized campaigns yet" detail="No campaign was returned for the current 90-day findings window. This is not an all-clear result." icon={Network} actions={[{ label: "Run a scan", href: "/scan" }, { label: "Review findings", href: "/findings", variant: "secondary" }]} />
      ) : <div className="risk-campaign-header">
        <div>
          <div className="risk-campaign-kicker">Prioritized remediation</div>
          <h2 id="risk-campaigns-title" className="risk-page-title">Risk campaigns</h2>
          <p className="risk-page-copy">{campaigns.length} campaigns cluster {campaignFindingCount} finding{campaignFindingCount === 1 ? "" : "s"} into owner-ready work.</p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <Link href="/security-graph" className="risk-campaign-investigate">Open investigation</Link>
          <span className="risk-campaign-window">Last {windowDays} days</span>
        </div>
      </div>}
      {!loading && !error && campaigns.length > 0 && truncated ? (
        <div role="status" className="risk-campaign-truncated">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--status-warn)]" />
          <span>
            <strong className="text-[color:var(--foreground)]">Results may be incomplete.</strong>{" "}
            The bounded window covers {totalFindings === null ? "an unknown total" : `${totalApproximate ? "approximately " : ""}${totalFindings.toLocaleString()} total findings`}; narrow the scope before treating this as the full estate.
          </span>
        </div>
      ) : null}
      <VerificationQueue />
      {!loading && !error && campaigns.length > 0 ? (
        <>
          <div className="grid gap-1.5">
            {campaigns.map((campaign) => <CampaignCard key={campaign.id} campaign={campaign} onChanged={updateCampaign} connections={connections} onReload={() => void load()} />)}
          </div>
          <div className="risk-proof-note">
            <CheckCircle2 className="h-3.5 w-3.5" /> Priority is supplied by the server; modeled reduction appears only with its server-authored basis. Ticket actions use stored connections.
          </div>
        </>
      ) : null}
    </section>
  );
}
