"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock3,
  Network,
  RefreshCw,
  ShieldCheck,
  Ticket,
} from "lucide-react";

import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { api } from "@/lib/api";
import type {
  RiskCampaign,
  RiskCampaignState,
  RiskCampaignTicketCreateResult,
  RiskCampaignTicketSyncResult,
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
  result: RiskCampaignTicketCreateResult | RiskCampaignTicketSyncResult,
  verb: "created" | "synced",
): string {
  const successful = "created" in result ? result.created : result.synced;
  if (result.failed > 0) {
    return `${successful} ticket${successful === 1 ? "" : "s"} ${verb}; ${result.failed} failed`;
  }
  return `${successful} ticket${successful === 1 ? "" : "s"} ${verb}`;
}

function CampaignCard({
  campaign,
  onChanged,
  connections,
}: {
  campaign: RiskCampaign;
  onChanged: (campaign: RiskCampaign) => void;
  connections: TicketingConnection[];
}) {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionMessage, setActionMessage] = useState("");
  const [actionError, setActionError] = useState("");
  const [connectionId, setConnectionId] = useState(connections[0]?.id ?? "");
  const [editingAssignment, setEditingAssignment] = useState(false);
  const [owner, setOwner] = useState(campaign.owner ?? "");
  const [slaDate, setSlaDate] = useState(campaign.sla_due_at?.slice(0, 10) ?? "");

  useEffect(() => {
    if (!connectionId || !connections.some((connection) => connection.id === connectionId)) {
      setConnectionId(connections[0]?.id ?? "");
    }
  }, [connectionId, connections]);

  const updateState = useCallback(
    async (state: RiskCampaignState) => {
      setBusy(true);
      setActionError("");
      try {
        onChanged(await api.updateRiskCampaign(campaign.id, { state }));
      } catch (error: unknown) {
        setActionError(error instanceof Error ? error.message : "Campaign update failed");
      } finally {
        setBusy(false);
      }
    },
    [campaign.id, onChanged],
  );

  const ticketAction = useCallback(
    async (mode: "create" | "sync") => {
      if (!connectionId) {
        setActionError("Connect an active ticketing integration before creating campaign tickets");
        return;
      }
      setBusy(true);
      setActionError("");
      setActionMessage("");
      try {
        const result =
          mode === "create"
            ? await api.createRiskCampaignTickets(campaign.id, { connection_id: connectionId })
            : await api.syncRiskCampaignTickets(campaign.id);
        if (result.per_action_credential !== false) {
          setActionError("Ticket action rejected: connect-once credential boundary was not confirmed");
          return;
        }
        setActionMessage(resultMessage(result, mode === "create" ? "created" : "synced"));
      } catch (error: unknown) {
        setActionError(error instanceof Error ? error.message : "Ticket action failed");
      } finally {
        setBusy(false);
      }
    },
    [campaign.id, connectionId],
  );

  const saveAssignment = useCallback(async () => {
    setBusy(true);
    setActionError("");
    try {
      const updated = await api.updateRiskCampaign(campaign.id, {
        owner: owner.trim() || null,
        sla_due_at: slaDate ? new Date(`${slaDate}T00:00:00.000Z`).toISOString() : null,
      });
      onChanged(updated);
      setEditingAssignment(false);
    } catch (error: unknown) {
      setActionError(error instanceof Error ? error.message : "Campaign assignment failed");
    } finally {
      setBusy(false);
    }
  }, [campaign.id, onChanged, owner, slaDate]);

  const factors = Object.entries(campaign.score_factors) as Array<
    [keyof RiskCampaign["score_factors"], RiskCampaign["score_factors"][keyof RiskCampaign["score_factors"]]]
  >;

  return (
    <article className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 shadow-sm md:p-5">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--status-danger)]">
              {campaign.severity}
            </span>
            <span className="text-xs text-[color:var(--text-tertiary)]">
              {campaign.finding_count} correlated finding{campaign.finding_count === 1 ? "" : "s"}
            </span>
            <span className="text-xs text-[color:var(--text-tertiary)]">Source: {campaign.source}</span>
          </div>
          <h3 className="mt-2 text-base font-semibold leading-6 text-[color:var(--foreground)] md:text-lg">
            {campaign.title}
          </h3>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[color:var(--text-secondary)]">
            <span><strong className="text-[color:var(--foreground)]">Owner:</strong> {campaign.owner || "Unassigned"}</span>
            <span className="inline-flex items-center gap-1"><Clock3 className="h-3.5 w-3.5" />{formatDate(campaign.sla_due_at)}</span>
            <span className="inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" />{VERIFICATION_LABELS[campaign.verification_status]}</span>
          </div>
        </div>

        <div className="grid shrink-0 grid-cols-2 gap-2 sm:min-w-[19rem]">
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
            <div className="text-[10px] font-medium uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Priority</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-[color:var(--foreground)]">{campaign.priority_score}</div>
            <button
              type="button"
              onClick={() => setExpanded((current) => !current)}
              className="mt-1 inline-flex items-center gap-1 text-xs font-medium text-[color:var(--accent)]"
              aria-expanded={expanded}
            >
              Why this priority {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
          </div>
          <div className="rounded-xl border border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] p-3">
            <div className="text-[10px] font-medium uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Expected reduction</div>
            <div className="mt-1 text-lg font-semibold tabular-nums text-[color:var(--status-success)]">
              {campaign.expected_risk_reduction.modeled_window_percent}% modeled window risk
            </div>
            <div className="text-[10px] text-[color:var(--text-tertiary)]">{campaign.expected_risk_reduction.modeled_risk_points} modeled points</div>
            {!campaign.expected_risk_reduction.portfolio_complete ? (
              <div className="mt-1 text-[10px] text-[color:var(--status-warn)]">Bounded window; not full portfolio</div>
            ) : null}
          </div>
        </div>
      </div>

      {expanded ? (
        <div className="mt-4 grid gap-3 border-t border-[color:var(--border-subtle)] pt-4 lg:grid-cols-[1fr_1.3fr]">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <p className="col-span-2 text-[10px] uppercase tracking-wide text-[color:var(--text-tertiary)] sm:col-span-4">
              Context evidence — not priority-score weights
            </p>
            {factors.map(([factor, evidence]) => (
              <div key={factor} className="rounded-lg bg-[color:var(--surface-muted)] p-2.5">
                <div className="text-[10px] uppercase tracking-wide text-[color:var(--text-tertiary)]">{factor.replace("_", " ")}</div>
                <div className="mt-1 text-sm font-semibold tabular-nums text-[color:var(--foreground)]">
                  {evidence.value === null
                    ? "Unknown"
                    : typeof evidence.value === "boolean"
                      ? evidence.value ? "Reachable" : "Not reachable"
                      : String(evidence.value).replaceAll("_", " ")}
                </div>
                <div className="mt-0.5 text-[10px] uppercase tracking-wide text-[color:var(--text-tertiary)]">{evidence.status}</div>
              </div>
            ))}
          </div>
          <div className="rounded-lg border border-[color:var(--border-subtle)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
            <p>{campaign.expected_risk_reduction.assumption}</p>
            <p className="mt-1 text-[color:var(--text-tertiary)]">{campaign.expected_risk_reduction.method}</p>
            <p className="mt-1 text-[color:var(--text-tertiary)]">Scope: {campaign.expected_risk_reduction.scope}</p>
            <p className="mt-1 text-[color:var(--text-tertiary)]">Priority method: {campaign.priority_score_method}</p>
          </div>
        </div>
      ) : null}

      <div className="mt-4 flex flex-col gap-3 border-t border-[color:var(--border-subtle)] pt-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs text-[color:var(--text-tertiary)]" htmlFor={`campaign-state-${campaign.id}`}>Campaign state</label>
          <select
            id={`campaign-state-${campaign.id}`}
            aria-label="Campaign state"
            value={campaign.state}
            disabled={busy}
            onChange={(event) => void updateState(event.target.value as RiskCampaignState)}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--background)] px-2.5 py-1.5 text-xs text-[color:var(--foreground)]"
          >
            {Object.entries(STATE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <span className="rounded-full border border-[color:var(--border-subtle)] px-2 py-1 text-[10px] font-medium uppercase tracking-wide text-[color:var(--text-secondary)]">
            {VERIFICATION_LABELS[campaign.verification_status]}
          </span>
          <button type="button" onClick={() => setEditingAssignment((current) => !current)} className="text-xs font-medium text-[color:var(--accent)]">
            Edit owner and SLA
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {connections.length > 1 ? (
            <select aria-label="Ticketing connection" value={connectionId} onChange={(event) => setConnectionId(event.target.value)} className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--background)] px-2.5 py-1.5 text-xs text-[color:var(--foreground)]">
              {connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.display_name || connection.provider}</option>)}
            </select>
          ) : null}
          <button type="button" disabled={busy} onClick={() => void ticketAction("create")} className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-xs font-medium text-[color:var(--accent)] disabled:opacity-50">
            <Ticket className="h-3.5 w-3.5" /> Create campaign tickets
          </button>
          <button type="button" disabled={busy} onClick={() => void ticketAction("sync")} className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs font-medium text-[color:var(--text-secondary)] disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${busy ? "animate-spin" : ""}`} /> Sync tickets
          </button>
        </div>
      </div>
      {editingAssignment ? (
        <div className="mt-3 grid gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3 sm:grid-cols-[1fr_12rem_auto] sm:items-end">
          <label className="text-xs text-[color:var(--text-secondary)]">
            Campaign owner
            <input aria-label="Campaign owner" value={owner} onChange={(event) => setOwner(event.target.value)} className="mt-1 block w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--background)] px-2.5 py-2 text-xs text-[color:var(--foreground)]" />
          </label>
          <label className="text-xs text-[color:var(--text-secondary)]">
            Campaign SLA
            <input aria-label="Campaign SLA" type="date" value={slaDate} onChange={(event) => setSlaDate(event.target.value)} className="mt-1 block w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--background)] px-2.5 py-2 text-xs text-[color:var(--foreground)]" />
          </label>
          <button type="button" disabled={busy} onClick={() => void saveAssignment()} className="rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-xs font-medium text-[color:var(--accent)] disabled:opacity-50">Save owner and SLA</button>
        </div>
      ) : null}
      {actionMessage ? <p role="status" className="mt-3 text-xs text-[color:var(--text-secondary)]">{actionMessage}</p> : null}
      {actionError ? <p role="alert" className="mt-3 text-xs text-[color:var(--status-danger)]">{actionError}</p> : null}
      {connections.length === 0 ? <p className="mt-3 text-xs text-[color:var(--text-tertiary)]"><Link href="/connections">Connect ticketing</Link> to create or sync campaign tickets.</p> : null}
    </article>
  );
}

export function RiskCampaignCommandCenter() {
  const [campaigns, setCampaigns] = useState<RiskCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [windowDays, setWindowDays] = useState(90);
  const [connections, setConnections] = useState<TicketingConnection[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.listRiskCampaigns();
      setCampaigns(response.campaigns);
      setTruncated(response.truncated);
      setWindowDays(response.finding_window_days);
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

  const totalFindings = useMemo(() => campaigns.reduce((sum, campaign) => sum + campaign.finding_count, 0), [campaigns]);
  const updateCampaign = useCallback((updated: RiskCampaign) => {
    setCampaigns((current) => current.map((campaign) => campaign.id === updated.id ? updated : campaign));
  }, []);

  if (loading) return <PageLoadingState title="Loading prioritized campaigns" detail="Reading server-authored risk priorities and workflow state." />;
  if (error) return <PageErrorState title={error} detail="No campaign status has been inferred. Retry the authoritative API." action={{ label: "Retry campaigns", onClick: () => void load() }} />;
  if (campaigns.length === 0) return <PageEmptyState title="No prioritized campaigns yet" detail="No campaign was returned for the current 90-day findings window. This is not an all-clear result." icon={Network} actions={[{ label: "Run a scan", href: "/scan" }, { label: "Review findings", href: "/findings", variant: "secondary" }]} />;

  return (
    <section aria-labelledby="risk-campaigns-title" className="space-y-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-[0.18em] text-[color:var(--accent)]">Prioritized remediation</div>
          <h2 id="risk-campaigns-title" className="mt-1 text-xl font-semibold tracking-tight text-[color:var(--foreground)]">Risk campaigns</h2>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">{campaigns.length} campaigns cluster {totalFindings} finding{totalFindings === 1 ? "" : "s"} into owner-ready work.</p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <Link href="/security-graph" className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-[color:var(--text-secondary)]">Open investigation</Link>
          <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[color:var(--text-tertiary)]">Last {windowDays} days</span>
        </div>
      </div>
      {truncated ? (
        <div role="status" className="flex items-start gap-2 rounded-xl border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] px-3 py-2.5 text-xs text-[color:var(--text-secondary)]">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--status-warn)]" />
          <span><strong className="text-[color:var(--foreground)]">Results may be incomplete.</strong> The server reached its findings limit; narrow the scope before treating this as the full estate.</span>
        </div>
      ) : null}
      <div className="grid gap-4 2xl:grid-cols-2">
        {campaigns.map((campaign) => <CampaignCard key={campaign.id} campaign={campaign} onChanged={updateCampaign} connections={connections} />)}
      </div>
      <div className="flex items-center gap-2 text-xs text-[color:var(--text-tertiary)]">
        <CheckCircle2 className="h-3.5 w-3.5" /> Priority and expected reduction are supplied by the server; ticket actions use stored connections.
      </div>
    </section>
  );
}
