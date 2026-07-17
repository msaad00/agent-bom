"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowRight, Loader2, RefreshCw, Ticket as TicketIcon } from "lucide-react";
import {
  api,
  RemediationItem,
  TicketingConnection,
  TicketLink,
} from "@/lib/api";

// ── Finding → ticket helpers (exported for the row + tests) ────────────────────

/**
 * Stable dedupe key for a remediation item, mirroring the backend's
 * `_finding_id` (vulnerability + package). Passed as `finding_id` so a repeat
 * request returns the same ticket and the row can match its existing ticket.
 */
export function findingKey(item: RemediationItem): string {
  const vuln = (item.vulnerabilities?.[0] ?? "").trim() || item.package;
  return `${vuln}:${item.package}`;
}

/** Non-secret finding dict the server turns into a ticket (TicketDraft.from_finding). */
export function buildFinding(item: RemediationItem): Record<string, unknown> {
  return {
    vulnerability_id: item.vulnerabilities?.[0] ?? "",
    package: item.package,
    severity: item.severity,
    risk_score: item.impact_score,
    fixed_version: item.fixed_version ?? "",
    affected_agents: item.affected_agents ?? [],
  };
}

/** Faithful preview of the summary the server will file (models.py from_finding). */
export function ticketPreviewTitle(item: RemediationItem): string {
  const vuln = (item.vulnerabilities?.[0] ?? "").trim() || "finding";
  const pkg = item.package ? ` in ${item.package}` : "";
  return `[agent-bom] ${vuln}${pkg} (risk ${item.impact_score.toFixed(1)}/10)`;
}

// ── Status chip (token-themed, light + dark) ───────────────────────────────────

const STATUS_META: Record<
  "open" | "in_progress" | "done" | "unknown",
  { label: string; className: string }
> = {
  open: {
    label: "Open",
    className:
      "border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]",
  },
  in_progress: {
    label: "In progress",
    className:
      "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
  },
  done: {
    label: "Done",
    className:
      "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
  },
  unknown: {
    label: "Unknown",
    className:
      "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-tertiary)]",
  },
};

export function TicketStatusChip({ status }: { status: string }) {
  const meta =
    STATUS_META[status as keyof typeof STATUS_META] ?? STATUS_META.unknown;
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${meta.className}`}
    >
      {meta.label}
    </span>
  );
}

function connectionLabel(c: TicketingConnection): string {
  return c.display_name || `${c.provider} (${c.transport})`;
}

// ── Modal ──────────────────────────────────────────────────────────────────────

export function TicketModal({
  item,
  existingTickets,
  onClose,
  onChanged,
}: {
  item: RemediationItem;
  existingTickets: TicketLink[];
  onClose: () => void;
  /** Called after a create/sync so the parent can refresh its ticket map. */
  onChanged?: (ticket: TicketLink) => void;
}) {
  const [connections, setConnections] = useState<TicketingConnection[] | null>(
    null,
  );
  const [connError, setConnError] = useState("");
  const [selectedConn, setSelectedConn] = useState("");
  const [project, setProject] = useState("");
  const [tickets, setTickets] = useState<TicketLink[]>(existingTickets);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const resp = await api.listTicketingConnections();
        if (!active) return;
        const activeConns = resp.connections.filter(
          (c) => c.status === "active",
        );
        setConnections(activeConns);
        const first = activeConns[0];
        if (first) {
          setSelectedConn(first.id);
          setProject(first.auth_params?.default_project ?? "");
        }
      } catch (e: unknown) {
        if (active)
          setConnError(
            e instanceof Error ? e.message : "Failed to load connections",
          );
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  // Keep the project default in sync with the selected connection.
  useEffect(() => {
    if (!connections) return;
    const conn = connections.find((c) => c.id === selectedConn);
    if (conn) setProject(conn.auth_params?.default_project ?? "");
  }, [selectedConn, connections]);

  const handleCreate = useCallback(async () => {
    setBusy(true);
    setActionError("");
    try {
      const result = await api.createTicket({
        connection_id: selectedConn,
        finding_id: findingKey(item),
        project: project.trim(),
        finding: buildFinding(item),
      });
      setTickets((prev) => {
        const rest = prev.filter((t) => t.id !== result.ticket.id);
        return [result.ticket, ...rest];
      });
      onChanged?.(result.ticket);
    } catch (e: unknown) {
      setActionError(e instanceof Error ? e.message : "Failed to create ticket");
    } finally {
      setBusy(false);
    }
  }, [selectedConn, project, item, onChanged]);

  const handleSync = useCallback(
    async (ticketId: string) => {
      setBusy(true);
      setActionError("");
      try {
        const result = await api.syncTicket(ticketId);
        setTickets((prev) =>
          prev.map((t) => (t.id === result.ticket.id ? result.ticket : t)),
        );
        onChanged?.(result.ticket);
      } catch (e: unknown) {
        setActionError(e instanceof Error ? e.message : "Failed to sync ticket");
      } finally {
        setBusy(false);
      }
    },
    [onChanged],
  );

  const loading = connections === null && !connError;
  const hasConnection = (connections?.length ?? 0) > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative w-full max-w-md overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] shadow-2xl">
        <div className="border-b border-[var(--border-subtle)] px-5 py-4">
          <h2 className="text-sm font-semibold text-[var(--foreground)]">
            Create a ticket
          </h2>
          <p className="mt-0.5 text-xs text-[var(--text-tertiary)]">
            {item.package} {item.current_version}
          </p>
        </div>

        <div className="space-y-4 px-5 py-5">
          {/* Existing tickets for this finding */}
          {tickets.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">
                Filed tickets
              </div>
              {tickets.map((t) => (
                <div
                  key={t.id}
                  className="flex items-center justify-between gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <TicketIcon className="h-3.5 w-3.5 flex-shrink-0 text-[var(--text-tertiary)]" />
                    {t.url ? (
                      <a
                        href={t.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="truncate font-mono text-xs text-[var(--accent)] hover:underline"
                      >
                        {t.key || t.external_id || "ticket"}
                      </a>
                    ) : (
                      <span className="truncate font-mono text-xs text-[var(--foreground)]">
                        {t.key || t.external_id || "ticket"}
                      </span>
                    )}
                    <TicketStatusChip status={t.status} />
                  </div>
                  <button
                    type="button"
                    onClick={() => handleSync(t.id)}
                    disabled={busy}
                    className="flex items-center gap-1 rounded px-1.5 py-1 text-xs text-[var(--text-secondary)] transition-colors hover:text-[var(--foreground)] disabled:opacity-50"
                    title="Sync status"
                    aria-label="Sync ticket status"
                  >
                    <RefreshCw
                      className={`h-3 w-3 ${busy ? "animate-spin" : ""}`}
                    />
                    Sync
                  </button>
                </div>
              ))}
            </div>
          )}

          {loading && (
            <div className="flex items-center justify-center py-6 text-[var(--text-secondary)]">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              <span className="text-xs">Loading connections…</span>
            </div>
          )}

          {connError && (
            <p className="text-xs text-[color:var(--status-danger)]">
              {connError}
            </p>
          )}

          {/* No active connection → guide to Connections, never a credential */}
          {!loading && !connError && !hasConnection && (
            <>
              <p className="text-sm leading-6 text-[var(--text-secondary)]">
                Ticketing is configured once in{" "}
                <span className="font-medium text-[var(--foreground)]">
                  Connections
                </span>
                . Connect your ITSM there — credentials are brokered and
                encrypted, never entered per action — then file tickets straight
                from this row.
              </p>
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:text-[var(--foreground)]"
                >
                  Close
                </button>
                <Link
                  href="/connections"
                  className="flex items-center gap-1.5 rounded-lg bg-[var(--accent-strong)] px-3 py-1.5 text-xs font-medium text-[color:var(--accent-contrast)] transition-colors hover:bg-[var(--accent)]"
                >
                  Open Connections
                  <ArrowRight className="h-3 w-3" />
                </Link>
              </div>
            </>
          )}

          {/* Active connection → compact create form (no credential fields) */}
          {!loading && !connError && hasConnection && (
            <div className="space-y-3">
              {connections!.length > 1 && (
                <label className="block">
                  <span className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">
                    Connection
                  </span>
                  <select
                    value={selectedConn}
                    onChange={(e) => setSelectedConn(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-[var(--border-subtle)] bg-[var(--background)] px-2.5 py-1.5 text-xs text-[var(--foreground)]"
                  >
                    {connections!.map((c) => (
                      <option key={c.id} value={c.id}>
                        {connectionLabel(c)}
                      </option>
                    ))}
                  </select>
                </label>
              )}

              <label className="block">
                <span className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">
                  Project
                </span>
                <input
                  type="text"
                  value={project}
                  onChange={(e) => setProject(e.target.value)}
                  placeholder="e.g. SEC"
                  className="mt-1 w-full rounded-lg border border-[var(--border-subtle)] bg-[var(--background)] px-2.5 py-1.5 font-mono text-xs text-[var(--foreground)]"
                />
              </label>

              <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2">
                <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">
                  Ticket preview
                </div>
                <p className="mt-1 break-words text-xs text-[var(--foreground)]">
                  {ticketPreviewTitle(item)}
                </p>
                <p className="mt-1 text-[11px] text-[var(--text-tertiary)]">
                  Severity {item.severity}
                  {item.fixed_version ? ` · fix ${item.fixed_version}` : ""}
                </p>
              </div>

              {actionError && (
                <p className="text-xs text-[color:var(--status-danger)]">
                  {actionError}
                </p>
              )}

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:text-[var(--foreground)]"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={handleCreate}
                  disabled={busy}
                  className="flex items-center gap-1.5 rounded-lg bg-[var(--accent-strong)] px-3 py-1.5 text-xs font-medium text-[color:var(--accent-contrast)] transition-colors hover:bg-[var(--accent)] disabled:opacity-50"
                >
                  {busy ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <TicketIcon className="h-3 w-3" />
                  )}
                  Create ticket
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
