"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Boxes, CheckCircle2, GitBranch, Plus, RefreshCcw, Send, XCircle } from "lucide-react";

import {
  api,
  type BlueprintDetailResponse,
  type BlueprintRecord,
  type BlueprintVersion,
} from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { ErrorBanner } from "@/components/empty-state";
import { PageEmptyState } from "@/components/states/page-state";
import { PageLaneHeader } from "@/components/page-lane";
import { Drawer } from "@/components/drawer";
import { Collapsible } from "@/components/collapsible";

function statusTone(status: string): string {
  switch (status) {
    case "approved":
      return "border-emerald-900/60 bg-emerald-950/30 text-emerald-300";
    case "pending":
      return "border-amber-900/60 bg-amber-950/30 text-amber-300";
    case "rejected":
      return "border-red-900/60 bg-red-950/30 text-red-300";
    default:
      return "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]";
  }
}

function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-medium capitalize ${statusTone(status)}`}
    >
      {status}
    </span>
  );
}

const COMPOSITION_AXES: Array<{ key: keyof BlueprintVersion["composition"]; label: string }> = [
  { key: "agents", label: "Agents" },
  { key: "models", label: "Models" },
  { key: "tools", label: "Tools" },
  { key: "datasets", label: "Datasets" },
  { key: "identities", label: "Identities" },
  { key: "owners", label: "Owners" },
  { key: "guardrails", label: "Guardrails" },
];

export default function BlueprintsPage() {
  const { hasCapability, session } = useAuthState();
  const authRequired = Boolean(session?.auth_required);
  // Authoring (create / seed / submit) is a contributor action; approving or
  // rejecting is an admin action. When auth is disabled everything is allowed.
  const canAuthor = !authRequired || hasCapability("scan.run");
  const canApprove = !authRequired || hasCapability("policy.manage");

  const [blueprints, setBlueprints] = useState<BlueprintRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [detail, setDetail] = useState<BlueprintDetailResponse | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listBlueprints(100, 0);
      setBlueprints(result.blueprints);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load blueprints.");
      setBlueprints([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const loadDetail = useCallback(async (blueprintId: string) => {
    setDetailError(null);
    setDetail(null);
    try {
      setDetail(await api.getBlueprint(blueprintId));
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : "Failed to load blueprint detail.");
    }
  }, []);

  useEffect(() => {
    if (detailId) void loadDetail(detailId);
  }, [detailId, loadDetail]);

  const seed = useCallback(async () => {
    setBusy(true);
    try {
      await api.seedBlueprints();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to seed blueprints.");
    } finally {
      setBusy(false);
    }
  }, [refresh]);

  const runVersionAction = useCallback(
    async (action: "submit" | "approve" | "reject", blueprintId: string, version: number) => {
      setBusy(true);
      try {
        if (action === "submit") await api.submitBlueprintVersion(blueprintId, version);
        else if (action === "approve") await api.approveBlueprintVersion(blueprintId, version);
        else await api.rejectBlueprintVersion(blueprintId, version);
        await Promise.all([refresh(), loadDetail(blueprintId)]);
      } catch (err) {
        setDetailError(err instanceof Error ? err.message : `Failed to ${action} version.`);
      } finally {
        setBusy(false);
      }
    },
    [refresh, loadDetail],
  );

  const approvedCount = useMemo(
    () => blueprints.filter((b) => b.approval_status === "approved").length,
    [blueprints],
  );
  const pendingCount = useMemo(
    () => blueprints.filter((b) => b.approval_status === "pending").length,
    [blueprints],
  );

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="governance"
        title="Blueprints"
        subtitle="Persisted, versioned AI-system blueprints — the approved agents, models, tools, datasets, identities, owners, and guardrails that compose each system, with an accountable approval workflow."
        actions={
          <>
            <button
              onClick={() => void refresh()}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <RefreshCcw className="h-4 w-4" />
              Refresh
            </button>
            <button
              onClick={() => void seed()}
              disabled={!canAuthor || busy}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
              Seed from role archetypes
            </button>
          </>
        }
        banner={
          <div className="grid gap-3 sm:grid-cols-3">
            <StatTile label="Blueprints" value={loading ? "…" : blueprints.length} />
            <StatTile label="Approved" value={loading ? "…" : approvedCount} />
            <StatTile label="Pending approval" value={loading ? "…" : pendingCount} />
          </div>
        }
      />

      {error ? (
        <ErrorBanner message={error} onRetry={() => void refresh()} />
      ) : loading ? (
        <div className="space-y-2" aria-busy="true">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-14 animate-pulse rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]"
            />
          ))}
        </div>
      ) : blueprints.length === 0 ? (
        <PageEmptyState
          icon={Boxes}
          title="No AI-system blueprints yet"
          detail="Seed the canonical role archetypes into stored, versioned blueprints, then edit and route new versions through approval. Each blueprint is a durable, queryable object the graph and drift evaluation reference by id."
          command={'curl -X POST $AGENT_BOM_URL/v1/governance/blueprints/seed -H "X-Api-Key: $KEY"'}
          actions={[{ label: "Seed from role archetypes", onClick: () => void seed() }]}
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[color:var(--border-subtle)]">
          <table className="w-full min-w-[720px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[11px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
                <th className="px-4 py-3 font-medium">Blueprint</th>
                <th className="px-4 py-3 font-medium">Owner</th>
                <th className="px-4 py-3 font-medium">Current / latest version</th>
                <th className="px-4 py-3 font-medium">Approval</th>
              </tr>
            </thead>
            <tbody>
              {blueprints.map((bp) => (
                <tr
                  key={bp.blueprint_id}
                  onClick={() => setDetailId(bp.blueprint_id)}
                  className="cursor-pointer border-b border-[color:var(--border-subtle)] transition hover:bg-[color:var(--surface-elevated)]"
                  data-testid={`blueprint-row-${bp.blueprint_id}`}
                >
                  <td className="px-4 py-3">
                    <div className="font-medium text-[color:var(--foreground)]">{bp.name}</div>
                    {bp.seeded_from ? (
                      <div className="text-[11px] text-[color:var(--text-tertiary)]">seeded from {bp.seeded_from}</div>
                    ) : null}
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-secondary)]">{bp.owner || "—"}</td>
                  <td className="px-4 py-3 text-[color:var(--text-secondary)]">
                    <span className="inline-flex items-center gap-1">
                      <GitBranch className="h-3.5 w-3.5" />v{bp.current_version || "—"} / v{bp.latest_version}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={bp.approval_status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <BlueprintDrawer
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        detail={detail}
        error={detailError}
        busy={busy}
        canAuthor={canAuthor}
        canApprove={canApprove}
        onAction={runVersionAction}
      />
    </div>
  );
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-4 py-3">
      <div className="text-[11px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-[color:var(--foreground)]">{value}</div>
    </div>
  );
}

function BlueprintDrawer({
  open,
  onClose,
  detail,
  error,
  busy,
  canAuthor,
  canApprove,
  onAction,
}: {
  open: boolean;
  onClose: () => void;
  detail: BlueprintDetailResponse | null;
  error: string | null;
  busy: boolean;
  canAuthor: boolean;
  canApprove: boolean;
  onAction: (action: "submit" | "approve" | "reject", blueprintId: string, version: number) => void;
}) {
  const blueprint = detail?.blueprint ?? null;
  return (
    <Drawer
      open={open}
      onClose={onClose}
      eyebrow="AI-system blueprint"
      title={blueprint?.name ?? "Blueprint"}
      subtitle={blueprint ? `Owner ${blueprint.owner || "—"} · ${blueprint.blueprint_id}` : undefined}
      headerAside={blueprint ? <StatusPill status={blueprint.approval_status} /> : undefined}
    >
      {error ? (
        <div className="rounded-lg border border-red-900/60 bg-red-950/30 px-3 py-2 text-sm text-red-300">{error}</div>
      ) : null}
      {!detail ? (
        <div className="text-sm text-[color:var(--text-secondary)]">Loading blueprint…</div>
      ) : (
        <div className="space-y-4">
          {blueprint?.description ? (
            <p className="text-sm text-[color:var(--text-secondary)]">{blueprint.description}</p>
          ) : null}
          <div className="space-y-3">
            {detail.versions.map((version) => (
              <Collapsible
                key={version.version_id}
                defaultOpen={version.version === detail.blueprint.latest_version}
                title={
                  <span className="flex items-center gap-2">
                    Version {version.version}
                    <StatusPill status={version.status} />
                  </span>
                }
                subtitle={
                  version.approver
                    ? `${version.status} by ${version.approver}${version.decided_at ? ` · ${version.decided_at.slice(0, 10)}` : ""}`
                    : `created by ${version.created_by || "—"}`
                }
              >
                <div className="space-y-3">
                  <div className="grid gap-2 sm:grid-cols-2">
                    {COMPOSITION_AXES.map(({ key, label }) => {
                      const items = version.composition[key];
                      return (
                        <div key={key}>
                          <div className="text-[11px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
                            {label}
                          </div>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {items.length === 0 ? (
                              <span className="text-xs text-[color:var(--text-tertiary)]">—</span>
                            ) : (
                              items.map((item) => (
                                <span
                                  key={item}
                                  className="inline-flex rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 text-[11px] text-[color:var(--text-secondary)]"
                                >
                                  {item}
                                </span>
                              ))
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {version.decision_note ? (
                    <div className="text-xs text-[color:var(--text-secondary)]">Note: {version.decision_note}</div>
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    {version.status === "draft" ? (
                      <button
                        onClick={() => onAction("submit", version.blueprint_id, version.version)}
                        disabled={!canAuthor || busy}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <Send className="h-3.5 w-3.5" />
                        Submit for approval
                      </button>
                    ) : null}
                    {version.status === "pending" ? (
                      <>
                        <button
                          onClick={() => onAction("approve", version.blueprint_id, version.version)}
                          disabled={!canApprove || busy}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          Approve
                        </button>
                        <button
                          onClick={() => onAction("reject", version.blueprint_id, version.version)}
                          disabled={!canApprove || busy}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-red-900/60 bg-red-950/30 px-3 py-1.5 text-xs text-red-300 transition hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <XCircle className="h-3.5 w-3.5" />
                          Reject
                        </button>
                      </>
                    ) : null}
                  </div>
                  {version.status === "pending" && !canApprove ? (
                    <div className="text-[11px] text-[color:var(--text-tertiary)]">
                      Approval requires an admin (governance) role.
                    </div>
                  ) : null}
                </div>
              </Collapsible>
            ))}
          </div>
        </div>
      )}
    </Drawer>
  );
}
