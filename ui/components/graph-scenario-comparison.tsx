"use client";

import { useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, FlaskConical, Loader2 } from "lucide-react";

import { PermissionDeniedNotice } from "@/components/role-access";
import {
  api,
  ApiConflictError,
  type AuthMeResponse,
} from "@/lib/api";
import type {
  GraphScenario,
  GraphScenarioChange,
  GraphScenarioComparisonResponse,
} from "@/lib/api-types";
import {
  graphScenarioDifferenceGroups,
  type GraphScenarioViewState,
} from "@/lib/graph-scenario";
import { GRAPH_EDGE_KINDS, GRAPH_NODE_KINDS } from "@/lib/graph-schema";

type DraftChangeKind = GraphScenarioChange["kind"];

interface DraftChange {
  localId: number;
  kind: DraftChangeKind;
  nodeId: string;
  label: string;
  entityType: string;
  attributeKey: string;
  attributeValue: string;
  sourceId: string;
  targetId: string;
  relationship: string;
  original?: GraphScenarioChange | undefined;
}

function blankDraftChange(localId: number): DraftChange {
  return {
    localId,
    kind: "add_node",
    nodeId: "",
    label: "",
    entityType: "cloud_resource",
    attributeKey: "description",
    attributeValue: "",
    sourceId: "",
    targetId: "",
    relationship: "contains",
  };
}

const POSTURE_FIELDS = [
  "description",
  "environment",
  "owner",
  "provider",
  "region",
  "account_id",
  "repository",
  "fix_status",
  "disposition",
  "reachability",
] as const;

function graphScenarioChangeToDraft(
  change: GraphScenarioChange,
  localId: number,
): DraftChange {
  const draft = blankDraftChange(localId);
  if (change.kind === "add_node") {
    return {
      ...draft,
      kind: change.kind,
      nodeId: change.key,
      label: change.label,
      entityType: change.entity_type,
      original: change,
    };
  }
  if (change.kind === "remove_node") {
    return { ...draft, kind: change.kind, nodeId: change.node_id, original: change };
  }
  if (change.kind === "patch_node") {
    const entry = Object.entries(change.patch.attributes ?? {})[0];
    return {
      ...draft,
      kind: change.kind,
      nodeId: change.node_id,
      attributeKey: entry?.[0] ?? "description",
      attributeValue: entry ? String(entry[1]) : "",
      original: change,
    };
  }
  return {
    ...draft,
    kind: change.kind,
    sourceId: change.source,
    targetId: change.target,
    relationship: change.relationship,
    original: change,
  };
}

function draftChangeToApi(
  draft: DraftChange,
  index: number,
): GraphScenarioChange {
  if (draft.kind === "add_node") {
    return {
      kind: "add_node",
      key: draft.nodeId.trim() || `node-${index + 1}`,
      entity_type: draft.entityType.trim(),
      label: draft.label.trim() || draft.nodeId.trim(),
      presentation: {},
    };
  }
  if (draft.kind === "remove_node") {
    return { kind: "remove_node", node_id: draft.nodeId.trim() };
  }
  if (draft.kind === "patch_node") {
    return {
      kind: "patch_node",
      node_id: draft.nodeId.trim(),
      patch: {
        attributes: {
          [draft.attributeKey.trim()]: draft.attributeValue.trim(),
        },
      },
    };
  }
  if (draft.kind === "add_edge") {
    return {
      kind: "add_edge",
      source: draft.sourceId.trim(),
      target: draft.targetId.trim(),
      relationship: draft.relationship.trim(),
      direction: "directed",
      weight: 1,
      traversable: true,
      confidence: 1,
    };
  }
  return {
    kind: "remove_edge",
    source: draft.sourceId.trim(),
    target: draft.targetId.trim(),
    relationship: draft.relationship.trim(),
  };
}

function changeIsComplete(change: DraftChange): boolean {
  if (change.kind === "add_node") {
    return Boolean(change.nodeId.trim() && change.entityType.trim());
  }
  if (change.kind === "remove_node") return Boolean(change.nodeId.trim());
  if (change.kind === "patch_node") {
    return Boolean(change.nodeId.trim() && change.attributeKey.trim());
  }
  if (change.kind === "add_edge") {
    return Boolean(
      change.sourceId.trim() &&
        change.targetId.trim() &&
        change.relationship.trim(),
    );
  }
  return Boolean(
    change.sourceId.trim() &&
      change.targetId.trim() &&
      change.relationship.trim(),
  );
}

export function GraphScenarioSelector({
  scenarios,
  selectedId,
  loading,
  onSelect,
}: {
  scenarios: GraphScenario[];
  selectedId: string;
  loading: boolean;
  onSelect: (scenarioId: string) => void;
}) {
  return (
    <label className="sr-only">
      Architecture scenario
      <select
        aria-label="Architecture scenario"
        value={selectedId}
        disabled={loading}
        onChange={(event) => onSelect(event.target.value)}
        className="graph-page-select not-sr-only"
      >
        <option value="">Observed estate</option>
        {scenarios.map((scenario) => (
          <option key={scenario.scenario_id} value={scenario.scenario_id}>
            Scenario · {scenario.name}
          </option>
        ))}
      </select>
    </label>
  );
}

export function GraphScenarioAuthoring({
  scanId,
  scenario,
  session,
  canWrite,
  onSaved,
}: {
  scanId: string;
  scenario: GraphScenario | null;
  session: AuthMeResponse | null;
  canWrite: boolean;
  onSaved: (scenario: GraphScenario) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [assumptions, setAssumptions] = useState("");
  const [changes, setChanges] = useState<DraftChange[]>([blankDraftChange(1)]);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    setName(scenario?.name ?? "");
    setDescription(scenario?.description ?? "");
    setAssumptions((scenario?.assumptions ?? []).join("\n"));
    setChanges(
      scenario?.changes.length
        ? scenario.changes.map(graphScenarioChangeToDraft)
        : [blankDraftChange(1)],
    );
    setSaveError(null);
  }, [scenario]);

  if (!canWrite) {
    return (
      <PermissionDeniedNotice
        session={session}
        needed="analyst"
        action="design and save an architecture scenario"
        className="mt-3"
      />
    );
  }

  const updateChange = (localId: number, patch: Partial<DraftChange>) => {
    setChanges((current) =>
      current.map((change) =>
        change.localId === localId
          ? { ...change, ...patch, original: undefined }
          : change,
      ),
    );
  };
  const complete =
    Boolean(scanId && name.trim()) &&
    changes.length > 0 &&
    changes.every(changeIsComplete);

  const save = async () => {
    if (!complete) return;
    setSaving(true);
    setSaveError(null);
    const nextChanges = changes.map(
      (change, index) => change.original ?? draftChangeToApi(change, index),
    );
    const payload = {
      name: name.trim(),
      description: description.trim(),
      assumptions: assumptions
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean),
      changes: nextChanges,
    };
    try {
      const response = scenario
        ? await api.updateGraphScenario(scenario.scenario_id, {
            ...payload,
            expected_revision: scenario.revision,
          })
        : await api.createGraphScenario({ ...payload, base_scan_id: scanId });
      onSaved(response.scenario);
      setChanges([blankDraftChange(1)]);
    } catch (failure) {
      setSaveError(
        failure instanceof ApiConflictError
          ? "This scenario changed after it was opened. Refresh it before saving again."
          : "The scenario could not be saved. Review the typed changes and try again.",
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <details className="mt-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--background)]/60 group">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2.5 text-xs font-medium text-[var(--foreground)] [&::-webkit-details-marker]:hidden">
        <span>{scenario ? "Add a proposed change" : "Design a proposed scenario"}</span>
        <span className="text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)] group-open:hidden">expand</span>
        <span className="hidden text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)] group-open:inline">collapse</span>
      </summary>
      <div className="space-y-3 border-t border-[var(--border-subtle)] p-3">
        <div className="grid gap-2 md:grid-cols-2">
          <label className="text-xs text-[var(--text-secondary)]">
            Name
            <input aria-label="Scenario name" value={name} onChange={(event) => setName(event.target.value)} className="graph-page-search mt-1 w-full" />
          </label>
          <label className="text-xs text-[var(--text-secondary)]">
            Description
            <input aria-label="Scenario description" value={description} onChange={(event) => setDescription(event.target.value)} className="graph-page-search mt-1 w-full" />
          </label>
        </div>
        <label className="block text-xs text-[var(--text-secondary)]">
          Assumptions · one per line
          <textarea aria-label="Scenario assumptions" value={assumptions} onChange={(event) => setAssumptions(event.target.value)} rows={2} className="graph-page-search mt-1 w-full resize-y" />
        </label>
        <div className="space-y-2">
          {changes.map((change, index) => (
            <div key={change.localId} className="rounded-xl border border-[var(--border-subtle)] p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">Change {index + 1}</span>
                <select aria-label={`Change ${index + 1} type`} value={change.kind} onChange={(event) => updateChange(change.localId, { kind: event.target.value as DraftChangeKind })} className="graph-page-select">
                  <option value="add_node">Add asset</option>
                  <option value="remove_node">Remove asset</option>
                  <option value="patch_node">Change posture attribute</option>
                  <option value="add_edge">Add relationship</option>
                  <option value="remove_edge">Remove relationship</option>
                </select>
                {changes.length > 1 && (
                  <button type="button" className="graph-page-action ml-auto" onClick={() => setChanges((current) => current.filter((item) => item.localId !== change.localId))}>Remove change</button>
                )}
              </div>
              <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                {(change.kind === "add_node" || change.kind === "remove_node" || change.kind === "patch_node") && (
                  <input aria-label={`Change ${index + 1} node id`} placeholder={change.kind === "add_node" ? "Proposal key" : "Observed node ID"} value={change.nodeId} onChange={(event) => updateChange(change.localId, { nodeId: event.target.value })} className="graph-page-search" />
                )}
                {change.kind === "add_node" && (
                  <>
                    <input aria-label={`Change ${index + 1} node label`} placeholder="Display label" value={change.label} onChange={(event) => updateChange(change.localId, { label: event.target.value })} className="graph-page-search" />
                    <select aria-label={`Change ${index + 1} entity type`} value={change.entityType} onChange={(event) => updateChange(change.localId, { entityType: event.target.value })} className="graph-page-select">
                      {GRAPH_NODE_KINDS.map((kind) => <option key={kind} value={kind}>{kind.replaceAll("_", " ")}</option>)}
                    </select>
                  </>
                )}
                {change.kind === "patch_node" && (
                  <>
                    <select aria-label={`Change ${index + 1} attribute`} value={change.attributeKey} onChange={(event) => updateChange(change.localId, { attributeKey: event.target.value })} className="graph-page-select">
                      {POSTURE_FIELDS.map((field) => <option key={field} value={field}>{field.replaceAll("_", " ")}</option>)}
                    </select>
                    <input aria-label={`Change ${index + 1} attribute value`} placeholder="Proposed value" value={change.attributeValue} onChange={(event) => updateChange(change.localId, { attributeValue: event.target.value })} className="graph-page-search" />
                  </>
                )}
                {(change.kind === "add_edge" || change.kind === "remove_edge") && (
                  <>
                    <input aria-label={`Change ${index + 1} source id`} placeholder="Source node ID" value={change.sourceId} onChange={(event) => updateChange(change.localId, { sourceId: event.target.value })} className="graph-page-search" />
                    <input aria-label={`Change ${index + 1} target id`} placeholder="Target node ID" value={change.targetId} onChange={(event) => updateChange(change.localId, { targetId: event.target.value })} className="graph-page-search" />
                    <select aria-label={`Change ${index + 1} relationship`} value={change.relationship} onChange={(event) => updateChange(change.localId, { relationship: event.target.value })} className="graph-page-select">
                      {GRAPH_EDGE_KINDS.map((kind) => <option key={kind} value={kind}>{kind.replaceAll("_", " ")}</option>)}
                    </select>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="graph-page-action" onClick={() => setChanges((current) => [...current, blankDraftChange(Math.max(0, ...current.map((item) => item.localId)) + 1)])}>Add typed change</button>
          <button type="button" disabled={!complete || saving} className="graph-page-action disabled:cursor-not-allowed disabled:opacity-50" onClick={() => void save()}>{saving ? "Saving…" : scenario ? "Save new revision" : "Create scenario"}</button>
          <span className="text-[10px] text-[var(--text-tertiary)]">Pinned to {scenario?.base_scan_id.slice(0, 12) ?? scanId.slice(0, 12)} · proposed, never live evidence</span>
        </div>
        {saveError && <div role="alert" className="graph-callout-amber">{saveError}</div>}
      </div>
    </details>
  );
}

function tabClass(active: boolean, disabled: boolean): string {
  return [
    "rounded-lg border px-3 py-1.5 text-xs font-medium transition",
    active
      ? "border-sky-400/50 bg-sky-500/15 text-sky-100"
      : "border-[var(--border-subtle)] bg-[var(--background)]/70 text-[var(--text-secondary)]",
    disabled ? "cursor-not-allowed opacity-45" : "hover:border-sky-400/40",
  ].join(" ");
}

export function GraphScenarioComparisonPanel({
  scenario,
  comparison,
  state,
  loading,
  error,
  attackPathLens,
  baseSnapshotAvailable,
  onStateChange,
  onSwitchBase,
  authoring,
}: {
  scenario: GraphScenario | null;
  comparison: GraphScenarioComparisonResponse | null;
  state: GraphScenarioViewState;
  loading: boolean;
  error: string | null;
  attackPathLens: boolean;
  baseSnapshotAvailable: boolean;
  onStateChange: (state: GraphScenarioViewState) => void;
  onSwitchBase: () => void;
  authoring?: ReactNode;
}) {
  if (!scenario) {
    return authoring ? (
      <section aria-label="Architecture scenarios" className="mt-3">
        {authoring}
      </section>
    ) : null;
  }
  const baseMismatch = comparison?.available === false ||
    comparison?.current.scan_id !== scenario.base_scan_id;
  const modeledDisabled = attackPathLens || loading || Boolean(error) || baseMismatch;
  const proposedVisible = state === "proposed" || state === "difference";
  const differenceGroups = comparison
    ? graphScenarioDifferenceGroups(comparison.difference)
    : [];

  return (
    <section
      aria-label="Scenario comparison"
      data-testid="graph-scenario-comparison"
      className="mt-3 overflow-hidden rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)]/75"
    >
      <div className="flex flex-col gap-3 border-b border-[var(--border-subtle)] px-3 py-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-violet-300">
            Architecture scenario · revision {scenario.revision}
          </p>
          <p className="mt-1 truncate text-sm font-medium text-[var(--foreground)]">
            {scenario.name}
          </p>
          <p className="mt-0.5 text-xs text-[var(--text-tertiary)]">
            Pinned to observed snapshot {scenario.base_scan_id.slice(0, 12)}
            {comparison?.stale || comparison?.base_status === "stale"
              ? " · retained historical base"
              : ""}
          </p>
        </div>
        <div role="tablist" aria-label="Scenario state" className="flex flex-wrap gap-2">
          {(["current", "proposed", "difference"] as const).map((next) => {
            const disabled = next !== "current" && modeledDisabled;
            return (
              <button
                key={next}
                type="button"
                role="tab"
                aria-selected={state === next}
                disabled={disabled}
                className={tabClass(state === next, disabled)}
                onClick={() => onStateChange(next)}
              >
                {next[0]!.toUpperCase() + next.slice(1)}
              </button>
            );
          })}
        </div>
      </div>

      <div className="p-3">
        {loading ? (
          <div className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Loading server-authored comparison…
          </div>
        ) : error ? (
          <div className="graph-callout-amber">{error}</div>
        ) : attackPathLens ? (
          <div className="graph-callout-sky">
            Attack Paths remains observed-only. Proposed changes can touch an
            observed path, but cannot create detected evidence before a scan.
          </div>
        ) : baseMismatch ? (
          <div className="graph-callout-amber flex flex-wrap items-center justify-between gap-3">
            <span>
              <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5" />
              {comparison?.unavailable_reason ||
                "This scenario is pinned to a different observed snapshot."}
            </span>
            <button
              type="button"
              disabled={!baseSnapshotAvailable}
              onClick={onSwitchBase}
              className="graph-page-action disabled:cursor-not-allowed disabled:opacity-50"
            >
              {baseSnapshotAvailable ? "Switch to base snapshot" : "Base snapshot unavailable"}
            </button>
          </div>
        ) : comparison ? (
          <>
            {proposedVisible && (
              <div
                role="status"
                className="mb-3 flex items-start gap-2 rounded-xl border border-violet-400/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-100"
              >
                <FlaskConical className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  <strong>Proposed scenario — not observed or deployed.</strong>{" "}
                  Modeled changes use the server-authored overlay and the same
                  lens filters as the current estate.
                </span>
              </div>
            )}
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="rounded-xl border border-emerald-400/20 bg-emerald-500/5 p-3">
                <p className="text-[10px] uppercase tracking-[0.18em] text-emerald-300">
                  Current · observed
                </p>
                <p className="mt-1 text-sm text-[var(--foreground)]">
                  {comparison.current.node_count.toLocaleString()} nodes ·{" "}
                  {comparison.current.edge_count.toLocaleString()} relationships
                </p>
              </div>
              <div className="rounded-xl border border-violet-400/20 bg-violet-500/5 p-3">
                <p className="text-[10px] uppercase tracking-[0.18em] text-violet-300">
                  Proposed · modeled
                </p>
                <p className="mt-1 text-sm text-[var(--foreground)]">
                  {comparison.proposed.node_count.toLocaleString()} nodes ·{" "}
                  {comparison.proposed.edge_count.toLocaleString()} relationships
                </p>
              </div>
            </div>
            {state === "difference" && (
              <div className="mt-3 space-y-3" data-testid="graph-scenario-difference">
                <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
                  {differenceGroups.map((group) => (
                    <div key={group.id} className="rounded-xl border border-[var(--border-subtle)] p-2.5">
                      <p className="text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
                        {group.label}
                      </p>
                      <p className="mt-1 text-lg font-semibold text-[var(--foreground)]">
                        {group.items.length}
                      </p>
                      {group.items.length > 0 && (
                        <p className="mt-1 truncate text-[10px] text-[var(--text-tertiary)]" title={group.items.join(", ")}>
                          {group.items.slice(0, 3).join(", ")}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
                <div className="rounded-xl border border-sky-400/20 bg-sky-500/5 p-3 text-xs text-[var(--text-secondary)]">
                  <span className="font-medium text-sky-200">
                    {comparison.difference.touched_observed_path_count} touched observed paths
                  </span>
                  {comparison.difference.touched_observed_path_ids.length > 0 && (
                    <span className="ml-2 break-all text-[var(--text-tertiary)]">
                      {comparison.difference.touched_observed_path_ids.join(", ")}
                    </span>
                  )}
                </div>
              </div>
            )}
          </>
        ) : null}
        {authoring}
      </div>
    </section>
  );
}
