"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Background, BaseEdge, Controls, EdgeLabelRenderer, ReactFlow, getBezierPath, type EdgeProps, type Node, type NodeProps, Handle, Position } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useSearchParams } from "next/navigation";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import { api, type JobListItem } from "@/lib/api";
import type { GraphAgentsResponse } from "@/lib/api-types";
import type { UnifiedEdge, UnifiedGraphData } from "@/lib/graph-schema";
import { lineageNodeTypes, type LineageNodeData, type LineageNodeType } from "@/components/lineage-nodes";
import { RelationshipBadge } from "@/components/relationship-edge";
import { entityIcon } from "@/lib/entity-icons";
import { contextRelationshipLabel } from "@/lib/context-graph";
import { GRAPH_LAYER_ENTITY_TYPES } from "@/lib/graph-entity-mapping";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS, NODE_COLOR_MAP } from "@/lib/graph-utils";
import { useAuthState } from "@/components/auth-provider";
import { useIncidentNeighborhood, type IncidentDirection } from "@/hooks/use-incident-neighborhood";

export function AdminAssessment({ attributes }: { attributes: Record<string, unknown> }) {
  const status = attributes.admin_equivalence_status;
  if (typeof status !== "string") return null;
  const labels: Record<string, string> = { admin: "Admin", conditional_admin: "Conditional admin", not_admin: "Not admin", unknown: "Unknown" };
  return <div className="mt-2 text-sm"><p>Admin assessment: <strong>{labels[status] ?? "Unknown"}</strong></p>
    <p className="text-xs text-ink-secondary">{status === "conditional_admin" ? "Broad admin permissions are conditional. The required request context has not been verified." : status === "not_admin" ? "Collected policies do not establish admin permissions." : status === "admin" ? "Collected identity policies grant admin permissions within their recorded resource scope. Other authorization controls may still apply." : "Available evidence does not establish an admin verdict."}</p>
    {attributes.escalates_to_admin === true ? <p className="text-xs">Can assume an admin role.</p> : attributes.escalates_to_conditional_admin === true && <p className="text-xs">Can assume a conditional admin role. Its conditions have not been verified.</p>}
    {Array.isArray(attributes.admin_equivalence_resource_scopes) && attributes.admin_equivalence_resource_scopes.length > 0 && <p className="break-all text-xs">Scope: {attributes.admin_equivalence_resource_scopes.filter((scope): scope is string => typeof scope === "string").join(", ")}</p>}
  </div>;
}

const recordedLabel = (relationship: string) => relationship === "uses" ? "Recorded connection" : contextRelationshipLabel(relationship);

/** Curved recorded edges; direction markers and labels retain their evidence meaning. */
function ContextRecordedEdge(props: EdgeProps) {
  const [path, x, y] = getBezierPath(props);
  return <><BaseEdge id={props.id} path={path} style={props.style}
    {...(props.markerStart ? { markerStart: props.markerStart } : {})}
    {...(props.markerEnd ? { markerEnd: props.markerEnd } : {})} />
    {props.label != null && <EdgeLabelRenderer><div className="nodrag nopan" style={{ position: "absolute", transform: `translate(-50%, -50%) translate(${x}px, ${y}px)`, pointerEvents: "none", fontSize: 12 }}>
      <RelationshipBadge relationship={String(props.data?.relationship ?? "")}>{props.label}</RelationshipBadge>
    </div></EdgeLabelRenderer>}</>;
}
const contextEdgeTypes = { smoothstep: ContextRecordedEdge };

function ContextOverviewNode({ data, selected, targetPosition, sourcePosition }: NodeProps<Node<LineageNodeData>>) {
  const Icon = entityIcon(data.nodeType);
  return <div className={`h-[72px] w-[180px] rounded-xl border bg-surface px-3 py-2 shadow-sm ${selected ? "ring-2 ring-[var(--foreground)] ring-offset-2 ring-offset-[var(--surface)]" : ""}`} style={{ borderColor: NODE_COLOR_MAP[data.nodeType] ?? "var(--border-strong)" }}>
    <Handle type="target" position={targetPosition ?? Position.Left} className="!h-1.5 !w-1.5" />
    <div className="flex items-start gap-2"><Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><span data-testid="context-overview-title" className="min-w-0 line-clamp-2 break-normal [overflow-wrap:anywhere] text-[16px] font-semibold leading-5" title={data.label}>{data.label}</span></div>
    <p className="mt-1 truncate text-[11px] text-ink-secondary">{data.entityType?.replaceAll("_", " ") ?? data.nodeType}</p>
    <Handle type="source" position={sourcePosition ?? Position.Right} className="!h-1.5 !w-1.5" />
  </div>;
}
const contextNodeTypes = { ...lineageNodeTypes, contextOverview: ContextOverviewNode };

const layers = Object.fromEntries(Object.keys(GRAPH_LAYER_ENTITY_TYPES).map(key => [key, true])) as Record<LineageNodeType, boolean>;
const stats = { total_nodes: 0, total_edges: 0, node_types: {}, severity_counts: {}, relationship_types: {}, attack_path_count: 0, interaction_risk_count: 0, max_attack_path_risk: 0, highest_interaction_risk: 0 };

/** Persisted canonical IDs only; never joins a legacy label to stored evidence. */
export function PersistedContextView() {
  const params = useSearchParams();
  const { session, loading } = useAuthState();
  if (loading || !session) return <p role="status" className="p-4">Resolving access to persisted evidence…</p>;
  const owner = JSON.stringify(session);
  return <OwnedContextView key={JSON.stringify([owner, params?.get("scan")])} owner={owner} />;
}

function OwnedContextView({ owner }: { owner: string }) {
  const params = useSearchParams();
  const [jobOffset, setJobOffset] = useState(0);
  const [jobTotal, setJobTotal] = useState(0);
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [jobId, setJobId] = useState("");
  const [snapshot, setSnapshot] = useState<{ jobId: string; scanId: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    api.listJobs({ status: "done", limit: 24, offset: jobOffset }, controller.signal).then(data => {
      if (!active) return;
      const done = data.jobs.filter(job => job.status === "done");
      setJobs(done);
      setJobTotal(data.total ?? done.length);
      setJobId(current => current || params?.get("scan") || done[0]?.job_id || "");
    }).catch(() => { if (active) setError("Unable to load completed scans."); });
    return () => { active = false; controller.abort(); };
  }, [owner, params, jobOffset]);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setSnapshot(null);
    if (!jobId) return;
    // Graph deep links carry a snapshot ID, not necessarily a scan-job ID.
    if (jobId === params?.get("scan")) { setSnapshot({ jobId, scanId: jobId }); return; }
    api.getScanStatus(jobId, controller.signal).then(job => {
      if (!active) return;
      if (job.status !== "done" || typeof job.graph_scan_id !== "string" || !job.graph_scan_id.trim()) { setError("Persisted snapshot identity unavailable for this completed scan."); return; }
      setSnapshot({ jobId, scanId: job.graph_scan_id });
      setError(null);
    }).catch(() => { if (active) setError("Unable to resolve this scan's persisted snapshot."); });
    return () => { active = false; controller.abort(); };
  }, [jobId, owner, params]);
  const scanId = snapshot?.jobId === jobId ? snapshot.scanId : "";
  return <section aria-label="Persisted Context neighborhood" className="min-w-0 space-y-2 p-3">
    <GraphLensSwitcher variant="compact" scanId={scanId || undefined} />
    <header className="flex flex-wrap items-center justify-between gap-2"><div><h1 className="text-lg font-semibold">Context Map</h1><p className="text-xs text-ink-secondary">Recorded connections · investigate one neighborhood at a time</p></div>
    <label className="block text-sm">Completed scan <select aria-label="Completed scan" className="context-action ml-2 max-w-full" value={jobId} onChange={event => setJobId(event.target.value)}>
      {!jobs.length && <option value="">No completed scans</option>}
      {jobId && !jobs.some(job => job.job_id === jobId) && <option value={jobId}>{jobId}</option>}
      {jobs.map(job => <option key={job.job_id} value={job.job_id}>{job.job_id}</option>)}
    </select></label>
    <div className="flex gap-2">{jobOffset > 0 && <button className="context-action" onClick={() => setJobOffset(offset => Math.max(0, offset - 24))}>Previous scans</button>}{jobOffset + 24 < jobTotal && <button className="context-action" onClick={() => setJobOffset(offset => offset + 24)}>Next scans</button>}</div></header>
    {error && <p role="alert">{error}</p>}
    {scanId ? <SnapshotNeighborhood key={JSON.stringify([owner, scanId])} scanId={scanId} owner={owner} /> : <p role="status">{jobId ? "Resolving snapshot…" : "Choose a completed scan to inspect persisted relationships."}</p>}
  </section>;
}

export function SnapshotNeighborhood({ scanId, owner, initialRootId = "" }: { scanId: string; owner: string; initialRootId?: string }) {
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const update = () => setMobile(media.matches);
    update(); media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState<string | undefined>();
  const [selector, setSelector] = useState<GraphAgentsResponse | null>(null);
  const [selectorBusy, setSelectorBusy] = useState(false);
  const [selectorError, setSelectorError] = useState<string | null>(null);
  const [rootId, setRootId] = useState(initialRootId);
  const [direction, setDirection] = useState<IncidentDirection>("both");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [expandedCanvas, setExpandedCanvas] = useState(false);
  const [loadedQuery, setLoadedQuery] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    setSelectorBusy(true);
    const timer = setTimeout(() => {
      api.listGraphAgents({ scanId, query, limit: 24, ...(cursor ? { cursor } : {}) }, controller.signal).then(data => {
        if (controller.signal.aborted) return;
        if (data.scan_id !== scanId) { setSelectorError("Agent selector returned another snapshot. Retry this scan."); return; }
        setSelector(data); setSelectorError(null);
        // Initial selection comes from a returned canonical ID, never a label.
        setRootId(current => current || data.agents[0]?.id || "");
      }).catch(() => { if (!controller.signal.aborted) setSelectorError("Unable to load persisted agents. Choose another scan or retry the search."); })
        .finally(() => { if (!controller.signal.aborted) setSelectorBusy(false); });
    }, query ? 250 : 0);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [scanId, query, cursor]);
  const graph = useIncidentNeighborhood(scanId, rootId, direction, owner);
  const focus = focusId && graph.nodes.some(node => node.id === focusId) ? focusId : rootId;
  // Bound presentation independently of the loaded evidence cache. Every node
  // enters with a real connecting edge; isolated cache rows are not invented.
  const display = useMemo(() => {
    const ids = new Set<string>([focus]);
    const edges: UnifiedEdge[] = [];
    for (let pass = 0; pass < 3; pass++) for (const edge of graph.edges) {
      if (focusId && edge.source !== focus && edge.target !== focus) continue;
      if (edges.includes(edge) || edges.length >= (expandedCanvas ? 36 : 12) || (!ids.has(edge.source) && !ids.has(edge.target))) continue;
      const newCount = Number(!ids.has(edge.source)) + Number(!ids.has(edge.target));
      if (ids.size + newCount > (expandedCanvas ? 24 : 8)) continue;
      ids.add(edge.source); ids.add(edge.target); edges.push(edge);
    }
    return { nodes: graph.nodes.filter(node => ids.has(node.id)), edges };
  }, [graph.nodes, graph.edges, focus, focusId, expandedCanvas]);
  const flow = useMemo(() => buildUnifiedFlowGraph({ scan_id: scanId, tenant_id: "", created_at: "", ...display, attack_paths: [], interaction_risks: [], stats } satisfies UnifiedGraphData,
    { layers, severity: null, agentName: null, vulnOnly: false, maxDepth: 3 }), [scanId, display]);
  const directedEdges = useMemo(() => flow.edges.map(item => {
    const recorded = display.edges.find(edge => edge.source === item.source && edge.target === item.target && edge.relationship === item.data?.relationship);
    const arrow = recorded?.direction === "directed" || recorded?.direction === "bidirectional" ? item.markerEnd : undefined;
    const active = selectedEdge === JSON.stringify([item.source, item.target, item.data?.relationship]) || (!selectedEdge && selectedId && (item.source === selectedId || item.target === selectedId));
    const directed = { ...item, style: { ...item.style, strokeWidth: active ? 2.5 : 1.5 } };
    delete directed.markerEnd;
    delete directed.markerStart;
    delete directed.label;
    if (focusId && (selectedEdge === JSON.stringify([item.source, item.target, item.data?.relationship]) || (selectedId && (item.source === selectedId || item.target === selectedId)))) directed.label = recordedLabel(String(item.data?.relationship ?? ""));
    if (arrow) directed.markerEnd = arrow;
    if (arrow && recorded?.direction === "bidirectional") directed.markerStart = arrow;
    return directed;
  }), [flow.edges, display.edges, selectedEdge, selectedId, focusId]);
  const overviewNodes = useMemo(() => flow.nodes.map(node => ({ ...node, selected: node.id === selectedId, ...(!focusId ? { type: "contextOverview" } : {}) })), [flow.nodes, focusId, selectedId]);
  const layout = useGraphLayout("dagre", overviewNodes, directedEdges, { dagre: focusId
    ? { direction: mobile ? "TB" : "LR", nodeWidth: 260, nodeHeight: 130, rankSep: mobile ? 64 : 128, nodeSep: 32, minSeparation: { width: 260, height: 130, gap: 32 } }
    : { direction: mobile ? "TB" : "LR", nodeWidth: 180, nodeHeight: 72, rankSep: 64, nodeSep: 16, minSeparation: { width: 180, height: 72, gap: 16 } } });
  const selected = graph.nodes.find(node => node.id === (selectedId || focus));
  const incident = graph.edges.filter(edge => edge.source === selected?.id || edge.target === selected?.id);
  const pages = graph.pages.filter(page => page.node_id === selected?.id);
  const lastPage = pages.at(-1);
  const edge = graph.edges.find(item => JSON.stringify([item.source, item.target, item.relationship]) === selectedEdge);
  const label = (id: string) => graph.nodes.find(node => node.id === id)?.label || id;
  return <>
    <div className="flex flex-wrap items-center gap-2" aria-label="Neighborhood toolbar">
      <label className="min-w-0 max-w-full text-sm">Agent <select aria-label="Agent scope" className="context-action max-w-full" value={rootId} disabled={selectorBusy} onChange={event => { setRootId(event.target.value); setSelectedId(null); setSelectedEdge(null); setFocusId(null); setExpandedCanvas(false); }}>
        {!selector?.agents.length && <option value={rootId}>{rootId || "No persisted agents"}</option>}
        {rootId && selector?.agents.length && !selector.agents.some(agent => agent.id === rootId) ? <option value={rootId}>{rootId}</option> : null}
        {selector?.agents.map(agent => <option key={agent.id} value={agent.id}>{agent.label} · {agent.id}</option>)}
      </select></label>
      {selector && <span className="text-xs text-ink-secondary">{selector.pagination.total.toLocaleString()} {query ? "matching" : "recorded"} agents · snapshot scope</span>}
      {selector?.pagination.next_cursor && <button className="context-action" disabled={selectorBusy} onClick={() => setCursor(selector.pagination.next_cursor || undefined)}>Next agents</button>}
      {cursor && <button className="context-action" onClick={() => setCursor(undefined)}>First agents</button>}
      <details className="relative"><summary className="context-action cursor-pointer">Search &amp; direction</summary><div className="mt-2 flex flex-wrap gap-2 rounded-lg border border-outline bg-surface p-3">
      <label className="min-w-0 text-sm">Agent search<input aria-label="Agent search" className="context-action mt-1 block w-full" value={query} onChange={event => { setQuery(event.target.value); setCursor(undefined); }} placeholder="Search recorded agent names or IDs" /></label>
      <label className="text-sm">Direction<select aria-label="Relationship direction" className="context-action ml-2" value={direction} onChange={event => { setDirection(event.target.value as IncidentDirection); setSelectedId(null); setSelectedEdge(null); setFocusId(null); setExpandedCanvas(false); }}><option value="both">Incoming + outgoing</option><option value="in">Incoming</option><option value="out">Outgoing</option></select></label>
      </div></details>
      {focusId && <button className="context-action" onClick={() => { setFocusId(null); setSelectedEdge(null); }}>Back to neighborhood</button>}
      <button className="context-action" disabled={graph.busy || !rootId} onClick={() => { setSelectedId(null); setSelectedEdge(null); setFocusId(null); graph.restart(); }}>Restart neighborhood</button>
      <button className="context-action" aria-pressed={expandedCanvas} onClick={() => setExpandedCanvas(value => !value)}>{expandedCanvas ? "Compact canvas" : "Expand canvas"}</button><span className="ml-2 text-xs text-ink-secondary">{expandedCanvas ? "Up to 24 entities / 36 relationships" : "Up to 8 entities / 12 relationships"} · loaded evidence only</span>
    </div>
    {selectorError && <p role="alert">{selectorError}</p>}
    {!selectorBusy && !selector?.agents.length && !selectorError && <p>No persisted agent nodes match this search. Repository and SBOM evidence remains available in Repository or Lineage.</p>}
    {graph.error && <p role="alert">{graph.error}</p>}
    <p role="status" className="text-sm text-ink-secondary">{graph.busy ? "Loading relationships… " : ""}{graph.nodes.length} loaded entities · {graph.edges.length} loaded relationships · total unknown. Canvas: {display.nodes.length} entities, {display.edges.length} relationships.</p>
    {graph.pages.some(page => page.completeness.missing_endpoint_count > 0) && <p>Some recorded endpoints are unavailable; this neighborhood is incomplete.</p>}
    {graph.capped && <p>Loaded evidence limit reached (240 relationships / 10 pages). Restart or choose another agent to continue.</p>}
    <div className="grid min-w-0 gap-3 lg:grid-cols-[minmax(0,1fr)_19rem]">
      <div aria-label="Persisted neighborhood canvas" className="relative h-[32rem] lg:h-[36rem] min-w-0 rounded-xl border border-outline bg-surface">
        {!!layout.nodes.length && <ReactFlow deleteKeyCode={null} key={JSON.stringify([focus, focusId, mobile, layout.nodes.map(node => node.id), layout.pending])} nodes={layout.nodes} edges={layout.edges} nodeTypes={contextNodeTypes} edgeTypes={contextEdgeTypes} fitView fitViewOptions={{ padding: 0.08, minZoom: focusId ? (mobile ? 0.75 : 0.85) : 0.75, maxZoom: 1 }} minZoom={0.15} nodesDraggable={false}
          onNodeClick={(_, node) => { setSelectedId(node.id); setSelectedEdge(null); }} onEdgeClick={(_, selected) => { setSelectedEdge(JSON.stringify([selected.source, selected.target, selected.data?.relationship])); }}>
          <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} /><Controls className={CONTROLS_CLASS} />
        </ReactFlow>}
      </div>
      <aside aria-label="Agent neighborhood inspector" className="max-h-[32rem] lg:max-h-[36rem] overflow-y-auto min-w-0 space-y-3 rounded-xl border border-outline bg-surface p-4">
        <h2 className="break-words text-lg font-semibold">{edge ? recordedLabel(String(edge.relationship)) : selected?.label || "Select an entity"}</h2>
        {edge ? <><p className="break-words">{label(edge.source)} {edge.direction === "bidirectional" ? "↔" : edge.direction === "directed" ? "→" : "—"} {label(edge.target)}</p><p>Recorded direction: {edge.direction}</p><p className="break-words">Evidence basis: {String(edge.evidence.evidence_tier ?? edge.evidence.evidence_basis ?? edge.evidence.basis ?? "unknown")}</p><p className="break-words">Runtime outcome: {String(edge.evidence.runtime_outcome ?? "unknown")}</p><button className="context-action" onClick={() => setSelectedEdge(null)}>Close inspection</button></> : selected ? <>
          <Link className="context-action inline-block" href={buildGraphInvestigationHref({ scanId, rootId: selected.id })}>Investigate reach &amp; permissions</Link>
          <details><summary className="cursor-pointer text-sm">Recorded identity</summary><p className="text-sm">{String(selected.entity_type).replaceAll("_", " ")}</p><code className="block break-all text-xs">{selected.id}</code><AdminAssessment attributes={selected.attributes} /></details>
          <div className="flex flex-wrap gap-2"><button className="context-action" onClick={() => setFocusId(selected.id)}>Focus here</button>
            {!lastPage && <button className="context-action" disabled={graph.busy || graph.capped || graph.stale} onClick={() => void graph.load(selected.id)}>Expand connections</button>}
            {lastPage?.next_cursor && <button className="context-action" disabled={graph.busy || graph.capped || graph.stale} onClick={() => void graph.load(selected.id, lastPage.next_cursor!)}>Load more relationships</button>}
            {!!pages.length && selected.id !== rootId && <button className="context-action" onClick={() => { graph.collapse(selected.id); setFocusId(null); }}>Collapse connections</button>}
          </div>
          {!!pages.length && selected.id !== rootId && <p className="text-xs">Collapse also clears later expansions.</p>}
          <p className="text-sm text-ink-secondary">{incident.length} loaded relationships for this entity. {lastPage && !lastPage.next_cursor ? "End of recorded pages in this direction; source collection coverage remains unknown." : "Additional relationships not counted."}</p>
          <LoadedRelationshipList key={selected.id} nodeId={selected.id} incident={incident} label={label} onSelect={setSelectedEdge} />
        </> : <p>Choose a persisted agent to begin.</p>}
        <details><summary className="cursor-pointer font-semibold">Loaded entities ({graph.nodes.length})</summary>
          <label className="block py-2 text-xs">Find loaded entity<input aria-label="Find loaded entity" className="context-action mt-1 w-full" value={loadedQuery} onChange={event => setLoadedQuery(event.target.value)} placeholder="Name or exact identifier" /></label>
          <div className="max-h-60 overflow-y-auto">{[...new Set(graph.nodes.map(node => String(node.entity_type)))].sort().map(kind => {
            const items = graph.nodes.filter(node => node.entity_type === kind && `${node.id} ${node.label}`.toLocaleLowerCase().includes(loadedQuery.toLocaleLowerCase().trim()));
            return items.length ? <section key={kind} aria-label={`Loaded ${kind}`} className="py-1"><h3 className="text-xs font-semibold capitalize text-ink-secondary">{kind.replaceAll("_", " ")} · {items.length} loaded</h3>{items.map(node => <button className="context-connection" key={node.id} onClick={() => { setSelectedId(node.id); setSelectedEdge(null); }}><span className="block break-words">{node.label}</span><code className="break-all text-xs">{node.id}</code></button>)}</section> : null;
          })}</div>
        </details>
        <details><summary className="cursor-pointer text-sm">Scope &amp; evidence limits</summary><p className="break-all text-xs">Snapshot: {scanId}</p><p className="mt-2 text-sm text-ink-secondary">Permission and exploitability are not assessed by these pages. Shared infrastructure does not prove agents communicated. Page completeness is not estate or collection completeness.</p></details>
      </aside>
    </div>
  </>;
}

/** Presentation paging only: these relationships are already loaded evidence. */
export function LoadedRelationshipList({ nodeId, incident, label, onSelect }: {
  nodeId: string; incident: UnifiedEdge[]; label: (id: string) => string; onSelect: (id: string) => void;
}) {
  const [visibleCount, setVisibleCount] = useState(24);
  const shown = Math.min(visibleCount, incident.length);
  return <div>
    <p className="mb-2 text-xs text-ink-secondary" role="status">Showing {shown} of {incident.length} loaded relationships</p>
    <div className="max-h-64 space-y-2 overflow-y-auto">{incident.slice(0, visibleCount).map(item =>
      <button key={JSON.stringify([item.source, item.target, item.relationship])} className="context-connection" onClick={() => onSelect(JSON.stringify([item.source, item.target, item.relationship]))}>
        <span className="block text-xs">{item.direction === "bidirectional" ? "Bidirectional ↔" : item.direction === "directed" ? (item.source === nodeId ? "Outgoing →" : "← Incoming") : "Related ·"} {recordedLabel(String(item.relationship))}</span>
        <span className="block break-words">{label(item.source === nodeId ? item.target : item.source)}</span>
      </button>)}</div>
    <div className="mt-2 flex flex-wrap gap-2">
      {shown < incident.length && <button className="context-action" onClick={() => setVisibleCount(count => count + 24)}>Show {Math.min(24, incident.length - shown)} more relationships</button>}
      {visibleCount > 24 && <button className="context-action" onClick={() => setVisibleCount(24)}>Show fewer relationships</button>}
    </div>
  </div>;
}
