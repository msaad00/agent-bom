"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Background, Controls, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useSearchParams } from "next/navigation";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import { api, type JobListItem } from "@/lib/api";
import type { GraphAgentsResponse } from "@/lib/api-types";
import type { UnifiedEdge, UnifiedGraphData } from "@/lib/graph-schema";
import { lineageNodeTypes, type LineageNodeType } from "@/components/lineage-nodes";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { contextRelationshipLabel } from "@/lib/context-graph";
import { GRAPH_LAYER_ENTITY_TYPES } from "@/lib/graph-entity-mapping";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS } from "@/lib/graph-utils";
import { useAuthState } from "@/components/auth-provider";
import { useIncidentNeighborhood, type IncidentDirection } from "@/hooks/use-incident-neighborhood";

const recordedLabel = (relationship: string) => relationship === "uses" ? "Recorded connection" : contextRelationshipLabel(relationship);

const layers = Object.fromEntries(Object.keys(GRAPH_LAYER_ENTITY_TYPES).map(key => [key, true])) as Record<LineageNodeType, boolean>;
const stats = { total_nodes: 0, total_edges: 0, node_types: {}, severity_counts: {}, relationship_types: {}, attack_path_count: 0, interaction_risk_count: 0, max_attack_path_risk: 0, highest_interaction_risk: 0 };

/** Persisted canonical IDs only; never joins a legacy label to stored evidence. */
export function PersistedContextView() {
  const { session, loading } = useAuthState();
  if (loading || !session) return <p role="status" className="p-4">Resolving access to persisted evidence…</p>;
  const owner = JSON.stringify(session);
  return <OwnedContextView key={owner} owner={owner} />;
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
      setJobId((jobOffset === 0 ? params?.get("scan") : null) || done[0]?.job_id || "");
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
    api.getScan(jobId, controller.signal).then(job => {
      if (!active) return;
      if (!job.result || job.status !== "done") { setError("Completed scan evidence unavailable."); return; }
      setSnapshot({ jobId, scanId: job.result.scan_id || job.job_id });
      setError(null);
    }).catch(() => { if (active) setError("Unable to resolve this scan's persisted snapshot."); });
    return () => { active = false; controller.abort(); };
  }, [jobId, owner, params]);
  const scanId = snapshot?.jobId === jobId ? snapshot.scanId : "";
  return <section aria-label="Persisted Context neighborhood" className="min-w-0 space-y-3 p-3 md:p-5">
    <GraphLensSwitcher variant="compact" />
    <header><h1 className="text-xl font-semibold">Context Map</h1><p className="mt-1 text-sm text-[var(--text-secondary)]">Explore recorded connections from a persisted snapshot. Relationships do not establish permission, successful execution, or exploitability.</p></header>
    <label className="block text-sm">Completed scan <select aria-label="Completed scan" className="context-action ml-2 max-w-full" value={jobId} onChange={event => setJobId(event.target.value)}>
      {!jobs.length && <option value="">No completed scans</option>}
      {jobId && !jobs.some(job => job.job_id === jobId) && <option value={jobId}>{jobId}</option>}
      {jobs.map(job => <option key={job.job_id} value={job.job_id}>{job.job_id}</option>)}
    </select></label>
    <div className="flex gap-2">{jobOffset > 0 && <button className="context-action" onClick={() => setJobOffset(offset => Math.max(0, offset - 24))}>Previous scans</button>}{jobOffset + 24 < jobTotal && <button className="context-action" onClick={() => setJobOffset(offset => offset + 24)}>Next scans</button>}</div>
    {error && <p role="alert">{error}</p>}
    {scanId ? <SnapshotNeighborhood key={JSON.stringify([owner, scanId])} scanId={scanId} owner={owner} /> : <p role="status">{jobId ? "Resolving snapshot…" : "Choose a completed scan to inspect persisted relationships."}</p>}
  </section>;
}

function SnapshotNeighborhood({ scanId, owner }: { scanId: string; owner: string }) {
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
  const [rootId, setRootId] = useState("");
  const [direction, setDirection] = useState<IncidentDirection>("both");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [expandedCanvas, setExpandedCanvas] = useState(false);
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
      if (edges.includes(edge) || edges.length >= (expandedCanvas ? 36 : 12) || (!ids.has(edge.source) && !ids.has(edge.target))) continue;
      const newCount = Number(!ids.has(edge.source)) + Number(!ids.has(edge.target));
      if (ids.size + newCount > (expandedCanvas ? 24 : 8)) continue;
      ids.add(edge.source); ids.add(edge.target); edges.push(edge);
    }
    return { nodes: graph.nodes.filter(node => ids.has(node.id)), edges };
  }, [graph.nodes, graph.edges, focus, expandedCanvas]);
  const flow = useMemo(() => buildUnifiedFlowGraph({ scan_id: scanId, tenant_id: "", created_at: "", ...display, attack_paths: [], interaction_risks: [], stats } satisfies UnifiedGraphData,
    { layers, severity: null, agentName: null, vulnOnly: false, maxDepth: 3 }), [scanId, display]);
  const directedEdges = useMemo(() => flow.edges.map(item => {
    const recorded = display.edges.find(edge => edge.source === item.source && edge.target === item.target && edge.relationship === item.data?.relationship);
    const arrow = recorded?.direction === "directed" || recorded?.direction === "bidirectional" ? item.markerEnd : undefined;
    const directed = { ...item };
    delete directed.markerEnd;
    delete directed.markerStart;
    if (selectedEdge === JSON.stringify([item.source, item.target, item.data?.relationship]) || item.source === (selectedId || focus) || item.target === (selectedId || focus)) directed.label = recordedLabel(String(item.data?.relationship ?? ""));
    if (arrow) directed.markerEnd = arrow;
    if (arrow && recorded?.direction === "bidirectional") directed.markerStart = arrow;
    return directed;
  }), [flow.edges, display.edges, selectedEdge, selectedId, focus]);
  const layout = useGraphLayout("dagre", flow.nodes, directedEdges, { dagre: { direction: mobile ? "TB" : "LR", nodeWidth: 260, nodeHeight: 130, rankSep: 64, nodeSep: 32, minSeparation: { width: 260, height: 130, gap: 32 } } });
  const selected = graph.nodes.find(node => node.id === (selectedId || focus));
  const incident = graph.edges.filter(edge => edge.source === selected?.id || edge.target === selected?.id);
  const pages = graph.pages.filter(page => page.node_id === selected?.id);
  const lastPage = pages.at(-1);
  const edge = graph.edges.find(item => JSON.stringify([item.source, item.target, item.relationship]) === selectedEdge);
  const label = (id: string) => graph.nodes.find(node => node.id === id)?.label || id;
  return <>
    <p className="break-all text-xs text-[var(--text-tertiary)]">Snapshot: {scanId}</p>
    <div className="flex flex-wrap items-end gap-3">
      <label className="min-w-0 text-sm">Agent search<input aria-label="Agent search" className="context-action mt-1 block w-full" value={query} onChange={event => { setQuery(event.target.value); setCursor(undefined); }} placeholder="Search recorded agent names or IDs" /></label>
      <label className="min-w-0 max-w-full text-sm">Agent scope<select aria-label="Agent scope" className="context-action mt-1 block max-w-full" value={rootId} disabled={selectorBusy} onChange={event => { setRootId(event.target.value); setSelectedId(null); setSelectedEdge(null); setFocusId(null); setExpandedCanvas(false); }}>
        {!selector?.agents.length && <option value={rootId}>{rootId || "No persisted agents"}</option>}
        {rootId && selector?.agents.length && !selector.agents.some(agent => agent.id === rootId) ? <option value={rootId}>{rootId}</option> : null}
        {selector?.agents.map(agent => <option key={agent.id} value={agent.id}>{agent.label} · {agent.id}</option>)}
      </select></label>
      {selector?.pagination.next_cursor && <button className="context-action" disabled={selectorBusy} onClick={() => setCursor(selector.pagination.next_cursor || undefined)}>Next agents</button>}
      {cursor && <button className="context-action" onClick={() => setCursor(undefined)}>First agents</button>}
      <label className="text-sm">Direction<select aria-label="Relationship direction" className="context-action ml-2" value={direction} onChange={event => { setDirection(event.target.value as IncidentDirection); setSelectedId(null); setSelectedEdge(null); setFocusId(null); setExpandedCanvas(false); }}><option value="both">Incoming + outgoing</option><option value="in">Incoming</option><option value="out">Outgoing</option></select></label>
      <button className="context-action" disabled={graph.busy || !rootId} onClick={() => { setSelectedId(null); setSelectedEdge(null); setFocusId(null); graph.restart(); }}>Restart neighborhood</button>
    </div>
    <div><button className="context-action" aria-pressed={expandedCanvas} onClick={() => setExpandedCanvas(value => !value)}>{expandedCanvas ? "Compact canvas" : "Expand canvas"}</button><span className="ml-2 text-xs text-[var(--text-secondary)]">{expandedCanvas ? "Up to 24 entities / 36 relationships" : "Up to 8 entities / 12 relationships"} · loaded evidence only</span></div>
    {selectorError && <p role="alert">{selectorError}</p>}
    {!selectorBusy && !selector?.agents.length && !selectorError && <p>No persisted agent nodes match this search. Repository and SBOM evidence remains available in Repository or Lineage.</p>}
    {graph.error && <p role="alert">{graph.error}</p>}
    <p role="status" className="text-sm text-[var(--text-secondary)]">{graph.busy ? "Loading relationships… " : ""}{graph.nodes.length} loaded entities · {graph.edges.length} loaded relationships · total unknown. Canvas: {display.nodes.length} entities, {display.edges.length} relationships.</p>
    {graph.pages.some(page => page.completeness.missing_endpoint_count > 0) && <p>Some recorded endpoints are unavailable; this neighborhood is incomplete.</p>}
    {graph.capped && <p>Loaded evidence limit reached (240 relationships / 10 pages). Restart or choose another agent to continue.</p>}
    <div className="grid min-w-0 gap-3 lg:grid-cols-[minmax(0,1fr)_22rem]">
      <div aria-label="Persisted neighborhood canvas" className="relative h-[32rem] min-w-0 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]">
        {!!layout.nodes.length && <ReactFlow key={JSON.stringify([focus, mobile, layout.nodes.map(node => node.id), layout.pending])} nodes={layout.nodes} edges={layout.edges} nodeTypes={lineageNodeTypes} edgeTypes={relationshipEdgeTypes} fitView fitViewOptions={{ padding: 0.12, minZoom: mobile ? 0.75 : 0.65, maxZoom: 1 }} minZoom={0.15} nodesDraggable={false}
          onNodeClick={(_, node) => { setSelectedId(node.id); setSelectedEdge(null); }} onEdgeClick={(_, selected) => { setSelectedEdge(JSON.stringify([selected.source, selected.target, selected.data?.relationship])); }}>
          <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} /><Controls className={CONTROLS_CLASS} />
        </ReactFlow>}
      </div>
      <aside aria-label="Agent neighborhood inspector" className="max-h-[32rem] overflow-y-auto min-w-0 space-y-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4">
        <h2 className="break-words text-lg font-semibold">{edge ? recordedLabel(String(edge.relationship)) : selected?.label || "Select an entity"}</h2>
        {edge ? <><p className="break-words">{label(edge.source)} → {label(edge.target)}</p><p>Recorded direction: {edge.direction}</p><p className="break-words">Evidence basis: {String(edge.evidence.evidence_tier ?? edge.evidence.evidence_basis ?? edge.evidence.basis ?? "unknown")}</p><p className="break-words">Runtime outcome: {String(edge.evidence.runtime_outcome ?? "unknown")}</p><button className="context-action" onClick={() => setSelectedEdge(null)}>Close inspection</button></> : selected ? <>
          <Link className="context-action inline-block" href={buildGraphInvestigationHref({ scanId, rootId: selected.id })}>Investigate reach &amp; permissions</Link>
          <p className="text-sm">{String(selected.entity_type).replaceAll("_", " ")}</p><code className="block break-all text-xs">{selected.id}</code>
          <div className="flex flex-wrap gap-2"><button className="context-action" onClick={() => setFocusId(selected.id)}>Focus here</button>
            {!lastPage && <button className="context-action" disabled={graph.busy || graph.capped || graph.stale} onClick={() => void graph.load(selected.id)}>Expand connections</button>}
            {lastPage?.next_cursor && <button className="context-action" disabled={graph.busy || graph.capped || graph.stale} onClick={() => void graph.load(selected.id, lastPage.next_cursor!)}>Load more relationships</button>}
            {!!pages.length && selected.id !== rootId && <button className="context-action" onClick={() => { graph.collapse(selected.id); setFocusId(null); }}>Collapse connections</button>}
          </div>
          {!!pages.length && selected.id !== rootId && <p className="text-xs">Collapse also clears later expansions.</p>}
          <p className="text-sm text-[var(--text-secondary)]">{incident.length} loaded relationships for this entity. {lastPage && !lastPage.next_cursor ? "End of recorded pages in this direction; source collection coverage remains unknown." : "Additional relationships not counted."}</p>
          <div className="max-h-64 space-y-2 overflow-y-auto">{incident.slice(0, 24).map(item => <button key={JSON.stringify([item.source, item.target, item.relationship])} className="context-connection" onClick={() => setSelectedEdge(JSON.stringify([item.source, item.target, item.relationship]))}><span className="block text-xs">{item.source === selected.id ? "Outgoing →" : "← Incoming"} {recordedLabel(String(item.relationship))}</span><span className="block break-words">{label(item.source === selected.id ? item.target : item.source)}</span></button>)}</div>
        </> : <p>Choose a persisted agent to begin.</p>}
        <details><summary className="cursor-pointer font-semibold">Loaded entities</summary><div className="max-h-60 overflow-y-auto">{graph.nodes.map(node => <button className="context-connection" key={node.id} onClick={() => { setSelectedId(node.id); setSelectedEdge(null); }}><span className="block break-words">{node.label}</span><code className="break-all text-xs">{node.id}</code></button>)}</div></details>
        <p className="text-sm text-[var(--text-secondary)]">Permission and exploitability are not assessed by these pages. Shared infrastructure does not prove agents communicated. Page completeness is not estate or collection completeness.</p>
      </aside>
    </div>
  </>;
}
