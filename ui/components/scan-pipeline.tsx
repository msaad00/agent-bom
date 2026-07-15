"use client";

/**
 * Scan Pipeline DAG — shows scan execution as a branching React Flow graph.
 *
 * Discovery → Extraction fans out into parallel scanner lanes (SCA / secrets /
 * IaC / CIS / cloud) that converge back into Enrichment → Analysis → Report.
 * The branching shape and node ranks are derived from `lib/scan-pipeline-graph`
 * (dependency edges only) and laid out by the Sankey helper — no hand-placed
 * coordinates. Interactive: pan / zoom / drag / select, with click-to-drill-in
 * on any node.
 */

import { useCallback, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  ReactFlowProvider,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Search,
  Package,
  Bug,
  Zap,
  Shield,
  ShieldCheck,
  FileText,
  FileCode,
  KeyRound,
  Cloud,
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  SkipForward,
  Move,
} from "lucide-react";
import { useGraphLayout } from "@/lib/use-graph-layout";
import type { StepStatus, StepEvent } from "@/lib/api";
import {
  buildPipelineGraph,
  type DomainLaneData,
  type PipelineNodeKind,
  type ScannerDomain,
} from "@/lib/scan-pipeline-graph";

// ── Step node component ─────────────────────────────────────────────────────

interface PipelineNodeData {
  [key: string]: unknown;
  nodeId: string;
  stepId: string;
  label: string;
  description: string;
  kind: PipelineNodeKind;
  domain?: ScannerDomain | undefined;
  status: StepStatus;
  message?: string | undefined;
  stats?: Record<string, number> | undefined;
  startedAt?: string | undefined;
  completedAt?: string | undefined;
  progressPct?: number | undefined;
  findings?: number | null | undefined;
  ran?: boolean | undefined;
  detail?: string | undefined;
  summarized?: boolean | undefined;
  selected?: boolean | undefined;
}

// Icons keyed by DAG node id, falling back to the backend stage id.
const NODE_ICONS: Record<string, React.ElementType> = {
  discovery: Search,
  extraction: Package,
  scanning: Bug,
  enrichment: Zap,
  analysis: Shield,
  output: FileText,
  sca: Bug,
  secrets: KeyRound,
  iac: FileCode,
  cis: ShieldCheck,
  cloud: Cloud,
};

// Neutral (non-severity) surfaces use design tokens so the DAG tracks the
// active theme; running/done/failed keep their semantic emerald/red hues.
const STATUS_STYLES: Record<
  StepStatus,
  { border: string; bg: string; icon: React.ElementType; iconColor: string }
> = {
  pending: {
    border: "border-[var(--border-subtle)]",
    bg: "bg-[var(--surface)]",
    icon: Clock,
    iconColor: "text-[var(--text-tertiary)]",
  },
  running: {
    border: "border-emerald-500 animate-pulse",
    bg: "bg-emerald-500/15",
    icon: Loader2,
    iconColor: "text-emerald-400 animate-spin",
  },
  done: {
    border: "border-emerald-500/80",
    bg: "bg-emerald-500/10",
    icon: CheckCircle,
    iconColor: "text-emerald-400",
  },
  failed: {
    border: "border-red-500/80",
    bg: "bg-red-500/12",
    icon: XCircle,
    iconColor: "text-red-400",
  },
  skipped: {
    border: "border-dashed border-[var(--border-subtle)]",
    bg: "bg-[var(--surface-muted)]",
    icon: SkipForward,
    iconColor: "text-[var(--text-tertiary)]",
  },
};

function LaneFindings({ data }: { data: PipelineNodeData }) {
  if (data.status === "skipped" || data.ran === false) {
    return <p className="text-[10px] text-[var(--text-tertiary)]">not run</p>;
  }
  if (data.findings == null) {
    return (
      <p className="text-[10px] text-[var(--text-tertiary)]">
        {data.status === "running" ? "scanning…" : data.detail ?? "—"}
      </p>
    );
  }
  const hasFindings = data.findings > 0;
  return (
    <div className="flex items-center gap-1.5">
      <span
        className={`inline-flex items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] ${
          hasFindings
            ? "border-[var(--severity-high-border)] bg-[var(--severity-high-bg)] text-[color:var(--severity-high)]"
            : "border-[var(--status-success-border)] bg-[var(--status-success-bg)] text-[color:var(--status-success)]"
        }`}
      >
        {data.detail ?? (hasFindings ? `${data.findings} findings` : "clean")}
      </span>
    </div>
  );
}

function PipelineNode({ data }: { data: PipelineNodeData }) {
  const style = STATUS_STYLES[data.status];
  const StatusIcon = style.icon;
  const StepIcon = NODE_ICONS[data.nodeId] ?? NODE_ICONS[data.stepId] ?? Shield;
  const isScanner = data.kind === "scanner";

  const duration =
    data.completedAt && data.startedAt
      ? (
          (new Date(data.completedAt).getTime() - new Date(data.startedAt).getTime()) /
          1000
        ).toFixed(1)
      : null;

  return (
    <div
      className={`rounded-2xl border-2 ${style.border} ${style.bg} ${
        isScanner ? "min-w-[150px] max-w-[178px]" : "min-w-[176px] max-w-[208px]"
      } cursor-pointer overflow-hidden shadow-lg shadow-[var(--shadow-color)] transition-shadow ${
        data.selected ? "ring-2 ring-emerald-400/70 ring-offset-1 ring-offset-transparent" : ""
      }`}
    >
      <Handle type="target" position={Position.Left} className="!bg-[var(--border-strong)]" />

      <div className="border-b border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-2">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-xl bg-[var(--surface)] ring-1 ring-[var(--border-subtle)]">
            <StepIcon className="h-4 w-4 shrink-0 text-[var(--text-secondary)]" />
          </div>
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
              {isScanner ? "scanner" : data.nodeId}
            </div>
            <span className="block truncate text-sm font-semibold text-[var(--foreground)]">
              {data.label}
            </span>
          </div>
          <StatusIcon className={`ml-auto h-3.5 w-3.5 ${style.iconColor}`} />
        </div>
      </div>

      <div className="px-3 py-2.5">
        {isScanner ? (
          <LaneFindings data={data} />
        ) : (
          <>
            <p className="text-[10px] leading-tight text-[var(--text-tertiary)]">
              {data.status !== "pending" && data.message ? data.message : data.description}
            </p>

            {data.stats && Object.keys(data.stats).length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {Object.entries(data.stats).map(([k, v]) => (
                  <span
                    key={k}
                    className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[9px] text-[var(--text-secondary)]"
                  >
                    {v} {k}
                  </span>
                ))}
              </div>
            )}

            {data.progressPct != null && data.status === "running" && (
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--surface-muted)]">
                <div
                  className="h-full bg-emerald-500 transition-all duration-300"
                  style={{ width: `${data.progressPct}%` }}
                />
              </div>
            )}

            {duration && (
              <p className="mt-1 font-mono text-[9px] text-[var(--text-tertiary)]">{duration}s</p>
            )}
          </>
        )}
      </div>

      <Handle type="source" position={Position.Right} className="!bg-[var(--border-strong)]" />
    </div>
  );
}

const nodeTypes = { pipelineStep: PipelineNode };

// ── Main component ──────────────────────────────────────────────────────────

interface ScanPipelineProps {
  steps: Map<string, StepEvent>;
  /** Per-domain finding counts driving the scanner lanes. */
  lanes?: Record<ScannerDomain, DomainLaneData> | undefined;
  className?: string | undefined;
  /** Currently drilled-in node (adds a selection ring). */
  selectedStepId?: string | null | undefined;
  /** Fired when a node is clicked, for drill-in panels. Receives the DAG node id. */
  onStepClick?: ((nodeId: string) => void) | undefined;
  /** Enable pan/zoom/drag/select + on-canvas controls. Defaults to true. */
  interactive?: boolean | undefined;
}

function ScanPipelineInner({
  steps,
  lanes,
  className,
  selectedStepId,
  onStepClick,
  interactive = true,
}: ScanPipelineProps) {
  const { rawNodes, rawEdges } = useMemo(() => {
    const built = buildPipelineGraph({ steps, lanes, selectedNodeId: selectedStepId });
    return { rawNodes: built.nodes, rawEdges: built.edges };
  }, [steps, lanes, selectedStepId]);

  const { nodes, edges } = useGraphLayout("sankey", rawNodes, rawEdges, {
    sankey: {
      nodeWidth: 180,
      nodeHeight: 78,
      columnGap: 64,
      rowGap: 16,
    },
  });

  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      onStepClick?.(node.id);
    },
    [onStepClick],
  );

  return (
    <div className={`relative h-[180px] ${className ?? ""}`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        // Re-fit whenever the node set changes so a live pipeline that grows
        // scanner lanes mid-run always frames the whole DAG in the container
        // instead of clipping the tail off-screen.
        fitViewOptions={{ padding: 0.16, maxZoom: 1 }}
        minZoom={0.25}
        maxZoom={1.5}
        panOnDrag={interactive}
        zoomOnScroll={interactive}
        nodesDraggable={interactive}
        nodesConnectable={false}
        elementsSelectable={interactive}
        onNodeClick={handleNodeClick}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="var(--border-subtle)" gap={16} />
        {interactive ? (
          <Controls
            showInteractive={false}
            className="!border !border-[var(--border-subtle)] !bg-[var(--surface)] !shadow-md"
          />
        ) : null}
      </ReactFlow>
      {interactive ? (
        <div className="pointer-events-none absolute right-2 top-2 inline-flex items-center gap-1.5 rounded-full border border-[var(--border-subtle)] bg-[var(--surface)]/90 px-2.5 py-1 text-[10px] font-medium text-[var(--text-tertiary)] backdrop-blur">
          <Move className="h-3 w-3" aria-hidden="true" />
          Drag to pan · scroll to zoom · click a stage
        </div>
      ) : null}
    </div>
  );
}

export function ScanPipeline(props: ScanPipelineProps) {
  return (
    <ReactFlowProvider>
      <ScanPipelineInner {...props} />
    </ReactFlowProvider>
  );
}
