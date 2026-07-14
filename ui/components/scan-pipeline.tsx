"use client";

/**
 * Scan Pipeline DAG — shows scan execution stages as a React Flow graph
 * with live status updates from SSE step events. Interactive: pan / zoom /
 * drag / select, with click-to-drill-in on any stage.
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
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Search,
  Package,
  Bug,
  Zap,
  Shield,
  FileText,
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  SkipForward,
} from "lucide-react";
import { useGraphLayout } from "@/lib/use-graph-layout";
import type { StepEvent, StepStatus } from "@/lib/api";
import { PIPELINE_STEPS } from "@/lib/api";

// ── Step node component ─────────────────────────────────────────────────────

interface PipelineNodeData {
  [key: string]: unknown;
  label: string;
  description: string;
  stepId: string;
  status: StepStatus;
  message?: string | undefined;
  stats?: Record<string, number> | undefined;
  startedAt?: string | undefined;
  completedAt?: string | undefined;
  progressPct?: number | undefined;
  selected?: boolean | undefined;
}

const STEP_ICONS: Record<string, React.ElementType> = {
  discovery: Search,
  extraction: Package,
  scanning: Bug,
  enrichment: Zap,
  analysis: Shield,
  output: FileText,
};

// Neutral (non-severity) surfaces use design tokens so the DAG tracks the
// active theme; running/done/failed keep their semantic emerald/red hues.
const STATUS_STYLES: Record<
  StepStatus,
  {
    border: string;
    bg: string;
    icon: React.ElementType;
    iconColor: string;
  }
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
    border: "border-[var(--border-subtle)]",
    bg: "bg-[var(--surface-muted)]",
    icon: SkipForward,
    iconColor: "text-[var(--text-tertiary)]",
  },
};

const STEP_DESCRIPTIONS: Record<string, string> = {
  discovery: "Find MCP agents and configs",
  extraction: "Extract packages from servers",
  scanning: "Query vulnerability databases",
  enrichment: "NVD CVSS, EPSS, CISA KEV",
  analysis: "Compute blast radius",
  output: "Generate final report",
};

function PipelineNode({ data }: { data: PipelineNodeData }) {
  const style = STATUS_STYLES[data.status];
  const StatusIcon = style.icon;
  const StepIcon = STEP_ICONS[data.stepId] ?? Shield;

  const duration =
    data.completedAt && data.startedAt
      ? (
          (new Date(data.completedAt).getTime() -
            new Date(data.startedAt).getTime()) /
          1000
        ).toFixed(1)
      : null;

  return (
    <div
      className={`rounded-2xl border-2 ${style.border} ${style.bg} min-w-[176px] max-w-[208px] cursor-pointer overflow-hidden shadow-lg shadow-[var(--shadow-color)] transition-shadow ${
        data.selected ? "ring-2 ring-emerald-400/70 ring-offset-1 ring-offset-transparent" : ""
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[var(--border-strong)]"
      />

      <div className="border-b border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-2">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-xl bg-[var(--surface)] ring-1 ring-[var(--border-subtle)]">
            <StepIcon className="h-4 w-4 shrink-0 text-[var(--text-secondary)]" />
          </div>
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
              {data.stepId}
            </div>
            <span className="block truncate text-sm font-semibold text-[var(--foreground)]">
              {data.label}
            </span>
          </div>
          <StatusIcon className={`ml-auto h-3.5 w-3.5 ${style.iconColor}`} />
        </div>
      </div>

      <div className="px-3 py-2.5">
        <p className="text-[10px] leading-tight text-[var(--text-tertiary)]">
          {data.status !== "pending"
            ? data.message
            : STEP_DESCRIPTIONS[data.stepId] ?? data.description}
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
          <p className="mt-1 font-mono text-[9px] text-[var(--text-tertiary)]">
            {duration}s
          </p>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[var(--border-strong)]"
      />
    </div>
  );
}

const nodeTypes = { pipelineStep: PipelineNode };

// ── Main component ──────────────────────────────────────────────────────────

interface ScanPipelineProps {
  steps: Map<string, StepEvent>;
  className?: string | undefined;
  /** Currently drilled-in step (adds a selection ring). */
  selectedStepId?: string | null | undefined;
  /** Fired when a stage node is clicked, for drill-in panels. */
  onStepClick?: ((stepId: string) => void) | undefined;
  /** Enable pan/zoom/drag/select + on-canvas controls. Defaults to true. */
  interactive?: boolean | undefined;
}

function ScanPipelineInner({
  steps,
  className,
  selectedStepId,
  onStepClick,
  interactive = true,
}: ScanPipelineProps) {
  const { rawNodes, rawEdges } = useMemo(() => {
    const rawNodes: Node[] = PIPELINE_STEPS?.map((step) => ({
      id: step.id,
      type: "pipelineStep",
      position: { x: 0, y: 0 },
      data: {
        label: step.label,
        description: STEP_DESCRIPTIONS[step.id] ?? "",
        stepId: step.id,
        status: (steps.get(step.id)?.status ?? "pending") as StepStatus,
        message: steps.get(step.id)?.message,
        stats: steps.get(step.id)?.stats,
        startedAt: steps.get(step.id)?.started_at,
        completedAt: steps.get(step.id)?.completed_at,
        progressPct: steps.get(step.id)?.progress_pct,
        selected: selectedStepId === step.id,
      } satisfies PipelineNodeData,
    }));

    const rawEdges: Edge[] = PIPELINE_STEPS.slice(1).map((step, i) => {
      const prevId = PIPELINE_STEPS[i]!.id;
      const prevStatus = steps.get(prevId)?.status;
      const curStatus = steps.get(step.id)?.status;

      return {
        id: `e-${prevId}-${step.id}`,
        source: prevId,
        target: step.id,
        type: "default",
        // Motion only while something is actively running.
        animated: prevStatus === "running" || curStatus === "running",
        style: {
          stroke:
            curStatus === "done"
              ? "#10b981"
              : curStatus === "failed"
                ? "#ef4444"
                : "var(--border-strong)",
          strokeWidth: 2,
        },
      };
    });

    return { rawNodes, rawEdges };
  }, [steps, selectedStepId]);

  const { nodes, edges } = useGraphLayout("sankey", rawNodes, rawEdges, {
    sankey: {
      nodeWidth: 190,
      nodeHeight: 90,
      columnGap: 50,
      rowGap: 20,
    },
  });

  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      onStepClick?.(node.id);
    },
    [onStepClick],
  );

  return (
    <div className={`h-[180px] ${className ?? ""}`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.4}
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
