"use client";

/**
 * Scan Pipeline DAG — shows scan execution stages as a React Flow graph
 * with live status updates from SSE step events.
 */

import { useMemo } from "react";
import {
  ReactFlow,
  Background,
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
import { applyDagreLayout } from "@/lib/dagre-layout";
import type { StepEvent, StepStatus } from "@/lib/api";
import { PIPELINE_STEPS } from "@/lib/api";

// ── Step node component ─────────────────────────────────────────────────────

interface PipelineNodeData {
  [key: string]: unknown;
  label: string;
  description: string;
  stepId: string;
  status: StepStatus;
  message?: string;
  stats?: Record<string, number>;
  startedAt?: string;
  completedAt?: string;
  progressPct?: number;
}

const STEP_ICONS: Record<string, React.ElementType> = {
  discovery: Search,
  extraction: Package,
  scanning: Bug,
  enrichment: Zap,
  analysis: Shield,
  output: FileText,
};

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
    border: "border-zinc-700",
    bg: "bg-zinc-900",
    icon: Clock,
    iconColor: "text-zinc-500",
  },
  running: {
    border: "border-emerald-500 animate-pulse",
    bg: "bg-emerald-950/50",
    icon: Loader2,
    iconColor: "text-emerald-400 animate-spin",
  },
  done: {
    border: "border-emerald-600",
    bg: "bg-emerald-950/30",
    icon: CheckCircle,
    iconColor: "text-emerald-400",
  },
  failed: {
    border: "border-red-600",
    bg: "bg-red-950/30",
    icon: XCircle,
    iconColor: "text-red-400",
  },
  skipped: {
    border: "border-zinc-700",
    bg: "bg-zinc-900/50",
    icon: SkipForward,
    iconColor: "text-zinc-600",
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
      className={`rounded-xl border-2 ${style.border} ${style.bg} p-3 min-w-[170px] max-w-[200px] shadow-lg`}
    >
      <Handle type="target" position={Position.Left} className="!bg-zinc-600" />

      {/* Header */}
      <div className="flex items-center gap-2 mb-1.5">
        <StepIcon className="w-4 h-4 text-zinc-400 shrink-0" />
        <span className="text-sm font-semibold text-zinc-100">
          {data.label}
        </span>
        <StatusIcon className={`w-3.5 h-3.5 ml-auto ${style.iconColor}`} />
      </div>

      {/* Message */}
      <p className="text-[10px] text-zinc-500 leading-tight truncate">
        {data.status !== "pending"
          ? data.message
          : STEP_DESCRIPTIONS[data.stepId] ?? data.description}
      </p>

      {/* Stats chips */}
      {data.stats && Object.keys(data.stats).length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {Object.entries(data.stats).map(([k, v]) => (
            <span
              key={k}
              className="text-[9px] font-mono bg-zinc-800 border border-zinc-700 rounded px-1 py-0.5 text-zinc-400"
            >
              {v} {k}
            </span>
          ))}
        </div>
      )}

      {/* Progress bar */}
      {data.progressPct != null && data.status === "running" && (
        <div className="mt-2 h-1 bg-zinc-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-emerald-500 transition-all duration-300"
            style={{ width: `${data.progressPct}%` }}
          />
        </div>
      )}

      {/* Duration */}
      {duration && (
        <p className="text-[9px] text-zinc-600 mt-1 font-mono">{duration}s</p>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-zinc-600"
      />
    </div>
  );
}

const nodeTypes = { pipelineStep: PipelineNode };

// ── Main component ──────────────────────────────────────────────────────────

interface ScanPipelineProps {
  steps: Map<string, StepEvent>;
  className?: string;
}

function ScanPipelineInner({ steps, className }: ScanPipelineProps) {
  const { nodes, edges } = useMemo(() => {
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
      } satisfies PipelineNodeData,
    }));

    const rawEdges: Edge[] = PIPELINE_STEPS.slice(1).map((step, i) => {
      const prevId = PIPELINE_STEPS[i].id;
      const prevStatus = steps.get(prevId)?.status;
      const curStatus = steps.get(step.id)?.status;

      return {
        id: `e-${prevId}-${step.id}`,
        source: prevId,
        target: step.id,
        type: "default",
        animated: prevStatus === "running" || curStatus === "running",
        style: {
          stroke:
            curStatus === "done"
              ? "#10b981"
              : curStatus === "failed"
                ? "#ef4444"
                : "#3f3f46",
          strokeWidth: 2,
        },
      };
    });

    return applyDagreLayout(rawNodes, rawEdges, {
      direction: "LR",
      nodeWidth: 190,
      nodeHeight: 90,
      rankSep: 50,
      nodeSep: 20,
    });
  }, [steps]);

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
        panOnDrag={false}
        zoomOnScroll={false}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#27272a" gap={16} />
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
