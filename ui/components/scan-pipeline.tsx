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
import { useDagreLayout } from "@/lib/use-dagre-layout";
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
      className={`rounded-2xl border-2 ${style.border} ${style.bg} min-w-[176px] max-w-[208px] overflow-hidden shadow-lg shadow-black/20`}
    >
      <Handle type="target" position={Position.Left} className="!bg-zinc-600" />

      <div className="border-b border-white/5 bg-white/[0.03] px-3 py-2">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-xl bg-zinc-950/60 ring-1 ring-white/5">
            <StepIcon className="h-4 w-4 text-zinc-300 shrink-0" />
          </div>
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{data.stepId}</div>
            <span className="block truncate text-sm font-semibold text-zinc-100">{data.label}</span>
          </div>
          <StatusIcon className={`ml-auto h-3.5 w-3.5 ${style.iconColor}`} />
        </div>
      </div>

      <div className="px-3 py-2.5">
        <p className="text-[10px] leading-tight text-zinc-500">
          {data.status !== "pending"
            ? data.message
            : STEP_DESCRIPTIONS[data.stepId] ?? data.description}
        </p>

        {data.stats && Object.keys(data.stats).length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(data.stats).map(([k, v]) => (
              <span
                key={k}
                className="rounded-lg border border-zinc-700 bg-zinc-950/70 px-1.5 py-0.5 font-mono text-[9px] text-zinc-400"
              >
                {v} {k}
              </span>
            ))}
          </div>
        )}

        {data.progressPct != null && data.status === "running" && (
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-zinc-800">
            <div
              className="h-full bg-emerald-500 transition-all duration-300"
              style={{ width: `${data.progressPct}%` }}
            />
          </div>
        )}

        {duration && (
          <p className="mt-1 font-mono text-[9px] text-zinc-600">{duration}s</p>
        )}
      </div>

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

    return { rawNodes, rawEdges };
  }, [steps]);

  const { nodes, edges } = useDagreLayout(rawNodes, rawEdges, {
    direction: "LR",
    nodeWidth: 190,
    nodeHeight: 90,
    rankSep: 50,
    nodeSep: 20,
  });

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
