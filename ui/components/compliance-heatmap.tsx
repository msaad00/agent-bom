"use client";

import { useState } from "react";
import type { ComplianceResponse, ComplianceControl } from "@/lib/api";

interface ComplianceHeatmapProps {
  data: ComplianceResponse;
}

interface FrameworkRow {
  label: string;
  field: keyof Pick<
    ComplianceResponse,
    "owasp_llm_top10" | "owasp_mcp_top10" | "owasp_agentic_top10" | "mitre_atlas" | "nist_ai_rmf" | "eu_ai_act"
  >;
}

const FRAMEWORKS: FrameworkRow[] = [
  { label: "OWASP LLM Top 10", field: "owasp_llm_top10" },
  { label: "OWASP MCP Top 10", field: "owasp_mcp_top10" },
  { label: "OWASP Agentic Top 10", field: "owasp_agentic_top10" },
  { label: "MITRE ATLAS", field: "mitre_atlas" },
  { label: "NIST AI RMF", field: "nist_ai_rmf" },
  { label: "EU AI Act", field: "eu_ai_act" },
];

function cellColor(status: string): string {
  switch (status) {
    case "pass":    return "#34d399";
    case "warning": return "#facc15";
    case "fail":    return "#f87171";
    default:        return "var(--border-strong)";
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case "pass":    return "Pass";
    case "warning": return "Warning";
    case "fail":    return "Fail";
    default:        return "N/A";
  }
}

export function ComplianceHeatmap({ data }: ComplianceHeatmapProps) {
  const [tooltip, setTooltip] = useState<{ code: string; status: string; x: number; y: number } | null>(null);

  // Find max number of controls across all frameworks for column sizing
  const maxControls = Math.max(
    ...FRAMEWORKS?.map((fw) => (data[fw.field] as ComplianceControl[]).length)
  );

  return (
    <div className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-2xl p-6 overflow-x-auto relative">
      <h3 className="text-sm font-semibold text-[color:var(--text-secondary)] uppercase tracking-wider mb-4">
        Compliance Heatmap
      </h3>

      {/* Legend */}
      <div className="flex gap-4 mb-4 text-xs text-[color:var(--text-tertiary)]">
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded" style={{ backgroundColor: "#34d399" }} /> Pass
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded" style={{ backgroundColor: "#facc15" }} /> Warning
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded" style={{ backgroundColor: "#f87171" }} /> Fail
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded" style={{ backgroundColor: "var(--border-strong)" }} /> N/A
        </span>
      </div>

      <div className="space-y-1.5">
        {FRAMEWORKS?.map((fw) => {
          const controls = data[fw.field] as ComplianceControl[];
          return (
            <div key={fw.field} className="flex items-center gap-3">
              {/* Framework label */}
              <div className="w-44 shrink-0 text-xs text-[color:var(--text-secondary)] font-medium truncate" title={fw.label}>
                {fw.label}
              </div>

              {/* Control cells */}
              <div className="flex gap-1">
                {controls?.map((ctrl) => (
                  <div
                    key={ctrl.code}
                    className="w-7 h-7 rounded cursor-pointer transition-transform hover:scale-125 hover:z-10 relative"
                    style={{ backgroundColor: cellColor(ctrl.status) }}
                    onMouseEnter={(e) => {
                      const rect = (e.target as HTMLElement).getBoundingClientRect();
                      setTooltip({ code: ctrl.code, status: ctrl.status, x: rect.left + rect.width / 2, y: rect.top });
                    }}
                    onMouseLeave={() => setTooltip(null)}
                  />
                ))}
                {/* Fill empty slots to keep grid alignment */}
                {Array.from({ length: maxControls - controls.length }).map((_, i) => (
                  <div
                    key={`empty-${i}`}
                    className="w-7 h-7 rounded"
                    style={{ backgroundColor: "var(--border-strong)" }}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 px-3 py-1.5 rounded-lg bg-[color:var(--surface-muted)] border border-[color:var(--border-strong)] text-xs text-[color:var(--foreground)] shadow-xl pointer-events-none"
          style={{
            left: tooltip.x,
            top: tooltip.y - 40,
            transform: "translateX(-50%)",
          }}
        >
          <span className="font-mono font-semibold">{tooltip.code}</span>
          <span className="text-[color:var(--text-tertiary)] mx-1.5">&middot;</span>
          <span>{statusLabel(tooltip.status)}</span>
        </div>
      )}
    </div>
  );
}
