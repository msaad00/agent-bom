import type { ExposureEntityRole } from "@/lib/exposure-path";

export interface GraphRoleStyle {
  fill: string;
  stroke: string;
  text: string;
  accent: string;
}

export const GRAPH_ROLE_STYLE: Record<ExposureEntityRole, GraphRoleStyle> = {
  agent: { fill: "#052e24", stroke: "#10b981", text: "#d1fae5", accent: "#34d399" },
  server: { fill: "#082f49", stroke: "#0ea5e9", text: "#e0f2fe", accent: "#38bdf8" },
  package: { fill: "#422006", stroke: "#f59e0b", text: "#fef3c7", accent: "#fbbf24" },
  finding: { fill: "#450a0a", stroke: "#ef4444", text: "#fee2e2", accent: "#f87171" },
  credential: { fill: "#3b0764", stroke: "#d946ef", text: "#fae8ff", accent: "#e879f9" },
  tool: { fill: "#2e1065", stroke: "#a855f7", text: "#f3e8ff", accent: "#c084fc" },
  environment: { fill: "#164e63", stroke: "#06b6d4", text: "#cffafe", accent: "#22d3ee" },
  cluster: { fill: "#312e81", stroke: "#6366f1", text: "#e0e7ff", accent: "#818cf8" },
  unknown: { fill: "#1e293b", stroke: "#64748b", text: "#f1f5f9", accent: "#94a3b8" },
};
