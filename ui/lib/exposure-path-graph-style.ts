import type { ExposureEntityRole } from "@/lib/exposure-path";

export interface GraphRoleStyle {
  fill: string;
  stroke: string;
  text: string;
  accent: string;
}

/**
 * How much of the role hue is mixed into the node surface. 10% keeps the hue
 * readable as a tint in both themes while leaving the role accent (the hue at
 * full strength) above 4.5:1 against the resulting fill.
 */
const NODE_FILL_MIX = "10%";

function roleStyle(hue: string): GraphRoleStyle {
  return {
    fill: `color-mix(in srgb, var(${hue}) ${NODE_FILL_MIX}, var(--surface))`,
    stroke: `var(${hue})`,
    text: "var(--foreground)",
    accent: `var(${hue})`,
  };
}

/**
 * Paint for one exposure-path node per semantic role. Every value resolves
 * through theme tokens (`--graph-*` in `app/globals.css`) so the board follows
 * the active theme instead of rendering a fixed dark slab on a light card.
 */
export const GRAPH_ROLE_STYLE: Record<ExposureEntityRole, GraphRoleStyle> = {
  agent: roleStyle("--graph-agent"),
  server: roleStyle("--graph-server"),
  package: roleStyle("--graph-package"),
  finding: roleStyle("--graph-finding"),
  credential: roleStyle("--graph-credential"),
  tool: roleStyle("--graph-tool"),
  environment: roleStyle("--graph-environment"),
  cluster: roleStyle("--graph-cluster"),
  unknown: roleStyle("--graph-unknown"),
};
