"use client";

import dynamic from "next/dynamic";
import { useSearchParams } from "next/navigation";

import { GraphPanelSkeleton } from "@/components/graph-state-panels";
import GraphPageClient from "./graph-page-client";

// One graph surface, several lenses selected by URL params. Lineage (default)
// and Asset Drift
// (`?scope=asset-drift`) render the full unified-graph client; the Agent Mesh
// and Context lenses render their own bespoke pipelines — each a distinct data
// source (raw scan mesh / context-graph API) with distinct panels — so they are
// composed in here rather than folded into the unified-graph filter model.
//
// The lens views are lazily loaded (ssr:false) so the default lineage bundle
// never pays for the mesh/context pipelines and they never run during static
// prerender. The canonical `/security-graph` investigation route composes this
// surface for non-attack-path lenses; `/graph` remains a compatible direct
// entry point for existing deep links.
const MeshLensView = dynamic(
  () => import("@/components/mesh-lens-view").then((mod) => mod.MeshLensView),
  {
    ssr: false,
    loading: () => (
      <div className="h-[80vh]">
        <GraphPanelSkeleton
          title="Loading agent mesh"
          detail="Preparing the bounded agent-centered topology."
        />
      </div>
    ),
  },
);

const ContextLensView = dynamic(
  () =>
    import("@/components/context-lens-view").then((mod) => mod.ContextLensView),
  {
    ssr: false,
    loading: () => (
      <div className="h-[80vh]">
        <GraphPanelSkeleton
          title="Loading context map"
          detail="Preparing the focused lateral-movement window."
        />
      </div>
    ),
  },
);

export function GraphSurface() {
  const lens = useSearchParams()?.get("lens");
  if (lens === "mesh") return <MeshLensView />;
  if (lens === "context") return <ContextLensView />;
  return <GraphPageClient />;
}
