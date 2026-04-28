"use client";

import type { PostureCountsResponse } from "@/lib/api";
import {
  getDeploymentSurfaceState,
  type DeploymentSurface,
} from "@/lib/deployment-context";
import { IntegrationRequiredState } from "@/components/integration-required-state";

export function DeploymentSurfaceRequiredState({
  surface,
  counts,
  detail,
  onRetry,
}: {
  surface: DeploymentSurface;
  counts: PostureCountsResponse | null;
  detail?: string | null | undefined;
  onRetry?: (() => void) | undefined;
}) {
  const state = getDeploymentSurfaceState(surface, counts, detail);

  return (
    <IntegrationRequiredState
      title={state.title}
      summary={state.summary}
      requirement={state.requirement}
      command={state.command}
      capabilities={state.capabilities}
      detail={state.detail}
      onRetry={onRetry}
    />
  );
}
