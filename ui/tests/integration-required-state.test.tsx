import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IntegrationRequiredState } from "@/components/integration-required-state";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { getDeploymentSurfaceState } from "@/lib/deployment-context";

describe("IntegrationRequiredState", () => {
  it("shows an in-product action button alongside (not instead of) the CLI command", () => {
    render(
      <IntegrationRequiredState
        title="Agent Mesh is not active in this deployment"
        summary="The Agent Mesh needs relationship-rich scan data."
        requirement="Completed scans with agent and runtime relationship context"
        command="agent-bom scan --introspect --preset enterprise"
        capabilities={["Runtime-aware graph exploration instead of a raw scan list"]}
        primaryAction={{ label: "Run introspection scan", href: "/scan" }}
      />,
    );

    // First-class UI action…
    const action = screen.getByRole("link", { name: /Run introspection scan/ });
    expect(action).toHaveAttribute("href", "/scan");
    // …and the headless CLI equivalent is still present, never removed.
    expect(
      screen.getByText("agent-bom scan --introspect --preset enterprise"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Headless \/ agent equivalent/)).toBeInTheDocument();
  });
});

describe("DeploymentSurfaceRequiredState", () => {
  it("wires the scan-driven surfaces to the in-product New-Scan flow", () => {
    // The mesh surface definition carries a scan action…
    const state = getDeploymentSurfaceState("mesh", {
      has_mesh: false,
      deployment_mode: "local",
    } as never);
    expect(state.actionHref).toBe("/scan?preset=enterprise");

    render(
      <DeploymentSurfaceRequiredState
        surface="mesh"
        counts={{ has_mesh: false, deployment_mode: "local" } as never}
      />,
    );

    expect(screen.getByRole("link", { name: /Run introspection scan/ })).toHaveAttribute(
      "href",
      "/scan?preset=enterprise",
    );
    expect(
      screen.getByText("agent-bom scan --introspect --preset enterprise"),
    ).toBeInTheDocument();
  });
});
