import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  PermissionDeniedNotice,
  RoleBadge,
  RolePermissionsPanel,
} from "@/components/role-access";
import type { AuthMeResponse } from "@/lib/api";

// Demo detection is read from the shared hook; keep it mutable so a test can
// flip the deployment into the public-demo posture without a real /health call.
const demoState = { isDemoMode: false, loading: false };
vi.mock("@/hooks/use-demo-mode", () => ({
  useDemoMode: () => demoState,
}));

beforeEach(() => {
  demoState.isDemoMode = false;
});

function session(overrides: Partial<AuthMeResponse> = {}): AuthMeResponse {
  return {
    authenticated: true,
    auth_required: true,
    configured_modes: [],
    recommended_ui_mode: "api_key",
    auth_method: "api_key",
    subject: "svc",
    tenant_id: "default",
    role: "viewer",
    role_summary: null,
    memberships: [],
    request_id: null,
    trace_id: null,
    span_id: null,
    ...overrides,
  };
}

describe("RolePermissionsPanel", () => {
  it("renders the viewer/contributor/admin ladder and highlights the active role", () => {
    render(<RolePermissionsPanel session={session({ role: "analyst" })} />);
    expect(screen.getByText("Roles & permissions")).toBeInTheDocument();
    expect(screen.getByTestId("role-card-viewer")).toBeInTheDocument();
    expect(screen.getByTestId("role-card-admin")).toBeInTheDocument();

    const contributor = screen.getByTestId("role-card-analyst");
    // analyst is the active role → flagged as "You".
    expect(contributor).toHaveAttribute("aria-current", "true");
    expect(within(contributor).getByText("You")).toBeInTheDocument();
    // Viewer card is not the active one.
    expect(screen.getByTestId("role-card-viewer")).not.toHaveAttribute(
      "aria-current",
      "true",
    );
  });

  it("maps the analyst role_summary onto the Contributor card", () => {
    render(
      <RolePermissionsPanel
        session={session({
          role: "analyst",
          role_summary: {
            role: "analyst",
            ui_role: "contributor",
            display_name: "Contributor",
            description: "",
            capabilities: ["scan.run"],
            capability_matrix: [],
            can_see: [],
            can_do: [],
            cannot_do: [],
          },
        })}
      />,
    );
    expect(screen.getByTestId("role-card-analyst")).toHaveAttribute(
      "aria-current",
      "true",
    );
  });
});

describe("RoleBadge", () => {
  it("names the current role", () => {
    render(<RoleBadge session={session({ role: "admin" })} />);
    expect(screen.getByText(/Your role · Admin/)).toBeInTheDocument();
  });

  it("renders nothing without a resolvable role", () => {
    const { container } = render(<RoleBadge session={session({ role: null })} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("PermissionDeniedNotice", () => {
  it("points an authenticated viewer at an admin grant, not a raw 403", () => {
    render(<PermissionDeniedNotice session={session({ role: "viewer" })} />);
    expect(screen.getByText(/read-only for this action/i)).toBeInTheDocument();
    expect(screen.getByText(/Ask an admin to grant Contributor access/i)).toBeInTheDocument();
    // Honest: no fabricated "self-elevate" affordance.
    expect(screen.queryByText(/AGENT_BOM_NO_AUTH_ROLE/)).toBeNull();
  });

  it("gives a self-host operator the concrete env-var lever", () => {
    render(
      <PermissionDeniedNotice
        session={session({ role: "viewer", auth_required: false })}
      />,
    );
    expect(screen.getByText(/AGENT_BOM_NO_AUTH_ROLE=analyst/)).toBeInTheDocument();
    expect(screen.getByText(/AGENT_BOM_DEMO_ESTATE/)).toBeInTheDocument();
  });

  it("never leaks operator env-var config to a public demo visitor", () => {
    demoState.isDemoMode = true;
    render(
      <PermissionDeniedNotice
        session={session({ role: "viewer", auth_required: false })}
      />,
    );
    // The self-host env-var elevation steps must not reach a demo visitor.
    expect(screen.queryByText(/AGENT_BOM_NO_AUTH_ROLE/)).toBeNull();
    expect(screen.queryByText(/AGENT_BOM_DEMO_ESTATE/)).toBeNull();
    // A concise, neutral read-only line replaces them.
    expect(screen.getByText(/read-only public demo/i)).toBeInTheDocument();
  });

  it("renders as a collapsible details notice, not an always-open band", () => {
    const { container } = render(
      <PermissionDeniedNotice session={session({ role: "viewer" })} />,
    );
    const details = container.querySelector("details");
    expect(details).not.toBeNull();
    // Compact by default: the guidance is disclosed on demand, not pre-expanded.
    expect(details).not.toHaveAttribute("open");
    expect(container.querySelector("summary")).not.toBeNull();
  });

  it("attributes denial to environment policy when the current role is already sufficient", () => {
    render(<PermissionDeniedNotice session={session({ role: "admin", auth_required: false })} />);

    expect(screen.getByText(/This environment is read-only for this action/i)).toBeInTheDocument();
    expect(screen.getByText(/current role already meets the Contributor requirement/i)).toBeInTheDocument();
    expect(screen.queryByText(/Your Admin role is read-only/i)).not.toBeInTheDocument();
  });
});
