import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { FirstRunJourney } from "@/components/first-run-journey";
import type { AuthMeResponse } from "@/lib/api";

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    ...rest
  }: {
    href: string;
    children: React.ReactNode;
  } & React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

function session(overrides: Partial<AuthMeResponse> = {}): AuthMeResponse {
  return {
    authenticated: true,
    auth_required: false,
    configured_modes: [],
    recommended_ui_mode: "no_auth",
    auth_method: "no_auth",
    subject: null,
    tenant_id: "default",
    role: "analyst",
    role_summary: null,
    memberships: [],
    request_id: null,
    trace_id: null,
    span_id: null,
    ...overrides,
  };
}

describe("FirstRunJourney", () => {
  it("marks connect as current on a fresh instance and exposes the connect action", () => {
    const onConnect = vi.fn();
    render(
      <FirstRunJourney
        connectionsCount={0}
        scanCount={0}
        findingsCount={0}
        canManage
        session={session()}
        onConnect={onConnect}
      />,
    );

    expect(screen.getByTestId("first-run-journey")).toBeInTheDocument();
    expect(screen.getByText("0 of 3 done")).toBeInTheDocument();
    expect(screen.getByTestId("journey-step-connect")).toHaveAttribute(
      "data-status",
      "current",
    );

    fireEvent.click(screen.getByRole("button", { name: /Connect cloud account/ }));
    expect(onConnect).toHaveBeenCalledTimes(1);
  });

  it("checks a step off only when the estate really has it (honest progress)", () => {
    render(
      <FirstRunJourney
        connectionsCount={2}
        scanCount={0}
        findingsCount={0}
        canManage
        session={session()}
        onConnect={vi.fn()}
      />,
    );
    // Connected is real → done; scan is the current step; results still todo.
    expect(screen.getByText("1 of 3 done")).toBeInTheDocument();
    expect(screen.getByTestId("journey-step-connect")).toHaveAttribute("data-status", "done");
    expect(screen.getByTestId("journey-step-scan")).toHaveAttribute("data-status", "current");
    expect(screen.getByTestId("journey-step-results")).toHaveAttribute("data-status", "todo");
  });

  it("disappears once the whole journey is complete (no clutter on a live instance)", () => {
    const { container } = render(
      <FirstRunJourney
        connectionsCount={1}
        scanCount={3}
        findingsCount={12}
        canManage
        session={session()}
        onConnect={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a viewer the elevation path instead of a dead connect button", () => {
    render(
      <FirstRunJourney
        connectionsCount={0}
        scanCount={0}
        findingsCount={0}
        canManage={false}
        session={session({ role: "viewer", auth_required: false })}
        onConnect={vi.fn()}
      />,
    );
    expect(
      screen.queryByRole("button", { name: /Connect cloud account/ }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/AGENT_BOM_NO_AUTH_ROLE=analyst/)).toBeInTheDocument();
  });
});
