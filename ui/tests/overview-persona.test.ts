import { describe, expect, it } from "vitest";

import type { AuthMeResponse } from "@/lib/api";
import {
  defaultOverviewPersona,
  overviewPersonaDrillDown,
  overviewPersonaZoomOut,
} from "@/lib/overview-persona";

function session(role: string, uiRole = ""): AuthMeResponse {
  return {
    authenticated: true,
    auth_required: true,
    configured_modes: [],
    recommended_ui_mode: "session_api_key",
    auth_method: "api_key",
    subject: "user",
    tenant_id: "default",
    role,
    role_summary: uiRole
      ? {
          role,
          ui_role: uiRole,
          display_name: role,
          description: "",
          capabilities: [],
          capability_matrix: [],
          can_see: [],
          can_do: [],
          cannot_do: [],
        }
      : null,
    memberships: [],
    request_id: null,
    trace_id: null,
    span_id: null,
  };
}

describe("defaultOverviewPersona", () => {
  it("defaults analysts and admins to engineer altitude", () => {
    expect(defaultOverviewPersona(session("analyst"))).toBe("engineer");
    expect(defaultOverviewPersona(session("admin"))).toBe("engineer");
    expect(defaultOverviewPersona(session("viewer", "contributor"))).toBe("engineer");
  });

  it("defaults auditors to trust altitude", () => {
    expect(defaultOverviewPersona(session("auditor"))).toBe("trust");
    expect(defaultOverviewPersona(session("viewer", "compliance"))).toBe("trust");
  });

  it("defaults viewers to CISO altitude", () => {
    expect(defaultOverviewPersona(session("viewer"))).toBe("ciso");
    expect(defaultOverviewPersona(null)).toBe("ciso");
  });
});

describe("overview altitude navigation", () => {
  it("drills down CISO → Trust → Engineer", () => {
    expect(overviewPersonaDrillDown("ciso")).toBe("trust");
    expect(overviewPersonaDrillDown("trust")).toBe("engineer");
    expect(overviewPersonaDrillDown("engineer")).toBeNull();
  });

  it("zooms out Engineer → Trust → CISO", () => {
    expect(overviewPersonaZoomOut("engineer")).toBe("trust");
    expect(overviewPersonaZoomOut("trust")).toBe("ciso");
    expect(overviewPersonaZoomOut("ciso")).toBeNull();
  });
});
