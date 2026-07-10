import { describe, expect, it } from "vitest";

import type { AuthMeResponse } from "@/lib/api";
import { defaultOverviewPersona } from "@/lib/overview-persona";

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
  it("defaults analysts and admins to engineer lens", () => {
    expect(defaultOverviewPersona(session("analyst"))).toBe("engineer");
    expect(defaultOverviewPersona(session("admin"))).toBe("engineer");
    expect(defaultOverviewPersona(session("viewer", "contributor"))).toBe("engineer");
  });

  it("defaults viewers to executive lens", () => {
    expect(defaultOverviewPersona(session("viewer"))).toBe("executive");
    expect(defaultOverviewPersona(null)).toBe("executive");
  });
});
