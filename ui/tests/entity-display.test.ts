import { describe, expect, it } from "vitest";

import {
  formatExposureEntityDisplay,
  formatExposurePathSequence,
} from "@/lib/entity-display";

describe("entity-display", () => {
  it("formats agent and server labels for executive-readable attack paths", () => {
    expect(formatExposureEntityDisplay("claude-desktop", "agent", { agent_type: "claude-desktop" })).toEqual({
      title: "Claude Desktop",
      subtitle: "Claude Desktop",
    });
    expect(formatExposureEntityDisplay("github", "server", { transport: "stdio", protocol: "mcp" })).toEqual({
      title: "GitHub connector",
      subtitle: "stdio MCP server",
    });
    expect(formatExposureEntityDisplay("github-enterprise MCP", "server", { transport: "sse", protocol: "mcp" })).toEqual({
      title: "Github Enterprise MCP",
      subtitle: "sse MCP server",
    });
  });

  it("splits package coordinates into name and version subtitle", () => {
    expect(formatExposureEntityDisplay("form-data@4.0.0", "package", { ecosystem: "npm" })).toEqual({
      title: "form-data",
      subtitle: "v4.0.0 · NPM",
    });
  });

  it("builds arrow-separated path titles", () => {
    expect(
      formatExposurePathSequence([
        { label: "claude-desktop", role: "agent", attributes: { agent_type: "claude-desktop" } },
        { label: "github", role: "server" },
        { label: "form-data@4.0.0", role: "package" },
        { label: "CVE-2025-7783", role: "finding" },
      ]),
    ).toBe("Claude Desktop → GitHub connector → form-data → CVE-2025-7783");
  });
});

it("entity kinds do not assert reachability or secret exposure without assessment", () => {
  expect(formatExposureEntityDisplay("CVE-fixture", "finding").subtitle).toBe("Vulnerability finding");
  expect(formatExposureEntityDisplay("TOKEN_REF", "credential").subtitle).toBe("Credential reference");
});

it("requires structured protocol evidence before calling a generic server MCP", () => {
  expect(formatExposureEntityDisplay("internal-api", "server").subtitle).toBe("Server");
  expect(formatExposureEntityDisplay("MCP production", "server", { transport: "http" }).subtitle).toBe("http server");
});
