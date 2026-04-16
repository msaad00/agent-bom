import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  PostureGrade,
  postureDimensionHint,
  postureDimensionHref,
  postureDimensionTone,
} from "@/components/posture-grade";

describe("posture-grade helpers", () => {
  it("maps dimension labels to evidence destinations", () => {
    expect(postureDimensionHref("vulnerability_exposure", "Vulnerability Exposure")).toBe("/findings");
    expect(postureDimensionHref("credential_reach", "Credential Reach")).toBe("/mesh");
    expect(postureDimensionHref("runtime_watch", "Runtime Watch")).toBe("/proxy");
  });

  it("returns readable drilldown hints", () => {
    expect(postureDimensionHint("agent_trust", "Agent Trust")).toBe("discovery and trust");
    expect(postureDimensionHint("framework_alignment", "Framework Alignment")).toBe("policy and controls");
  });

  it("assigns score tones consistently", () => {
    expect(postureDimensionTone(85).label).toBe("strong");
    expect(postureDimensionTone(70).label).toBe("watch");
    expect(postureDimensionTone(40).label).toBe("critical");
  });
});

describe("PostureGrade", () => {
  it("renders linked score breakdown rows when drilldown is enabled", () => {
    render(
      <PostureGrade
        grade="B"
        score={78}
        drilldown
        dimensions={{
          vulnerability_exposure: {
            label: "Vulnerability Exposure",
            score: 81,
            details: "High-risk packages remain reachable by agents.",
          },
          credential_reach: {
            label: "Credential Reach",
            score: 58,
          },
        }}
      />,
    );

    expect(screen.getByRole("link", { name: /Vulnerability Exposure/i })).toHaveAttribute("href", "/findings");
    expect(screen.getByRole("link", { name: /Credential Reach/i })).toHaveAttribute("href", "/mesh");
    expect(screen.getByText("High-risk packages remain reachable by agents.")).toBeInTheDocument();
  });

  it("renders one unified panel with a collapsible evidence breakdown", () => {
    render(
      <PostureGrade
        grade="F"
        score={40.4}
        drilldown
        variant="panel"
        summary="Weak security posture driven by credential exposure and undeclared MCP tools."
        dimensions={{
          vulnerability_exposure: {
            label: "Packages and CVEs",
            score: 10,
            details: "44 vulnerable packages remain in scope.",
          },
          credential_reach: {
            label: "Reach and exposure",
            score: 23,
            details: "7 credentials remain exposed across reachable agents.",
          },
        }}
      />,
    );

    expect(screen.getByText(/Weak security posture driven by credential exposure/i)).toBeInTheDocument();
    expect(screen.queryByText("44 vulnerable packages remain in scope.")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Show evidence breakdown/i }));

    expect(screen.getByText("44 vulnerable packages remain in scope.")).toBeInTheDocument();
    const packageLinks = screen.getAllByRole("link", { name: /Packages and CVEs/i });
    expect(packageLinks[0]).toHaveAttribute("href", "/findings");
  });
});
