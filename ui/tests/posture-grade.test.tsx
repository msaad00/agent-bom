import { render, screen } from "@testing-library/react";
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
});
