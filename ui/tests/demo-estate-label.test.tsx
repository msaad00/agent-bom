import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DemoEstateLabel } from "@/components/demo-estate-label";

vi.mock("@/lib/use-capture-mode", () => ({ useCaptureMode: () => true, useReferenceEvidenceLabMode: () => false }));
vi.mock("@/hooks/use-deployment-context", () => ({ useDeploymentContext: () => ({ counts: null }) }));

describe("DemoEstateLabel", () => {
  it("keeps disclosure in document flow so it cannot cover graph controls", () => {
    render(<DemoEstateLabel />);
    const badge = screen.getByRole("link", { name: "Open the synthetic enterprise demo story" });
    expect(badge).toHaveTextContent("Demo data — sample environment");
    expect(badge).toHaveClass("block");
    expect(badge.className).not.toMatch(/(?:^|\s)(?:sm:)?(?:fixed|absolute)(?:\s|$)/);
  });
});
