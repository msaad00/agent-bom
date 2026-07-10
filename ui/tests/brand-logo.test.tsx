import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { BrandLogo } from "@/components/brand-logo";

vi.mock("@/lib/theme-mode", () => ({
  useThemeMode: () => "dark",
}));

describe("BrandLogo", () => {
  it("renders canonical mark and wordmark assets for the active theme", () => {
    const { container } = render(<BrandLogo />);
    const images = container.querySelectorAll("img");
    expect(images).toHaveLength(2);
    expect(images[0]?.getAttribute("src")).toBe("/brand/mark-dark.svg");
    expect(images[1]?.getAttribute("src")).toBe("/brand/wordmark-dark.svg");
    expect(images[1]).toHaveAttribute("alt", "agent-bom");
  });

  it("can hide the wordmark for compact placements", () => {
    const { container } = render(<BrandLogo showWordmark={false} />);
    const images = container.querySelectorAll("img");
    expect(images).toHaveLength(1);
    expect(images[0]).toHaveAttribute("src", "/brand/mark-dark.svg");
  });

  it("renders the canonical tagline when requested", () => {
    const { getByText } = render(<BrandLogo showTagline />);
    expect(getByText("AI supply-chain & infrastructure security")).toBeInTheDocument();
  });
});
