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
    expect(images[0]?.getAttribute("src")).toMatch(/^\/brand\/mark-dark\.svg\?/);
    expect(images[1]?.getAttribute("src")).toMatch(/^\/brand\/wordmark-dark\.svg\?/);
    expect(images[1]).toHaveAttribute("alt", "agent-bom");
  });

  it("can hide the wordmark for compact placements", () => {
    const { container } = render(<BrandLogo showWordmark={false} />);
    const images = container.querySelectorAll("img");
    expect(images).toHaveLength(1);
    expect(images[0]?.getAttribute("src")).toMatch(/^\/brand\/mark-dark\.svg\?/);
  });

  it("does not render a lockup tagline", () => {
    const { container, queryByText } = render(<BrandLogo showTagline />);
    expect(queryByText("BOM for humans & agents")).not.toBeInTheDocument();
    expect(container.querySelectorAll("img")).toHaveLength(2);
  });
});
