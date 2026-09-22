import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RelationshipBadge } from "@/components/relationship-edge";

describe("relationship badges", () => {
  it("keeps ownership and usage readable with different decorative icons", () => {
    const { container } = render(<>
      <RelationshipBadge relationship="owns">owns</RelationshipBadge>
      <RelationshipBadge relationship="uses">uses</RelationshipBadge>
    </>);
    expect(screen.getByText("owns")).toBeVisible();
    expect(screen.getByText("uses")).toBeVisible();
    const icons = container.querySelectorAll("svg");
    expect(icons).toHaveLength(2);
    expect(icons[0]!.innerHTML).not.toEqual(icons[1]!.innerHTML);
    for (const icon of icons) expect(icon).toHaveAttribute("aria-hidden", "true");
  });

  it("preserves unfamiliar recorded verbs with a neutral fallback icon", () => {
    render(<RelationshipBadge relationship="future_relation">future relation</RelationshipBadge>);
    expect(screen.getByText("future relation")).toBeVisible();
  });
});
