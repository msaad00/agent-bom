import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { GraphCompletenessBanner } from "@/components/graph-completeness-banner";

describe("GraphCompletenessBanner", () => {
  it("hides when the result set is complete", () => {
    const { container } = render(
      <GraphCompletenessBanner
        completeness={{
          status: "complete",
          complete: true,
          truncated: false,
          sampled: false,
          returned: 10,
          total: 10,
        }}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows visible/omitted honesty and load-more", async () => {
    const user = userEvent.setup();
    const onLoadMore = vi.fn();
    render(
      <GraphCompletenessBanner
        visibleCount={12}
        omittedCount={40}
        onLoadMore={onLoadMore}
      />,
    );
    expect(screen.getByTestId("graph-completeness-banner")).toHaveTextContent(
      "Showing 12 of 52",
    );
    expect(screen.getByText(/40 omitted/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Load more/i }));
    expect(onLoadMore).toHaveBeenCalled();
  });

  it("does not invent an exhaustive total for traversal-budget truncation", () => {
    render(
      <GraphCompletenessBanner
        completeness={{
          status: "truncated",
          complete: false,
          truncated: true,
          sampled: false,
          returned: 2,
          reason: "traversal_budget",
        }}
      />,
    );

    expect(screen.getByTestId("graph-completeness-banner")).toHaveTextContent(
      "Showing 2 items",
    );
    expect(screen.getByText("traversal_budget")).toBeInTheDocument();
    expect(screen.queryByText(/2 of 2/i)).not.toBeInTheDocument();
  });
});

describe("counts always reconcile", () => {
  it("never claims to show more than the total", () => {
    // Observed live: "Showing 5,264 of 4,904 · 4,798 omitted".
    // `returned` and `total` came from the API envelope while `omitted` came
    // from the local prop, so three numbers from two derivations landed in one
    // sentence and none of them added up. Shown > total is arithmetically
    // impossible and reads as a broken product.
    render(
      <GraphCompletenessBanner
        completeness={{ returned: 5264, total: 4904, truncated: true }}
        visibleCount={5264}
        omittedCount={4798}
      />,
    );

    const text = screen.getByTestId("graph-completeness-banner").textContent ?? "";
    const shown = Number((text.match(/Showing ([\d,]+)/)?.[1] ?? "0").replace(/,/g, ""));
    const total = Number((text.match(/of ([\d,]+)/)?.[1] ?? "0").replace(/,/g, ""));

    expect(shown).toBeLessThanOrEqual(total);
  });

  it("keeps shown + omitted equal to the total", () => {
    render(
      <GraphCompletenessBanner
        completeness={{ returned: 5264, total: 4904, truncated: true }}
        visibleCount={5264}
        omittedCount={4798}
      />,
    );

    const text = screen.getByTestId("graph-completeness-banner").textContent ?? "";
    const shown = Number((text.match(/Showing ([\d,]+)/)?.[1] ?? "0").replace(/,/g, ""));
    const total = Number((text.match(/of ([\d,]+)/)?.[1] ?? "0").replace(/,/g, ""));
    const omitted = Number((text.match(/([\d,]+) omitted/)?.[1] ?? "0").replace(/,/g, ""));

    expect(shown + omitted).toBe(total);
  });

  it("prefers the API envelope wholesale rather than blending sources", () => {
    // One derivation per sentence: if the envelope supplies the numbers, the
    // local props must not contribute a third value to the same sentence.
    render(
      <GraphCompletenessBanner
        completeness={{ returned: 300, total: 5000, truncated: true }}
        visibleCount={999}
        omittedCount={111}
      />,
    );

    const text = screen.getByTestId("graph-completeness-banner").textContent ?? "";
    expect(text).toContain("300");
    expect(text).toContain("5,000");
    expect(text).toContain("4,700");
    expect(text).not.toContain("111");
  });
});
