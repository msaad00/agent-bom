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
});
