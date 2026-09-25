import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphRollupChildPager } from "@/components/graph-rollup-child-pager";
import type { GraphRollupPagination } from "@/lib/api-types";

const firstPage: GraphRollupPagination = { offset: 0, limit: 200, returned: 200, total: 250, has_more: true, next_offset: 200 };

describe("GraphRollupChildPager", () => {
  it("states the returned slice of the total and requests the next page", () => {
    const onPage = vi.fn();
    render(<GraphRollupChildPager pagination={firstPage} onPage={onPage} />);
    expect(screen.getByText("Showing 1–200 of 250 direct children")).toBeVisible();
    expect(screen.getByRole("button", { name: "Previous children" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next children" }));
    expect(onPage).toHaveBeenCalledWith(200);
  });

  it("steps back by the page size from the last page", () => {
    const onPage = vi.fn();
    render(
      <GraphRollupChildPager
        pagination={{ offset: 200, limit: 200, returned: 50, total: 250, has_more: false, next_offset: null }}
        onPage={onPage}
      />,
    );
    expect(screen.getByText("Showing 201–250 of 250 direct children")).toBeVisible();
    expect(screen.getByRole("button", { name: "Next children" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Previous children" }));
    expect(onPage).toHaveBeenCalledWith(0);
  });

  it("renders nothing when every child fits in one page or metadata is absent", () => {
    const { container, rerender } = render(<GraphRollupChildPager onPage={() => undefined} />);
    expect(container).toBeEmptyDOMElement();
    rerender(
      <GraphRollupChildPager
        pagination={{ offset: 0, limit: 200, returned: 3, total: 3, has_more: false, next_offset: null }}
        onPage={() => undefined}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
