import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PaginationBar } from "@/components/pagination-bar";

describe("PaginationBar continuation state", () => {
  it("surfaces an unknown total without disabling an available continuation", () => {
    const onNext = vi.fn();
    render(
      <PaginationBar
        page={2}
        totalPages={null}
        totalItems={null}
        hasMore
        itemLabel="findings"
        onPrevious={() => {}}
        onNext={onNext}
      />,
    );

    expect(screen.getByText("Page 2 · total unavailable")).toBeInTheDocument();
    const next = screen.getByRole("button", { name: /Next/i });
    expect(next).toBeEnabled();
    fireEvent.click(next);
    expect(onNext).toHaveBeenCalledOnce();
  });
});
