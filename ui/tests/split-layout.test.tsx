import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SplitLayout } from "@/components/split-layout";

describe("SplitLayout", () => {
  it("renders both master and detail panes", () => {
    render(
      <SplitLayout master={<div>list pane</div>} detail={<div>detail pane</div>} />,
    );
    expect(screen.getByText("list pane")).toBeInTheDocument();
    expect(screen.getByText("detail pane")).toBeInTheDocument();
  });

  it("shows the placeholder when no detail is selected", () => {
    render(
      <SplitLayout
        master={<div>list pane</div>}
        detail={null}
        placeholder="Pick a row"
      />,
    );
    expect(screen.getByText("Pick a row")).toBeInTheDocument();
  });

  it("applies the master width as a CSS custom property", () => {
    render(
      <SplitLayout
        master={<div>list pane</div>}
        detail={<div>detail pane</div>}
        masterWidth="30rem"
      />,
    );
    const master = screen.getByText("list pane").parentElement;
    expect(master?.style.getPropertyValue("--split-master-w")).toBe("30rem");
  });

  it("reverses pane order when detailFirst is set", () => {
    const { container } = render(
      <SplitLayout master={<div>list</div>} detail={<div>detail</div>} detailFirst />,
    );
    expect(container.firstChild).toHaveClass("md:flex-row-reverse");
  });
});
