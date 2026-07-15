import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DataTable, type DataTableColumn } from "@/components/data-table";

type Row = { id: string; pkg: string; cvss: number };

const rows: Row[] = [
  { id: "a", pkg: "left-pad", cvss: 9.8 },
  { id: "b", pkg: "log4j", cvss: 10 },
];

const columns: DataTableColumn<Row>[] = [
  { key: "pkg", header: "Package", cell: (r) => r.pkg },
  { key: "cvss", header: "CVSS", align: "right", sortable: true, cell: (r) => r.cvss.toFixed(1) },
];

describe("DataTable", () => {
  it("renders headers and row cells", () => {
    render(<DataTable rows={rows} columns={columns} rowKey={(r) => r.id} />);
    expect(screen.getByRole("columnheader", { name: /Package/ })).toBeInTheDocument();
    expect(screen.getByText("left-pad")).toBeInTheDocument();
    expect(screen.getByText("10.0")).toBeInTheDocument();
  });

  it("fires onRowClick for pointer and keyboard activation", () => {
    const onRowClick = vi.fn();
    render(
      <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} onRowClick={onRowClick} />,
    );
    const firstRow = screen.getByRole("button", { name: /left-pad/ });
    fireEvent.click(firstRow);
    fireEvent.keyDown(firstRow, { key: "Enter" });
    expect(onRowClick).toHaveBeenCalledTimes(2);
    expect(onRowClick).toHaveBeenCalledWith(rows[0]);
  });

  it("reflects the active sort on the sortable header", () => {
    const onSortChange = vi.fn();
    render(
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        sort={{ key: "cvss", direction: "desc" }}
        onSortChange={onSortChange}
      />,
    );
    const header = screen.getByRole("columnheader", { name: /CVSS/ });
    expect(header).toHaveAttribute("aria-sort", "descending");
    fireEvent.click(screen.getByRole("button", { name: /CVSS/ }));
    expect(onSortChange).toHaveBeenCalledWith("cvss");
  });

  it("marks the selected row via data-selected", () => {
    render(
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        onRowClick={vi.fn()}
        selectedKey="b"
      />,
    );
    const selected = screen.getByRole("button", { name: /log4j/ });
    expect(selected).toHaveAttribute("data-selected", "true");
    expect(selected).toHaveAttribute("aria-pressed", "true");
  });

  it("shows the empty state when there are no rows", () => {
    render(
      <DataTable rows={[]} columns={columns} rowKey={(r) => r.id} empty="Nothing here" />,
    );
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("renders skeleton rows while loading and hides the empty state", () => {
    const { container } = render(
      <DataTable
        rows={[]}
        columns={columns}
        rowKey={(r) => r.id}
        loading
        loadingRows={3}
        empty="Nothing here"
      />,
    );
    expect(screen.queryByText("Nothing here")).toBeNull();
    expect(container.querySelectorAll("tbody tr")).toHaveLength(3);
  });
});
