"use client";

import { useMemo, useState } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  createColumnHelper,
  SortingState,
  ColumnFiltersState,
} from "@tanstack/react-table";
import {
  ComplianceResponse,
  ComplianceControl,
  OWASP_LLM_TOP10,
  OWASP_MCP_TOP10,
  OWASP_AGENTIC_TOP10,
  EU_AI_ACT,
  MITRE_ATLAS,
  NIST_AI_RMF,
} from "@/lib/api";
import {
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Download,
  Search,
  Filter,
} from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────

interface MatrixRow {
  framework: string;
  code: string;
  name: string;
  status: "pass" | "warning" | "fail";
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  affectedPackages: string[];
  affectedAgents: string[];
}

// ─── Data transform ──────────────────────────────────────────────────────────

const FRAMEWORK_MAP: Array<{
  key: keyof ComplianceResponse;
  label: string;
  catalog: Record<string, string>;
}> = [
  { key: "owasp_llm_top10", label: "OWASP LLM", catalog: OWASP_LLM_TOP10 },
  { key: "owasp_mcp_top10", label: "OWASP MCP", catalog: OWASP_MCP_TOP10 },
  { key: "owasp_agentic_top10", label: "OWASP Agentic", catalog: OWASP_AGENTIC_TOP10 },
  { key: "mitre_atlas", label: "MITRE ATLAS", catalog: MITRE_ATLAS },
  { key: "nist_ai_rmf", label: "NIST AI RMF", catalog: NIST_AI_RMF },
  { key: "eu_ai_act", label: "EU AI Act", catalog: EU_AI_ACT },
];

function flattenControls(data: ComplianceResponse): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const { key, label, catalog } of FRAMEWORK_MAP) {
    const controls = data[key] as ComplianceControl[];
    for (const c of controls) {
      rows.push({
        framework: label,
        code: c.code,
        name: catalog[c.code] ?? c.name,
        status: c.status,
        findings: c.findings,
        critical: c.severity_breakdown.critical ?? 0,
        high: c.severity_breakdown.high ?? 0,
        medium: c.severity_breakdown.medium ?? 0,
        low: c.severity_breakdown.low ?? 0,
        affectedPackages: c.affected_packages,
        affectedAgents: c.affected_agents,
      });
    }
  }
  return rows;
}

// ─── Column definitions ──────────────────────────────────────────────────────

const col = createColumnHelper<MatrixRow>();

const columns = [
  col.accessor("framework", {
    header: "Framework",
    cell: (info) => (
      <span className="text-xs font-medium text-zinc-400">
        {info.getValue()}
      </span>
    ),
    filterFn: "equals",
  }),
  col.accessor("code", {
    header: "Control",
    cell: (info) => (
      <span className="font-mono text-xs font-semibold text-zinc-200">
        {info.getValue()}
      </span>
    ),
  }),
  col.accessor("name", {
    header: "Description",
    cell: (info) => (
      <span className="text-xs text-zinc-400 leading-snug">
        {info.getValue()}
      </span>
    ),
  }),
  col.accessor("status", {
    header: "Status",
    cell: (info) => {
      const s = info.getValue();
      const styles = {
        pass: "bg-emerald-950 text-emerald-300 border-emerald-800",
        warning: "bg-yellow-950 text-yellow-300 border-yellow-800",
        fail: "bg-red-950 text-red-300 border-red-800",
      };
      const labels = { pass: "Pass", warning: "Warning", fail: "Fail" };
      return (
        <span
          className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${styles[s]}`}
        >
          {labels[s]}
        </span>
      );
    },
    filterFn: "equals",
  }),
  col.accessor("findings", {
    header: "Findings",
    cell: (info) => {
      const v = info.getValue();
      return (
        <span
          className={`font-mono text-xs ${v > 0 ? "text-zinc-200" : "text-zinc-700"}`}
        >
          {v}
        </span>
      );
    },
  }),
  col.accessor("critical", {
    header: "Crit",
    cell: (info) => {
      const v = info.getValue();
      return v > 0 ? (
        <span className="font-mono text-xs font-semibold text-red-400">
          {v}
        </span>
      ) : (
        <span className="text-zinc-700">—</span>
      );
    },
  }),
  col.accessor("high", {
    header: "High",
    cell: (info) => {
      const v = info.getValue();
      return v > 0 ? (
        <span className="font-mono text-xs font-semibold text-orange-400">
          {v}
        </span>
      ) : (
        <span className="text-zinc-700">—</span>
      );
    },
  }),
  col.accessor("medium", {
    header: "Med",
    cell: (info) => {
      const v = info.getValue();
      return v > 0 ? (
        <span className="font-mono text-xs text-yellow-400">{v}</span>
      ) : (
        <span className="text-zinc-700">—</span>
      );
    },
  }),
  col.accessor("low", {
    header: "Low",
    cell: (info) => {
      const v = info.getValue();
      return v > 0 ? (
        <span className="font-mono text-xs text-blue-400">{v}</span>
      ) : (
        <span className="text-zinc-700">—</span>
      );
    },
  }),
  col.accessor("affectedPackages", {
    header: "Packages",
    cell: (info) => {
      const pkgs = info.getValue();
      if (pkgs.length === 0) return <span className="text-zinc-700">—</span>;
      return (
        <span className="text-xs text-zinc-500" title={pkgs.join(", ")}>
          {pkgs.length} pkg{pkgs.length !== 1 ? "s" : ""}
        </span>
      );
    },
    enableSorting: false,
  }),
];

// ─── CSV export ──────────────────────────────────────────────────────────────

function exportCsv(rows: MatrixRow[]) {
  const header =
    "Framework,Control,Description,Status,Findings,Critical,High,Medium,Low,Packages,Agents\n";
  const body = rows
    .map(
      (r) =>
        `"${r.framework}","${r.code}","${r.name.replace(/"/g, '""')}",${r.status},${r.findings},${r.critical},${r.high},${r.medium},${r.low},"${r.affectedPackages.join("; ")}","${r.affectedAgents.join("; ")}"`
    )
    .join("\n");
  const blob = new Blob([header + body], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "compliance-matrix.csv";
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Component ───────────────────────────────────────────────────────────────

export function ComplianceMatrix({ data }: { data: ComplianceResponse }) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [globalFilter, setGlobalFilter] = useState("");

  const rows = useMemo(() => flattenControls(data), [data]);

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, columnFilters, globalFilter },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  const frameworks = useMemo(
    () => [...new Set(rows?.map((r) => r.framework))],
    [rows]
  );
  const activeFramework =
    (columnFilters.find((f) => f.id === "framework")?.value as string) ?? "";
  const activeStatus =
    (columnFilters.find((f) => f.id === "status")?.value as string) ?? "";

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
          <input
            type="text"
            placeholder="Search controls..."
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-9 pr-3 py-2 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
        </div>

        {/* Framework filter */}
        <div className="flex items-center gap-1">
          <Filter className="w-3.5 h-3.5 text-zinc-500" />
          <select
            value={activeFramework}
            onChange={(e) => {
              const val = e.target.value;
              setColumnFilters((prev) => {
                const without = prev.filter((f) => f.id !== "framework");
                return val ? [...without, { id: "framework", value: val }] : without;
              });
            }}
            className="bg-zinc-900 border border-zinc-800 rounded-lg px-2 py-1.5 text-xs text-zinc-300 focus:outline-none focus:border-zinc-600"
          >
            <option value="">All frameworks</option>
            {frameworks?.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </div>

        {/* Status filter */}
        <div className="flex gap-1">
          {(["", "pass", "warning", "fail"] as const).map((s) => (
            <button
              key={s}
              onClick={() => {
                setColumnFilters((prev) => {
                  const without = prev.filter((f) => f.id !== "status");
                  return s ? [...without, { id: "status", value: s }] : without;
                });
              }}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-medium border transition-colors ${
                activeStatus === s
                  ? "bg-emerald-600 text-white border-emerald-600"
                  : "bg-zinc-900 text-zinc-400 border-zinc-800 hover:border-zinc-600"
              }`}
            >
              {s === "" ? "All" : s === "pass" ? "Pass" : s === "warning" ? "Warn" : "Fail"}
            </button>
          ))}
        </div>

        {/* Export */}
        <button
          onClick={() => exportCsv(table.getFilteredRowModel().rows?.map((r) => r.original))}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 border border-zinc-700 rounded-lg text-xs text-zinc-300 hover:text-zinc-100 hover:border-zinc-600 transition-colors ml-auto"
        >
          <Download className="w-3.5 h-3.5" />
          CSV
        </button>
      </div>

      {/* Count */}
      <div className="text-xs text-zinc-600">
        {table.getFilteredRowModel().rows.length} of {rows.length} controls
      </div>

      {/* Table */}
      <div className="border border-zinc-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900 border-b border-zinc-800">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers?.map((header) => (
                    <th
                      key={header.id}
                      className="text-left px-3 py-2.5 text-[10px] font-medium text-zinc-500 uppercase tracking-wider whitespace-nowrap"
                    >
                      {header.isPlaceholder ? null : (
                        <button
                          className={`flex items-center gap-1 ${
                            header.column.getCanSort()
                              ? "cursor-pointer select-none hover:text-zinc-300"
                              : ""
                          }`}
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                          {header.column.getCanSort() && (
                            <>
                              {header.column.getIsSorted() === "asc" ? (
                                <ArrowUp className="w-3 h-3" />
                              ) : header.column.getIsSorted() === "desc" ? (
                                <ArrowDown className="w-3 h-3" />
                              ) : (
                                <ArrowUpDown className="w-3 h-3 opacity-30" />
                              )}
                            </>
                          )}
                        </button>
                      )}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-zinc-800/50 bg-zinc-950">
              {table.getRowModel().rows?.map((row) => (
                <tr
                  key={row.id}
                  className="hover:bg-zinc-900/50 transition-colors"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-3 py-2.5">
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
