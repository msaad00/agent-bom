"use client";

function countLabel(value: number | null, total: number | null, noun: string): string {
  if (value === null || total === null) return "Unavailable";
  return `${value.toLocaleString()} of ${total.toLocaleString()} ${noun}`;
}

function capturedLabel(value: string | null): string {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString();
}

export function GraphEvidenceSummary({
  capturedAt,
  returnedNodes,
  totalNodes,
  evidencedEdges,
  totalEdges,
  completeness,
}: {
  capturedAt: string | null;
  returnedNodes: number | null;
  totalNodes: number | null;
  evidencedEdges: number | null;
  totalEdges: number | null;
  completeness: string | null;
}) {
  const items = [
    {
      label: "Snapshot freshness",
      value: capturedLabel(capturedAt),
      detail: capturedAt ? "Captured" : undefined,
    },
    {
      label: "Completeness",
      value: countLabel(returnedNodes, totalNodes, "nodes"),
      detail: completeness ? completeness.replaceAll("_", " ") : "Unavailable",
    },
    {
      label: "Relationship provenance",
      value: countLabel(evidencedEdges, totalEdges, "relationships"),
      detail: evidencedEdges === null ? "Evidence metadata not reported" : "with evidence metadata",
    },
  ];

  return (
    <section aria-label="Graph evidence status" className="graph-evidence-summary">
      {items.map(({ label, value, detail }) => (
        <div key={label} className="graph-evidence-item">
          <div className="graph-evidence-label">
            {label}
          </div>
          <p className="graph-evidence-value" title={value}>{value}</p>
          {detail ? <p className="graph-evidence-detail">{detail}</p> : null}
        </div>
      ))}
    </section>
  );
}
