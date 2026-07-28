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

function completenessLabel(
  returned: number | null,
  scopeTotal: number | null,
  snapshotTotal: number | null,
  status: string | null,
): string {
  if (returned === null) return "Unavailable";
  if (status === "truncated" || status === "sampled") {
    return snapshotTotal === null
      ? `${returned.toLocaleString()} nodes returned`
      : `${returned.toLocaleString()} nodes returned · ${snapshotTotal.toLocaleString()} nodes in snapshot`;
  }
  const denominator = snapshotTotal ?? scopeTotal;
  return denominator === null
    ? `${returned.toLocaleString()} nodes in current scope`
    : `${returned.toLocaleString()} of ${denominator.toLocaleString()} nodes in current scope`;
}

function completenessDetail(status: string | null, reason: string | null): string {
  if (status === "complete") return "Complete for current scope";
  const value = reason || status;
  if (!value) return "Unavailable";
  const normalized = value.replaceAll("_", " ");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

export function GraphEvidenceSummary({
  capturedAt,
  returnedNodes,
  totalNodes,
  snapshotTotalNodes,
  evidencedEdges,
  totalEdges,
  completeness,
  completenessReason = null,
  showCompleteness = true,
  showRelationships = true,
}: {
  capturedAt: string | null;
  returnedNodes: number | null;
  totalNodes: number | null;
  snapshotTotalNodes: number | null;
  evidencedEdges: number | null;
  totalEdges: number | null;
  completeness: string | null;
  completenessReason?: string | null;
  showCompleteness?: boolean;
  showRelationships?: boolean;
}) {
  const items: Array<{ label: string; value: string; detail?: string }> = [
    {
      label: "Snapshot freshness",
      value: capturedLabel(capturedAt),
      ...(capturedAt ? { detail: "Captured" } : {}),
    },
  ];
  if (showCompleteness) {
    items.push({
      label: "Completeness",
      value: completenessLabel(
        returnedNodes,
        totalNodes,
        snapshotTotalNodes,
        completeness,
      ),
      detail: completenessDetail(completeness, completenessReason),
    });
  }
  if (showRelationships) {
    items.push({
      label: "Relationship provenance",
      value: countLabel(evidencedEdges, totalEdges, "relationships"),
      detail: evidencedEdges === null ? "Evidence metadata not reported" : "with evidence metadata",
    });
  }

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
