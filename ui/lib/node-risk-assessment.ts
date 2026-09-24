/** A numeric graph-node score alone does not establish an assessment. */
export interface NodeRiskAssessment {
  status: "assessed" | "not_assessed";
  basis: string | null;
  scope: string | null;
}

export function nodeRiskAssessment(value: unknown): NodeRiskAssessment {
  const record = (value ?? {}) as Record<string, unknown>;
  const basis = typeof record.basis === "string" ? record.basis.trim() : "";
  const scope = typeof record.scope === "string" ? record.scope.trim() : "";
  return record.status === "assessed" && basis && scope
    ? { status: "assessed", basis, scope }
    : { status: "not_assessed", basis: null, scope: null };
}

export function nodeRiskLabel(score: number | undefined, assessment: unknown): string {
  if (nodeRiskAssessment(assessment).status !== "assessed") return "Not assessed";
  return typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : "Unavailable";
}
