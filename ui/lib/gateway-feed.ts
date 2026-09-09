/** An authenticated submitter does not authenticate the reported producer. */
export function producerEvidenceLabel(assurance: unknown): string {
  return assurance === "caller_asserted" ? "Reported producer" : "Producer unknown";
}

export const PRODUCER_EVIDENCE_HINT =
  "Producer identity is not independently verified. Receipt freshness and retained event counts are separate evidence.";
