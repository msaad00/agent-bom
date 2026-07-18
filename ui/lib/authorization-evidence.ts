import type { AuthorizationEvidenceSummary } from "@/lib/api-types";

export function authorizationEvidenceCopy(summary: AuthorizationEvidenceSummary): {
  label: "Complete" | "Partial" | "Indeterminate";
  detail: string;
} {
  if (summary.status === "complete") {
    return {
      label: "Complete",
      detail: `${summary.complete_source_count} of ${summary.required_source_count} required evidence sources are complete for this scan.`,
    };
  }
  if (summary.status === "partial") {
    return {
      label: "Partial",
      detail: `${summary.complete_source_count} of ${summary.required_source_count} required evidence sources are complete. Authorization decisions may remain indeterminate.`,
    };
  }
  return {
    label: "Indeterminate",
    detail: "Authorization evidence is not conclusive for this scan. No allow or deny should be inferred.",
  };
}
