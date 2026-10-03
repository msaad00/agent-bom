import { expect, it } from "vitest";
import { componentControlEvidence } from "@/lib/component-compliance-evidence";
import type { UnifiedNode, UnifiedEdge } from "@/lib/graph-schema";

const node = (id: string, attrs = {}, tags = ["CIS-1.1"], type = "misconfiguration") => ({ id, entity_type: type, attributes: attrs, compliance_tags: tags } as UnifiedNode);
const edge = { source: "check", target: "asset", relationship: "affects" } as UnifiedEdge;
it("tags and severity alone never imply an evaluated result", () => {
  const rows = componentControlEvidence("asset", [node("asset", { status: "pass" }, ["SOC2-CC6"], "package"), node("check")], [edge]);
  expect(rows.map(row => row.status)).toEqual(["not_evaluated", "not_evaluated"]);
});
it("uses explicit failed-check evidence only on the recorded affected resource", () => {
  const check = node("check", { check_id: "1.1", evaluation_status: "fail", evaluation_scope: "resource" });
  expect(componentControlEvidence("asset", [check], [edge])[0]?.status).toBe("recorded_fail");
  expect(componentControlEvidence("other", [check], [edge])).toEqual([]);
  expect(componentControlEvidence("asset", [check], [{ ...edge, relationship: "contains" }])[0]?.status).toBe("not_evaluated");
});
it("retains separate evidence for each node and each control tag", () => {
  const rows = componentControlEvidence("asset", [node("asset", {}, ["SOC2-CC6", "SOC2-CC6"], "package"), node("check", {}, ["CIS-1.1", "NIST-AC-2"])], [edge]);
  expect(rows).toHaveLength(3);
  expect(new Set(rows.map(row => row.node.id))).toEqual(new Set(["asset", "check"]));
});
it("ignores unrelated nodes with identical labels and distinguishes account scope", () => {
  const check = node("check", { check_id: "1.1", evaluation_status: "fail", evaluation_scope: "account" });
  const rows = componentControlEvidence("asset", [check, node("unrelated")], [edge]);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.scope).toBe("account");
});
