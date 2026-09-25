import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { AdminAssessment } from "@/components/persisted-context-view";

it.each([["admin", "Admin"], ["conditional_admin", "Conditional admin"], ["not_admin", "Not admin"], ["unknown", "Unknown"]])("displays %s without conflating authority states", (status, label) => {
  render(<AdminAssessment attributes={{ admin_equivalence_status: status }} />);
  expect(screen.getByText(label, { selector: "strong" })).toBeInTheDocument();
});
it("discloses conditional evidence and recorded resource scope", () => {
  render(<AdminAssessment attributes={{ admin_equivalence_status: "conditional_admin", admin_equivalence_resource_scopes: ["arn:aws:iam::123456789012:*"] }} />);
  expect(screen.getByText(/request context has not been verified/)).toBeInTheDocument();
  expect(screen.getByText(/Scope: arn:aws:iam::123456789012/)).toBeInTheDocument();
});
it.each([
  [{ escalates_to_admin: true }, /Can assume an admin role\./],
  [{ escalates_to_conditional_admin: true }, /Can assume a conditional admin role\. Its conditions have not been verified\./],
])("keeps confirmed and conditional admin escalation distinct", (escalation, text) => {
  render(<AdminAssessment attributes={{ admin_equivalence_status: "unknown", ...escalation }} />);
  expect(screen.getByText(text)).toBeInTheDocument();
  expect(screen.getAllByText(/Can assume/)).toHaveLength(1);
});
it("omits escalation text when no admin escalation was derived", () => {
  render(<AdminAssessment attributes={{ admin_equivalence_status: "not_admin", can_escalate_privilege: true }} />);
  expect(screen.queryByText(/Can assume/)).not.toBeInTheDocument();
});
it("does not invent an assessment for legacy snapshots", () => {
  const { container } = render(<AdminAssessment attributes={{ admin_equivalent: false }} />);
  expect(container).toBeEmptyDOMElement();
});
