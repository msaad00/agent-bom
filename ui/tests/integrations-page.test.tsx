import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import IntegrationsPage from "@/app/integrations/page";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams("tab=siem"),
}));

vi.mock("@/components/integrations/webhooks-panel", () => ({ WebhooksPanel: () => <div>webhooks panel</div> }));
vi.mock("@/components/integrations/siem-panel", () => ({ SiemPanel: () => <div>siem panel</div> }));
vi.mock("@/components/integrations/intel-panel", () => ({ IntelPanel: () => <div>intel panel</div> }));
vi.mock("@/components/integrations/reports-panel", () => ({ ReportsPanel: () => <div>reports panel</div> }));

describe("IntegrationsPage", () => {
  it("renders the tab shell and the selected tab's panel", async () => {
    render(<IntegrationsPage />);
    expect(await screen.findByRole("heading", { name: /Operations & Integrations/i })).toBeInTheDocument();
    expect(screen.getByText("siem panel")).toBeInTheDocument();
    expect(screen.queryByText("webhooks panel")).not.toBeInTheDocument();
  });
});
