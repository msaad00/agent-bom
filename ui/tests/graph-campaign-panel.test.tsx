import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { GraphCampaignPanel } from "@/components/graph-campaign-panel";

describe("GraphCampaignPanel", () => {
  it("distinguishes fusion clusters from remediation ticket campaigns", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <GraphCampaignPanel
        selectedCampaignId={null}
        onSelect={onSelect}
        campaigns={[
          {
            campaign_id: "c1",
            crown_jewel: "ds:secrets",
            crown_jewel_label: "Secrets store",
            path_count: 3,
            top_path_summary: "Agent reaches regulated data",
          },
        ]}
      />,
    );
    expect(screen.getByTestId("graph-campaign-panel")).toHaveTextContent("Crown-jewel clusters");
    expect(screen.getByText(/Not remediation ticket campaigns/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Secrets store/i }));
    expect(onSelect).toHaveBeenCalled();
  });
});
