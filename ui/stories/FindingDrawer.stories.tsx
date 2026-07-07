import type { Meta, StoryObj } from "@storybook/react-vite";

import { FindingDrawer } from "@/components/finding-drawer";
import { makeVuln, makeTriage } from "./_mocks";

// The finding drawer is fixed inset-0, so render it fullscreen with no padding.
const meta = {
  title: "Findings/FindingDrawer",
  component: FindingDrawer,
  parameters: { layout: "fullscreen" },
  args: {
    vuln: makeVuln(),
    triage: makeTriage(),
    triageBusy: false,
    onTriageDecision: () => {},
    onClose: () => {},
  },
} satisfies Meta<typeof FindingDrawer>;

export default meta;
type Story = StoryObj<typeof meta>;

export const CriticalReachable: Story = {};

export const TriageBusy: Story = {
  name: "Triage in flight",
  args: { triageBusy: true },
};

export const NoTriageYet: Story = {
  args: { triage: undefined },
};

export const UnreachableMedium: Story = {
  args: {
    vuln: makeVuln({
      id: "CVE-2025-8890",
      severity: "medium",
      cvss_score: 5.4,
      epss_score: 0.08,
      is_kev: false,
      cisa_kev: false,
      packages: ["pyyaml"],
      agents: [],
      affected_servers: [],
      exposed_credentials: [],
      reachable_tools: [],
      graph_reachable: false,
      graph_min_hop_distance: null,
      effective_reach_score: 12,
      effective_reach_band: "low",
      fixed_version: undefined,
      remediation_items: [],
    }),
    triage: undefined,
  },
};
