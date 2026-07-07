import type { Meta, StoryObj } from "@storybook/react-vite";

import { AttackPathCard } from "@/components/attack-path-card";

const meta = {
  title: "Dashboard/AttackPathCard",
  component: AttackPathCard,
  parameters: { layout: "centered" },
  args: {
    riskScore: 9.4,
    nodes: [
      { type: "agent", label: "analyst-agent", severity: "critical" },
      { type: "server", label: "database" },
      { type: "package", label: "werkzeug@2.2.2", severity: "critical" },
      { type: "cve", label: "CVE-2026-0001", severity: "critical" },
      { type: "credential", label: "DATABASE_URL" },
    ],
  },
} satisfies Meta<typeof AttackPathCard>;

export default meta;
type Story = StoryObj<typeof meta>;

export const CriticalPath: Story = {};

export const ModerateRisk: Story = {
  args: {
    riskScore: 5.6,
    nodes: [
      { type: "agent", label: "ops-agent" },
      { type: "server", label: "http-fetch" },
      { type: "package", label: "requests@2.31.0", severity: "high" },
      { type: "cve", label: "CVE-2026-0114", severity: "high" },
    ],
  },
};

export const LowRisk: Story = {
  args: {
    riskScore: 2.3,
    nodes: [
      { type: "package", label: "urllib3@2.1.0", severity: "low" },
      { type: "cve", label: "CVE-2025-4412", severity: "low" },
    ],
  },
};

export const CaptureMode: Story = {
  name: "Capture mode (product proof)",
  args: { captureMode: true },
};
