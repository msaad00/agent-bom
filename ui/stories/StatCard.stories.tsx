import type { Meta, StoryObj } from "@storybook/react-vite";

import { StatCard } from "@/components/stat-card";

const meta = {
  title: "Primitives/StatCard",
  component: StatCard,
  args: { label: "Critical", value: 12, accent: "critical" },
  argTypes: {
    accent: {
      control: "inline-radio",
      options: ["neutral", "critical", "high", "medium", "info"],
    },
  },
} satisfies Meta<typeof StatCard>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Critical: Story = {};

export const NeutralZero: Story = {
  args: { label: "Suppressed", value: 0, accent: "neutral" },
};

export const ZeroStaysNeutral: Story = {
  name: "Zero count stays neutral",
  args: { label: "Critical", value: 0, accent: "critical" },
};

export const Row: Story = {
  render: () => (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
      <StatCard label="Critical" value={12} accent="critical" />
      <StatCard label="High" value={38} accent="high" />
      <StatCard label="Medium" value={91} accent="medium" />
      <StatCard label="Reachable" value={27} accent="info" />
      <StatCard label="Total" value={412} accent="neutral" />
    </div>
  ),
};
