import type { Meta, StoryObj } from "@storybook/react-vite";

import { SeverityBadge } from "@/components/severity-badge";

const meta = {
  title: "Primitives/SeverityBadge",
  component: SeverityBadge,
  args: { severity: "critical" },
  argTypes: {
    severity: {
      control: "inline-radio",
      options: ["critical", "high", "medium", "low", "none"],
    },
  },
} satisfies Meta<typeof SeverityBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Critical: Story = {};

export const AllSeverities: Story = {
  render: () => (
    <div className="flex flex-wrap items-center gap-2">
      {["critical", "high", "medium", "low", "none"].map((severity) => (
        <SeverityBadge key={severity} severity={severity} />
      ))}
    </div>
  ),
};
