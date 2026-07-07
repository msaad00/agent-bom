import type { Meta, StoryObj } from "@storybook/react-vite";

import { ComplianceMatrix } from "@/components/compliance-matrix";
import { makeCompliance, emptyCompliance } from "./_mocks";

const meta = {
  title: "Compliance/ComplianceMatrix",
  component: ComplianceMatrix,
  parameters: { layout: "fullscreen" },
  args: { data: makeCompliance() },
} satisfies Meta<typeof ComplianceMatrix>;

export default meta;
type Story = StoryObj<typeof meta>;

export const MixedControls: Story = {};

export const AllPassing: Story = {
  args: { data: emptyCompliance },
};
