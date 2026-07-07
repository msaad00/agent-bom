import type { Meta, StoryObj } from "@storybook/react-vite";

import { ExposurePathCommandCenter } from "@/components/exposure-path-command-center";
import { exposurePath } from "./_mocks";

const meta = {
  title: "Graph/ExposurePathCommandCenter",
  component: ExposurePathCommandCenter,
  parameters: { layout: "fullscreen" },
  args: {
    path: exposurePath,
    actions: [
      {
        title: "Validate the lead finding",
        detail: "Open CVE-2026-0001 evidence and confirm the reachable execute path.",
        href: "/findings?cve=CVE-2026-0001",
      },
      {
        title: "Rotate DATABASE_URL",
        detail: "The database credential sits inside the blast radius.",
        href: "/mesh?credential=DATABASE_URL",
      },
    ],
  },
} satisfies Meta<typeof ExposurePathCommandCenter>;

export default meta;
type Story = StoryObj<typeof meta>;

export const CriticalPath: Story = {};

export const NoRecommendedActions: Story = {
  args: { actions: [] },
};
