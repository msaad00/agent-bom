import type { Meta, StoryObj } from "@storybook/react-vite";

import { PostureGrade, type PostureDimension } from "@/components/posture-grade";

const dimensions: Record<string, PostureDimension> = {
  vulnerabilities: { score: 42, label: "Vulnerabilities", details: "1 critical, 2 high reachable" },
  credentials: { score: 68, label: "Credential exposure", details: "2 live creds in blast radius" },
  agents: { score: 81, label: "Agent trust", details: "All agents discovered and signed" },
  compliance: { score: 55, label: "Compliance", details: "3 failing OWASP controls" },
  runtime: { score: 74, label: "Runtime posture", details: "Proxy observing 4 servers" },
};

const meta = {
  title: "Dashboard/PostureGrade",
  component: PostureGrade,
  parameters: { layout: "centered" },
  args: {
    grade: "C",
    score: 62,
    summary: "Reachable criticals and failing compliance controls are dragging the fleet grade down.",
    dimensions,
  },
} satisfies Meta<typeof PostureGrade>;

export default meta;
type Story = StoryObj<typeof meta>;

export const CompactWithDrilldown: Story = {
  args: { variant: "compact", drilldown: true },
};

export const Panel: Story = {
  args: { variant: "panel", drilldown: true, defaultExpanded: true },
};

export const StrongGrade: Story = {
  args: {
    grade: "A",
    score: 93,
    summary: "No reachable criticals; all compliance controls passing.",
    dimensions: {
      vulnerabilities: { score: 96, label: "Vulnerabilities" },
      credentials: { score: 90, label: "Credential exposure" },
      agents: { score: 94, label: "Agent trust" },
    },
    variant: "panel",
    defaultExpanded: true,
  },
};

export const FailingGrade: Story = {
  args: { grade: "F", score: 21, variant: "compact", drilldown: true },
};

export const NotAssessed: Story = {
  args: { grade: "N/A", score: 0, summary: "Run a scan to compute a posture grade.", dimensions: {} },
};
