import type { Meta, StoryObj } from "@storybook/react-vite";
import { ShieldOff } from "lucide-react";

import {
  PageState,
  PageEmptyState,
  PageErrorState,
  PageLoadingState,
} from "@/components/states/page-state";

// PageState is the shared harness every dashboard route uses for its
// non-happy paths. Covering it once documents the loading / empty / error /
// permission-denied surfaces the rest of the app reuses.
const meta = {
  title: "States/PageState",
  component: PageState,
  parameters: { layout: "fullscreen" },
  // Baseline args so each story can override via its own render() while the
  // required title/detail props stay satisfied at the type level.
  args: {
    title: "No findings yet",
    detail: "Run a scan to populate the findings queue.",
  },
} satisfies Meta<typeof PageState>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Empty: Story = {
  render: () => (
    <PageEmptyState
      title="No findings yet"
      detail="Run a scan to populate the findings queue with reachable vulnerabilities."
      suggestions={[
        "Point the scanner at an MCP config or agent manifest",
        "Connect a registry to pull live inventory",
      ]}
      command="agent-bom scan ./my-agent"
      action={{ label: "Start a scan", href: "/scan" }}
    />
  ),
};

export const Loading: Story = {
  render: () => (
    <PageLoadingState
      title="Loading findings"
      detail="Fetching the latest reachable vulnerabilities across your fleet."
    />
  ),
};

export const Error: Story = {
  render: () => (
    <PageErrorState
      title="Could not reach the API"
      detail="The findings service returned a 503. Retry, or check the collector status."
      actions={[
        { label: "Retry", variant: "primary" },
        { label: "View status", href: "/status", variant: "secondary" },
      ]}
    />
  ),
};

export const PermissionDenied: Story = {
  render: () => (
    <PageState
      tone="warning"
      icon={ShieldOff}
      title="You do not have access to this workspace"
      detail="Your role lacks the findings:read scope for the acme tenant. Ask an admin to grant access."
      suggestions={["Request the Security Analyst role", "Switch to a workspace you own"]}
      action={{ label: "Back to overview", href: "/" }}
    />
  ),
};

export const Success: Story = {
  render: () => (
    <PageState
      tone="success"
      title="All controls passing"
      detail="No open findings map to a failing compliance control in this workspace."
      action={{ label: "View compliance", href: "/compliance" }}
    />
  ),
};
