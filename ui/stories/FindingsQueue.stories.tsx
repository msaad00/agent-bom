import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";

import { FindingsQueueTable } from "@/components/findings-queue";
import type { EnrichedVuln, SortKey } from "@/lib/findings-view";
import { denseVulns } from "./_mocks";

// The queue table is a controlled component: it renders from props and calls
// back on sort / select. This harness wires the local state a page would own
// so the interactions work inside a story.
function QueueHarness({
  vulns,
  showLifecycle = false,
}: {
  vulns: EnrichedVuln[];
  showLifecycle?: boolean;
}) {
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [suppressed, setSuppressed] = useState<Set<string>>(new Set());

  return (
    <FindingsQueueTable
      vulns={vulns}
      sortKey={sortKey}
      sortDir={sortDir}
      handleSort={(field) => {
        if (field === sortKey) {
          setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
        } else {
          setSortKey(field);
          setSortDir("desc");
        }
      }}
      suppressed={suppressed}
      onMarkFP={(vulnId) =>
        setSuppressed((prev) => {
          const next = new Set(prev);
          next.add(vulnId);
          return next;
        })
      }
      selectedId={selectedId}
      onSelect={setSelectedId}
      showLifecycle={showLifecycle}
    />
  );
}

const meta = {
  title: "Findings/FindingsQueueTable",
  component: FindingsQueueTable,
  parameters: { layout: "fullscreen" },
  // Baseline args satisfy the controlled component's required props; every
  // story replaces them via the stateful QueueHarness render below.
  args: {
    vulns: denseVulns,
    sortKey: "severity",
    sortDir: "desc",
    handleSort: () => {},
    suppressed: new Set<string>(),
    onMarkFP: () => {},
    selectedId: null,
    onSelect: () => {},
  },
} satisfies Meta<typeof FindingsQueueTable>;

export default meta;
type Story = StoryObj<typeof meta>;

export const DenseQueue: Story = {
  render: () => <QueueHarness vulns={denseVulns} />,
};

export const WithLifecycle: Story = {
  name: "With lifecycle columns",
  render: () => <QueueHarness vulns={denseVulns} showLifecycle />,
};

export const Empty: Story = {
  render: () => <QueueHarness vulns={[]} />,
};
