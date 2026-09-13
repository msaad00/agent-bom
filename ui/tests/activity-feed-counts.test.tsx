import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ActivityFeed } from "@/components/activity-feed";
import type { JobListItem } from "@/lib/api-types";

describe("Activity scan metric units", () => {
  it("keeps vulnerability totals distinct from critical finding occurrences", () => {
    render(<ActivityFeed refresh={false} initialJobs={[{
      job_id: "scan-units", status: "done", created_at: "2026-09-13T12:00:00Z",
      completed_at: "2026-09-13T12:01:00Z", summary: { total_vulnerabilities: 21, critical_findings: 112 },
    } as JobListItem]} />);
    expect(screen.getByText("Scan completed: 21 vulnerabilities · 112 critical findings")).toBeVisible();
    expect(screen.queryByText(/21 findings/)).not.toBeInTheDocument();
  });
});
