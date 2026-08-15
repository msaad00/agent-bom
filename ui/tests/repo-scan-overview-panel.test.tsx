import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RepoScanOverviewPanel } from "@/components/repo-scan-overview-panel";

vi.mock("next/link", () => ({
  default: ({ href, children, className }: { href: string; children: React.ReactNode; className?: string }) => (
    <a href={href} className={className}>{children}</a>
  ),
}));

describe("RepoScanOverviewPanel", () => {
  it("presents one scan-to-artifact-to-context-graph journey", async () => {
    const user = userEvent.setup();
    const onDownloadArtifact = vi.fn();

    render(
      <RepoScanOverviewPanel
        scanId="scan-repo-1"
        repoUrl="https://github.com/example/repo"
        result={{ agents: [], blast_radius: [] }}
        artifactLabel="CycloneDX SBOM"
        onDownloadArtifact={onDownloadArtifact}
      />,
    );

    expect(screen.getByRole("heading", { name: "Repository evidence journey" })).toBeInTheDocument();
    expect(screen.getByText("1. Scan complete")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Download CycloneDX SBOM" }));
    expect(onDownloadArtifact).toHaveBeenCalledOnce();
    expect(screen.getByRole("link", { name: "Explore repository context graph" })).toHaveAttribute(
      "href",
      "/graph?scan_id=scan-repo-1&layers=directory%2Csource_file%2Cconfig_file%2Cpackage%2Cframework%2Cvulnerability",
    );
  });
});
