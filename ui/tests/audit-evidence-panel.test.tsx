import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuditEvidencePanel } from "@/components/audit-evidence-panel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    exportAuditPacket: vi.fn(),
    verifyAuditPacket: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

const SIGNATURE = "a".repeat(64);

beforeEach(() => {
  apiMock.exportAuditPacket.mockReset();
  apiMock.verifyAuditPacket.mockReset();
  // jsdom lacks object URLs; stub so the download path does not throw.
  (URL as unknown as { createObjectURL: () => string }).createObjectURL = vi.fn(() => "blob:x");
  (URL as unknown as { revokeObjectURL: () => void }).revokeObjectURL = vi.fn();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AuditEvidencePanel", () => {
  it("exports a signed packet and verifies the fresh round-trip as PASS", async () => {
    const packet = { payload: { entries: [], integrity: { verified: 3 } }, signature: SIGNATURE };
    apiMock.exportAuditPacket.mockResolvedValue(packet);
    apiMock.verifyAuditPacket.mockResolvedValue({ valid: true, payload_bytes: 128 });

    render(<AuditEvidencePanel />);
    fireEvent.click(screen.getByRole("button", { name: "Export & verify" }));

    await waitFor(() => expect(apiMock.exportAuditPacket).toHaveBeenCalled());
    await waitFor(() =>
      expect(apiMock.verifyAuditPacket).toHaveBeenCalledWith(packet.payload, SIGNATURE),
    );

    const result = await screen.findByTestId("audit-verify-result");
    expect(result).toHaveAttribute("data-valid", "true");
    expect(result).toHaveTextContent("PASS");
  });

  it("verifies a pasted packet and renders FAIL when the signature does not match", async () => {
    apiMock.verifyAuditPacket.mockResolvedValue({ valid: false, payload_bytes: 64 });

    render(<AuditEvidencePanel />);
    const wrapper = JSON.stringify({ payload: { entries: [] }, signature: SIGNATURE });
    fireEvent.change(screen.getByLabelText("Exported audit packet"), {
      target: { value: wrapper },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() =>
      expect(apiMock.verifyAuditPacket).toHaveBeenCalledWith({ entries: [] }, SIGNATURE),
    );
    const result = await screen.findByTestId("audit-verify-result");
    expect(result).toHaveAttribute("data-valid", "false");
    expect(result).toHaveTextContent("FAIL");
  });

  it("rejects an empty verify without calling the endpoint", async () => {
    render(<AuditEvidencePanel />);
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Paste an exported audit packet");
    expect(apiMock.verifyAuditPacket).not.toHaveBeenCalled();
  });
});
