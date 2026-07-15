import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SiemPanel } from "@/components/integrations/siem-panel";

const { apiMock, authMock } = vi.hoisted(() => ({
  apiMock: {
    listSiemConnectors: vi.fn(),
    listSiemFormats: vi.fn(),
    testSiemConnection: vi.fn(),
  },
  authMock: { value: { session: { auth_required: true }, hasCapability: (c: string): boolean => c === "policy.manage" } },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => authMock.value }));

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  authMock.value = { session: { auth_required: true }, hasCapability: (c: string): boolean => c === "policy.manage" };
  apiMock.listSiemConnectors.mockResolvedValue({ connectors: ["splunk", "datadog", "syslog"] });
  apiMock.listSiemFormats.mockResolvedValue({ formats: ["raw", "ocsf"] });
});

describe("SiemPanel", () => {
  it("renders connector types and formats", async () => {
    render(<SiemPanel />);
    const connectors = await screen.findByTestId("siem-connectors");
    expect(connectors).toHaveTextContent("splunk");
    expect(connectors).toHaveTextContent("syslog");
    expect(screen.getByTestId("siem-formats")).toHaveTextContent("ocsf");
  });

  it("runs a connectivity test and shows the healthy result", async () => {
    apiMock.testSiemConnection.mockResolvedValue({ siem_type: "splunk", healthy: true });
    render(<SiemPanel />);
    await screen.findByTestId("siem-connectors");

    fireEvent.change(screen.getByTestId("siem-url-input"), {
      target: { value: "https://siem.example.com/collector" },
    });
    fireEvent.click(screen.getByTestId("siem-test-submit"));

    await waitFor(() => expect(apiMock.testSiemConnection).toHaveBeenCalledTimes(1));
    expect(apiMock.testSiemConnection.mock.calls[0]![0]).toBe("splunk");
    expect(apiMock.testSiemConnection.mock.calls[0]![1]).toBe("https://siem.example.com/collector");
    expect(await screen.findByTestId("siem-test-result")).toHaveTextContent(/healthy/i);
  });

  it("gates the test action for non-admins", async () => {
    authMock.value = { session: { auth_required: true }, hasCapability: (): boolean => false };
    render(<SiemPanel />);
    await screen.findByTestId("siem-connectors");
    expect(screen.getByTestId("siem-test-submit")).toBeDisabled();
  });
});
