import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { SsoSetupPresets } from "@/components/sso-setup-presets";

describe("SsoSetupPresets", () => {
  it("defaults to Okta OIDC and shows the issuer template, never a secret value", async () => {
    render(<SsoSetupPresets />);
    expect(screen.getByText("SSO provider presets")).toBeInTheDocument();
    expect(screen.getByText("https://{yourOktaDomain}/oauth2/default")).toBeInTheDocument();

    // The client-secret row is present but shows guidance, not a value.
    const secretEnv = screen.getByText("AGENT_BOM_OIDC_CLIENT_SECRET");
    const secretRow = secretEnv.closest("div")?.parentElement as HTMLElement;
    expect(within(secretRow).getByText(/never prefilled/i)).toBeInTheDocument();
  });

  it("switching to Google OIDC swaps in the fixed accounts.google.com issuer", async () => {
    const user = userEvent.setup();
    render(<SsoSetupPresets />);
    await user.click(screen.getByRole("button", { name: "Google Workspace" }));
    expect(screen.getByText("https://accounts.google.com")).toBeInTheDocument();
    expect(screen.getByText("https://www.googleapis.com/oauth2/v3/certs")).toBeInTheDocument();
  });

  it("Generic OIDC leaves the issuer blank (placeholder only)", async () => {
    const user = userEvent.setup();
    render(<SsoSetupPresets />);
    await user.click(screen.getByRole("button", { name: "Generic OIDC" }));
    // No prefilled issuer template is rendered for the generic preset.
    expect(screen.queryByText("https://{yourOktaDomain}/oauth2/default")).not.toBeInTheDocument();
    expect(screen.getByText("https://idp.your-org.example")).toBeInTheDocument();
  });
});
