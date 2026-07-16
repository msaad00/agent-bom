import { describe, expect, it } from "vitest";

import { ssoLoginPreset } from "@/lib/sso-login-presets";

describe("ssoLoginPreset", () => {
  it("brands the sign-in button for known providers", () => {
    expect(ssoLoginPreset("okta")).toEqual({
      id: "okta",
      label: "Okta",
      buttonLabel: "Sign in with Okta",
    });
    expect(ssoLoginPreset("entra")).toEqual({
      id: "entra",
      label: "Microsoft",
      buttonLabel: "Sign in with Microsoft",
    });
    expect(ssoLoginPreset("google")).toEqual({
      id: "google",
      label: "Google",
      buttonLabel: "Sign in with Google",
    });
  });

  it("falls back to the generic SSO label for null/undefined/unknown", () => {
    const generic = {
      id: "generic",
      label: "SSO",
      buttonLabel: "Sign in with SSO",
    };
    expect(ssoLoginPreset(null)).toEqual(generic);
    expect(ssoLoginPreset(undefined)).toEqual(generic);
    expect(ssoLoginPreset("")).toEqual(generic);
    expect(ssoLoginPreset("snowflake")).toEqual(generic);
    expect(ssoLoginPreset("not-a-provider")).toEqual(generic);
  });
});
