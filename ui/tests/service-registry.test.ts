import { describe, expect, it } from "vitest";

import {
  SERVICE_META,
  serviceEntry,
  serviceRequiresLabel,
  serviceStateLabel,
} from "@/lib/service-registry";

describe("service registry helpers", () => {
  it("defaults missing services to locked", () => {
    expect(serviceEntry(undefined, "cloud_accounts")).toEqual({ state: "locked", count: 0 });
  });

  it("labels states consistently", () => {
    expect(serviceStateLabel("live")).toBe("Live");
    expect(serviceStateLabel("connected")).toBe("Connected");
  });

  it("describes ai spend dependencies", () => {
    const label = serviceRequiresLabel(
      {
        runtime_proxy: { state: "locked", count: 0 },
        ai_spend: { state: "locked", count: 0, requires: ["runtime_proxy"] },
      },
      "ai_spend",
    );
    expect(label).toBe("Runtime proxy");
  });

  it("maps unlock destinations for connect surfaces", () => {
    expect(SERVICE_META.cloud_accounts.unlockHref).toBe("/connections");
    expect(SERVICE_META.data_sources.unlockHref).toBe("/connections?tab=sources");
  });
});
