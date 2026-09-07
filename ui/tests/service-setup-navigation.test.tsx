import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ServiceStateBanner, ServiceStateChip } from "@/components/service-state-chip";
import type { ServiceEntry, ServiceId } from "@/lib/api-types";

describe("AI Spend setup navigation", () => {
  it.each([
    ["proxy dependency", { runtime_proxy: { state: "locked", count: 0 } }, ["runtime_proxy"], "proxy"],
    ["gateway dependency", {}, ["runtime_gateway"], "gateway"],
    ["gateway already connected", { runtime_gateway: { state: "connected", count: 0 } }, ["runtime_proxy"], "gateway"],
    ["proxy already live", { runtime_proxy: { state: "live", count: 1 } }, ["runtime_gateway"], "proxy"],
    ["no dependency metadata", {}, [], "proxy"],
  ] as const)("opens relevant runtime setup for %s", (_case, services, requires, surface) => {
    const entry: ServiceEntry = { state: "locked", count: 0, requires: [...requires] };
    const registry = services as Partial<Record<ServiceId, ServiceEntry>>;
    render(<><ServiceStateBanner serviceId="ai_spend" entry={entry} registry={registry} /><ServiceStateChip serviceId="ai_spend" entry={entry} registry={registry} /></>);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(2);
    for (const link of links) {
      expect(link).toHaveAttribute("href", `/runtime?tab=${surface}`);
      expect(link).not.toHaveAttribute("href", "/cost");
    }
  });
});
