import type { ReactNode } from "react";

// The Inventory section no longer shares one graph read across every page.
//
// The index takes its card counts from `stats.node_types` over the whole
// snapshot, but each asset-type page needs ROWS of its own type — and a ranked
// page of the estate is not that. Agents, MCP servers and container images all
// rank below a misconfiguration-dominated cut, so those pages rendered "nothing
// discovered yet" while their own card advertised hundreds.
//
// Each route now provides its own `InventoryProvider` with the right scope.
export default function InventoryLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
