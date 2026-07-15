import type { ReactNode } from "react";

import { InventoryProvider } from "@/lib/inventory-context";

// One graph read for the whole Inventory section — shared with every asset-type
// page so navigating between them is instant and never refetches.
export default function InventoryLayout({ children }: { children: ReactNode }) {
  return <InventoryProvider>{children}</InventoryProvider>;
}
