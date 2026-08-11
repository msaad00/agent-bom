import { InventoryIndex } from "@/components/inventory/inventory-index";
import { InventoryProvider } from "@/lib/inventory-context";

// Unified Asset Inventory landing — one card per asset type, correlated back to
// findings and the security graph. Unscoped on purpose: the index needs every
// kind at once, and its counts come from `stats.node_types` rather than rows.
export default function InventoryPage() {
  return (
    <InventoryProvider>
      <InventoryIndex />
    </InventoryProvider>
  );
}
