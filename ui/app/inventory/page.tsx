import { InventoryIndex } from "@/components/inventory/inventory-index";

// Unified Asset Inventory landing — one card per asset type, correlated back to
// findings and the security graph. Supersedes the former /inventory → /manifest
// redirect (the AI BOM now lives under this section as "AI agents").
export default function InventoryPage() {
  return <InventoryIndex />;
}
