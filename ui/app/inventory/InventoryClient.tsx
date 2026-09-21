"use client";

import { InventoryIndex } from "@/components/inventory/inventory-index";
import { InventoryProvider } from "@/lib/inventory-context";
import { useInventoryUrlScope } from "@/lib/inventory-url-scope";

export default function InventoryClient() {
  const scope = useInventoryUrlScope();
  return <InventoryProvider {...scope}><InventoryIndex /></InventoryProvider>;
}
