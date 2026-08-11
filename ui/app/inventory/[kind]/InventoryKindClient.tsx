"use client";

import { useParams } from "next/navigation";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
import { InventoryProvider } from "@/lib/inventory-context";
import { PageEmptyState } from "@/components/states/page-state";
import { ASSET_KIND_BY_ID, type AssetKindId } from "@/lib/inventory";

export default function InventoryKindClient() {
  const params = useParams();
  const raw = Array.isArray(params.kind) ? params.kind[0] : params.kind;

  if (!raw || !(raw in ASSET_KIND_BY_ID)) {
    return (
      <PageEmptyState
        title="Unknown asset type"
        detail="That asset type is not part of the inventory. Pick a type from the inventory overview."
        action={{ label: "Back to inventory", href: "/inventory", variant: "primary" }}
      />
    );
  }

  const kind = raw as AssetKindId;
  // Scoped to this kind's entity types so the rows are of the type the page is
  // about, rather than whatever survived a ranked cut of the whole estate.
  return (
    <InventoryProvider entityTypes={ASSET_KIND_BY_ID[kind].entityTypes}>
      <AssetInventoryView kind={kind} />
    </InventoryProvider>
  );
}
