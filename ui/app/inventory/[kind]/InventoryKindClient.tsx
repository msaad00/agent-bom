"use client";

import { useParams } from "next/navigation";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
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

  return <AssetInventoryView kind={raw as AssetKindId} />;
}
