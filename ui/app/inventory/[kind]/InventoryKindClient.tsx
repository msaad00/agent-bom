"use client";

import { usePathname, useParams, useRouter, useSearchParams } from "next/navigation";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
import { InventoryProvider } from "@/lib/inventory-context";
import { PageEmptyState } from "@/components/states/page-state";
import { ASSET_KIND_BY_ID, type AssetKindId } from "@/lib/inventory";

export default function InventoryKindClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const raw = Array.isArray(params.kind) ? params.kind[0] : params.kind;
  const requestedSeverity = searchParams.get("severity")?.toLowerCase() ?? "all";
  const severity = ["critical", "high", "medium", "low"].includes(requestedSeverity)
    ? requestedSeverity
    : "all";

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
  const changeSeverity = (nextSeverity: string) => {
    const next = new URLSearchParams(searchParams.toString());
    if (nextSeverity === "all") next.delete("severity");
    else next.set("severity", nextSeverity);
    const query = next.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };
  // Scoped to this kind's entity types so the rows are of the type the page is
  // about, rather than whatever survived a ranked cut of the whole estate.
  return (
    <InventoryProvider
      entityTypes={ASSET_KIND_BY_ID[kind].entityTypes}
      minSeverity={severity === "all" ? undefined : severity}
    >
      <AssetInventoryView
        kind={kind}
        severityFilter={severity}
        onSeverityFilterChange={changeSeverity}
      />
    </InventoryProvider>
  );
}
