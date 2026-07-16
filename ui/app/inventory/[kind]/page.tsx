// Server wrapper for the per-asset-type inventory page.
//
// `/inventory/[kind]` is a dynamic segment, but every valid kind is known at
// build time, so `generateStaticParams` enumerates them all — the static
// export (shipped in the Python package) prerenders one HTML page per asset
// type while sharing a single client chunk. A `"use client"` page may not
// export `generateStaticParams`, so this stays a server component that
// delegates to the client child (which reads the kind from the URL).
import InventoryKindClient from "./InventoryKindClient";
import { ASSET_KINDS } from "@/lib/inventory";

export function generateStaticParams() {
  return ASSET_KINDS.map((kind) => ({ kind: kind.id }));
}

// Required by `output: export`: only the enumerated kinds are valid; anything
// else 404s instead of rendering at runtime.
export const dynamicParams = false;

export default function InventoryKindPage() {
  return <InventoryKindClient />;
}
