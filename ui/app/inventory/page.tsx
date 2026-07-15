import { redirect } from "next/navigation";

// The AI inventory now lives on the AI BOM surface. Keep `/inventory` as a
// permanent server-side redirect so legacy deep links and bookmarks resolve to
// the canonical route instead of a 404.
export default function InventoryRedirect() {
  redirect("/manifest");
}
