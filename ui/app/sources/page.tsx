import { redirect } from "next/navigation";

// Data Sources folded into the consolidated Connections hub as its "Sources"
// segment. Keep `/sources` as a permanent server-side redirect so legacy deep
// links and bookmarks land on the canonical route instead of a 404.
export default function SourcesRedirect() {
  redirect("/connections?tab=sources");
}
