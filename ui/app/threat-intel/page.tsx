import { redirect } from "next/navigation";

// Threat-intel lookups are now a tab on the consolidated Integrations surface.
// Keep `/threat-intel` as a permanent server-side redirect so legacy deep links
// and bookmarks land on the canonical route instead of a 404.
export default function ThreatIntelRedirect() {
  redirect("/integrations?tab=intel");
}
