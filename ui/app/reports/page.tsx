import { redirect } from "next/navigation";

// Report exports are now a tab on the consolidated Integrations surface. Keep
// `/reports` as a permanent server-side redirect so legacy deep links and
// bookmarks land on the canonical route instead of a 404.
export default function ReportsRedirect() {
  redirect("/integrations?tab=reports");
}
