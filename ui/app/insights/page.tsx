import { redirect } from "next/navigation";

// Deep analytics now live on the dashboard so the app has one home and one
// source of truth for risk charts. Keep the legacy route as a server redirect
// for bookmarks and docs links without rendering a duplicate page. The home
// page has no `tab` param — the analytics view is the dashboard itself — so we
// redirect to "/" honestly rather than to an anchor that is silently ignored.
export default function InsightsRedirect() {
  redirect("/");
}
