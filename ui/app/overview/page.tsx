import { redirect } from "next/navigation";

// The dashboard (`/`) is now the single home. `/overview` is kept as a permanent
// redirect so existing deep links and bookmarks land on the consolidated home
// instead of a duplicate command-center surface. Keep this server-side so the
// route does not flash a client spinner before navigation.
export default function OverviewRedirect() {
  redirect("/");
}
