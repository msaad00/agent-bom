"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

// The dashboard (`/`) is now the single home. `/overview` is kept as a permanent
// redirect so existing deep links and bookmarks land on the consolidated home
// instead of a duplicate command-center surface.
export default function OverviewRedirect() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/");
  }, [router]);

  return (
    <div className="flex min-h-[40vh] items-center justify-center" aria-busy="true">
      <Loader2 className="h-8 w-8 animate-spin text-[color:var(--text-secondary)]" />
    </div>
  );
}
