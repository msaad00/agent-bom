"use client";

import { useEffect, type ReactNode } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { FileText } from "lucide-react";

import { LoginPanel } from "@/components/login-panel";
import { useAuthState } from "@/components/auth-provider";
import { defaultOperatorLanding } from "@/lib/operator-landing";
import { enableOfflineReportMode } from "@/lib/offline-report-mode";
import { safeReturnPath } from "@/lib/safe-return-path";

export function LoginPageContent({ trialInvitation }: { trialInvitation: ReactNode }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { session, loading } = useAuthState();
  const returnTo = defaultOperatorLanding(safeReturnPath(searchParams.get("returnTo")));

  useEffect(() => {
    if (loading) return;
    if (session && (!session.auth_required || session.authenticated)) {
      router.replace(returnTo);
    }
  }, [loading, returnTo, router, session]);

  return (
    <>
      <LoginPanel title="Sign in to agent-bom" trialInvitation={trialInvitation} />
      {/*
        A 401 lands every route here, including the home page that hosts the
        in-browser report importer. Without this, a user holding a report file
        and no working sign-in has nowhere left to go.
      */}
      <div className="pb-10 text-center">
        <button
          type="button"
          onClick={() => {
            enableOfflineReportMode();
            router.replace("/");
          }}
          className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]"
        >
          <FileText className="h-4 w-4" />
          Continue offline with a report file
        </button>
      </div>
    </>
  );
}
