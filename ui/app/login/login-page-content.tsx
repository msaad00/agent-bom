"use client";

import { useEffect, type ReactNode } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { LoginPanel } from "@/components/login-panel";
import { useAuthState } from "@/components/auth-provider";
import { defaultOperatorLanding } from "@/lib/operator-landing";
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

  return <LoginPanel title="Sign in to agent-bom" trialInvitation={trialInvitation} />;
}
