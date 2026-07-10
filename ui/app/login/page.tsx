"use client";

import { Suspense, useEffect } from "react";
import { Loader2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";

import { LoginPanel } from "@/components/login-panel";
import { useAuthState } from "@/components/auth-provider";
import { safeReturnPath } from "@/lib/safe-return-path";

function LoginPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { session, loading } = useAuthState();
  const returnTo = safeReturnPath(searchParams.get("returnTo"));

  useEffect(() => {
    if (loading) return;
    if (session && (!session.auth_required || session.authenticated)) {
      router.replace(returnTo);
    }
  }, [loading, returnTo, router, session]);

  return <LoginPanel title="Sign in to agent-bom" />;
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center text-zinc-400">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
          Loading sign-in...
        </div>
      }
    >
      <LoginPageContent />
    </Suspense>
  );
}
