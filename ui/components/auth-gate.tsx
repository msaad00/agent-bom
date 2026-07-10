"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

import { useAuthState } from "@/components/auth-provider";

function isAuthFailure(message: string): boolean {
  const normalized = message.toLowerCase();
  return normalized.includes("unauthorized") || normalized.includes("invalid api key") || normalized.includes("forbidden");
}

function isApiReachabilityFailure(message: string): boolean {
  const normalized = message.toLowerCase();
  return (
    normalized.includes("network request failed") ||
    normalized.includes("failed to fetch") ||
    normalized.includes("econnrefused") ||
    normalized.includes("500 internal server error") ||
    normalized.includes("502 bad gateway") ||
    normalized.includes("503 service unavailable") ||
    normalized.includes("504 gateway timeout") ||
    normalized.includes("timed out") ||
    normalized.includes("timeout")
  );
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { session, loading, error } = useAuthState();

  const needsAuth =
    !loading &&
    (!session || (session.auth_required && !session.authenticated)) &&
    (!error || isAuthFailure(error));

  useEffect(() => {
    if (!needsAuth || pathname === "/login") return;
    const returnTo = encodeURIComponent(pathname || "/");
    router.replace(`/login?returnTo=${returnTo}`);
  }, [needsAuth, pathname, router]);

  if (loading) {
    return (
      <div className="flex min-h-[calc(100vh-5rem)] items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
      </div>
    );
  }

  if (session && (!session.auth_required || session.authenticated)) {
    return <>{children}</>;
  }

  if (error && isApiReachabilityFailure(error)) {
    return (
      <div className="flex min-h-[calc(100vh-5rem)] items-center justify-center px-4 py-10">
        <div className="w-full max-w-xl rounded-3xl border border-amber-900/50 bg-amber-950/20 p-8 text-center shadow-2xl shadow-black/20">
          <h1 className="text-xl font-semibold tracking-tight text-zinc-100">Control plane unreachable</h1>
          <p className="mt-3 text-sm leading-6 text-zinc-400">
            Authentication could not be verified because the API is offline or returned a server error.
          </p>
          <p className="mt-2 text-xs text-zinc-500">{error}</p>
        </div>
      </div>
    );
  }

  if (needsAuth) {
    return (
      <div className="flex min-h-[calc(100vh-5rem)] items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-5rem)] items-center justify-center px-4 py-10">
      <div className="max-w-xl rounded-2xl border border-red-900/50 bg-red-950/20 p-6 text-sm text-red-300">{error}</div>
    </div>
  );
}
