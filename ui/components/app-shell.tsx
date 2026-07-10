"use client";

import { usePathname } from "next/navigation";

import { AuthGate } from "@/components/auth-gate";
import { DemoEstateLabel } from "@/components/demo-estate-label";
import { Nav } from "@/components/nav";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLoginRoute = pathname === "/login";

  if (isLoginRoute) {
    return <div className="min-h-screen bg-background text-foreground">{children}</div>;
  }

  return (
    <>
      <DemoEstateLabel />
      <Nav />
      <AuthGate>
        <main id="main-content" className="min-h-screen pt-14 transition-[padding-left] duration-200 lg:pl-[240px]">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {children}
          </div>
        </main>
      </AuthGate>
    </>
  );
}
