"use client";

import { usePathname } from "next/navigation";

import { AuthGate } from "@/components/auth-gate";
import { DemoEstateLabel } from "@/components/demo-estate-label";
import { Nav } from "@/components/nav";
import {
  SidebarLayoutProvider,
  mainContentPaddingClass,
  useSidebarLayout,
} from "@/components/sidebar-layout";

function ShellMain({ children }: { children: React.ReactNode }) {
  const { collapsed } = useSidebarLayout();
  return (
    <main
      id="main-content"
      className={`min-h-screen pt-16 transition-[padding-left] duration-200 ${mainContentPaddingClass(collapsed)}`}
    >
      <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-6">{children}</div>
    </main>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLoginRoute = pathname === "/login";

  if (isLoginRoute) {
    return <div className="min-h-screen bg-background text-foreground">{children}</div>;
  }

  return (
    <SidebarLayoutProvider>
      <DemoEstateLabel />
      <Nav />
      <AuthGate>
        <ShellMain>{children}</ShellMain>
      </AuthGate>
    </SidebarLayoutProvider>
  );
}
