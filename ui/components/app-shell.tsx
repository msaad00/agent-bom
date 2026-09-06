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
      <div className="mx-auto w-full max-w-[2560px] px-4 py-6 sm:px-6 lg:px-8">{children}</div>
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
      <a
        href="#main-content"
        className="fixed left-4 top-3 z-[100] -translate-y-20 rounded-lg bg-[color:var(--accent)] px-3 py-2 text-sm font-semibold text-white shadow-lg transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>
      <DemoEstateLabel />
      <Nav />
      <AuthGate>
        <ShellMain>{children}</ShellMain>
      </AuthGate>
    </SidebarLayoutProvider>
  );
}
