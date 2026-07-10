import type { Metadata } from "next";
import localFont from "next/font/local";
import Script from "next/script";
import "./globals.css";
import { AuthProvider } from "@/components/auth-provider";
import { AppShell } from "@/components/app-shell";
// Theme bootstrap script lives in lib/csp-source.ts so its sha256 stays in
// sync with the script-src hash that lib/security-headers.ts emits in CSP.
// Editing the script body in only one place will cause the sync test to fail.
import { THEME_BOOTSTRAP_SCRIPT } from "@/lib/csp-source.mjs";

// Local fonts — no network fetch at build time (works in air-gapped environments)
const inter = localFont({
  src: [
    { path: "../public/fonts/inter-var.woff2", style: "normal" },
  ],
  variable: "--font-sans",
  display: "swap",
  fallback: ["system-ui", "-apple-system", "Segoe UI", "sans-serif"],
});
const mono = localFont({
  src: [
    { path: "../public/fonts/jetbrains-mono-var.woff2", style: "normal" },
  ],
  variable: "--font-mono",
  display: "swap",
  fallback: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
});

export const metadata: Metadata = {
  title: "agent-bom",
  description: "Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head />
      <body className={`${inter.variable} ${mono.variable} font-sans bg-background text-foreground min-h-screen antialiased selection:bg-emerald-500/20`}>
        <Script src="/runtime-config.js" strategy="beforeInteractive" />
        <Script id="theme-bootstrap" strategy="beforeInteractive">
          {THEME_BOOTSTRAP_SCRIPT}
        </Script>
        <AuthProvider>
          <AppShell>{children}</AppShell>
        </AuthProvider>
      </body>
    </html>
  );
}
