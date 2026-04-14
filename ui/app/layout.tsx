import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { Nav } from "@/components/nav";

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
  description: "AI supply chain security scanner — CVEs, config security, blast radius, compliance",
  icons: { icon: "/favicon.ico" },
};

const themeBootstrap = `
(function () {
  try {
    var stored = localStorage.getItem("agent-bom-theme");
    var theme = stored === "light" || stored === "dark" ? stored : "dark";
    var root = document.documentElement;
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
  } catch (error) {
    document.documentElement.dataset.theme = "dark";
    document.documentElement.style.colorScheme = "dark";
  }
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body className={`${inter.variable} ${mono.variable} font-sans bg-background text-foreground min-h-screen antialiased selection:bg-emerald-500/20`}>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
        <Nav />
        {/* Main content — offset by sidebar width on desktop, offset by top bar on mobile */}
        <main id="main-content" className="lg:pl-[240px] pt-14 lg:pt-0 min-h-screen transition-[padding-left] duration-200">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
