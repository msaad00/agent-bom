import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Nav } from "@/components/nav";

const inter = Inter({ subsets: ["latin"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "agent-bom",
  description: "AI supply chain security scanner — CVEs, config security, blast radius, compliance",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} ${mono.variable} font-sans bg-[#0a0a0b] text-zinc-100 min-h-screen antialiased selection:bg-emerald-500/20`}>
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
