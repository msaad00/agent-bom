"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  ShieldAlert,
  Scan,
  Server,
  Bug,
  Activity,
  GitBranch,
  Library,
  Shield,
  Lock,
  Users,
  Network,
  Waypoints,
  Eye,
  Clock,
  Menu,
  X,
} from "lucide-react";
import { api } from "@/lib/api";

const NAV_GROUPS = [
  {
    label: "Scan",
    links: [
      { href: "/",           label: "Dashboard",   icon: Activity },
      { href: "/scan",       label: "New Scan",    icon: Scan },
      { href: "/jobs",       label: "Jobs",        icon: ShieldAlert },
    ],
  },
  {
    label: "Inventory",
    links: [
      { href: "/agents",     label: "Agents",      icon: Server },
      { href: "/vulns",      label: "Vulns",       icon: Bug },
      { href: "/fleet",      label: "Fleet",       icon: Users },
      { href: "/registry",   label: "Registry",    icon: Library },
    ],
  },
  {
    label: "Graphs",
    links: [
      { href: "/graph",      label: "Lineage",     icon: GitBranch },
      { href: "/mesh",       label: "Mesh",        icon: Network },
      { href: "/context",    label: "Context",     icon: Waypoints },
    ],
  },
  {
    label: "Govern",
    links: [
      { href: "/gateway",    label: "Gateway",     icon: Lock },
      { href: "/compliance", label: "Compliance",  icon: Shield },
      { href: "/governance", label: "Governance",  icon: Eye },
      { href: "/activity",   label: "Activity",    icon: Clock },
    ],
  },
];

const allLinks = NAV_GROUPS.flatMap((g) => g.links);

export function Nav() {
  const path = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [path]);

  return (
    <nav className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <ShieldAlert className="w-5 h-5 text-emerald-400 group-hover:text-emerald-300 transition-colors" />
            <span className="font-mono font-semibold text-sm text-zinc-100">agent-bom</span>
            <span className="text-xs text-zinc-500 font-mono hidden sm:inline">AI BOM</span>
          </Link>

          {/* Desktop links with grouped separators */}
          <div className="hidden lg:flex items-center gap-0.5">
            {NAV_GROUPS.map((group, gi) => (
              <div key={group.label} className="flex items-center">
                {gi > 0 && <div className="w-px h-4 bg-zinc-800 mx-1.5" />}
                {group.links.map(({ href, label, icon: Icon }) => {
                  const active = href === "/" ? path === "/" : path.startsWith(href);
                  return (
                    <Link
                      key={href}
                      href={href}
                      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
                        active
                          ? "bg-zinc-800 text-zinc-100"
                          : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900"
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      {label}
                    </Link>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Right: API status + hamburger */}
          <div className="flex items-center gap-3">
            <ApiStatus />
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="lg:hidden p-1.5 rounded-md text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
              aria-label="Toggle navigation"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="lg:hidden border-t border-zinc-800 bg-zinc-950/95 backdrop-blur-sm">
          <div className="max-w-7xl mx-auto px-4 py-3 space-y-4">
            {NAV_GROUPS.map((group) => (
              <div key={group.label}>
                <div className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest mb-1.5 px-2">
                  {group.label}
                </div>
                <div className="grid grid-cols-2 gap-1">
                  {group.links.map(({ href, label, icon: Icon }) => {
                    const active = href === "/" ? path === "/" : path.startsWith(href);
                    return (
                      <Link
                        key={href}
                        href={href}
                        className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                          active
                            ? "bg-zinc-800 text-zinc-100"
                            : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900"
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                        {label}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </nav>
  );
}

function ApiStatus() {
  const [status, setStatus] = useState<"checking" | "online" | "offline">("checking");
  const [version, setVersion] = useState<string>("");

  useEffect(() => {
    let mounted = true;
    const check = () => {
      api
        .health()
        .then((res) => {
          if (mounted) {
            setStatus("online");
            setVersion(res.version || "");
          }
        })
        .catch(() => {
          if (mounted) setStatus("offline");
        });
    };
    check();
    const interval = setInterval(check, 30_000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const dotColor =
    status === "online"
      ? "bg-emerald-500"
      : status === "offline"
      ? "bg-red-500"
      : "bg-zinc-500 animate-pulse";

  return (
    <div className="flex items-center gap-1.5 text-xs text-zinc-500">
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      <span className="hidden sm:inline">
        {status === "online"
          ? `API ${version}`
          : status === "offline"
          ? "Offline"
          : "API"}
      </span>
    </div>
  );
}
