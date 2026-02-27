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
  Eye,
  Clock,
} from "lucide-react";
import { api } from "@/lib/api";

const links = [
  { href: "/",           label: "Dashboard",   icon: Activity },
  { href: "/scan",       label: "New Scan",    icon: Scan },
  { href: "/agents",     label: "Agents",      icon: Server },
  { href: "/vulns",      label: "Vulns",       icon: Bug },
  { href: "/fleet",      label: "Fleet",       icon: Users },
  { href: "/gateway",    label: "Gateway",     icon: Lock },
  { href: "/compliance", label: "Compliance",  icon: Shield },
  { href: "/graph",      label: "Graph",       icon: GitBranch },
  { href: "/mesh",       label: "Mesh",        icon: Network },
  { href: "/governance", label: "Governance",  icon: Eye },
  { href: "/activity",   label: "Activity",    icon: Clock },
  { href: "/registry",   label: "Registry",    icon: Library },
  { href: "/jobs",       label: "Jobs",        icon: ShieldAlert },
];

export function Nav() {
  const path = usePathname();

  return (
    <nav className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <ShieldAlert className="w-5 h-5 text-emerald-400 group-hover:text-emerald-300 transition-colors" />
            <span className="font-mono font-semibold text-sm text-zinc-100">agent-bom</span>
            <span className="text-xs text-zinc-500 font-mono">AI BOM</span>
          </Link>

          {/* Links */}
          <div className="flex items-center gap-1">
            {links.map(({ href, label, icon: Icon }) => {
              const active = href === "/" ? path === "/" : path.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
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

          {/* API status dot */}
          <ApiStatus />
        </div>
      </div>
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
