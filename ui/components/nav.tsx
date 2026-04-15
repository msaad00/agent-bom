"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, useCallback } from "react";
import {
  ShieldAlert,
  Scan,
  Server,
  Bug,
  Activity,
  GitBranch,
  Shield,
  Lock,
  Users,
  Network,
  Waypoints,
  Eye,
  Clock,
  Radio,
  BarChart3,
  FileText,
  ChevronDown,
  ChevronRight,
  PanelLeftClose,
  PanelLeft,
  Search,
  LayoutDashboard,
  Wrench,
} from "lucide-react";
import { api } from "@/lib/api";
import { ThemeToggle } from "@/components/theme-toggle";

// ─── Navigation Structure ──────────────────────────────────────────────────

interface NavLink {
  href: string;
  label: string;
  icon: React.ElementType;
  badge?: "critical" | "high";
}

interface NavGroup {
  label: string;
  description: string;
  icon: React.ElementType;
  links: NavLink[];
  /** Accent color from architecture diagram — matches the product layer */
  accent: string;
}

function activeGroupForPath(path: string | null): string {
  const matched = NAV_GROUPS.find((group) =>
    group.links.some((link) => (link.href === "/" ? path === "/" : Boolean(path?.startsWith(link.href))))
  );
  return matched?.label ?? NAV_GROUPS[0].label;
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Discover",
    description: "Inventory, coverage, and starting points",
    icon: LayoutDashboard,
    accent: "#58a6ff", // blue — discovery layer
    links: [
      { href: "/", label: "Dashboard", icon: LayoutDashboard },
      { href: "/agents", label: "Agents", icon: Server },
      { href: "/fleet", label: "Fleet", icon: Users },
    ],
  },
  {
    label: "Scan",
    description: "Run scans, track jobs, and review findings",
    icon: Scan,
    accent: "#f85149", // red — scanning layer
    links: [
      { href: "/scan", label: "New Scan", icon: Scan },
      { href: "/jobs", label: "Scan Jobs", icon: Clock },
      { href: "/vulns", label: "Vulnerabilities", icon: Bug, badge: "critical" },
    ],
  },
  {
    label: "Analyze",
    description: "Trace blast radius and graph relationships",
    icon: GitBranch,
    accent: "#d29922", // amber — analysis layer
    links: [
      { href: "/security-graph", label: "Security Graph", icon: Network },
      { href: "/graph", label: "Lineage Graph", icon: GitBranch },
      { href: "/mesh", label: "Agent Mesh", icon: Network },
      { href: "/context", label: "Context Map", icon: Waypoints },
      { href: "/insights", label: "Insights", icon: BarChart3 },
    ],
  },
  {
    label: "Protect",
    description: "Proxy, policy, and runtime enforcement surfaces",
    icon: Shield,
    accent: "#f778ba", // pink — enforcement layer
    links: [
      { href: "/proxy", label: "Proxy", icon: Shield },
      { href: "/audit", label: "Audit Log", icon: FileText },
      { href: "/gateway", label: "Gateway", icon: Lock },
    ],
  },
  {
    label: "Govern",
    description: "Evidence, remediation, governance, and activity",
    icon: Eye,
    accent: "#3fb950", // green — output/governance layer
    links: [
      { href: "/compliance", label: "Compliance", icon: Shield },
      { href: "/remediation", label: "Remediation", icon: Wrench },
      { href: "/governance", label: "Governance", icon: Eye },
      { href: "/traces", label: "Traces", icon: Radio },
      { href: "/activity", label: "Activity", icon: Activity },
    ],
  },
];

// ─── Risk counts for badges ─────────────────────────────────────────────────

interface RiskCounts {
  critical: number;
  high: number;
  kev: number;
  compound_issues: number;
  has_mcp_context?: boolean;
  has_agent_context?: boolean;
  scan_sources?: string[];
  scan_count?: number;
}

const MCP_ONLY_PAGES = new Set(["/agents", "/fleet", "/mesh", "/context"]);

// ─── Sidebar Component ──────────────────────────────────────────────────────

export function Nav() {
  const path = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    () => new Set([activeGroupForPath(path)])
  );
  const [counts, setCounts] = useState<RiskCounts | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Close mobile on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [path]);

  useEffect(() => {
    if (!collapsed) {
      setExpandedGroups(new Set([activeGroupForPath(path)]));
    }
  }, [collapsed, path]);

  // Sync main content padding with sidebar collapsed state
  useEffect(() => {
    const main = document.getElementById("main-content");
    if (main) {
      main.style.paddingLeft = collapsed ? "60px" : "";
    }
  }, [collapsed]);

  // Fetch risk counts for badges
  useEffect(() => {
    let mounted = true;
    const load = () => {
      api
        .getPostureCounts()
        .then((c) => {
          if (mounted) setCounts(c as RiskCounts);
        })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 60_000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const toggleGroup = useCallback((label: string) => {
    setExpandedGroups((prev) => {
      if (prev.has(label) && prev.size === 1) {
        return new Set();
      }
      return new Set([label]);
    });
  }, []);

  const isDimmed = (href: string): boolean => {
    if (!counts || (counts.scan_count ?? 0) === 0) return false;
    if (MCP_ONLY_PAGES.has(href) && !counts.has_mcp_context) return true;
    return false;
  };

  // Keyboard shortcut: Cmd/Ctrl+K for search, Cmd/Ctrl+B for sidebar
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((v) => !v);
      }
      if ((e.metaKey || e.ctrlKey) && e.key === "b") {
        e.preventDefault();
        setCollapsed((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Filter nav links by search
  const filteredGroups = searchQuery
    ? NAV_GROUPS.map((g) => ({
        ...g,
        links: g.links.filter((l) => l.label.toLowerCase().includes(searchQuery.toLowerCase())),
      })).filter((g) => g.links.length > 0)
    : NAV_GROUPS;

  const sidebarContent = (
    <>
      {/* Logo */}
      <div
        className={`border-b border-[color:var(--border-subtle)] ${
          collapsed
            ? "flex h-20 flex-col items-center justify-center gap-2 px-2 py-2"
            : "flex h-14 items-center justify-between px-4"
        }`}
      >
        <Link href="/" className="flex items-center gap-2.5 group min-w-0">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0 group-hover:bg-emerald-500/20 transition-colors">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <span className="font-semibold text-sm text-[color:var(--foreground)] block truncate">agent-bom</span>
              <span className="text-[10px] text-[color:var(--text-secondary)] font-mono block">AI Supply Chain</span>
            </div>
          )}
        </Link>
        <button
          onClick={() => setCollapsed((value) => !value)}
          className="hidden rounded-md p-1.5 text-[color:var(--text-secondary)] transition-colors hover:bg-[color:var(--surface-elevated)] hover:text-[color:var(--foreground)] lg:flex"
          title={collapsed ? "Expand sidebar (⌘B)" : "Collapse sidebar (⌘B)"}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <PanelLeft className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
        </button>
      </div>

      {/* Search */}
      {!collapsed && (
        <div className="px-3 py-3">
          <button
            onClick={() => setSearchOpen(true)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] text-xs hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)] transition-colors"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Search pages...</span>
            <kbd className="ml-auto text-[10px] font-mono bg-[color:var(--surface-elevated)] border border-[color:var(--border-subtle)] rounded px-1.5 py-0.5 text-[color:var(--text-secondary)]">⌘K</kbd>
          </button>
        </div>
      )}
      {collapsed && (
        <div className="px-2 py-3 flex justify-center">
          <button
            onClick={() => { setCollapsed(false); setSearchOpen(true); }}
            className="p-2 rounded-lg text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-elevated)] transition-colors"
            title="Search (⌘K)"
          >
            <Search className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-2 scrollbar-thin">
        {filteredGroups.map((group) => {
          const isExpanded = expandedGroups.has(group.label);
          const GroupIcon = group.icon;
          const hasActiveChild = group.links.some(
            (l) => (l.href === "/" ? path === "/" : path.startsWith(l.href))
          );

          return (
            <div key={group.label} className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
              {/* Group Header */}
              <button
                onClick={() => collapsed ? setCollapsed(false) : toggleGroup(group.label)}
                className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-xl text-xs font-medium transition-colors border-l-2 ${
                  hasActiveChild
                    ? "text-[color:var(--foreground)] bg-[color:var(--surface-elevated)]"
                    : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]"
                }`}
                style={{ borderLeftColor: group.accent }}
                title={collapsed ? group.label : undefined}
              >
                <GroupIcon
                  className="w-4 h-4 shrink-0"
                  style={{ color: hasActiveChild ? group.accent : group.accent + "99" }}
                />
                {!collapsed && (
                  <>
                    <div className="min-w-0 flex-1 text-left">
                      <span className="block uppercase tracking-wider text-[10px] font-semibold">
                        {group.label}
                      </span>
                    </div>
                    <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 text-[9px] font-mono text-[color:var(--text-tertiary)]">
                      {group.links.length}
                    </span>
                    {isExpanded ? (
                      <ChevronDown className="w-3 h-3 text-[color:var(--text-tertiary)]" />
                    ) : (
                      <ChevronRight className="w-3 h-3 text-[color:var(--text-tertiary)]" />
                    )}
                  </>
                )}
              </button>

              {/* Group Links */}
              {(isExpanded || collapsed) && !collapsed && (
                <div className="mx-2 mb-2 mt-1 space-y-0.5 border-l border-[color:var(--border-subtle)] pl-2">
                  <p className="px-3 pb-1 text-[11px] leading-5 text-[color:var(--text-tertiary)]">
                    {group.description}
                  </p>
                  {group.links.map(({ href, label, icon: Icon, badge }) => {
                    const active = href === "/" ? path === "/" : path.startsWith(href);
                    const dimmed = isDimmed(href);
                    const isVulns = href === "/vulns";

                    return (
                      <Link
                        key={href}
                        href={href}
                        className={`flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all group relative ${
                          active
                            ? "border-l-2 ml-0 pl-2.5"
                            : dimmed
                            ? "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)] hover:bg-[color:var(--surface-muted)]"
                            : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]"
                        }`}
                        style={active ? {
                          color: group.accent,
                          borderLeftColor: group.accent,
                          backgroundColor: `${group.accent}10`,
                        } : undefined}
                        title={dimmed ? "No MCP servers detected" : undefined}
                      >
                        <Icon
                          className={`w-3.5 h-3.5 shrink-0 ${!active && (dimmed ? "opacity-40" : "text-[color:var(--text-tertiary)] group-hover:text-[color:var(--text-secondary)]")}`}
                          style={active ? { color: group.accent } : undefined}
                        />
                        <span className="truncate">{label}</span>

                        {/* Vuln count badges */}
                        {isVulns && counts && counts.critical > 0 && (
                          <span className="ml-auto flex items-center gap-1">
                            <span className="text-[9px] font-mono font-bold text-red-400 bg-red-950/60 border border-red-800/40 rounded-full px-1.5 py-0 leading-4">
                              {counts.critical}
                            </span>
                            {counts.high > 0 && (
                              <span className="text-[9px] font-mono font-bold text-orange-400 bg-orange-950/60 border border-orange-800/40 rounded-full px-1.5 py-0 leading-4">
                                {counts.high}
                              </span>
                            )}
                          </span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              )}

              {/* Collapsed: just show icons as tooltips */}
              {collapsed && (
                <div className="space-y-0.5 mt-0.5">
                  {group.links.map(({ href, label, icon: Icon }) => {
                    const active = href === "/" ? path === "/" : path.startsWith(href);
                    return (
                      <Link
                        key={href}
                        href={href}
                        className={`flex items-center justify-center p-2 rounded-lg transition-colors ${
                          active
                            ? "bg-emerald-500/10 text-emerald-400"
                            : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]"
                        }`}
                        title={label}
                      >
                        <Icon className="w-4 h-4" />
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Bottom section */}
      <div className={`border-t border-[color:var(--border-subtle)] ${collapsed ? "px-2 py-3" : "px-3 py-3"}`}>
        <div className="space-y-2">
          <ThemeToggle compact={collapsed} />
          <ApiStatus collapsed={collapsed} />
        </div>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside
        className={`hidden lg:flex flex-col fixed left-0 top-0 bottom-0 z-40 bg-[color:var(--surface)] border-r border-[color:var(--border-subtle)] transition-[width] duration-200 ${
          collapsed ? "w-[60px]" : "w-[240px]"
        }`}
      >
        {sidebarContent}
      </aside>

      {/* Mobile Top Bar */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 h-14 bg-[color:var(--surface)] backdrop-blur-sm border-b border-[color:var(--border-subtle)] flex items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-2 group">
          <div className="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <span className="font-semibold text-sm text-[color:var(--foreground)]">agent-bom</span>
        </Link>
        <div className="flex items-center gap-2">
          <ThemeToggle compact />
          <ApiStatus collapsed={false} />
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="p-2 rounded-lg text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-elevated)] transition-colors"
          >
            {mobileOpen ? (
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            ) : (
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>
            )}
          </button>
        </div>
      </div>

      {/* Mobile Drawer Overlay */}
      {mobileOpen && (
        <>
          <div className="lg:hidden fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside className="lg:hidden fixed left-0 top-0 bottom-0 z-50 w-[260px] bg-[color:var(--surface)] border-r border-[color:var(--border-subtle)] flex flex-col animate-slide-in">
            {sidebarContent}
          </aside>
        </>
      )}

      {/* Command Palette / Search */}
      {searchOpen && (
        <CommandPalette
          query={searchQuery}
          setQuery={setSearchQuery}
          onClose={() => { setSearchOpen(false); setSearchQuery(""); }}
        />
      )}
    </>
  );
}

// ─── Command Palette ────────────────────────────────────────────────────────

const allLinks = NAV_GROUPS.flatMap((g) => g.links.map((l) => ({ ...l, group: g.label })));

function CommandPalette({
  query,
  setQuery,
  onClose,
}: {
  query: string;
  setQuery: (q: string) => void;
  onClose: () => void;
}) {
  const filtered = query
    ? allLinks.filter(
        (l) =>
          l.label.toLowerCase().includes(query.toLowerCase()) ||
          l.group.toLowerCase().includes(query.toLowerCase())
      )
    : allLinks;

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl shadow-2xl overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border-subtle)]">
          <Search className="w-4 h-4 text-[color:var(--text-secondary)] shrink-0" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search pages, commands..."
            className="flex-1 bg-transparent text-sm text-[color:var(--foreground)] placeholder:text-[color:var(--text-secondary)] outline-none"
          />
          <kbd className="text-[10px] font-mono bg-[color:var(--surface-elevated)] border border-[color:var(--border-subtle)] rounded px-1.5 py-0.5 text-[color:var(--text-secondary)]">ESC</kbd>
        </div>
        <div className="max-h-[50vh] overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">No results found</div>
          ) : (
            filtered.map(({ href, label, icon: Icon, group }) => (
              <Link
                key={href}
                href={href}
                onClick={onClose}
                className="flex items-center gap-3 px-4 py-2.5 text-sm text-[color:var(--foreground)] hover:bg-[color:var(--surface-elevated)] transition-colors"
              >
                <Icon className="w-4 h-4 text-[color:var(--text-secondary)]" />
                <span className="flex-1">{label}</span>
                <span className="text-[10px] text-[color:var(--text-tertiary)] uppercase tracking-wider">{group}</span>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// ─── API Status ─────────────────────────────────────────────────────────────

function ApiStatus({ collapsed }: { collapsed: boolean }) {
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

  if (collapsed) {
    return (
      <div className="flex justify-center">
        <span className={`w-2 h-2 rounded-full ${dotColor}`} title={status === "online" ? `API ${version}` : status} />
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs text-[color:var(--text-secondary)]">
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor} shrink-0`} />
      <span className="truncate">
        {status === "online" ? `API ${version}` : status === "offline" ? "API Offline" : "Connecting..."}
      </span>
    </div>
  );
}
