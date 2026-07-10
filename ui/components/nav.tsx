"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import {
  Scan,
  Bug,
  MessageSquareQuote,
  Database,
  Activity,
  GitBranch,
  Shield,
  Users,
  Network,
  Waypoints,
  Eye,
  Clock,
  Radio,
  FileText,
  ChevronDown,
  ChevronRight,
  PanelLeftClose,
  PanelLeft,
  Search,
  LayoutGrid,
  Wrench,
  RefreshCw,
  Focus,
  Copy,
  SunMoon,
  DollarSign,
  Fingerprint,
  Radar,
  Bot,
  Boxes,
  Cloud,
  ClipboardList,
  FileCheck,
  Layers,
} from "lucide-react";
import { api } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { BrandLogo } from "@/components/brand-logo";
import { CommandPalette, type CommandPaletteAction } from "@/components/command-palette";
import { DemoNavSignIn } from "@/components/demo-mode-cta";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  deploymentModeLabel,
  isNavLinkVisible,
  navLinkNeedsSetup,
} from "@/lib/deployment-context";
import { useDeploymentContext } from "@/hooks/use-deployment-context";

// ─── Navigation Structure ──────────────────────────────────────────────────

interface NavLink {
  href: string;
  label: string;
  icon: React.ElementType;
  capability?: string;
}

interface NavGroup {
  label: string;
  icon: React.ElementType;
  links: NavLink[];
  /**
   * Graph lens destinations grouped under Posture with an explicit subheader
   * (not a generic "More" bucket).
   */
  secondary?: NavLink[];
}

function activeGroupForPath(path: string | null): string {
  const matched = NAV_GROUPS.find((group) =>
    [...group.links, ...(group.secondary ?? [])].some((link) =>
      link.href === "/" ? path === "/" : Boolean(path?.startsWith(link.href))
    )
  );
  return matched?.label ?? NAV_GROUPS[0]!.label;
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Posture",
    icon: LayoutGrid,
    links: [
      { href: "/", label: "Overview", icon: LayoutGrid },
      { href: "/findings", label: "Findings", icon: Bug },
      { href: "/security-graph", label: "Security Graph", icon: Network },
      { href: "/remediation", label: "Remediation", icon: Wrench },
    ],
    secondary: [
      { href: "/graph", label: "Lineage", icon: GitBranch },
      { href: "/mesh", label: "Agent Mesh", icon: Waypoints },
      { href: "/context", label: "Context", icon: Layers },
    ],
  },
  {
    label: "AI inventory",
    icon: Bot,
    links: [
      { href: "/agents", label: "Agents", icon: Bot },
      { href: "/manifest", label: "AI BOM", icon: ClipboardList },
      { href: "/fleet", label: "Fleet", icon: Users },
    ],
  },
  {
    label: "Cloud & Data",
    icon: Cloud,
    links: [
      { href: "/connections", label: "Cloud Accounts", icon: Cloud, capability: "scan.run" },
      { href: "/sources", label: "Data Sources", icon: Database, capability: "sources.manage" },
      { href: "/scan", label: "New Scan", icon: Scan, capability: "scan.run" },
      { href: "/identity", label: "Identity", icon: Fingerprint },
      { href: "/drift", label: "Drift", icon: Radar },
    ],
  },
  {
    label: "Runtime",
    icon: Shield,
    links: [
      { href: "/runtime", label: "Runtime", icon: Shield },
      { href: "/traces", label: "Traces", icon: Radio },
    ],
  },
  {
    label: "Governance",
    icon: Eye,
    links: [
      { href: "/compliance", label: "Compliance", icon: FileCheck },
      { href: "/governance", label: "Governance", icon: Eye, capability: "policy.manage" },
      { href: "/audit", label: "Audit Log", icon: FileText },
    ],
  },
  {
    label: "Reference",
    icon: Boxes,
    links: [{ href: "/registry", label: "MCP Catalog", icon: Boxes }],
  },
  {
    label: "Operations",
    icon: Activity,
    links: [
      { href: "/cost", label: "AI Spend", icon: DollarSign },
      { href: "/jobs", label: "Scan Jobs", icon: Clock },
      { href: "/activity", label: "Activity", icon: Activity },
    ],
  },
];

const ALL_GROUP_LABELS = NAV_GROUPS.map((group) => group.label);

/** Per-route icon tint — semantic color without rainbow group chrome. */
const NAV_LINK_ICON_CLASS: Record<string, string> = {
  "/": "text-sky-400",
  "/findings": "text-red-400",
  "/security-graph": "text-violet-400",
  "/remediation": "text-emerald-400",
  "/graph": "text-sky-400",
  "/mesh": "text-fuchsia-400",
  "/context": "text-amber-400",
  "/agents": "text-emerald-400",
  "/manifest": "text-cyan-400",
  "/fleet": "text-blue-400",
  "/connections": "text-purple-400",
  "/sources": "text-indigo-400",
  "/scan": "text-orange-400",
  "/identity": "text-pink-400",
  "/drift": "text-rose-400",
  "/runtime": "text-pink-400",
  "/traces": "text-violet-400",
  "/compliance": "text-emerald-400",
  "/governance": "text-amber-400",
  "/audit": "text-stone-400",
  "/registry": "text-amber-400",
  "/cost": "text-yellow-400",
  "/jobs": "text-orange-400",
  "/activity": "text-lime-400",
};

const NAV_GROUP_ICON_CLASS: Record<string, string> = {
  Posture: "text-sky-400",
  "AI inventory": "text-emerald-400",
  "Cloud & Data": "text-purple-400",
  Runtime: "text-pink-400",
  Governance: "text-emerald-400",
  Reference: "text-amber-400",
  Operations: "text-orange-400",
};

function navLinkIconClass(href: string, active: boolean, hoverGroup = "group"): string {
  const tone = NAV_LINK_ICON_CLASS[href];
  if (tone) {
    return active ? tone : `${tone} opacity-80 ${hoverGroup}-hover:opacity-100`;
  }
  return active
    ? "text-[color:var(--foreground)]"
    : `text-[color:var(--text-tertiary)] ${hoverGroup}-hover:text-[color:var(--text-secondary)]`;
}

function navGroupIconClass(label: string, hasActiveChild: boolean): string {
  const tone = NAV_GROUP_ICON_CLASS[label];
  if (tone) {
    return hasActiveChild ? tone : `${tone} opacity-75`;
  }
  return hasActiveChild ? "text-[color:var(--foreground)]" : "text-[color:var(--text-tertiary)]";
}

// ─── Risk counts for badges ─────────────────────────────────────────────────

// ─── Sidebar Component ──────────────────────────────────────────────────────

export function Nav() {
  const path = usePathname();
  const [captureMode, setCaptureMode] = useState(false);
  const [collapsed, setCollapsed] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    () => new Set(captureMode ? ALL_GROUP_LABELS : [activeGroupForPath(path)])
  );
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [collapsedFlyoutGroup, setCollapsedFlyoutGroup] = useState<string | null>(null);
  const [collapsedFlyoutTop, setCollapsedFlyoutTop] = useState(96);
  const collapsedFlyoutTimer = useRef<number | null>(null);
  const { counts } = useDeploymentContext();
  const { session, loading: authLoading, hasCapability } = useAuthState();

  // Close mobile on route change
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setMobileOpen(false);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [path]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const capture = new URLSearchParams(window.location.search).get("capture") === "1";
      setCaptureMode(capture);
      if (capture) {
        setCollapsed(false);
        setExpandedGroups(new Set(ALL_GROUP_LABELS));
        setSearchOpen(false);
        return;
      }
      if (!collapsed) {
        setExpandedGroups(new Set([activeGroupForPath(path)]));
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [captureMode, collapsed, path]);

  // Sync main content padding with sidebar collapsed state
  useEffect(() => {
    const main = document.getElementById("main-content");
    if (main) {
      main.style.paddingLeft = collapsed ? "60px" : "240px";
    }
  }, [collapsed]);

  const toggleGroup = useCallback((label: string) => {
    if (captureMode) {
      return;
    }
    setExpandedGroups((prev) => {
      if (prev.has(label) && prev.size === 1) {
        return new Set();
      }
      return new Set([label]);
    });
  }, [captureMode]);

  const cancelCollapsedFlyoutClose = useCallback(() => {
    if (collapsedFlyoutTimer.current) {
      window.clearTimeout(collapsedFlyoutTimer.current);
      collapsedFlyoutTimer.current = null;
    }
  }, []);

  const scheduleCollapsedFlyoutClose = useCallback(() => {
    cancelCollapsedFlyoutClose();
    collapsedFlyoutTimer.current = window.setTimeout(() => {
      setCollapsedFlyoutGroup(null);
    }, 280);
  }, [cancelCollapsedFlyoutClose]);

  const openCollapsedFlyout = useCallback(
    (label: string, target: HTMLElement) => {
      if (!collapsed) return;
      cancelCollapsedFlyoutClose();
      const rect = target.getBoundingClientRect();
      setCollapsedFlyoutTop(Math.max(12, Math.min(rect.top - 10, window.innerHeight - 380)));
      setCollapsedFlyoutGroup(label);
    },
    [cancelCollapsedFlyoutClose, collapsed],
  );

  useEffect(() => {
    if (!collapsed) {
      setCollapsedFlyoutGroup(null);
    }
  }, [collapsed]);

  useEffect(() => {
    return () => {
      if (collapsedFlyoutTimer.current) {
        window.clearTimeout(collapsedFlyoutTimer.current);
      }
    };
  }, []);

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
        secondary: (g.secondary ?? []).filter((l) => l.label.toLowerCase().includes(searchQuery.toLowerCase())),
      })).filter((g) => g.links.length > 0 || (g.secondary?.length ?? 0) > 0)
    : NAV_GROUPS;

  const roleAllowsLink = useCallback(
    (link: NavLink) => {
      if (!link.capability || !session?.auth_required) {
        return true;
      }
      if (!session.authenticated || !session.role_summary) {
        return false;
      }
      return hasCapability(link.capability);
    },
    [hasCapability, session]
  );

  const navGroups = filteredGroups
    .map((group) => {
      const secondaryLinks = (group.secondary ?? []).filter(roleAllowsLink);
      if (searchQuery) {
        return { ...group, visibleLinks: group.links.filter(roleAllowsLink), hiddenLinks: [] as NavLink[], secondaryLinks };
      }
      const roleAllowed = group.links.filter(roleAllowsLink);
      const visibleLinks = roleAllowed.filter((link) => isNavLinkVisible(link.href, counts));
      const hiddenLinks = roleAllowed.filter((link) => !isNavLinkVisible(link.href, counts));
      return { ...group, visibleLinks, hiddenLinks, secondaryLinks };
    })
    .filter((group) => group.visibleLinks.length > 0 || group.hiddenLinks.length > 0 || group.secondaryLinks.length > 0);
  const commandLinks = navGroups.flatMap((group) =>
    [...group.visibleLinks, ...group.secondaryLinks].map((link) => ({ ...link, group: group.label }))
  );
  const commandActions = useMemo<CommandPaletteAction[]>(
    () => [
      {
        id: "refresh-view",
        label: "Refresh current view",
        group: "Action",
        icon: RefreshCw,
        keywords: ["reload", "update"],
        run: () => window.location.reload(),
      },
      {
        id: "focus-main",
        label: "Focus main content",
        group: "Action",
        icon: Focus,
        keywords: ["skip", "content"],
        run: () => {
          const main = document.getElementById("main-content");
          if (!main) return;
          if (!main.hasAttribute("tabindex")) {
            main.setAttribute("tabindex", "-1");
          }
          main.focus();
        },
      },
      {
        id: "copy-url",
        label: "Copy current URL",
        group: "Action",
        icon: Copy,
        keywords: ["share", "link"],
        run: () => {
          void navigator.clipboard?.writeText(window.location.href);
        },
      },
      {
        id: "toggle-theme",
        label: "Toggle theme",
        group: "Action",
        icon: SunMoon,
        keywords: ["dark", "light"],
        run: () => {
          const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
          const next = current === "dark" ? "light" : "dark";
          document.documentElement.dataset.theme = next;
          document.documentElement.style.colorScheme = next;
          window.localStorage.setItem("agent-bom-theme", next);
          window.dispatchEvent(new Event("agent-bom-theme-change"));
        },
      },
    ],
    []
  );

  const renderSidebarContent = (isCollapsed: boolean, allowCollapse: boolean) => (
    <>
      {/* Sidebar controls */}
      <div
        className={`border-b border-[color:var(--border-subtle)] ${
          isCollapsed
            ? "flex h-11 items-center justify-center px-2"
            : "flex h-11 items-center justify-between px-3"
        }`}
      >
        {!isCollapsed && (
          <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
            Navigate
          </span>
        )}
        {allowCollapse && <button
          onClick={() => setCollapsed((value) => !value)}
          className="hidden rounded-md p-1.5 text-[color:var(--text-secondary)] transition-colors hover:bg-[color:var(--surface-elevated)] hover:text-[color:var(--foreground)] lg:flex"
          title={isCollapsed ? "Expand sidebar (⌘B)" : "Collapse sidebar (⌘B)"}
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {isCollapsed ? <PanelLeft className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
        </button>}
      </div>

      {/* Search */}
      {!isCollapsed && (
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
      {isCollapsed && (
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
      <nav className={`${isCollapsed ? "overflow-visible" : "overflow-y-auto scrollbar-thin"} flex-1 px-2 py-2 space-y-2`}>
        {navGroups.map((group) => {
          const isExpanded = captureMode || expandedGroups.has(group.label);
          const GroupIcon = group.icon;
          const hasActiveChild = [...group.visibleLinks, ...group.hiddenLinks, ...group.secondaryLinks].some(
            (l) => (l.href === "/" ? path === "/" : path.startsWith(l.href))
          );

          return (
            <div
              key={group.label}
              className={`rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] ${
                isCollapsed ? "group/navlane relative" : ""
              }`}
            >
              {/* Group Header */}
              <button
                onClick={() => {
                  if (captureMode) {
                    return;
                  }
                  if (isCollapsed) {
                    return;
                  } else {
                    toggleGroup(group.label);
                  }
                }}
                onMouseEnter={isCollapsed ? (event) => openCollapsedFlyout(group.label, event.currentTarget) : undefined}
                onMouseLeave={isCollapsed ? scheduleCollapsedFlyoutClose : undefined}
                onFocus={isCollapsed ? (event) => openCollapsedFlyout(group.label, event.currentTarget) : undefined}
                onBlur={isCollapsed ? scheduleCollapsedFlyoutClose : undefined}
                className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-xl text-xs font-medium transition-colors border-l-2 ${
                  isCollapsed ? "justify-center px-2 py-3" : ""
                } ${
                  hasActiveChild
                    ? "border-[color:var(--border-strong)] text-[color:var(--foreground)] bg-[color:var(--surface-elevated)]"
                    : "border-transparent text-[color:var(--text-secondary)] hover:border-[color:var(--border-subtle)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]"
                }`}
                aria-expanded={isCollapsed ? collapsedFlyoutGroup === group.label : isExpanded}
                aria-label={isCollapsed ? group.label : undefined}
              >
                <GroupIcon
                  className={`${isCollapsed ? "h-5 w-5" : "h-4 w-4"} shrink-0 ${navGroupIconClass(group.label, hasActiveChild)}`}
                />
                {!isCollapsed && (
                  <>
                    <div className="min-w-0 flex-1 text-left">
                      <span className="block uppercase tracking-wider text-[10px] font-semibold">
                        {group.label}
                      </span>
                    </div>
                    <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 text-[9px] font-mono text-[color:var(--text-tertiary)]">
                      {group.visibleLinks.length}
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
              {isExpanded && !isCollapsed && (
                <div className="mx-2 mb-2 mt-1 space-y-0.5 border-l border-[color:var(--border-subtle)] pl-2">
                  {group.visibleLinks.map(({ href, label, icon: Icon }) => {
                    const active =
                      href === "/"
                        ? path === "/"
                        : href === "/findings"
                        ? path.startsWith("/findings")
                        : path.startsWith(href);
                    const isFindings = href === "/findings";
                    const showVulnBadge = isFindings && counts && counts.critical > 0;
                    const needsSetup = !active && !showVulnBadge && navLinkNeedsSetup(href, counts);

                    return (
                      <Link
                        key={href}
                        href={href}
                        className={`flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all group relative ${
                          active
                            ? "border-l-2 border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)] ml-0 pl-2.5"
                            : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]"
                        }`}
                      >
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${navLinkIconClass(href, active)}`} />
                        <span className="truncate">{label}</span>

                        {/* Capable-but-unconnected hint */}
                        {needsSetup && (
                          <span className="ml-auto rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0 text-[9px] font-medium uppercase tracking-[0.12em] leading-4 text-[color:var(--text-tertiary)]">
                            Set up
                          </span>
                        )}

                        {/* Vuln count badges */}
                        {showVulnBadge && (
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
                  {group.hiddenLinks.length > 0 && (
                    <details className="mt-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2">
                      <summary className="cursor-pointer list-none text-[11px] font-medium uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">
                        Unused in {deploymentModeLabel(counts?.deployment_mode)} ({group.hiddenLinks.length})
                      </summary>
                      <div className="mt-2 space-y-0.5">
                        {group.hiddenLinks.map(({ href, label, icon: Icon }) => (
                          <Link
                            key={href}
                            href={href}
                            className="flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-[12px] text-[color:var(--text-tertiary)] transition-colors hover:bg-[color:var(--surface-muted)] hover:text-[color:var(--text-secondary)]"
                            title="Hidden until this deployment mode is detected"
                          >
                            <Icon className={`h-3.5 w-3.5 shrink-0 opacity-60 ${NAV_LINK_ICON_CLASS[href] ?? ""}`} />
                            <span className="truncate">{label}</span>
                          </Link>
                        ))}
                      </div>
                    </details>
                  )}
                  {group.secondaryLinks.length > 0 && (
                    <div className="mt-2 border-t border-[color:var(--border-subtle)] pt-2">
                      <p className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                        Graph lenses
                      </p>
                      <div className="space-y-0.5">
                        {group.secondaryLinks.map(({ href, label, icon: Icon }) => {
                          const active = path.startsWith(href);
                          return (
                            <Link
                              key={href}
                              href={href}
                              className={`flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-[13px] transition-colors ${
                                active
                                  ? "border-l-2 border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)] ml-0 pl-2.5 font-medium"
                                  : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]"
                              }`}
                            >
                              <Icon className={`h-3.5 w-3.5 shrink-0 ${navLinkIconClass(href, active)}`} />
                              <span className="truncate">{label}</span>
                            </Link>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {isCollapsed && collapsedFlyoutGroup === group.label && (
                <div
                  className="fixed left-[52px] z-[70] w-[340px] pl-4"
                  style={{ top: collapsedFlyoutTop }}
                  onMouseEnter={cancelCollapsedFlyoutClose}
                  onMouseLeave={scheduleCollapsedFlyoutClose}
                  onFocus={cancelCollapsedFlyoutClose}
                  onBlur={scheduleCollapsedFlyoutClose}
                >
                  <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3 shadow-2xl shadow-black/45">
                    <div className="mb-3 flex items-start gap-3">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
                        <GroupIcon className={`h-5 w-5 ${navGroupIconClass(group.label, hasActiveChild)}`} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-[color:var(--foreground)]">
                          {group.label}
                        </p>
                      </div>
                    </div>
                    <div className="space-y-1">
                      {group.visibleLinks.map(({ href, label, icon: Icon }) => {
                        const active =
                          href === "/"
                            ? path === "/"
                            : href === "/findings"
                            ? path.startsWith("/findings")
                            : path.startsWith(href);
                        return (
                          <Link
                            key={href}
                            href={href}
                            className={`group/link flex items-start gap-3 rounded-xl px-3 py-2.5 transition-colors ${
                              active
                                ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                                : "text-[color:var(--text-secondary)] hover:bg-[color:var(--surface-muted)] hover:text-[color:var(--foreground)]"
                            }`}
                            onClick={() => setCollapsedFlyoutGroup(null)}
                          >
                            <Icon
                              className={`mt-0.5 h-4 w-4 shrink-0 ${navLinkIconClass(href, active, "group/link")}`}
                            />
                            <span className="min-w-0">
                              <span className="block text-sm font-medium">{label}</span>
                            </span>
                          </Link>
                        );
                      })}
                      {group.secondaryLinks.length > 0 && (
                        <p className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                          Graph lenses
                        </p>
                      )}
                      {group.secondaryLinks.map(({ href, label, icon: Icon }) => {
                        const active = path.startsWith(href);
                        return (
                          <Link
                            key={href}
                            href={href}
                            className={`group/link flex items-start gap-3 rounded-xl px-3 py-2 transition-colors ${
                              active
                                ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                                : "text-[color:var(--text-tertiary)] hover:bg-[color:var(--surface-muted)] hover:text-[color:var(--foreground)]"
                            }`}
                            onClick={() => setCollapsedFlyoutGroup(null)}
                          >
                            <Icon
                              className={`mt-0.5 h-4 w-4 shrink-0 ${navLinkIconClass(href, active, "group/link")}`}
                            />
                            <span className="min-w-0">
                              <span className="block text-[13px]">{label}</span>
                            </span>
                          </Link>
                        );
                      })}
                    </div>
                    {group.hiddenLinks.length > 0 && (
                      <p className="mt-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[11px] text-[color:var(--text-tertiary)]">
                        {group.hiddenLinks.length} page{group.hiddenLinks.length === 1 ? "" : "s"} hidden for{" "}
                        {deploymentModeLabel(counts?.deployment_mode)} mode.
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Bottom section — collapsed by default so nav lanes keep vertical space */}
      <SidebarFooter
        collapsed={isCollapsed}
        authLoading={authLoading}
        session={session}
        path={path}
      />
    </>
  );

  return (
    <>
      {/* Product chrome — Snowflake-style top bar with canonical agent-bom lockup */}
      <header className="fixed inset-x-0 top-0 z-[60] flex h-16 items-center gap-3 border-b border-[color:var(--border-subtle)] bg-[color:var(--surface)]/95 px-4 backdrop-blur-sm">
        <Link href="/" className="group flex min-w-0 items-center transition-opacity hover:opacity-90">
          <BrandLogo
            showTagline
            markClassName="h-9 w-9"
            wordmarkClassName="h-[26px] w-auto max-w-[11rem]"
            className="transition-transform duration-200 group-hover:scale-[1.01]"
          />
        </Link>
        {counts?.deployment_mode && (
          <span
            className="hidden rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-0.5 text-[10px] font-mono uppercase tracking-[0.16em] text-[color:var(--text-tertiary)] sm:inline-flex"
            title={`${deploymentModeLabel(counts.deployment_mode)} deployment — evidence scope for this control plane`}
          >
            {deploymentModeLabel(counts.deployment_mode)}
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => setSearchOpen(true)}
            className="hidden items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)] lg:flex"
            title="Search pages (⌘K)"
          >
            <Search className="h-3.5 w-3.5" />
            <span>Search</span>
            <kbd className="ml-1 rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-[color:var(--text-secondary)]">
              ⌘K
            </kbd>
          </button>
          <ThemeToggle compact />
          <ApiStatus collapsed={false} />
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="rounded-lg p-2 text-[color:var(--text-secondary)] transition-colors hover:bg-[color:var(--surface-elevated)] hover:text-[color:var(--foreground)] lg:hidden"
            aria-label={mobileOpen ? "Close navigation menu" : "Open navigation menu"}
          >
            {mobileOpen ? (
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            )}
          </button>
        </div>
      </header>

      {/* Desktop Sidebar */}
      <aside
        className={`hidden lg:flex flex-col fixed left-0 top-16 bottom-0 z-40 bg-[color:var(--surface)] border-r border-[color:var(--border-subtle)] transition-[width] duration-200 ${
          collapsed ? "w-[60px]" : "w-[240px]"
        }`}
      >
        {renderSidebarContent(collapsed, true)}
      </aside>

      {/* Mobile Drawer Overlay */}
      {mobileOpen && (
        <>
          <div className="lg:hidden fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside aria-label="Mobile navigation" className="lg:hidden fixed left-0 top-16 bottom-0 z-50 w-[260px] bg-[color:var(--surface)] border-r border-[color:var(--border-subtle)] flex flex-col animate-slide-in">
            {renderSidebarContent(false, false)}
          </aside>
        </>
      )}

      {/* Command Palette / Search */}
      {searchOpen && (
        <CommandPalette
          query={searchQuery}
          links={commandLinks}
          actions={commandActions}
          setQuery={setSearchQuery}
          onClose={() => { setSearchOpen(false); setSearchQuery(""); }}
        />
      )}
    </>
  );
}

function SidebarFooter({
  collapsed,
  authLoading,
  session,
  path,
}: {
  collapsed: boolean;
  authLoading: boolean;
  session: ReturnType<typeof useAuthState>["session"];
  path: string | null;
}) {
  const feedbackLink = (
    <Link
      href={`/help?from=${encodeURIComponent(path ?? "/")}`}
      className={`flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[12px] text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)] ${collapsed ? "justify-center px-2" : ""}`}
      title="Share feedback or report a bug"
    >
      <MessageSquareQuote className="h-4 w-4 shrink-0" />
      {!collapsed && <span>Feedback &amp; Bug Report</span>}
    </Link>
  );

  if (collapsed) {
    return (
      <div className="border-t border-[color:var(--border-subtle)] px-2 py-3">
        <div className="space-y-2">
          <SessionStatus collapsed loading={authLoading} session={session} />
          <DemoNavSignIn collapsed />
          {feedbackLink}
        </div>
      </div>
    );
  }

  const footerHint = authLoading
    ? "Checking session…"
    : session?.authenticated
      ? `Signed in · ${session.subject ?? session.role_summary?.display_name ?? session.role ?? "user"}`
      : "Sign-in required";

  return (
    <div className="border-t border-[color:var(--border-subtle)] px-3 py-3">
      <details className="group/footer">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[11px] text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
          <span className="truncate">{footerHint}</span>
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-[color:var(--text-tertiary)] transition-transform group-open/footer:rotate-90" />
        </summary>
        <div className="mt-2 space-y-2">
          <SessionStatus collapsed={false} loading={authLoading} session={session} embedded />
          <DemoNavSignIn />
          {feedbackLink}
        </div>
      </details>
    </div>
  );
}

function SessionStatus({
  collapsed,
  loading,
  session,
  embedded = false,
}: {
  collapsed: boolean;
  loading: boolean;
  session: ReturnType<typeof useAuthState>["session"];
  embedded?: boolean;
}) {
  if (collapsed) {
    if (loading) {
      return <div className="mx-auto h-2 w-2 rounded-full bg-zinc-500 animate-pulse" title="Checking session" />;
    }
    if (session?.authenticated) {
      return (
        <div
          className="mx-auto h-2 w-2 rounded-full bg-emerald-500"
          title={`${session.role_summary?.display_name ?? session.role ?? "Authenticated"} · tenant ${session.tenant_id}`}
        />
      );
    }
    return <div className="mx-auto h-2 w-2 rounded-full bg-amber-500" title="Authentication required" />;
  }

  if (loading) {
    return (
      <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[12px] text-[color:var(--text-secondary)]">
        Checking session…
      </div>
    );
  }

  if (!session?.authenticated) {
    if (embedded) {
      return null;
    }
    return (
      <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[12px] text-[color:var(--text-secondary)]">
        Sign-in required for protected control-plane actions
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Signed in</p>
      <p className="mt-1 truncate text-[12px] font-medium text-[color:var(--foreground)]">{session.subject ?? "Authenticated user"}</p>
      <p className="mt-1 text-[11px] text-[color:var(--text-secondary)]">
        {session.role_summary?.display_name ?? session.role ?? "Unknown"} · tenant {session.tenant_id}
      </p>
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
        <span className={`w-2 h-2 rounded-full ${dotColor}`} title={status === "online" ? `Control plane online · v${version}` : status} />
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs text-[color:var(--text-secondary)]">
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor} shrink-0`} />
      <span className="truncate">
        {status === "online" ? `Control plane · v${version}` : status === "offline" ? "Control plane offline" : "Connecting…"}
      </span>
    </div>
  );
}
