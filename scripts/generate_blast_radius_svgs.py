#!/usr/bin/env python3
"""Generate README blast-radius SVGs with clipped text inside every container."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_doc_architecture_svgs import (  # noqa: E402
    _audit_github_safe,
    _audit_layout,
    _esc,
    _text,
)

OUT = ROOT / "docs" / "images"

THEMES = {
    "dark": {
        "bg": "#0a0a0b",
        "frame": "#26262a",
        "title": "#f4f4f5",
        "subtitle": "#a1a1aa",
        "arrow": "#5c5c66",
        "arrow_danger": "#f87171",
        "package_fill": "#1f1710",
        "package_stroke": "#92400e",
        "package_label": "#f59e0b",
        "package_title": "#fde68a",
        "finding_fill": "#241114",
        "finding_stroke": "#991b1b",
        "finding_label": "#fca5a5",
        "finding_title": "#fecaca",
        "mcp_fill": "#171326",
        "mcp_stroke": "#5b21b6",
        "mcp_label": "#c4b5fd",
        "mcp_title": "#ddd6fe",
        "agent_fill": "#101827",
        "agent_stroke": "#1d4ed8",
        "agent_label": "#93c5fd",
        "agent_title": "#dbeafe",
        "muted": "#8b8b94",
        "blast_fill": "#1b1012",
        "blast_stroke": "#fb7185",
        "blast_title": "#fca5a5",
        "blast_divider": "#7f1d1d",
        "cred_label": "#fdba74",
        "cred_fill": "#21160f",
        "cred_stroke": "#9a3412",
        "cred_text": "#fed7aa",
        "tool_label": "#67e8f9",
        "tool_fill": "#0d1f24",
        "tool_stroke": "#0e7490",
        "tool_text": "#a5f3fc",
        "rce_fill": "#f87171",
        "stats_fill": "#161619",
        "stats_stroke": "#2b2b30",
        "stats_divider": "#26262a",
        "stat_red": "#fca5a5",
        "stat_cyan": "#67e8f9",
        "fix_fill": "#06251a",
        "fix_stroke": "#0c5a44",
        "fix_label": "#34d399",
        "fix_text": "#6ee7b7",
        "badge_fill": "#241114",
        "badge_stroke": "#f87171",
        "badge_text": "#fca5a5",
        "spine": "#f87171",
        "ic_pkg": "#fbbf24",
        "ic_find": "#f87171",
        "ic_mcp": "#a78bfa",
        "ic_agent": "#60a5fa",
    },
    "light": {
        "bg": "#ffffff",
        "frame": "#e4e4e7",
        "title": "#18181b",
        "subtitle": "#71717a",
        "arrow": "#9ca3af",
        "arrow_danger": "#ef4444",
        "package_fill": "#fffbeb",
        "package_stroke": "#f59e0b",
        "package_label": "#b45309",
        "package_title": "#78350f",
        "finding_fill": "#fef2f2",
        "finding_stroke": "#ef4444",
        "finding_label": "#dc2626",
        "finding_title": "#7f1d1d",
        "mcp_fill": "#f5f3ff",
        "mcp_stroke": "#8b5cf6",
        "mcp_label": "#6d28d9",
        "mcp_title": "#3b0764",
        "agent_fill": "#eff6ff",
        "agent_stroke": "#3b82f6",
        "agent_label": "#1d4ed8",
        "agent_title": "#1e3a8a",
        "muted": "#71717a",
        "blast_fill": "#fff7ed",
        "blast_stroke": "#fb7185",
        "blast_title": "#dc2626",
        "blast_divider": "#fca5a5",
        "cred_label": "#c2410c",
        "cred_fill": "#fff7ed",
        "cred_stroke": "#fdba74",
        "cred_text": "#9a3412",
        "tool_label": "#0e7490",
        "tool_fill": "#ecfeff",
        "tool_stroke": "#67e8f9",
        "tool_text": "#0e7490",
        "rce_fill": "#ef4444",
        "stats_fill": "#fafafa",
        "stats_stroke": "#e4e4e7",
        "stats_divider": "#ececef",
        "stat_red": "#dc2626",
        "stat_cyan": "#0e7490",
        "fix_fill": "#ecfdf5",
        "fix_stroke": "#a7f3d0",
        "fix_label": "#059669",
        "fix_text": "#047857",
        "badge_fill": "#fef2f2",
        "badge_stroke": "#ef4444",
        "badge_text": "#dc2626",
        "spine": "#ef4444",
        "ic_pkg": "#d97706",
        "ic_find": "#dc2626",
        "ic_mcp": "#7c3aed",
        "ic_agent": "#2563eb",
    },
}


def _svg_open(w: int, h: int, title: str, desc: str) -> list[str]:
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" fill="none" font-family="system-ui, -apple-system, \'Segoe UI\', sans-serif">',
        f"<title>{_esc(title)}</title>",
        f"<desc>{_esc(desc)}</desc>",
    ]


def _clip_def(clip_id: str, x: float, y: float, w: float, h: float) -> str:
    return f'<clipPath id="{clip_id}"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="2"/></clipPath>'


def _clipped_text(
    clip_id: str,
    x: float,
    y: float,
    content: str,
    *,
    w: float,
    anchor: str = "start",
    **attrs: str,
) -> str:
    attr_bits = " ".join(f'{key}="{value}"' for key, value in attrs.items())
    return f'<text x="{x}" y="{y}" text-anchor="{anchor}" clip-path="url(#{clip_id})" {attr_bits}>{_esc(content)}</text>'


def _bezier_arrow(x1: float, y1: float, x2: float, y2: float, color: str, *, width: float = 1.6) -> str:
    mid_x = (x1 + x2) / 2
    return (
        f'<path d="M{x1} {y1} C{mid_x} {y1} {mid_x} {y2} {x2 - 8} {y2}" '
        f'stroke="{color}" stroke-width="{width}" fill="none"/>'
        f'<polygon points="{x2 - 1},{y2} {x2 - 8},{y2 - 3.5} {x2 - 8},{y2 + 3.5}" fill="{color}"/>'
    )


def _flow_card(
    clip_id: str,
    x: int,
    y: int,
    w: int,
    h: int,
    *,
    fill: str,
    stroke: str,
    label: str,
    label_color: str,
    title: str,
    title_color: str,
    subtitle: str,
    icon: str,
    muted: str,
) -> str:
    pad_x = 38
    text_x = x + pad_x
    text_w = w - pad_x - 10
    label_y = y + 18
    title_y = y + 34
    subtitle_y = y + 48
    return (
        _clip_def(clip_id, text_x, y + 8, text_w, h - 14)
        + f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="{stroke}" stroke-width="1"/>'
        + icon
        + _clipped_text(
            clip_id,
            text_x,
            label_y,
            label,
            w=text_w,
            **{
                "font-size": "7.5",
                "font-weight": "700",
                "letter-spacing": "0.09em",
                "fill": label_color,
            },
        )
        + _clipped_text(
            clip_id,
            text_x,
            title_y,
            title,
            w=text_w,
            **{"font-size": "11.5", "font-weight": "700", "fill": title_color},
        )
        + _clipped_text(
            clip_id,
            text_x,
            subtitle_y,
            subtitle,
            w=text_w,
            **{"font-size": "9", "fill": muted},
        )
    )


def _list_chip(
    clip_id: str,
    x: int,
    y: int,
    w: int,
    h: int,
    label: str,
    *,
    fill: str,
    stroke: str,
    text_color: str,
    icon: str,
    danger: bool = False,
    badge: str | None = None,
) -> str:
    text_x = x + 26
    text_w = w - 34 - (28 if badge else 8)
    text_y = y + h - 8
    badge_svg = ""
    if badge:
        badge_svg = f'<rect x="{x + w - 30}" y="{y + 5}" width="24" height="14" rx="7" fill="#ffffff" opacity="0.22"/>' + _text(
            x + w - 18,
            y + 15,
            badge,
            **{
                "text-anchor": "middle",
                "font-size": "6.5",
                "font-weight": "800",
                "fill": "#ffffff",
            },
        )
    return (
        _clip_def(clip_id, text_x, y + 4, text_w, h - 8)
        + f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{fill}" stroke="{stroke}" stroke-width="1"/>'
        + icon
        + _clipped_text(
            clip_id,
            text_x,
            text_y,
            label,
            w=text_w,
            **{
                "font-size": "8.5",
                "font-weight": "600" if not danger else "700",
                "font-family": "ui-monospace, monospace",
                "fill": text_color,
            },
        )
        + badge_svg
    )


def blast_radius(theme_name: str) -> str:
    t = THEMES[theme_name]
    w, h = 960, 560
    cy = 272
    node_h = 64
    node_w = 154
    mcp_w = 158
    agent_w = 160

    def cid(name: str) -> str:
        return f"br-{theme_name}-{name}"

    parts = _svg_open(w, h, "Attack-path blast radius", "Package to finding to MCP to agent to blast radius.")
    parts.append("<defs>")
    parts.append(
        '<linearGradient id="conv" gradientUnits="userSpaceOnUse" x1="728" y1="0" x2="766" y2="0">'
        f'<stop offset="0" stop-color="{t["arrow"]}"/>'
        f'<stop offset="1" stop-color="{t["arrow_danger"]}"/>'
        "</linearGradient>"
    )
    parts.append("</defs>")
    parts.append(f'<rect x="16" y="16" width="928" height="528" rx="18" fill="{t["bg"]}" stroke="{t["frame"]}" stroke-width="1"/>')
    parts.append(
        _text(
            w // 2,
            48,
            "Attack-path blast radius from one vulnerable package",
            **{
                "text-anchor": "middle",
                "font-size": "17",
                "font-weight": "700",
                "fill": t["title"],
            },
        )
    )
    parts.append(
        _text(
            w // 2,
            68,
            "package -> finding -> MCP server -> AI agent -> credentials and tools",
            **{"text-anchor": "middle", "font-size": "10", "fill": t["subtitle"]},
        )
    )

    pkg_x, find_x = 36, 212
    mcp_x, agent_x = 396, 586
    blast_x, blast_w = 758, 174
    blast_y, blast_h = 108, 332

    pkg_icon = (
        f'<path d="M{pkg_x + 19} {cy - 9:.1f} L{pkg_x + 26} {cy - 5:.1f} V{cy + 3:.1f} L{pkg_x + 19} {cy + 7:.1f} '
        f'L{pkg_x + 12} {cy + 3:.1f} V{cy - 5:.1f} Z" stroke="{t["ic_pkg"]}" stroke-width="1.5" fill="none" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="M{pkg_x + 12} {cy - 5:.1f} L{pkg_x + 19} {cy - 1:.1f} L{pkg_x + 26} {cy - 5:.1f} '
        f'M{pkg_x + 19} {cy - 1:.1f} V{cy + 7:.1f}" '
        f'stroke="{t["ic_pkg"]}" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    )
    find_icon = (
        f'<path d="M{find_x + 19} {cy - 10:.1f} L{find_x + 25} {cy - 7:.1f} V{cy - 2:.1f} '
        f"C{find_x + 25} {cy + 3:.1f} {find_x + 19} {cy + 6:.1f} {find_x + 19} {cy + 6:.1f} "
        f'C{find_x + 19} {cy + 6:.1f} {find_x + 13} {cy + 3:.1f} {find_x + 13} {cy - 2:.1f} V{cy - 7:.1f} Z" '
        f'stroke="{t["ic_find"]}" stroke-width="1.5" fill="none"/>'
        f'<path d="M{find_x + 19} {cy - 4:.1f} V{cy + 1:.1f}" stroke="{t["ic_find"]}" stroke-width="1.5"/>'
        f'<circle cx="{find_x + 19}" cy="{cy + 4:.1f}" r="0.9" fill="{t["ic_find"]}"/>'
    )

    parts.append(_bezier_arrow(pkg_x + node_w, cy, find_x, cy, t["ic_pkg"], width=1.8))
    parts.append(_bezier_arrow(find_x + node_w, cy, mcp_x, cy - 86, t["ic_mcp"]))
    parts.append(_bezier_arrow(find_x + node_w, cy, mcp_x, cy + 86, t["ic_mcp"]))

    for ay in (cy - 86, cy, cy + 86):
        parts.append(_bezier_arrow(agent_x + agent_w, ay, blast_x, cy, t["arrow_danger"], width=2.0))

    node_y = cy - node_h // 2
    parts.append(
        _flow_card(
            cid("pkg"),
            pkg_x,
            node_y,
            node_w,
            node_h,
            fill=t["package_fill"],
            stroke=t["package_stroke"],
            label="PACKAGE",
            label_color=t["package_label"],
            title="better-sqlite3",
            title_color=t["package_title"],
            subtitle="npm · v9.0.0",
            icon=pkg_icon,
            muted=t["muted"],
        )
    )
    parts.append(
        _flow_card(
            cid("find"),
            find_x,
            node_y,
            node_w,
            node_h,
            fill=t["finding_fill"],
            stroke=t["finding_stroke"],
            label="FINDING",
            label_color=t["finding_label"],
            title="OSV/GHSA",
            title_color=t["finding_title"],
            subtitle="Critical · advisory",
            icon=find_icon,
            muted=t["muted"],
        )
    )

    mcp_nodes = [
        (cy - 86, "sqlite-mcp", "unverified · 3 tools"),
        (cy + 86, "db-tools", "verified · 5 tools"),
    ]
    for idx, (ny, name, sub) in enumerate(mcp_nodes):
        my = ny - node_h // 2
        ix = mcp_x + 12
        iy = ny
        mcp_icon = (
            f'<path d="M{ix + 6} {iy:.1f} a3.2 3.2 0 0 1 0.4 -6.3 a4.4 4.4 0 0 1 8.4 -1.2 a3.4 3.4 0 0 1 0.6 6.7 Z" '
            f'stroke="{t["ic_mcp"]}" stroke-width="1.5" fill="none"/>'
            f'<path d="M{ix + 12.7} {iy + 1:.1f} V{iy - 5:.1f} M{ix + 10} {iy - 2.5:.1f} '
            f'L{ix + 12.7} {iy - 5:.1f} L{ix + 15.4} {iy - 2.5:.1f}" '
            f'stroke="{t["ic_mcp"]}" stroke-width="1.5" fill="none"/>'
        )
        parts.append(
            _flow_card(
                cid(f"mcp-{idx}"),
                mcp_x,
                my,
                mcp_w,
                node_h,
                fill=t["mcp_fill"],
                stroke=t["mcp_stroke"],
                label="MCP SERVER",
                label_color=t["mcp_label"],
                title=name,
                title_color=t["mcp_title"],
                subtitle=sub,
                icon=mcp_icon,
                muted=t["muted"],
            )
        )
        parts.append(_bezier_arrow(mcp_x + mcp_w, ny, agent_x, ny, t["ic_mcp"]))

    agent_nodes = [
        (cy - 86, "code-agent", "4 servers · 12 tools"),
        (cy, "desktop-agent", "3 servers · 8 tools", True),
        (cy + 86, "review-agent", "2 servers · 6 tools"),
    ]
    for idx, row in enumerate(agent_nodes):
        ny, name, sub = row[0], row[1], row[2]
        show_badge = len(row) > 3 and row[3]
        ay = ny - node_h // 2
        ax = agent_x + 19
        agent_icon = (
            f'<path d="M{ax} {ny - 11:.1f} V{ny - 8:.1f}" stroke="{t["ic_agent"]}" stroke-width="1.5"/>'
            f'<circle cx="{ax}" cy="{ny - 12:.1f}" r="1.1" fill="{t["ic_agent"]}"/>'
            f'<rect x="{ax - 7}" y="{ny - 8:.1f}" width="14" height="12" rx="3" stroke="{t["ic_agent"]}" stroke-width="1.5"/>'
            f'<circle cx="{ax - 3}" cy="{ny - 2:.1f}" r="1.1" fill="{t["ic_agent"]}"/>'
            f'<circle cx="{ax + 3}" cy="{ny - 2:.1f}" r="1.1" fill="{t["ic_agent"]}"/>'
            f'<path d="M{ax - 9} {ny - 3:.1f} V{ny:.1f} M{ax + 9} {ny - 3:.1f} V{ny:.1f}" stroke="{t["ic_agent"]}" stroke-width="1.5"/>'
        )
        parts.append(
            _flow_card(
                cid(f"agent-{idx}"),
                agent_x,
                ay,
                agent_w,
                node_h,
                fill=t["agent_fill"],
                stroke=t["agent_stroke"],
                label="AI AGENT",
                label_color=t["agent_label"],
                title=name,
                title_color=t["agent_title"],
                subtitle=sub,
                icon=agent_icon,
                muted=t["muted"],
            )
        )
        if show_badge:
            bx = agent_x + agent_w - 8
            badge_fill = t["badge_fill"]
            badge_stroke = t["badge_stroke"]
            parts.append(
                f'<rect x="{bx}" y="{ny - 8}" width="28" height="16" rx="8" '
                f'fill="{badge_fill}" stroke="{badge_stroke}" stroke-width="0.8"/>'
                + _text(
                    bx + 14,
                    ny + 3,
                    "2x",
                    **{"text-anchor": "middle", "font-size": "8", "font-weight": "800", "fill": t["badge_text"]},
                )
            )

    blast_cx = blast_x + blast_w // 2
    inner_x = blast_x + 14
    inner_w = blast_w - 28
    chip_h = 24
    chip_gap = 6
    parts.append(
        f'<rect x="{blast_x}" y="{blast_y}" width="{blast_w}" height="{blast_h}" rx="14" fill="{t["blast_fill"]}" '
        f'stroke="{t["blast_stroke"]}" stroke-width="1.6"/>'
        + _text(
            blast_cx,
            blast_y + 22,
            "BLAST RADIUS",
            **{
                "text-anchor": "middle",
                "font-size": "9.5",
                "font-weight": "800",
                "letter-spacing": "0.08em",
                "fill": t["blast_title"],
            },
        )
        + f'<line x1="{inner_x}" y1="{blast_y + 30}" x2="{blast_x + blast_w - 14}" y2="{blast_y + 30}" '
        f'stroke="{t["blast_divider"]}" stroke-width="1" opacity="0.6"/>'
        + f'<circle cx="{inner_x + 2}" cy="{cy}" r="2.6" fill="{t["spine"]}"/>'
    )

    cred_y = blast_y + 44
    parts.append(
        _text(
            inner_x + 4,
            cred_y,
            "CREDENTIALS",
            **{"font-size": "7.5", "font-weight": "700", "letter-spacing": "0.09em", "fill": t["cred_label"], "opacity": "0.92"},
        )
    )
    creds = ["ANTHROPIC_KEY", "DB_URL", "AWS_SECRET"]
    row_y = cred_y + 8
    key_icon_tpl = (
        '<circle cx="{cx}" cy="{cy}" r="3.2" stroke="{c}" stroke-width="1.3" fill="none"/>'
        '<path d="M{kx} {cy} H{hx} M{mx} {cy} V{vy} M{hx} {cy} V{vy}" stroke="{c}" stroke-width="1.3" fill="none"/>'
    )
    for i, name in enumerate(creds):
        cy_chip = row_y + i * (chip_h + chip_gap) + chip_h // 2
        cx_k = inner_x + 9
        icon = key_icon_tpl.format(cx=cx_k, cy=cy_chip, c=t["cred_label"], kx=cx_k + 3, hx=cx_k + 11, mx=cx_k + 8, vy=cy_chip + 3)
        parts.append(
            _list_chip(
                cid(f"cred-{i}"),
                inner_x,
                row_y + i * (chip_h + chip_gap),
                inner_w,
                chip_h,
                name,
                fill=t["cred_fill"],
                stroke=t["cred_stroke"],
                text_color=t["cred_text"],
                icon=icon,
            )
        )
        spine_y = row_y + i * (chip_h + chip_gap) + chip_h // 2
        parts.append(f'<path d="M{inner_x + 2} {spine_y} H{inner_x + 12}" stroke="{t["spine"]}" stroke-width="1.3" opacity="0.55"/>')

    tools_y = row_y + len(creds) * (chip_h + chip_gap) + 10
    parts.append(
        _text(
            inner_x + 4,
            tools_y,
            "TOOLS REACHABLE",
            **{"font-size": "7.5", "font-weight": "700", "letter-spacing": "0.09em", "fill": t["tool_label"], "opacity": "0.92"},
        )
    )
    tools = ["query_db", "read_file", "write_file", "exec_sql", "run_shell"]
    tool_row = tools_y + 8
    wrench_tpl = (
        '<path d="M{wx} {wy:.1f} a3.6 3.6 0 0 0 -4.7 4.7 L{lx} {ly:.1f} a1.6 1.6 0 0 0 2.2 2.2 L{rx} {ry:.1f} '
        'a3.6 3.6 0 0 0 4.7 -4.7 L{tx:.1f} {ty:.1f} L{ux:.1f} {uy:.1f} Z" stroke="{c}" stroke-width="1.3" fill="none"/>'
    )
    for i, name in enumerate(tools):
        y_chip = tool_row + i * (chip_h + chip_gap)
        cy_chip = y_chip + chip_h // 2
        danger = name == "run_shell"
        if danger:
            parts.append(
                _list_chip(
                    cid(f"tool-{i}"),
                    inner_x,
                    y_chip,
                    inner_w,
                    chip_h,
                    name,
                    fill=t["rce_fill"],
                    stroke=t["rce_fill"],
                    text_color="#ffffff",
                    icon=(
                        f'<rect x="{inner_x + 6}" y="{cy_chip - 6}" width="14" height="12" rx="2.4" stroke="#ffffff" stroke-width="1.4"/>'
                        f'<path d="M{inner_x + 9} {cy_chip - 2} L{inner_x + 11.5} {cy_chip} L{inner_x + 9} {cy_chip + 2} '
                        f'M{inner_x + 13.5} {cy_chip + 2.5} H{inner_x + 17}" stroke="#ffffff" stroke-width="1.4"/>'
                    ),
                    danger=True,
                    badge="RCE",
                )
            )
        else:
            cx_w = inner_x
            icon = wrench_tpl.format(
                wx=cx_w + 9,
                wy=cy_chip - 5,
                lx=cx_w - 3,
                ly=cy_chip + 6,
                rx=cx_w + 5,
                ry=cy_chip + 1.5,
                tx=cx_w + 6.4,
                ty=cy_chip - 0.4,
                ux=cx_w + 4.4,
                uy=cy_chip - 2.4,
                c=t["tool_label"],
            )
            parts.append(
                _list_chip(
                    cid(f"tool-{i}"),
                    inner_x,
                    y_chip,
                    inner_w,
                    chip_h,
                    name,
                    fill=t["tool_fill"],
                    stroke=t["tool_stroke"],
                    text_color=t["tool_text"],
                    icon=icon,
                )
            )
        parts.append(f'<path d="M{inner_x + 2} {cy_chip} H{inner_x + 12}" stroke="{t["spine"]}" stroke-width="1.3" opacity="0.55"/>')

    parts.append(
        f'<path d="M{inner_x + 2} {cred_y + 8} V{tool_row + len(tools) * (chip_h + chip_gap) - chip_gap}" '
        f'stroke="{t["spine"]}" stroke-width="1.3" opacity="0.55"/>'
    )

    stats_y, stats_h = 452, 88
    stats_fill = t["stats_fill"]
    stats_stroke = t["stats_stroke"]
    parts.append(f'<rect x="40" y="{stats_y}" width="468" height="{stats_h}" rx="12" fill="{stats_fill}" stroke="{stats_stroke}"/>')
    stats = [
        ("3", "agents", "compromised", t["stat_red"]),
        ("3", "credentials", "exposed", t["stat_red"]),
        ("5", "tools", "reachable", t["stat_cyan"]),
        ("1", "exec-capable", "tool exposed", t["stat_red"]),
    ]
    col_w = 468 // 4
    for i, (num, line1, line2, color) in enumerate(stats):
        cx_stat = 40 + col_w * i + col_w // 2
        parts.append(
            _text(cx_stat, stats_y + 36, num, **{"text-anchor": "middle", "font-size": "22", "font-weight": "800", "fill": color})
            + _text(cx_stat, stats_y + 54, line1, **{"text-anchor": "middle", "font-size": "9", "fill": t["muted"]})
            + _text(cx_stat, stats_y + 68, line2, **{"text-anchor": "middle", "font-size": "9", "fill": t["muted"]})
        )
        if i:
            lx = 40 + col_w * i
            parts.append(f'<line x1="{lx}" y1="{stats_y + 14}" x2="{lx}" y2="{stats_y + stats_h - 14}" stroke="{t["stats_divider"]}"/>')

    fix_x, fix_w = 524, 408
    fix_pad = 18
    fix_fill = t["fix_fill"]
    fix_stroke = t["fix_stroke"]
    parts.append(f'<rect x="{fix_x}" y="{stats_y}" width="{fix_w}" height="{stats_h}" rx="12" fill="{fix_fill}" stroke="{fix_stroke}"/>')
    parts.append(_clip_def(cid("fix"), fix_x + fix_pad, stats_y + 12, fix_w - fix_pad * 2, stats_h - 20))
    parts.append(
        _clipped_text(
            cid("fix"),
            fix_x + fix_pad,
            stats_y + 28,
            "RECOMMENDED FIX",
            w=fix_w - fix_pad * 2,
            **{"font-size": "9", "font-weight": "700", "letter-spacing": "0.06em", "fill": t["fix_label"]},
        )
        + _clipped_text(
            cid("fix"),
            fix_x + fix_pad,
            stats_y + 50,
            "upgrade better-sqlite3 -> 11.7.0",
            w=fix_w - fix_pad * 2,
            **{
                "font-size": "12",
                "font-weight": "700",
                "font-family": "ui-monospace, monospace",
                "fill": t["fix_text"],
            },
        )
        + _clipped_text(
            cid("fix"),
            fix_x + fix_pad,
            stats_y + 70,
            "Resolves all 3 agent exposures in one upgrade",
            w=fix_w - fix_pad * 2,
            **{"font-size": "9", "fill": t["fix_label"]},
        )
    )

    parts.append("</svg>")
    return "\n".join(parts)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for theme, name in (("dark", "blast-radius-dark.svg"), ("light", "blast-radius-light.svg")):
        svg = blast_radius(theme) + "\n"
        issues = _audit_layout(svg)
        if issues:
            raise SystemExit(f"{name} layout issues: {issues[:5]}")
        github_issues = _audit_github_safe(svg)
        if github_issues:
            raise SystemExit(f"{name} GitHub SVG issues: {github_issues}")
        path = OUT / name
        path.write_text(svg, encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
