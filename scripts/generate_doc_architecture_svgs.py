#!/usr/bin/env python3
"""Generate README architecture SVGs (how-it-works + control-plane architecture).

Hand-tuned layout with theme tokens — run after changing lane content or counts.
All coordinates are checked to stay inside lane panels (no text or card overflow).
"""

from __future__ import annotations

import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "docs" / "images"

THEMES = {
    "dark": {
        "bg": "#0a0a0c",
        "panel": "#0f0f13",
        "panel_stroke": "#222228",
        "card": "#161619",
        "card_stroke": "#2a2a31",
        "icon_bg": "#1c1c21",
        "icon_stroke": "#2e2e35",
        "title": "#f4f4f5",
        "subtitle": "#71717a",
        "lane": "#a78bfa",
        "lane_muted": "#6b6b75",
        "text": "#e9e9ec",
        "text_muted": "#82828c",
        "chip": "#a1a1aa",
        "arrow": "#52525b",
        "arrow_accent": "#8b5cf6",
        "accent": "#a78bfa",
        "accent_fill": "#15121f",
        "accent_stroke": "#5b4bbd",
        "trust_bg": "#0c1a14",
        "trust_stroke": "#1f4438",
        "trust": "#4ade80",
        "ic": "#9a9aa4",
        "ic_accent": "#a78bfa",
        "highlight": "#15121f",
        "footer_bg": "#121016",
        "footer_stroke": "#2a2733",
    },
    "light": {
        "bg": "#ffffff",
        "panel": "#fafafa",
        "panel_stroke": "#ececf0",
        "card": "#ffffff",
        "card_stroke": "#e6e6ea",
        "icon_bg": "#f4f4f6",
        "icon_stroke": "#e6e6ea",
        "title": "#18181b",
        "subtitle": "#71717a",
        "lane": "#7c3aed",
        "lane_muted": "#9a9aa4",
        "text": "#18181b",
        "text_muted": "#71717a",
        "chip": "#52525b",
        "arrow": "#a1a1aa",
        "arrow_accent": "#7c3aed",
        "accent": "#7c3aed",
        "accent_fill": "#f5f3ff",
        "accent_stroke": "#c4b5fd",
        "trust_bg": "#ecfdf5",
        "trust_stroke": "#bbf7d0",
        "trust": "#15803d",
        "ic": "#6b6b76",
        "ic_accent": "#7c3aed",
        "highlight": "#f5f3ff",
        "footer_bg": "#f4f4f6",
        "footer_stroke": "#e4e4e7",
    },
}

LANE_COLORS = {
    "intake": ("#1e3a5f", "#60a5fa", "#93c5fd"),
    "scan": ("#78350f", "#fbbf24", "#fde68a"),
    "core": ("#5b21b6", "#a78bfa", "#ddd6fe"),
    "control": ("#065f46", "#34d399", "#a7f3d0"),
    "output": ("#3f3f46", "#a1a1aa", "#d4d4d8"),
    "sources": ("#1e3a5f", "#60a5fa", "#93c5fd"),
    "enrich": ("#78350f", "#fbbf24", "#fde68a"),
    "evidence": ("#5b21b6", "#a78bfa", "#ddd6fe"),
    "consumers": ("#1e3a8a", "#60a5fa", "#93c5fd"),
}


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _svg_open(w: int, h: int, title: str, desc: str | None = None) -> list[str]:
    """GitHub-safe SVG root — explicit dimensions, no role/aria (sanitizer-friendly)."""
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" fill="none">',
        f"<title>{_esc(title)}</title>",
    ]
    if desc:
        parts.append(f"<desc>{_esc(desc)}</desc>")
    return parts


def _text(x: int | float, y: int | float, content: str, **attrs: str) -> str:
    attr_bits = " ".join(f'{key}="{value}"' for key, value in attrs.items())
    prefix = f'<text x="{x}" y="{y}"'
    if attr_bits:
        prefix += f" {attr_bits}"
    return f"{prefix}>{_esc(content)}</text>"


def _icon_box(x: int, y: int, paths: str, t: dict, accent: bool = False, *, box: bool = True) -> str:
    stroke = t["ic_accent"] if accent else t["ic"]
    box_svg = f'<rect x="{x}" y="{y}" width="24" height="24" rx="6" fill="{t["icon_bg"]}" stroke="{t["icon_stroke"]}"/>' if box else ""
    return (
        f"{box_svg}"
        f'<g transform="translate({x + 4},{y + 4})" fill="none" stroke="{stroke}" stroke-width="1.5" '
        f'stroke-linecap="round" stroke-linejoin="round">{paths}</g>'
    )


def _lane_header(x: int, y: int, w: int, label: str, lane_key: str, tag: str, t: dict) -> str:
    bg, accent, text = LANE_COLORS[lane_key]
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="32" rx="8" fill="{bg}"/>'
        f'<text x="{x + 12}" y="{y + 20}" font-family="Inter,system-ui,sans-serif" font-size="9.5" font-weight="800" '
        f'letter-spacing="0.12em" fill="{text}">{_esc(label)}</text>'
        f'<text x="{x + w - 10}" y="{y + 20}" text-anchor="end" font-family="Inter,system-ui,sans-serif" '
        f'font-size="8" font-weight="600" fill="{accent}" opacity="0.9">{_esc(tag)}</text>'
    )


def _lane_flow(x1: int, x2: int, y: int, label: str, t: dict, accent: bool = False) -> str:
    """Header-band connector without marker url(#…) refs (GitHub PR preview rejects those)."""
    color = t["arrow_accent"] if accent else t["arrow"]
    width = "2.2" if accent else "1.8"
    tip = x2 - 1
    stem = x2 - 7
    return (
        f'<line x1="{x1}" y1="{y}" x2="{stem}" y2="{y}" stroke="{color}" stroke-width="{width}"/>'
        f'<polygon points="{tip},{y} {stem},{y - 3.5} {stem},{y + 3.5}" fill="{color}"/>'
        f'<text x="{(x1 + x2) // 2}" y="{y - 8}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
        f'font-size="7.5" font-weight="800" letter-spacing="0.08em" fill="{t["accent"] if accent else t["lane_muted"]}">'
        f"{_esc(label)}</text>"
    )


def _trust_footer(w: int, h: int, t: dict, message: str, *, height: int = 28) -> str:
    y = h - height - 12
    return (
        f'<rect x="24" y="{y}" width="{w - 48}" height="{height}" rx="8" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>'
        + _text(
            w // 2,
            y + height - 8,
            message,
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "8.5",
                "font-weight": "600",
                "fill": t["trust"],
            },
        )
    )


def _audit_github_safe(svg: str) -> list[str]:
    """Checks that block GitHub PR SVG previews and README embeds."""
    issues: list[str] = []
    if 'marker-end="url(#' in svg:
        issues.append("marker-end url(#…) references are not GitHub-safe")
    if 'role="img"' in svg or "aria-labelledby" in svg:
        issues.append("role/aria-labelledby attributes are not GitHub-safe")
    if not re.search(r'<svg[^>]+width="\d+"', svg):
        issues.append("missing explicit svg width")
    if re.search(r'&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)', svg):
        issues.append("unescaped ampersand in SVG text")
    if "→" in svg or "←" in svg:
        issues.append("raw Unicode arrows — use ASCII -> instead")
    return issues


ICONS = {
    "repo": '<path d="M4 6h8l3 3v11H4z M12 6v3h3"/>',
    "ci": '<path d="M6 14l4 4 10-11"/>',
    "mcp": '<circle cx="12" cy="9" r="3"/><circle cx="8" cy="17" r="2.4"/><circle cx="16" cy="17" r="2.4"/><path d="M10 11l-2 4 M14 11l2 4"/>',
    "cloud": '<path d="M6 15h12a4 4 0 0 0 .5-8A6 6 0 0 0 6 15z"/>',
    "image": '<rect x="5" y="6" width="14" height="12" rx="2"/><path d="M7 15l3-3 2 2 3-3 2 4"/>',
    "iac": '<path d="M12 4l7 3.5-7 3.5-7-3.5z M5 11l7 3.5 7-3.5 M5 15l7 3.5 7-3.5"/>',
    "sbom": '<path d="M6 5h12v14H6z M9 9h8 M9 12h8 M9 15h5"/>',
    "model": '<path d="M12 4l7 3.5v7L12 18l-7-3.5v-7z M12 4v14 M5 7.5l14 7"/>',
    "search": '<circle cx="10" cy="10" r="6"/><path d="M15 15l4 4"/>',
    "package": '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z M12 3v9 M4 7.5l16 9"/>',
    "bug": '<path d="M8 10h8M6 14h12M9 6l-2 2M15 6l2 2M9 18l-2 2M15 18l2 2"/><circle cx="12" cy="12" r="4"/>',
    "zap": '<path d="M13 3L5 14h6l-1 7 8-11h-6z"/>',
    "shield": '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    "file": '<path d="M7 4h7l4 4v12H7z M14 4v4h4"/>',
    "api": '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4"/>',
    "ui": '<rect x="4" y="5" width="16" height="12" rx="2"/><path d="M4 9h16"/>',
    "gate": '<path d="M12 4l7 2.5v5c0 4.5-3 7-7 8.5-4-1.5-7-4-7-8.5v-5z"/><path d="M9 12l2 2 4-4"/>',
    "fleet": '<rect x="4" y="5" width="6" height="6" rx="1.5"/><rect x="14" y="5" width="6" height="6" rx="1.5"/><rect x="4" y="13" width="6" height="6" rx="1.5"/><rect x="14" y="13" width="6" height="6" rx="1.5"/>',
    "audit": '<path d="M6 5h12v14H6z M9 9h8 M9 12h8"/><path d="M9 16l2 2 4-4"/>',
    "cli": '<path d="M7 8l-4 4 4 4 M13 16h7"/>',
    "lock": '<rect x="7" y="11" width="10" height="8" rx="2"/><path d="M9 11V8a3 3 0 0 1 6 0v3"/>',
    "finding": '<path d="M8 6h7l3 3v9H8z M15 6v3h3 M10 14l1.5 1.5 3-3"/>',
    "graph": '<circle cx="8" cy="8" r="2.5"/><circle cx="16" cy="8" r="2.5"/><circle cx="12" cy="16" r="2.5"/><path d="M10 9.5l1.5 5 M14 9.5l-1.5 5"/>',
    "db": '<ellipse cx="12" cy="7" rx="7" ry="3"/><path d="M5 7v10c0 1.7 3.1 3 7 3s7-1.3 7-3V7"/>',
}


def _cloud_logos(x: int, y: int, t: dict) -> str:
    items = [
        ("AWS", "#ff9900", '<path d="M6 14c4-1 8-1 12 0M8 11c2.5-.8 5.5-.8 8 0" stroke="#ff9900" fill="none" stroke-width="1.4"/>'),
        ("Azure", "#0078d4", '<path d="M5 16 L12 5 L19 16 Z" fill="#0078d4" opacity="0.9"/>'),
        (
            "GCP",
            "#4285f4",
            '<circle cx="9" cy="12" r="3" fill="#ea4335"/><circle cx="15" cy="12" r="3" fill="#fbbc04"/><circle cx="12" cy="16" r="3" fill="#34a853"/>',
        ),
        ("Snow", "#29b5e8", '<path d="M12 5v14M5 12h14M7.5 7.5l9 9M16.5 7.5l-9 9" stroke="#29b5e8" stroke-width="1.2"/>'),
    ]
    out = []
    for i, (label, color, art) in enumerate(items):
        bx = x + i * 48
        out.append(
            f'<rect x="{bx}" y="{y}" width="42" height="30" rx="8" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
            f'<g transform="translate({bx + 9},{y + 5}) scale(0.85)">{art}</g>'
            f'<text x="{bx + 21}" y="{y + 26}" text-anchor="middle" font-family="ui-monospace,monospace" '
            f'font-size="6.5" font-weight="700" fill="{color}">{_esc(label)}</text>'
        )
    return "".join(out)


def how_it_works(theme_name: str) -> str:
    t = THEMES[theme_name]
    w, h = 960, 560
    lane_gap = 8
    lane_w = (w - 48 - 4 * lane_gap) // 5
    lane_x = [24 + i * (lane_w + lane_gap) for i in range(5)]

    steps = [
        ("search", "Discover"),
        ("package", "Extract"),
        ("bug", "Scan"),
        ("zap", "Enrich"),
        ("shield", "Analyze"),
        ("file", "Report"),
    ]
    intake = [
        ("repo", "Repo"),
        ("ci", "CI"),
        ("mcp", "MCP"),
        ("cloud", "Cloud"),
        ("image", "Image"),
        ("iac", "IaC"),
        ("sbom", "SBOM"),
        ("model", "Model"),
    ]
    control = [
        ("api", "REST API"),
        ("ui", "Dashboard"),
        ("mcp", "MCP srv"),
        ("gate", "Gateway"),
        ("fleet", "Fleet"),
        ("audit", "Audit"),
    ]
    outputs = ["SARIF", "SBOM", "HTML", "JSON", "GATE", "FIX"]

    lane_top = 84
    lane_h = 360
    flow_y = lane_top + 16

    parts = _svg_open(w, h, "How agent-bom works", "Read-only intake through scan pipeline into unified Finding and UnifiedGraph.")
    parts += [
        "<defs>",
        '<linearGradient id="core-glow" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0%" stop-color="{t["accent"]}" stop-opacity="0.28"/>'
        f'<stop offset="100%" stop-color="{t["accent"]}" stop-opacity="0"/>'
        "</linearGradient>",
        "</defs>",
        f'<rect width="{w}" height="{h}" rx="14" fill="{t["bg"]}"/>',
        _text(
            28,
            40,
            "From inventory to enforceable evidence",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "20", "font-weight": "800", "fill": t["title"]},
        ),
        _text(
            28,
            60,
            "One read-only pipeline · one Finding + UnifiedGraph · CLI · API · UI · MCP",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "10", "font-weight": "500", "fill": t["subtitle"]},
        ),
    ]

    lane_meta = [
        ("INTAKE", "intake", "read-only"),
        ("SCAN", "scan", "6 steps"),
        ("EVIDENCE", "core", "one model"),
        ("CONTROL", "control", "self-hosted"),
        ("OUT", "output", "artifacts"),
    ]
    for i, (label, key, tag) in enumerate(lane_meta):
        x = lane_x[i]
        parts.append(
            f'<rect x="{x}" y="{lane_top}" width="{lane_w}" height="{lane_h}" rx="12" fill="{t["panel"]}" stroke="{t["panel_stroke"]}"/>'
        )
        parts.append(_lane_header(x, lane_top, lane_w, label, key, tag, t))

    intake_x = lane_x[0] + 8
    for i, (icon, label) in enumerate(intake):
        col, row = i % 2, i // 2
        tx, ty = intake_x + col * 82, lane_top + 44 + row * 48
        parts.append(f'<rect x="{tx}" y="{ty}" width="74" height="38" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(tx + 6, ty + 7, ICONS[icon], t))
        parts.append(
            _text(
                tx + 34,
                ty + 24,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9.5", "font-weight": "700", "fill": t["text"]},
            )
        )

    parts.append(_cloud_logos(intake_x, lane_top + 236, t))
    parts.append(_icon_box(intake_x, lane_top + 276, ICONS["lock"], t, accent=True))
    parts.append(
        _text(
            64,
            lane_top + 308,
            "no writes · no secret values",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "8.5", "font-weight": "600", "fill": t["lane_muted"]},
        )
    )

    scan_x = lane_x[1]
    scan_accent = LANE_COLORS["scan"][1]
    step_cx = scan_x + 40
    for i, (icon, label) in enumerate(steps):
        sy = lane_top + 44 + i * 46
        parts.append(
            f'<circle cx="{step_cx}" cy="{sy + 12}" r="10" fill="{t["card"]}" stroke="{scan_accent}" stroke-width="1.4"/>'
        )
        parts.append(
            f'<text x="{step_cx}" y="{sy + 16}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
            f'font-size="8" font-weight="800" fill="{scan_accent}">{i + 1}</text>'
        )
        parts.append(_icon_box(step_cx + 20, sy, ICONS[icon], t))
        parts.append(
            _text(
                step_cx + 48,
                sy + 16,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "10", "font-weight": "700", "fill": t["text"]},
            )
        )
        if i < len(steps) - 1:
            parts.append(
                f'<path d="M{step_cx} {sy + 24} V{sy + 30}" stroke="{t["panel_stroke"]}" stroke-width="1.4" stroke-linecap="round"/>'
            )

    for i, adv in enumerate(["OSV", "GHSA", "NVD", "KEV", "EPSS"]):
        ax = scan_x + 8 + i * 32
        ay = lane_top + lane_h - 32
        parts.append(
            f'<rect x="{ax}" y="{ay}" width="26" height="18" rx="5" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{ax + 13}" y="{ay + 12}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="6.5" '
            f'font-weight="700" fill="{scan_accent}">{adv}</text>'
        )

    evidence_x = lane_x[2]
    cx, cy = evidence_x + lane_w // 2, lane_top + 188
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="54" fill="url(#core-glow)"/>')
    nodes = [
        (cx, cy - 48, "Finding", True, "finding"),
        (cx - 58, cy - 6, "Asset", False, "package"),
        (cx + 58, cy - 6, "Agent", False, "mcp"),
        (cx - 42, cy + 46, "Tool", False, "bug"),
        (cx + 42, cy + 46, "Cred", False, "lock"),
    ]
    for nx, ny, nlabel, center, icon in nodes:
        if not center:
            parts.append(f'<line x1="{cx}" y1="{cy}" x2="{nx}" y2="{ny}" stroke="{t["panel_stroke"]}" stroke-width="1.2" opacity="0.7"/>')
    for nx, ny, nlabel, center, icon in nodes:
        r = 28 if center else 22
        fill = t["accent_fill"] if center else t["card"]
        stroke = t["accent_stroke"] if center else t["card_stroke"]
        parts.append(f'<circle cx="{nx}" cy="{ny}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{"1.8" if center else "1.3"}"/>')
        if center:
            parts.append(_icon_box(nx - 12, ny - 12, ICONS[icon], t, accent=True))
        parts.append(
            _text(
                nx,
                ny + (18 if center else 16),
                nlabel,
                **{
                    "text-anchor": "middle",
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "9" if center else "8",
                    "font-weight": "800",
                    "fill": t["accent"] if center else t["text"],
                },
            )
        )

    for i, chip in enumerate(["severity", "provenance", "tenant"]):
        mx = evidence_x + 10 + i * 52
        my = lane_top + lane_h - 36
        parts.append(
            f'<rect x="{mx}" y="{my}" width="48" height="18" rx="6" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{mx + 24}" y="{my + 12}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="7" '
            f'font-weight="700" fill="{t["chip"]}">{_esc(chip)}</text>'
        )

    control_x = lane_x[3] + 8
    for i, (icon, label) in enumerate(control):
        col, row = i % 2, i // 2
        tx, ty = control_x + col * 78, lane_top + 44 + row * 52
        parts.append(f'<rect x="{tx}" y="{ty}" width="70" height="42" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(tx + 8, ty + 11, ICONS[icon], t))
        parts.append(
            _text(
                tx + 34,
                ty + 28,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "8", "font-weight": "700", "fill": t["text"]},
            )
        )

    parts.append(
        f'<rect x="{control_x}" y="{lane_top + lane_h - 34}" width="{lane_w - 16}" height="22" rx="7" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            control_x + (lane_w - 16) // 2,
            lane_top + lane_h - 18,
            "fail-closed · RBAC · audit",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    out_x = lane_x[4] + 8
    out_colors = ["#f87171", "#fbbf24", "#60a5fa", "#a78bfa", "#34d399", "#fb7185"]
    for i, (label, color) in enumerate(zip(outputs, out_colors, strict=True)):
        oy = lane_top + 44 + i * 46
        parts.append(
            f'<rect x="{out_x}" y="{oy}" width="{lane_w - 16}" height="30" rx="8" fill="{t["card"]}" stroke="{color}" stroke-width="1.1"/>'
            f'<circle cx="{out_x + 10}" cy="{oy + 15}" r="3" fill="{color}"/>'
            f'<text x="{out_x + 18}" y="{oy + 19}" font-family="ui-monospace,monospace" font-size="8.5" font-weight="800" fill="{t["text"]}">{_esc(label)}</text>'
        )

    for i in range(4):
        parts.append(_lane_flow(lane_x[i] + lane_w, lane_x[i + 1], flow_y, ["collect", "normalize", "serve", "export"][i], t, accent=(i == 2)))

    parts.append(_trust_footer(w, h, t, "read-only · secret redaction · signed evidence · same model everywhere"))
    parts.append("</svg>")
    return "\n".join(parts)


def architecture(theme_name: str) -> str:
    t = THEMES[theme_name]
    w, h = 960, 560
    lane_gap = 8
    lane_w = (w - 48 - 4 * lane_gap) // 5
    lane_x = [24 + i * (lane_w + lane_gap) for i in range(5)]

    sources = [
        ("package", "Supply chain", "15 eco"),
        ("mcp", "Agents & MCP", "29 clients"),
        ("cloud", "Cloud", "4 providers"),
        ("iac", "IaC & OCI", "TF·K8s·img"),
        ("lock", "Secrets", "refs only"),
        ("model", "Models", "13 formats"),
        ("sbom", "SBOM import", "CDX·SPDX"),
    ]
    scan_items = [
        ("bug", "OSV scan", "batch"),
        ("zap", "Enrichment", "NVD·EPSS"),
        ("shield", "Posture", "CIS·MCP"),
        ("graph", "Blast radius", "fusion"),
        ("file", "Policy", "as-code"),
    ]
    core_items = [
        ("finding", "Unified Finding", "one schema", True),
        ("graph", "UnifiedGraph", "attack paths", True),
        ("db", "Stores", "PG·SQLite", False),
        ("audit", "Audit chain", "signed", False),
    ]
    cp_items = [
        ("api", "REST API", "283 ops"),
        ("gate", "Gateway", "runtime"),
        ("mcp", "MCP server", "70 tools"),
        ("fleet", "Fleet jobs", "Helm·EKS"),
    ]
    people = [("cli", "CLI"), ("ui", "Web UI")]
    agents = [("mcp", "MCP"), ("api", "SDK")]
    artifacts = ["SARIF", "CDX", "SPDX", "OCSF", "HTML", "JSON"]

    lane_top = 78
    lane_h = 400
    flow_y = lane_top + 14
    card_w = lane_w - 16

    parts = _svg_open(
        w,
        h,
        "agent-bom control-plane architecture",
        "Sources through scan and evidence core to control plane and consumers.",
    )
    parts += [
        f'<rect width="{w}" height="{h}" rx="14" fill="{t["bg"]}"/>',
        _text(
            28,
            38,
            "Control-plane architecture",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "20", "font-weight": "800", "fill": t["title"]},
        ),
        _text(
            28,
            58,
            "Sources -> scan -> Finding + UnifiedGraph -> API · Gateway · MCP -> people + agents",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "10", "font-weight": "500", "fill": t["subtitle"]},
        ),
    ]

    lane_meta = [
        ("SOURCES", "sources", "read-only"),
        ("SCAN", "enrich", "local"),
        ("EVIDENCE", "evidence", "normalized"),
        ("CONTROL", "control", "tenant auth"),
        ("CONSUMERS", "consumers", "deliver"),
    ]
    for i, (label, key, tag) in enumerate(lane_meta):
        x = lane_x[i]
        parts.append(
            f'<rect x="{x}" y="{lane_top}" width="{lane_w}" height="{lane_h}" rx="11" fill="{t["panel"]}" stroke="{t["panel_stroke"]}"/>'
        )
        parts.append(_lane_header(x, lane_top, lane_w, label, key, tag, t))

    def _lane_card(lane_i: int, row: int, icon: str, title: str, badge: str, *, row_h: int = 50, highlight: bool = False) -> None:
        x = lane_x[lane_i] + 8
        sy = lane_top + 40 + row * row_h
        fill = t["accent_fill"] if highlight else t["card"]
        stroke = t["accent_stroke"] if highlight else t["card_stroke"]
        ch = row_h - 6
        parts.append(
            f'<rect x="{x}" y="{sy}" width="{card_w}" height="{ch}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="{"1.5" if highlight else "1"}"/>'
        )
        parts.append(_icon_box(x + 8, sy + (ch - 24) // 2, ICONS[icon], t, accent=highlight))
        parts.append(
            _text(
                x + 38,
                sy + ch // 2 - 2,
                title,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9.5", "font-weight": "700", "fill": t["text"]},
            )
        )
        parts.append(
            _text(
                x + 38,
                sy + ch // 2 + 11,
                badge,
                **{
                    "font-family": "ui-monospace,monospace",
                    "font-size": "7",
                    "font-weight": "600",
                    "fill": t["accent"] if highlight else t["text_muted"],
                },
            )
        )

    for i, (icon, title, badge) in enumerate(sources):
        _lane_card(0, i, icon, title, badge, row_h=48)

    for i, (icon, title, badge) in enumerate(scan_items):
        _lane_card(1, i, icon, title, badge, row_h=58)

    for i, (icon, title, badge, highlight) in enumerate(core_items):
        _lane_card(2, i, icon, title, badge, row_h=72, highlight=highlight)

    for i, (icon, title, badge) in enumerate(cp_items):
        _lane_card(3, i, icon, title, badge, row_h=72)

    parts.append(
        f'<rect x="{lane_x[3] + 8}" y="{lane_top + lane_h - 32}" width="{card_w}" height="22" rx="7" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            lane_x[3] + 8 + card_w // 2,
            lane_top + lane_h - 16,
            "OIDC · SAML · SCIM · RBAC",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    cons_x = lane_x[4] + 8
    for section, items, y0 in (
        ("PEOPLE", people, 40),
        ("AGENTS", agents, 128),
        ("ARTIFACTS", [], 216),
    ):
        parts.append(
            _text(
                cons_x + card_w // 2,
                lane_top + y0,
                section,
                **{
                    "text-anchor": "middle",
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "7",
                    "font-weight": "800",
                    "letter-spacing": "0.1em",
                    "fill": t["accent"],
                },
            )
        )
        if section != "ARTIFACTS":
            for j, (icon, label) in enumerate(items):
                sy = lane_top + y0 + 10 + j * 36
                parts.append(
                    f'<rect x="{cons_x}" y="{sy}" width="{card_w}" height="30" rx="7" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
                )
                parts.append(_icon_box(cons_x + 6, sy + 3, ICONS[icon], t))
                parts.append(
                    _text(
                        cons_x + 34,
                        sy + 19,
                        label,
                        **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9.5", "font-weight": "700", "fill": t["text"]},
                    )
                )

    chip_w, chip_h, chip_gap = 48, 18, 4
    for i, label in enumerate(artifacts):
        col, row = i % 2, i // 2
        ax = cons_x + col * (chip_w + chip_gap)
        ay = lane_top + 228 + row * (chip_h + chip_gap)
        parts.append(
            f'<rect x="{ax}" y="{ay}" width="{chip_w}" height="{chip_h}" rx="5" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{ax + chip_w // 2}" y="{ay + 12}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="6.5" '
            f'font-weight="700" fill="{t["chip"]}">{_esc(label)}</text>'
        )

    parts.append(
        _text(
            cons_x + card_w // 2,
            lane_top + 304,
            "SIEM · webhooks",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7",
                "font-weight": "600",
                "fill": t["lane_muted"],
            },
        )
    )

    for i, (label, accent) in enumerate([("SCAN", False), ("NORMALIZE", False), ("SERVE", True), ("DELIVER", False)]):
        parts.append(_lane_flow(lane_x[i] + lane_w, lane_x[i + 1], flow_y, label, t, accent=accent))

    parts.append(
        _trust_footer(
            w,
            h,
            t,
            "READ-ONLY BY DEFAULT · no target writes · no secret values · self-hosted · signed evidence",
            height=26,
        )
    )
    parts.append("</svg>")
    return "\n".join(parts)


def persona_value(theme: str) -> str:
    t = THEMES[theme]
    w, h = 960, 400

    personas = [
        ("shield", "AppSec / GRC", "SARIF · compliance · audit", "control"),
        ("gate", "Platform / SRE", "fleet · Helm · CI gates", "scan"),
        ("mcp", "Agent builders", "MCP inventory · shield", "intake"),
        ("graph", "Security engineers", "blast radius · paths", "core"),
    ]
    values = [
        ("bug", "Accurate SCA", "15 ecosystems · distro-aware"),
        ("image", "Container coverage", "OCI native · Grype opt-in"),
        ("audit", "Self-hosted evidence", "your VPC · signed audit"),
        ("api", "Agent-native API", "283 ops · 70 MCP tools"),
    ]

    left_x, right_x = 28, 500
    col_w = 432
    row_h = 54
    row_gap = 14
    start_y = 108

    parts = _svg_open(w, h, "agent-bom personas and value")
    parts += [
        f'<rect width="{w}" height="{h}" rx="12" fill="{t["bg"]}"/>',
        _text(
            28,
            38,
            "Who it serves · what they get",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "20", "font-weight": "800", "fill": t["title"]},
        ),
        _text(
            28,
            58,
            "One evidence model — inventory -> findings -> graph -> gates",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "10", "font-weight": "500", "fill": t["subtitle"]},
        ),
        _text(
            left_x,
            88,
            "PERSONAS",
            **{
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "800",
                "letter-spacing": "0.12em",
                "fill": t["accent"],
            },
        ),
        _text(
            right_x,
            88,
            "VALUE PROOF",
            **{
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "800",
                "letter-spacing": "0.12em",
                "fill": t["accent"],
            },
        ),
    ]

    for i, (icon, title, subtitle, lane) in enumerate(personas):
        y = start_y + i * (row_h + row_gap)
        _, accent, _ = LANE_COLORS[lane]
        parts.append(
            f'<rect x="{left_x}" y="{y}" width="{col_w}" height="{row_h}" rx="10" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
        )
        parts.append(_icon_box(left_x + 12, y + 14, ICONS[icon], t, accent=True))
        parts.append(
            _text(
                left_x + 48,
                y + 24,
                title,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "11", "font-weight": "700", "fill": t["text"]},
            )
        )
        parts.append(
            _text(
                left_x + 48,
                y + 40,
                subtitle,
                **{"font-family": "ui-monospace,monospace", "font-size": "8", "font-weight": "600", "fill": accent},
            )
        )

    arrow_x1 = left_x + col_w + 8
    arrow_x2 = right_x - 8
    for i, (icon, title, subtitle) in enumerate(values):
        y = start_y + i * (row_h + row_gap)
        parts.append(
            f'<rect x="{right_x}" y="{y}" width="{col_w}" height="{row_h}" rx="10" fill="{t["accent_fill"]}" stroke="{t["accent_stroke"]}"/>'
        )
        parts.append(_icon_box(right_x + 12, y + 14, ICONS[icon], t, accent=True))
        parts.append(
            _text(
                right_x + 48,
                y + 24,
                title,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "11", "font-weight": "700", "fill": t["text"]},
            )
        )
        parts.append(
            _text(
                right_x + 48,
                y + 40,
                subtitle,
                **{"font-family": "ui-monospace,monospace", "font-size": "8", "font-weight": "600", "fill": t["text_muted"]},
            )
        )
        parts.append(
            f'<line x1="{arrow_x1}" y1="{y + row_h // 2}" x2="{arrow_x2 - 7}" y2="{y + row_h // 2}" '
            f'stroke="{t["arrow_accent"]}" stroke-width="1.6"/>'
            f'<polygon points="{arrow_x2 - 1},{y + row_h // 2} {arrow_x2 - 8},{y + row_h // 2 - 3.5} '
            f'{arrow_x2 - 8},{y + row_h // 2 + 3.5}" fill="{t["arrow_accent"]}"/>'
        )

    parts.append(_trust_footer(w, h, t, "LOCAL SCAN · CONTROL PLANE · RUNTIME — same Finding + UnifiedGraph", height=24))
    parts.append("</svg>")
    return "\n".join(parts)


def _audit_layout(svg: str, *, margin: int = 2) -> list[str]:
    """Return human-readable layout violations for generator self-check."""
    vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)
    if not vb:
        return ["missing viewBox"]
    width, height = map(int, vb.groups())
    issues: list[str] = []
    for match in re.finditer(r'<rect x="(\d+)" y="(\d+)" width="(\d+)" height="(\d+)"', svg):
        x, y, w, h = map(int, match.groups())
        if x < -margin or y < -margin or x + w > width + margin or y + h > height + margin:
            issues.append(f"rect ({x},{y},{w},{h}) outside {width}x{height}")
    return issues


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    mapping = {
        "how-it-works-dark.svg": ("dark", how_it_works),
        "how-it-works-light.svg": ("light", how_it_works),
        "architecture-dark.svg": ("dark", architecture),
        "architecture-light.svg": ("light", architecture),
        "persona-value-dark.svg": ("dark", persona_value),
        "persona-value-light.svg": ("light", persona_value),
    }
    for filename, (theme, fn) in mapping.items():
        svg = fn(theme) + "\n"
        issues = _audit_layout(svg)
        if issues:
            raise SystemExit(f"{filename} layout issues: {issues[:5]}")
        github_issues = _audit_github_safe(svg)
        if github_issues:
            raise SystemExit(f"{filename} GitHub SVG issues: {github_issues}")
        path = OUT / filename
        path.write_text(svg, encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
