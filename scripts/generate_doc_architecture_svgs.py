#!/usr/bin/env python3
"""Generate README architecture SVGs (how-it-works + control-plane architecture).

Hand-tuned layout with theme tokens — run after changing lane content or counts.
"""

from __future__ import annotations

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
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _text(x: int | float, y: int | float, content: str, **attrs: str) -> str:
    """Emit a text element with XML-safe content."""
    attr_bits = " ".join(f'{key}="{value}"' for key, value in attrs.items())
    prefix = f'<text x="{x}" y="{y}"'
    if attr_bits:
        prefix += f" {attr_bits}"
    return f"{prefix}>{_esc(content)}</text>"


def _marker(theme: dict, name: str, color_key: str) -> str:
    return (
        f'<marker id="{name}" viewBox="0 0 10 8" refX="8.5" refY="4" '
        f'markerWidth="9" markerHeight="7" orient="auto">'
        f'<path d="M0 0 L10 4 L0 8 Z" fill="{theme[color_key]}"/></marker>'
    )


def _icon_box(x: int, y: int, paths: str, t: dict, accent: bool = False, *, box: bool = True) -> str:
    stroke = t["ic_accent"] if accent else t["ic"]
    box_svg = (
        f'<rect x="{x}" y="{y}" width="26" height="26" rx="7" fill="{t["icon_bg"]}" stroke="{t["icon_stroke"]}"/>'
        if box
        else ""
    )
    return (
        f"{box_svg}"
        f'<g transform="translate({x + 5},{y + 5})" fill="none" stroke="{stroke}" stroke-width="1.55" '
        f'stroke-linecap="round" stroke-linejoin="round">{paths}</g>'
    )


def _lane_header(x: int, y: int, w: int, label: str, lane_key: str, tag: str, t: dict) -> str:
    bg, accent, text = LANE_COLORS[lane_key]
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="36" rx="10" fill="{bg}"/>'
        f'<rect x="{x}" y="{y + 22}" width="{w}" height="14" fill="{bg}"/>'
        f'<text x="{x + 14}" y="{y + 22}" font-family="Inter,system-ui,sans-serif" font-size="10" font-weight="800" '
        f'letter-spacing="0.14em" fill="{text}">{_esc(label)}</text>'
        f'<text x="{x + w - 12}" y="{y + 22}" text-anchor="end" font-family="Inter,system-ui,sans-serif" '
        f'font-size="8.5" font-weight="600" fill="{accent}" opacity="0.85">{_esc(tag)}</text>'
    )


def _flow_arrow(x1: int, y1: int, x2: int, y2: int, label: str, t: dict, accent: bool = False) -> str:
    color = t["arrow_accent"] if accent else t["arrow"]
    marker = "hiw-a" if accent else "hiw"
    width = "2.4" if accent else "2"
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{width}" '
        f'marker-end="url(#{marker})"/>'
        f'<text x="{(x1 + x2) // 2}" y="{y1 - 10}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
        f'font-size="8" font-weight="800" letter-spacing="0.1em" fill="{t["accent"] if accent else t["lane_muted"]}">'
        f'{_esc(label)}</text>'
    )


# ── Icon path snippets (24×24 viewBox, placed at x+5,y+5 in 26×26 box) ───────

ICONS = {
    "repo": '<path d="M4 6h8l3 3v11H4z M12 6v3h3"/>',
    "ci": '<path d="M6 14l4 4 10-11"/>',
    "mcp": '<circle cx="12" cy="9" r="3"/><circle cx="8" cy="17" r="2.4"/><circle cx="16" cy="17" r="2.4"/><path d="M10 11l-2 4 M14 11l2 4"/>',
    "cloud": '<path d="M6 15h12a4 4 0 0 0 .5-8A6 6 0 0 0 6 15z"/>',
    "image": '<rect x="5" y="6" width="14" height="12" rx="2"/><path d="M7 15l3-3 2 2 3-3 2 4"/>',
    "iac": '<path d="M12 4l7 3.5-7 3.5-7-3.5z M5 11l7 3.5 7-3.5 M5 15l7 3.5 7-3.5"/>',
    "sbom": '<path d="M6 5h12v14H6z M9 9h8 M9 12h8 M9 15h5"/>',
    "model": '<path d="M12 4l7 3.5v7L12 18l-7-3.5v-7z M12 4v14 M5 7.5l14 7"/>',
    "runtime": '<circle cx="12" cy="12" r="7"/><path d="M12 8v4l3 2"/>',
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
    "sarif": '<path d="M6 5h12v14H6z M9 9h8 M9 13h5"/>',
    "lock": '<rect x="7" y="11" width="10" height="8" rx="2"/><path d="M9 11V8a3 3 0 0 1 6 0v3"/>',
    "finding": '<path d="M8 6h7l3 3v9H8z M15 6v3h3 M10 14l1.5 1.5 3-3"/>',
    "graph": '<circle cx="8" cy="8" r="2.5"/><circle cx="16" cy="8" r="2.5"/><circle cx="12" cy="16" r="2.5"/><path d="M10 9.5l1.5 5 M14 9.5l-1.5 5"/>',
    "db": '<ellipse cx="12" cy="7" rx="7" ry="3"/><path d="M5 7v10c0 1.7 3.1 3 7 3s7-1.3 7-3V7"/>',
}


def _cloud_logos(x: int, y: int, t: dict) -> str:
  """Simplified provider marks — brand-inspired colors, not official logos."""
  items = [
      ("AWS", "#ff9900", '<path d="M6 14c4-1 8-1 12 0M8 11c2.5-.8 5.5-.8 8 0" stroke="#ff9900" fill="none" stroke-width="1.4"/>'),
      ("Azure", "#0078d4", '<path d="M5 16 L12 5 L19 16 Z" fill="#0078d4" opacity="0.9"/>'),
      ("GCP", "#4285f4", '<circle cx="9" cy="12" r="3" fill="#ea4335"/><circle cx="15" cy="12" r="3" fill="#fbbc04"/><circle cx="12" cy="16" r="3" fill="#34a853"/>'),
      ("Snow", "#29b5e8", '<path d="M12 5v14M5 12h14M7.5 7.5l9 9M16.5 7.5l-9 9" stroke="#29b5e8" stroke-width="1.2"/>'),
  ]
  out = []
  for i, (label, color, art) in enumerate(items):
      bx = x + i * 52
      out.append(
          f'<rect x="{bx}" y="{y}" width="46" height="34" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
          f'<g transform="translate({bx + 11},{y + 6}) scale(0.9)">{art}</g>'
          f'<text x="{bx + 23}" y="{y + 30}" text-anchor="middle" font-family="ui-monospace,monospace" '
          f'font-size="7" font-weight="700" fill="{color}">{_esc(label)}</text>'
      )
  return "".join(out)


def how_it_works(theme_name: str) -> str:
    t = THEMES[theme_name]
    suffix = "d" if theme_name == "dark" else "l"
    w, h = 1200, 560

  # Pipeline steps — mirrors src/agent_bom/api/pipeline.py PIPELINE_STEPS
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

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" fill="none" role="img" '
        f'aria-labelledby="hiw-{suffix}-title hiw-{suffix}-desc">',
        f'<title id="hiw-{suffix}-title">How agent-bom works</title>',
        '<desc id="hiw-{suffix}-desc">Read-only intake through scan pipeline into unified Finding and '
        'UnifiedGraph, served by control plane, exported as reports and gates.</desc>'.format(suffix=suffix),
        "<defs>",
        _marker(t, "hiw", "arrow"),
        _marker(t, "hiw-a", "arrow_accent"),
        '<linearGradient id="core-glow" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0%" stop-color="{t["accent"]}" stop-opacity="0.35"/>'
        f'<stop offset="100%" stop-color="{t["accent"]}" stop-opacity="0"/>'
        "</linearGradient>",
        "</defs>",
        f'<rect width="{w}" height="{h}" rx="16" fill="{t["bg"]}"/>',
        f'<text x="36" y="44" font-family="Inter,system-ui,sans-serif" font-size="24" font-weight="850" fill="{t["title"]}">'
        "From inventory to enforceable evidence</text>",
        f'<text x="36" y="66" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="500" fill="{t["subtitle"]}">'
        "One read-only pipeline · one Finding + UnifiedGraph · CLI · API · UI · MCP · runtime gates</text>",
    ]

    # Lane panels
    lanes = [
        (28, 88, 210, "INTAKE", "intake", "read-only"),
        (258, 88, 188, "SCAN", "scan", "6 steps"),
        (466, 88, 248, "EVIDENCE", "core", "one model"),
        (734, 88, 188, "CONTROL", "control", "self-hosted"),
        (942, 88, 108, "OUT", "output", "artifacts"),
    ]
    for x, y, lw, label, key, tag in lanes:
        parts.append(
            f'<rect x="{x}" y="{y}" width="{lw}" height="400" rx="14" fill="{t["panel"]}" stroke="{t["panel_stroke"]}"/>'
        )
        parts.append(_lane_header(x, y, lw, label, key, tag, t))

    # Intake icon grid
    for i, (icon, label) in enumerate(intake):
        col, row = i % 2, i // 2
        tx, ty = 44 + col * 98, 138 + row * 54
        parts.append(f'<rect x="{tx}" y="{ty}" width="88" height="44" rx="11" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(tx + 8, ty + 9, ICONS[icon], t))
        parts.append(_text(tx + 42, ty + 28, label, **{"font-family": "Inter,system-ui,sans-serif", "font-size": "11", "font-weight": "700", "fill": t["text"]}))

    parts.append(_cloud_logos(44, 360, t))
    parts.append(_icon_box(44, 408, ICONS["lock"], t, accent=True))
    parts.append(
        f'<text x="78" y="426" font-family="Inter,system-ui,sans-serif" font-size="9" font-weight="600" fill="{t["lane_muted"]}">'
        "no writes · no secret values</text>"
    )

    # Scan pipeline — vertical stepped flow
    scan_bg, scan_accent, scan_text = LANE_COLORS["scan"]
    for i, (icon, label) in enumerate(steps):
        sy = 132 + i * 52
        parts.append(f'<circle cx="278" cy="{sy + 14}" r="14" fill="{t["card"]}" stroke="{scan_accent}" stroke-width="1.5"/>')
        parts.append(
            f'<text x="278" y="{sy + 18}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
            f'font-size="9" font-weight="800" fill="{scan_accent}">{i + 1}</text>'
        )
        parts.append(_icon_box(304, sy, ICONS[icon], t))
        parts.append(
            f'<text x="340" y="{sy + 17}" font-family="Inter,system-ui,sans-serif" font-size="12" font-weight="700" fill="{t["text"]}">{_esc(label)}</text>'
        )
        if i < len(steps) - 1:
            parts.append(
                f'<path d="M278 {sy + 28} V{sy + 38}" stroke="{t["panel_stroke"]}" stroke-width="1.5" stroke-linecap="round"/>'
            )

    advisories = ["OSV", "GHSA", "NVD", "KEV", "EPSS"]
    for i, adv in enumerate(advisories):
        ax = 272 + i * 34
        parts.append(
            f'<rect x="{ax}" y="448" width="30" height="20" rx="6" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{ax + 15}" y="461" text-anchor="middle" font-family="ui-monospace,monospace" font-size="7" '
            f'font-weight="700" fill="{scan_accent}">{adv}</text>'
        )

    # Evidence graph hub
    cx, cy = 590, 268
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="78" fill="url(#core-glow)"/>')
    nodes = [
        (cx, cy - 58, "Finding", True, "finding"),
        (cx - 72, cy - 10, "Asset", False, "package"),
        (cx + 72, cy - 10, "Agent", False, "mcp"),
        (cx - 52, cy + 58, "Tool", False, "bug"),
        (cx + 52, cy + 58, "Cred", False, "lock"),
    ]
    for nx, ny, nlabel, center, icon in nodes:
        if not center:
            parts.append(
                f'<line x1="{cx}" y1="{cy}" x2="{nx}" y2="{ny}" stroke="{t["panel_stroke"]}" stroke-width="1.4" opacity="0.75"/>'
            )
    for nx, ny, nlabel, center, icon in nodes:
        r = 34 if center else 28
        fill = t["accent_fill"] if center else t["card"]
        stroke = t["accent_stroke"] if center else t["card_stroke"]
        parts.append(f'<circle cx="{nx}" cy="{ny}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{"2" if center else "1.5"}"/>')
        if center:
            parts.append(_icon_box(nx - 13, ny - 13, ICONS[icon], t, accent=True))
        parts.append(
            f'<text x="{nx}" y="{ny + (22 if center else 20)}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
            f'font-size="{"10" if center else "9"}" font-weight="800" fill="{t["accent"] if center else t["text"]}">{_esc(nlabel)}</text>'
        )

    meta = ["severity", "provenance", "tenant"]
    for i, chip in enumerate(meta):
        mx = 494 + i * 72
        parts.append(
            f'<rect x="{mx}" y="390" width="64" height="22" rx="7" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{mx + 32}" y="404" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" '
            f'font-weight="700" fill="{t["chip"]}">{chip}</text>'
        )

    # Control plane tiles
    for i, (icon, label) in enumerate(control):
        col, row = i % 2, i // 2
        tx, ty = 748 + col * 86, 136 + row * 62
        parts.append(f'<rect x="{tx}" y="{ty}" width="78" height="52" rx="10" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(tx + 8, ty + 13, ICONS[icon], t))
        parts.append(_text(tx + 40, ty + 32, label, **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9.5", "font-weight": "700", "fill": t["text"]}))

    parts.append(
        f'<rect x="748" y="340" width="162" height="28" rx="8" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        f'<text x="829" y="358" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8.5" '
        f'font-weight="700" fill="{t["chip"]}">fail-closed · RBAC · audit</text>'
    )

    # Outputs column
    out_colors = ["#f87171", "#fbbf24", "#60a5fa", "#a78bfa", "#34d399", "#fb7185"]
    for i, (label, color) in enumerate(zip(outputs, out_colors, strict=True)):
        oy = 136 + i * 52
        parts.append(
            f'<rect x="956" y="{oy}" width="80" height="36" rx="10" fill="{t["card"]}" stroke="{color}" stroke-width="1.2"/>'
            f'<circle cx="970" cy="{oy + 18}" r="4" fill="{color}" opacity="0.85"/>'
            f'<text x="982" y="{oy + 22}" font-family="ui-monospace,monospace" font-size="10" font-weight="800" fill="{t["text"]}">{_esc(label)}</text>'
        )

    parts.append(
        f'<text x="996" y="468" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" '
        f'font-weight="600" fill="{t["lane_muted"]}">reports · gates · runtime</text>'
    )

    # Flow arrows between lanes
    parts.append(_flow_arrow(238, 288, 256, 288, "collect", t))
    parts.append(_flow_arrow(446, 288, 464, 288, "normalize", t))
    parts.append(_flow_arrow(714, 288, 732, 288, "serve", t, accent=True))
    parts.append(_flow_arrow(922, 288, 940, 288, "export", t))

    # Trust bar
    parts.append(
        f'<rect x="28" y="508" width="1144" height="36" rx="10" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>'
        f'<text x="52" y="530" font-family="Inter,system-ui,sans-serif" font-size="9" font-weight="800" fill="{t["trust"]}">'
        "TRUST</text>"
        f'<text x="100" y="530" font-family="Inter,system-ui,sans-serif" font-size="9" font-weight="600" fill="{t["chip"]}">'
        "read-only connectors · secret redaction · signed evidence · same model everywhere</text>"
    )

    parts.append("</svg>")
    return "\n".join(parts)


def architecture(theme_name: str) -> str:
    t = THEMES[theme_name]
    suffix = "d" if theme_name == "dark" else "l"
    w, h = 1200, 620

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

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" fill="none" role="img" '
        f'aria-labelledby="arch-{suffix}-title arch-{suffix}-desc">',
        f'<title id="arch-{suffix}-title">agent-bom control-plane architecture</title>',
        '<desc id="arch-{suffix}-desc">Sources through scan and evidence core to control plane and consumers.</desc>'.format(
            suffix=suffix
        ),
        "<defs>",
        _marker(t, f"arch-{suffix}", "arrow"),
        _marker(t, f"arch-a-{suffix}", "arrow_accent"),
        "</defs>",
        f'<rect width="{w}" height="{h}" rx="14" fill="{t["bg"]}"/>',
        f'<text x="36" y="42" font-family="Inter,system-ui,sans-serif" font-size="22" font-weight="850" fill="{t["title"]}">'
        f'Control-plane <tspan fill="{t["accent"]}">architecture</tspan></text>',
        f'<text x="36" y="62" font-family="Inter,system-ui,sans-serif" font-size="10.5" font-weight="500" fill="{t["subtitle"]}">'
        "Sources → scan → one Finding + UnifiedGraph → API · Gateway · MCP → people + agents</text>",
    ]

    lane_x = [32, 228, 424, 620, 816]
    lane_w = [184, 184, 184, 184, 352]
    lane_meta = [
        ("SOURCES", "sources", "read-only"),
        ("SCAN", "enrich", "local"),
        ("EVIDENCE", "evidence", "normalized"),
        ("CONTROL", "control", "tenant auth"),
        ("CONSUMERS", "consumers", "people+agents"),
    ]

    for i, (label, key, tag) in enumerate(lane_meta):
        x, lw = lane_x[i], lane_w[i]
        parts.append(
            f'<rect x="{x}" y="82" width="{lw}" height="468" rx="12" fill="{t["panel"]}" stroke="{t["panel_stroke"]}"/>'
        )
        parts.append(_lane_header(x, 82, lw, label, key, tag, t))

    # Sources column
    for i, (icon, title, badge) in enumerate(sources):
        sy = 128 + i * 58
        parts.append(f'<rect x="44" y="{sy}" width="160" height="48" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(54, sy + 11, ICONS[icon], t))
        parts.append(
            f'<text x="88" y="{sy + 22}" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="700" fill="{t["text"]}">{_esc(title)}</text>'
        )
        parts.append(
            f'<text x="88" y="{sy + 36}" font-family="ui-monospace,monospace" font-size="8" font-weight="600" fill="{t["text_muted"]}">{_esc(badge)}</text>'
        )

    for i, (icon, title, badge) in enumerate(scan_items):
        sy = 128 + i * 72
        parts.append(f'<rect x="240" y="{sy}" width="160" height="60" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(250, sy + 17, ICONS[icon], t))
        parts.append(
            f'<text x="284" y="{sy + 30}" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="700" fill="{t["text"]}">{_esc(title)}</text>'
        )
        parts.append(
            f'<text x="284" y="{sy + 44}" font-family="ui-monospace,monospace" font-size="8" font-weight="600" fill="{t["text_muted"]}">{_esc(badge)}</text>'
        )

    # Evidence column — highlighted core cards
    for i, (icon, title, badge, highlight) in enumerate(core_items):
        sy = 128 + i * 88
        fill = t["accent_fill"] if highlight else t["card"]
        stroke = t["accent_stroke"] if highlight else t["card_stroke"]
        parts.append(f'<rect x="436" y="{sy}" width="160" height="72" rx="9" fill="{fill}" stroke="{stroke}" stroke-width="{"1.6" if highlight else "1"}"/>')
        parts.append(_icon_box(446, sy + 23, ICONS[icon], t, accent=highlight))
        parts.append(
            f'<text x="480" y="{sy + 34}" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="700" fill="{t["text"]}">{_esc(title)}</text>'
        )
        parts.append(
            f'<text x="480" y="{sy + 50}" font-family="ui-monospace,monospace" font-size="8" font-weight="600" fill="{t["accent"] if highlight else t["text_muted"]}">{_esc(badge)}</text>'
        )

    # Control plane
    for i, (icon, title, badge) in enumerate(cp_items):
        sy = 128 + i * 88
        parts.append(f'<rect x="632" y="{sy}" width="156" height="72" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(642, sy + 23, ICONS[icon], t))
        parts.append(
            f'<text x="676" y="{sy + 34}" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="700" fill="{t["text"]}">{_esc(title)}</text>'
        )
        parts.append(
            f'<text x="676" y="{sy + 50}" font-family="ui-monospace,monospace" font-size="8" font-weight="600" fill="{t["text_muted"]}">{_esc(badge)}</text>'
        )

    parts.append(
        f'<rect x="632" y="490" width="156" height="32" rx="8" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        f'<text x="710" y="510" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="700" fill="{t["chip"]}">'
        "OIDC · SAML · SCIM · RBAC</text>"
    )

    # Consumers — three sub-columns inside the wide lane
    cx_base = 828
    parts.append(
        f'<text x="{cx_base + 52}" y="128" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="800" '
        f'letter-spacing="0.12em" fill="{t["accent"]}">PEOPLE</text>'
    )
    for i, (icon, label) in enumerate(people):
        sy = 136 + i * 54
        parts.append(f'<rect x="{cx_base}" y="{sy}" width="104" height="44" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(cx_base + 8, sy + 9, ICONS[icon], t))
        parts.append(
            f'<text x="{cx_base + 40}" y="{sy + 27}" font-family="Inter,system-ui,sans-serif" font-size="10.5" font-weight="700" fill="{t["text"]}">{_esc(label)}</text>'
        )

    ax_base = cx_base + 118
    parts.append(
        f'<text x="{ax_base + 52}" y="128" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="800" '
        f'letter-spacing="0.12em" fill="{t["accent"]}">AGENTS</text>'
    )
    for i, (icon, label) in enumerate(agents):
        sy = 136 + i * 54
        parts.append(f'<rect x="{ax_base}" y="{sy}" width="104" height="44" rx="9" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(ax_base + 8, sy + 9, ICONS[icon], t))
        parts.append(
            f'<text x="{ax_base + 40}" y="{sy + 27}" font-family="Inter,system-ui,sans-serif" font-size="10.5" font-weight="700" fill="{t["text"]}">{_esc(label)}</text>'
        )

    art_base = cx_base + 236
    parts.append(
        f'<text x="{art_base + 52}" y="128" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="800" '
        f'letter-spacing="0.12em" fill="{t["accent"]}">ARTIFACTS</text>'
    )
    for i, label in enumerate(artifacts):
        col, row = i % 2, i // 2
        ax, ay = art_base + col * 58, 136 + row * 28
        parts.append(
            f'<rect x="{ax}" y="{ay}" width="54" height="22" rx="7" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{ax + 27}" y="{ay + 15}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="7.5" '
            f'font-weight="700" fill="{t["chip"]}">{_esc(label)}</text>'
        )

    parts.append(
        f'<text x="{art_base + 52}" y="248" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="600" fill="{t["lane_muted"]}">'
        "→ SIEM · webhooks</text>"
    )

    # Inter-lane flow
    y_flow = 318
    flows = [
        (lane_x[0] + lane_w[0], y_flow, lane_x[1], y_flow, "SCAN", False),
        (lane_x[1] + lane_w[1], y_flow, lane_x[2], y_flow, "NORMALIZE", False),
        (lane_x[2] + lane_w[2], y_flow, lane_x[3], y_flow, "SERVE", True),
        (lane_x[3] + lane_w[3], y_flow, lane_x[4], y_flow, "DELIVER", False),
    ]
    for x1, y1, x2, y2, label, accent in flows:
        color = t["arrow_accent"] if accent else t["arrow"]
        marker = f"arch-a-{suffix}" if accent else f"arch-{suffix}"
        width = "2.3" if accent else "2"
        parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{width}" marker-end="url(#{marker})"/>'
        )
        parts.append(
            f'<text x="{(x1 + x2) // 2}" y="{y1 - 10}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
            f'font-size="8" font-weight="800" letter-spacing="0.1em" fill="{t["accent"] if accent else t["lane_muted"]}">{_esc(label)}</text>'
        )

    parts.append(
        f'<rect x="32" y="568" width="1136" height="32" rx="9" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>'
        f'<text x="600" y="588" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="9" font-weight="600" fill="{t["trust"]}">'
        "READ-ONLY BY DEFAULT · no target writes · no secret values · self-hosted · signed evidence</text>"
    )

    parts.append("</svg>")
    return "\n".join(parts)


def persona_value(theme: str) -> str:
    """Buyer persona → product value lanes (GTM visual, not a code map)."""
    t = THEMES[theme]
    suffix = theme
    w, h = 980, 420
    personas = [
        ("shield", "AppSec / GRC", "SARIF · compliance · audit chain", "control"),
        ("gate", "Platform / SRE", "fleet · Helm · CI gates", "scan"),
        ("mcp", "Agent builders", "MCP inventory · runtime shield", "intake"),
        ("graph", "Security engineers", "blast radius · attack paths", "core"),
    ]
    values = [
        ("bug", "Accurate SCA", "15 ecosystems · distro-aware"),
        ("image", "Container coverage", "OCI native · optional Grype"),
        ("audit", "Self-hosted evidence", "your VPC · signed audit"),
        ("api", "Agent-native API", "283 ops · 70 MCP tools"),
    ]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" fill="none" role="img" '
        f'aria-labelledby="pv-{suffix}-title">',
        f'<title id="pv-{suffix}-title">agent-bom personas and value</title>',
        f'<rect width="{w}" height="{h}" rx="14" fill="{t["bg"]}"/>',
        f'<text x="36" y="42" font-family="Inter,system-ui,sans-serif" font-size="22" font-weight="850" fill="{t["title"]}">'
        "Who it serves · what they get</text>",
        f'<text x="36" y="62" font-family="Inter,system-ui,sans-serif" font-size="10.5" font-weight="500" fill="{t["subtitle"]}">'
        "One evidence model — different buyers, same inventory → findings → graph → gates</text>",
        f'<text x="36" y="98" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="800" '
        f'letter-spacing="0.12em" fill="{t["accent"]}">PERSONAS</text>',
        f'<text x="500" y="98" font-family="Inter,system-ui,sans-serif" font-size="8" font-weight="800" '
        f'letter-spacing="0.12em" fill="{t["accent"]}">VALUE PROOF</text>',
    ]

    for i, (icon, title, subtitle, lane) in enumerate(personas):
        y = 112 + i * 68
        bg, accent, _ = LANE_COLORS[lane]
        parts.append(f'<rect x="36" y="{y}" width="420" height="56" rx="11" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(48, y + 14, ICONS[icon], t, accent=True))
        parts.append(
            f'<text x="88" y="{y + 26}" font-family="Inter,system-ui,sans-serif" font-size="12" font-weight="700" fill="{t["text"]}">{_esc(title)}</text>'
        )
        parts.append(
            f'<text x="88" y="{y + 42}" font-family="ui-monospace,monospace" font-size="8.5" font-weight="600" fill="{accent}">{_esc(subtitle)}</text>'
        )

    for i, (icon, title, subtitle) in enumerate(values):
        y = 112 + i * 68
        parts.append(f'<rect x="500" y="{y}" width="444" height="56" rx="11" fill="{t["accent_fill"]}" stroke="{t["accent_stroke"]}"/>')
        parts.append(_icon_box(512, y + 14, ICONS[icon], t, accent=True))
        parts.append(
            f'<text x="552" y="{y + 26}" font-family="Inter,system-ui,sans-serif" font-size="12" font-weight="700" fill="{t["text"]}">{_esc(title)}</text>'
        )
        parts.append(
            f'<text x="552" y="{y + 42}" font-family="ui-monospace,monospace" font-size="8.5" font-weight="600" fill="{t["text_muted"]}">{_esc(subtitle)}</text>'
        )
        parts.append(
            f'<line x1="456" y1="{y + 28}" x2="500" y2="{y + 28}" stroke="{t["arrow_accent"]}" stroke-width="1.8" marker-end="url(#pv-{suffix})"/>'
        )

    parts.insert(
        5,
        "<defs>"
        + _marker(t, f"pv-{suffix}", "arrow_accent")
        + "</defs>",
    )

    parts.append(
        f'<rect x="36" y="372" width="908" height="28" rx="8" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>'
        f'<text x="490" y="390" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="9" font-weight="600" fill="{t["trust"]}">'
        "LOCAL SCAN · CONTROL PLANE · RUNTIME ENFORCEMENT — same Finding + UnifiedGraph everywhere</text>"
    )
    parts.append("</svg>")
    return "\n".join(parts)


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
        path = OUT / filename
        path.write_text(fn(theme) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
