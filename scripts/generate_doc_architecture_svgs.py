#!/usr/bin/env python3
"""Generate README architecture SVGs (how-it-works + control-plane architecture).

Hand-tuned layout with theme tokens — run after changing lane content or counts.
All coordinates are checked to stay inside lane panels (no text or card overflow).
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import NamedTuple

from agent_bom.mcp_server_metadata import _SERVER_CARD_TOOLS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "images"
VENDOR_LOGO_DIR = ROOT / "ui" / "public" / "logos"
VENDOR_WORDMARK_DIR = VENDOR_LOGO_DIR / "wordmarks"
DIAGRAM_VENDOR_DIR = ROOT / "docs" / "images" / "vendor"
SIMPLE_ICON_DIR = DIAGRAM_VENDOR_DIR / "simple-icons"
MCP_TOOL_COUNT = len(_SERVER_CARD_TOOLS)
_OPENAPI = json.loads((ROOT / "docs" / "openapi" / "v1.json").read_text(encoding="utf-8"))
REST_OPERATION_COUNT = sum(
    1
    for operations in _OPENAPI["paths"].values()
    for method in operations
    if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
)

CLOUD_VENDOR_LOGOS = (
    ("aws", "AWS", "#232F3E"),
    ("azure", "Azure", "#0078D4"),
    ("gcp", "GCP", "#4285F4"),
    ("snowflake", "Snowflake", "#29B5E8"),
)

SIMPLE_ICON_MARKS = {
    "aws": ("amazonwebservices.svg", "AWS", "#FF9900"),
    "azure": ("microsoftazure.svg", "Azure", "#0078D4"),
    "gcp": ("googlecloud.svg", "Google Cloud", "#4285F4"),
    "kubernetes": ("kubernetes.svg", "Kubernetes", "#326CE5"),
    "snowflake": ("snowflake.svg", "Snowflake", "#29B5E8"),
    "databricks": ("databricks.svg", "Databricks", "#FF3621"),
    "clickhouse": ("clickhouse.svg", "ClickHouse", "#FFCC01"),
}

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
        "ic": "#c4c4ce",
        "ic_accent": "#c4b5fd",
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
        "ic": "#5c5c66",
        "ic_accent": "#6d28d9",
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

# Architecture diagram uses a cool layered palette — intentionally distinct from the
# warm left-to-right pipeline lanes in how-it-works.
ARCH_LAYER_COLORS = {
    "sources": ("#0c4a6e", "#38bdf8", "#bae6fd"),
    "engine": ("#312e81", "#818cf8", "#c7d2fe"),
    "platform": ("#134e4a", "#2dd4bf", "#99f6e4"),
    "consumers": ("#4c1d95", "#c084fc", "#e9d5ff"),
}


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _svg_open(w: int, h: int, title: str, desc: str | None = None) -> list[str]:
    """GitHub-safe SVG root — explicit dimensions, no role/aria (sanitizer-friendly)."""
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" fill="none">',
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


def _icon_box(
    x: int | float,
    y: int | float,
    paths: str,
    t: dict,
    accent: bool = False,
    *,
    box: bool = True,
    size: int = 24,
    stroke_width: float = 1.5,
) -> str:
    stroke = t["ic_accent"] if accent else t["ic"]
    pad = 4
    inner = size - pad * 2
    scale = inner / 24
    box_svg = (
        f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="6" fill="{t["icon_bg"]}" stroke="{t["icon_stroke"]}"/>' if box else ""
    )
    return (
        f"{box_svg}"
        f'<g transform="translate({x + pad},{y + pad}) scale({scale})" fill="none" stroke="{stroke}" '
        f'stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round">{paths}</g>'
    )


def _lane_header(x: int, y: int, w: int, label: str, lane_key: str, tag: str, t: dict, *, inset: int = 3) -> str:
    bg, accent, text = LANE_COLORS[lane_key]
    hx, hy, hw, hh = x + inset, y + inset, w - inset * 2, 32 - inset
    return (
        f'<rect x="{hx}" y="{hy}" width="{hw}" height="{hh}" rx="7" fill="{bg}"/>'
        f'<text x="{hx + 10}" y="{hy + 18}" font-family="Inter,system-ui,sans-serif" font-size="9.5" font-weight="800" '
        f'letter-spacing="0.12em" fill="{text}">{_esc(label)}</text>'
        f'<text x="{hx + hw - 8}" y="{hy + 18}" text-anchor="end" font-family="Inter,system-ui,sans-serif" '
        f'font-size="7.5" font-weight="600" fill="{accent}" opacity="0.95">{_esc(tag)}</text>'
    )


def _lane_flow(x1: int, x2: int, y: int, label: str, t: dict, accent: bool = False) -> str:
    """Gutter connector between lane panels — label sits above the arrow stem."""
    color = t["arrow_accent"] if accent else t["arrow"]
    width = "2.2" if accent else "1.8"
    tip = x2 - 1
    stem = x2 - 7
    mid = (x1 + x2) // 2
    return (
        f'<line x1="{x1}" y1="{y}" x2="{stem}" y2="{y}" stroke="{color}" stroke-width="{width}"/>'
        f'<polygon points="{tip},{y} {stem},{y - 3.5} {stem},{y + 3.5}" fill="{color}"/>'
        f'<text x="{mid}" y="{y - 10}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
        f'font-size="7" font-weight="800" letter-spacing="0.1em" fill="{t["accent"] if accent else t["lane_muted"]}">'
        f"{_esc(label.upper())}</text>"
    )


def _arch_tier_label(x: int, y: int, w: int, label: str, tag: str, layer_key: str, t: dict) -> str:
    """Left-stripe tier header for the layered architecture diagram."""
    _, accent, text_c = ARCH_LAYER_COLORS[layer_key]
    return (
        f'<rect x="{x}" y="{y}" width="4" height="22" rx="2" fill="{accent}"/>'
        + _text(
            x + 14,
            y + 15,
            label,
            **{
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "9.5",
                "font-weight": "800",
                "letter-spacing": "0.14em",
                "fill": accent,
            },
        )
        + _text(
            x + w - 10,
            y + 15,
            tag,
            **{
                "text-anchor": "end",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "600",
                "fill": text_c,
            },
        )
    )


def _tier_down_arrow(cx: int, y: int, label: str, color: str) -> str:
    """Vertical connector between architecture tiers."""
    return (
        f'<line x1="{cx}" y1="{y}" x2="{cx}" y2="{y + 14}" stroke="{color}" stroke-width="1.6" stroke-linecap="round"/>'
        f'<polygon points="{cx},{y + 18} {cx - 4},{y + 12} {cx + 4},{y + 12}" fill="{color}"/>'
        + _text(
            cx,
            y - 5,
            label,
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "11.5",
                "font-weight": "800",
                "letter-spacing": "0.1em",
                "fill": color,
            },
        )
    )


def _hub_node(
    nx: int,
    ny: int,
    size: int,
    label: str,
    icon: str,
    t: dict,
    *,
    center: bool = False,
) -> str:
    """Evidence-lane node card — large semantic icon with label below."""
    half = size // 2
    x, y = nx - half, ny - half
    fill = t["accent_fill"] if center else t["card"]
    stroke = t["accent_stroke"] if center else t["card_stroke"]
    icon_sz = max(30, int(size * 0.62)) if center else max(26, int(size * 0.56))
    icon_y = y + (10 if center else 8)
    label_y = y + size - 7
    label_size = "9" if center else "8"
    return (
        f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="{max(8, size // 5)}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{"2" if center else "1.4"}"/>'
        + _icon_box(
            nx - icon_sz // 2,
            icon_y,
            ICONS[icon],
            t,
            accent=center,
            box=False,
            size=icon_sz,
            stroke_width=2.0 if center else 1.7,
        )
        + _text(
            nx,
            label_y,
            label,
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": label_size,
                "font-weight": "800",
                "fill": t["accent"] if center else t["text"],
            },
        )
    )


def _trust_footer(w: int, h: int, t: dict, message: str, *, height: int = 28, font_size: float = 8.5) -> str:
    y = h - height - 12
    return f'<rect x="24" y="{y}" width="{w - 48}" height="{height}" rx="8" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>' + _text(
        w // 2,
        y + height - 8,
        message,
        **{
            "text-anchor": "middle",
            "font-family": "Inter,system-ui,sans-serif",
            "font-size": str(font_size),
            "font-weight": "600",
            "fill": t["trust"],
        },
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
    if re.search(r"&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)", svg):
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
    "finding": '<path d="M12 3l8 3v6.5c0 4.5-3.2 7.8-8 9.5-4.8-1.7-8-5-8-9.5V6z"/><path d="M12 9v4"/><path d="M12 16.5h.01"/>',
    "asset": '<rect x="5" y="6" width="14" height="5" rx="1.5"/><rect x="5" y="13" width="14" height="5" rx="1.5"/><path d="M8 8.5h.01 M8 15.5h.01"/>',
    "agent": '<rect x="5.5" y="8" width="13" height="11" rx="3.5"/><circle cx="9.2" cy="12.2" r="1.35"/><circle cx="14.8" cy="12.2" r="1.35"/><path d="M9 15.6h6"/><path d="M12 5.2V8"/><circle cx="12" cy="4.2" r="1.2"/><path d="M7.2 10.2h1.2M15.6 10.2h1.2"/>',
    "tool": '<path d="M14.7 6.3a4.5 4.5 0 0 0-6.1 6.1L5 16l3 3 3.6-3.6a4.5 4.5 0 0 0 6.1-6.1l-2.4 2.4"/>',
    "cred": '<circle cx="9" cy="12" r="3.5"/><path d="M12.5 12H19v2.5h-2V12"/>',
    "graph": '<circle cx="8" cy="8" r="2.5"/><circle cx="16" cy="8" r="2.5"/><circle cx="12" cy="16" r="2.5"/><path d="M10 9.5l1.5 5 M14 9.5l-1.5 5"/>',
    "db": '<ellipse cx="12" cy="7" rx="7" ry="3"/><path d="M5 7v10c0 1.7 3.1 3 7 3s7-1.3 7-3V7"/>',
}


def _vendor_viewbox(raw: str) -> tuple[float, float]:
    match = re.search(r'viewBox="\s*[\d.]+\s+[\d.]+\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s*"', raw)
    if match:
        return float(match.group(1)), float(match.group(2))
    match = re.search(r'width="(\d+(?:\.\d+)?)"\s+height="(\d+(?:\.\d+)?)"', raw)
    if match:
        return float(match.group(1)), float(match.group(2))
    return 24.0, 24.0


def _namespace_svg_ids(inner: str, *, uid: str) -> str:
    for gid in sorted(set(re.findall(r'id="([^"]+)"', inner)), key=len, reverse=True):
        namespaced = f"{uid}-{gid}"
        inner = inner.replace(f'id="{gid}"', f'id="{namespaced}"')
        inner = inner.replace(f"url(#{gid})", f"url(#{namespaced})")
    return inner


def _vendor_wordmark_inner(vendor: str, *, uid: str, theme: str) -> str:
    """Inline official horizontal wordmarks used in the workflow diagram cloud row."""
    raw = (VENDOR_WORDMARK_DIR / f"{vendor}.svg").read_text(encoding="utf-8")
    root_fill_match = re.search(r"<svg[^>]*\sfill=\"([^\"]+)\"", raw)
    inner = re.sub(r"^.*?<svg[^>]*>", "", raw, count=1, flags=re.DOTALL)
    inner = re.sub(r"</svg>\s*$", "", inner, flags=re.DOTALL)
    inner = re.sub(r"<text\b[^>]*>.*?</text>", "", inner, flags=re.DOTALL | re.IGNORECASE)
    if root_fill_match and 'fill="' not in inner:
        inner = f'<g fill="{root_fill_match.group(1)}">{inner}</g>'
    if vendor == "aws" and theme == "dark":
        ink = "#e9e9ec"
        inner = inner.replace('stroke="#000"', f'stroke="{ink}"')
        inner = re.sub(
            r'(<path\b(?:(?!fill=)[^>])*)(fill-rule="evenodd")',
            rf'\1fill="{ink}" \2',
            inner,
        )
        inner = re.sub(
            r'(<path d="M46\.998[^"]+"[^>]*)(/>)',
            lambda m: m.group(1) + f' fill="{ink}"' + m.group(2) if "fill=" not in m.group(1) else m.group(0),
            inner,
            count=1,
        )
    return _namespace_svg_ids(inner.strip(), uid=uid)


def _vendor_logo_inner(vendor: str, *, uid: str) -> str:
    """Inline public vector mark from ui/public/logos (same assets as the dashboard)."""
    raw = (VENDOR_LOGO_DIR / f"{vendor}.svg").read_text(encoding="utf-8")
    root_fill_match = re.search(r"<svg[^>]*\sfill=\"([^\"]+)\"", raw)
    inner = re.sub(r"^.*?<svg[^>]*>", "", raw, count=1, flags=re.DOTALL)
    inner = re.sub(r"</svg>\s*$", "", inner, flags=re.DOTALL)
    # Diagram cards add their own labels; drop embedded wordmark text from source SVGs.
    inner = re.sub(r"<text\b[^>]*>.*?</text>", "", inner, flags=re.DOTALL | re.IGNORECASE)
    if root_fill_match and 'fill="' not in inner:
        inner = inner.replace("<path ", f'<path fill="{root_fill_match.group(1)}" ', 1)
    return _namespace_svg_ids(inner.strip(), uid=uid)


def _diagram_vendor_inner(filename: str, *, uid: str) -> tuple[str, float, float]:
    """Inline a provenance-pinned icon from the official diagram asset set."""
    raw = (DIAGRAM_VENDOR_DIR / filename).read_text(encoding="utf-8")
    vb_w, vb_h = _vendor_viewbox(raw)
    inner = re.sub(r"^.*?<svg[^>]*>", "", raw, count=1, flags=re.DOTALL)
    inner = re.sub(r"</svg>\s*$", "", inner, flags=re.DOTALL)
    inner = re.sub(r"<title\b[^>]*>.*?</title>", "", inner, flags=re.DOTALL | re.IGNORECASE)
    inner = "\n".join(line.strip() for line in inner.splitlines() if line.strip())
    return _namespace_svg_ids(inner.strip(), uid=uid), vb_w, vb_h


def _simple_icon_mark(x: float, y: float, size: int, vendor: str, t: dict, *, uid: str) -> str:
    """Render a provenance-pinned Simple Icons vector in a neutral diagram tile."""
    filename, label, color = SIMPLE_ICON_MARKS[vendor]
    raw = (SIMPLE_ICON_DIR / filename).read_text(encoding="utf-8")
    vb_w, vb_h = _vendor_viewbox(raw)
    inner = re.sub(r"^.*?<svg[^>]*>", "", raw, count=1, flags=re.DOTALL)
    inner = re.sub(r"</svg>\s*$", "", inner, flags=re.DOTALL)
    inner = re.sub(r"<title\b[^>]*>.*?</title>", "", inner, flags=re.DOTALL | re.IGNORECASE)
    inner = _namespace_svg_ids(inner.strip(), uid=uid)
    pad = max(4, round(size * 0.2))
    scale = min((size - 2 * pad) / vb_w, (size - 2 * pad) / vb_h)
    return (
        f'<g data-vendor="{_esc(label)}"><title>{_esc(label)} vector mark</title>'
        f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="7" fill="{t["icon_bg"]}" stroke="{t["icon_stroke"]}"/>'
        f'<g transform="translate({x + pad},{y + pad}) scale({scale})" fill="{color}">{inner}</g></g>'
    )


def _cloud_logos(
    x: int,
    y: int,
    lane_inner_w: int,
    t: dict,
    *,
    theme: str,
    card_h: int = 44,
    icon_box: int = 30,
) -> tuple[str, int]:
    """2x2 connector grid: large official icon mark + label on a bright chip.

    Logos are the "Connect" step, so tiles are sized to read as first-class
    connectors — big marks, tight padding, minimal dead white space.
    """
    del theme  # icons use native brand colors on a light chip for both themes
    cols = 2
    gap_x = 8
    gap_y = 8
    card_w = (lane_inner_w - gap_x) // cols
    pad = 6
    out: list[str] = []
    for i, (vendor, label, _accent) in enumerate(CLOUD_VENDOR_LOGOS):
        col, row = i % cols, i // cols
        bx = x + col * (card_w + gap_x)
        by = y + row * (card_h + gap_y)
        raw = (VENDOR_LOGO_DIR / f"{vendor}.svg").read_text(encoding="utf-8")
        vb_w, vb_h = _vendor_viewbox(raw)
        # Fill the icon box tightly — only a 2px optical inset — so marks read big.
        scale = min((icon_box - 2) / vb_h, (icon_box - 2) / vb_w)
        render_w = vb_w * scale
        render_h = vb_h * scale
        icon_x = bx + pad + (icon_box - render_w) / 2
        icon_y = by + (card_h - render_h) / 2
        inner = _vendor_logo_inner(vendor, uid=f"cl-{vendor}")
        label_x = bx + pad + icon_box + 8
        out.append(
            f'<rect x="{bx}" y="{by}" width="{card_w}" height="{card_h}" rx="9" fill="#ffffff" stroke="#d4d4d8"/>'
            f'<rect x="{bx + pad}" y="{by + (card_h - icon_box) / 2}" width="{icon_box}" height="{icon_box}" '
            f'rx="7" fill="#f8fafc" stroke="#e4e4e7"/>'
            f'<g transform="translate({icon_x},{icon_y}) scale({scale})">{inner}</g>'
            f'<text x="{label_x}" y="{by + card_h / 2 + 4}" font-family="Inter,system-ui,sans-serif" '
            f'font-size="11.5" font-weight="700" fill="#18181b">{_esc(label)}</text>'
        )
    return "".join(out), gap_y + 2 * card_h


def _advisory_chips(x: int, y: int, lane_inner_w: int, accent: str, t: dict, *, chip_w: int = 48) -> str:
    """Compact advisory-source row — monospace labels with source-tint dots."""
    advisories = (
        ("OSV", "#34d399"),
        ("GHSA", "#a78bfa"),
        ("NVD", "#60a5fa"),
        ("KEV", "#f87171"),
        ("EPSS", "#fbbf24"),
    )
    chip_gap = 4
    row_w = len(advisories) * chip_w + (len(advisories) - 1) * chip_gap
    start = x + max(0, (lane_inner_w - row_w) // 2)
    parts: list[str] = []
    for i, (name, color) in enumerate(advisories):
        ax = start + i * (chip_w + chip_gap)
        parts.append(
            f'<rect x="{ax}" y="{y}" width="{chip_w}" height="20" rx="6" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<circle cx="{ax + 9}" cy="{y + 10}" r="3" fill="{color}"/>'
            f'<text x="{ax + (chip_w + 9) / 2}" y="{y + 14}" text-anchor="middle" font-family="ui-monospace,monospace" '
            f'font-size="7.5" font-weight="800" fill="{accent}">{_esc(name)}</text>'
        )
    return "".join(parts)


def _lane_sublabel(x: int | float, y: int | float, label: str, t: dict) -> str:
    """Small uppercase section caption inside a lane."""
    return _text(
        x,
        y,
        label,
        **{
            "font-family": "Inter,system-ui,sans-serif",
            "font-size": "7.5",
            "font-weight": "700",
            "letter-spacing": "0.08em",
            "fill": t["lane_muted"],
        },
    )


def _legacy_how_it_works(theme_name: str) -> str:
    t = THEMES[theme_name]
    w, h = 1160, 560
    margin_x = 26
    lane_gap = 16
    lane_w = 265
    lane_x = [margin_x + i * (lane_w + lane_gap) for i in range(4)]
    inner_pad = 8

    # Product front door: onboard read-only (Connect) is the FIRST action,
    # then Scan, Graph, Serve — mapped to the app's stages / sidebar nav.
    steps = [
        ("search", "Discover", "assets & deps"),
        ("package", "Extract", "SBOM + models"),
        ("bug", "Scan", "OSV · malware"),
        ("zap", "Enrich", "NVD · EPSS · KEV"),
        ("graph", "Analyze", "blast radius"),
        ("file", "Report", "export + gate"),
    ]
    sources = [
        ("repo", "Repo"),
        ("ci", "CI"),
        ("mcp", "MCP"),
        ("image", "Image"),
        ("iac", "IaC"),
        ("sbom", "SBOM"),
        ("model", "Model"),
        ("cloud", "Cloud"),
    ]
    # Deliver lane: report formats first (findings out), optional runtime second.
    runtime = [
        ("gate", "Gateway", "#34d399"),
        ("shield", "Proxy", "#60a5fa"),
        ("file", "Policy", "#a78bfa"),
    ]
    exports = [
        ("SARIF", "#f87171"),
        ("CDX", "#fbbf24"),
        ("SPDX", "#60a5fa"),
        ("HTML", "#a78bfa"),
        ("JSON", "#34d399"),
        ("OCSF", "#fb7185"),
    ]

    lane_top = 100
    lane_h = 352
    flow_y = 86

    parts = _svg_open(
        w,
        h,
        "How agent-bom works",
        "Connect a cloud or source read-only, scan and enrich into one ContextGraph, "
        "then review blast radius in one pane of glass via agent-bom serve.",
    )
    parts += [
        "<defs>",
        '<linearGradient id="core-glow" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0%" stop-color="{t["accent"]}" stop-opacity="0.28"/>'
        f'<stop offset="100%" stop-color="{t["accent"]}" stop-opacity="0"/>'
        "</linearGradient>",
        "</defs>",
        f'<rect width="{w}" height="{h}" rx="14" fill="{t["bg"]}"/>',
        f'<rect x="10" y="10" width="{w - 20}" height="{h - 20}" rx="16" fill="none" stroke="#34d399" stroke-width="2" opacity="0.35"/>',
        f'<rect x="{w - 96}" y="20" width="72" height="22" rx="11" fill="#064e3b" opacity="0.85"/>',
        _text(
            w - 60,
            35,
            "LANES",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "8",
                "font-weight": "800",
                "letter-spacing": "0.14em",
                "fill": "#a7f3d0",
            },
        ),
        _text(
            margin_x,
            40,
            "Connect -> Scan -> Graph -> Serve",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "20", "font-weight": "800", "fill": t["title"]},
        ),
        _text(
            margin_x,
            60,
            "onboard read-only  ->  scan + enrich  ->  ContextGraph + blast radius  ->  agent-bom serve",
            **{
                "font-family": "ui-monospace,SFMono-Regular,Menlo,monospace",
                "font-size": "10",
                "font-weight": "500",
                "fill": t["subtitle"],
            },
        ),
    ]

    lane_meta = [
        ("CONNECT", "sources", "read-only"),
        ("SCAN", "scan", "cli · ci · docker"),
        ("GRAPH", "core", "blast radius"),
        ("SERVE", "control", "one pane of glass"),
    ]
    for i, (label, key, tag) in enumerate(lane_meta):
        x = lane_x[i]
        parts.append(
            f'<rect x="{x}" y="{lane_top}" width="{lane_w}" height="{lane_h}" rx="12" fill="{t["panel"]}" stroke="{t["panel_stroke"]}"/>'
        )
        parts.append(_lane_header(x, lane_top, lane_w, label, key, tag, t))

    # ---- Lane 0: CONNECT — cloud/platform onboarding is the first action ----
    conn_x = lane_x[0] + inner_pad
    conn_inner = lane_w - inner_pad * 2
    parts.append(_lane_sublabel(conn_x, lane_top + 50, "CLOUD & DATA PLATFORMS", t))
    cloud_y = lane_top + 58
    cloud_svg, cloud_h = _cloud_logos(conn_x, cloud_y, conn_inner, t, theme=theme_name)
    parts.append(cloud_svg)

    src_label_y = cloud_y + cloud_h + 14
    parts.append(_lane_sublabel(conn_x, src_label_y, "CODE · AGENTS · ARTIFACTS", t))
    src_top = src_label_y + 8
    src_cols = 2
    src_gap = 6
    src_card_w = (conn_inner - src_gap) // src_cols
    src_card_h = 26
    for i, (icon, label) in enumerate(sources):
        col, row = i % src_cols, i // src_cols
        tx = conn_x + col * (src_card_w + src_gap)
        ty = src_top + row * (src_card_h + src_gap)
        parts.append(
            f'<rect x="{tx}" y="{ty}" width="{src_card_w}" height="{src_card_h}" rx="7" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
        )
        parts.append(_icon_box(tx + 5, ty + 4, ICONS[icon], t, size=18))
        parts.append(
            _text(
                tx + 30,
                ty + 17,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9", "font-weight": "700", "fill": t["text"]},
            )
        )
    parts.append(
        f'<rect x="{conn_x}" y="{lane_top + lane_h - 32}" width="{conn_inner}" height="22" rx="7" '
        f'fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            conn_x + conn_inner // 2,
            lane_top + lane_h - 16,
            "read-only · no secret values",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    # ---- Lane 1: SCAN — the numbered local engine pipeline ----
    scan_x = lane_x[1] + inner_pad
    scan_inner = lane_w - inner_pad * 2
    scan_accent = LANE_COLORS["scan"][1]
    parts.append(_lane_sublabel(scan_x, lane_top + 50, "SCAN ENGINE", t))
    step_top = lane_top + 58
    step_h = 34
    # faint rail connecting the numbered steps
    rail_x = scan_x + 11
    parts.append(
        f'<line x1="{rail_x}" y1="{step_top + 14}" x2="{rail_x}" y2="{step_top + (len(steps) - 1) * step_h + 14}" '
        f'stroke="{scan_accent}" stroke-width="1.4" opacity="0.35"/>'
    )
    for i, (icon, label, desc) in enumerate(steps):
        sy = step_top + i * step_h
        parts.append(f'<circle cx="{rail_x}" cy="{sy + 14}" r="8.5" fill="{t["card"]}" stroke="{scan_accent}" stroke-width="1.3"/>')
        parts.append(
            f'<text x="{rail_x}" y="{sy + 17}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" '
            f'font-size="7.5" font-weight="800" fill="{scan_accent}">{i + 1}</text>'
        )
        parts.append(_icon_box(rail_x + 16, sy + 4, ICONS[icon], t, size=20))
        parts.append(
            _text(
                rail_x + 42,
                sy + 13,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9.5", "font-weight": "700", "fill": t["text"]},
            )
        )
        parts.append(
            _text(
                rail_x + 42,
                sy + 24,
                desc,
                **{"font-family": "ui-monospace,monospace", "font-size": "7", "font-weight": "500", "fill": t["text_muted"]},
            )
        )

    adv_label_y = step_top + len(steps) * step_h + 4
    parts.append(_lane_sublabel(scan_x, adv_label_y, "ADVISORY + THREAT INTEL", t))
    parts.append(_advisory_chips(scan_x, adv_label_y + 8, scan_inner, scan_accent, t, chip_w=45))
    parts.append(
        f'<rect x="{scan_x}" y="{lane_top + lane_h - 32}" width="{scan_inner}" height="22" rx="7" '
        f'fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            scan_x + scan_inner // 2,
            lane_top + lane_h - 16,
            "local scan · no target writes",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    # ---- Lane 2: GRAPH — one evidence model / ContextGraph ----
    findings_x = lane_x[2]
    findings_inner = lane_w - inner_pad * 2
    cx = findings_x + lane_w // 2
    cy = lane_top + 140
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="62" fill="url(#core-glow)"/>')
    hub_nodes = [
        (cx, cy - 52, 62, "Finding", "finding", True),
        (cx - 54, cy + 4, 50, "Asset", "asset", False),
        (cx + 54, cy + 4, 50, "Agent", "agent", False),
        (cx - 33, cy + 54, 46, "Tool", "tool", False),
        (cx + 33, cy + 54, 46, "Cred", "cred", False),
    ]
    for nx, ny, _size, _label, _icon, center in hub_nodes:
        if not center:
            parts.append(f'<line x1="{cx}" y1="{cy}" x2="{nx}" y2="{ny}" stroke="{t["panel_stroke"]}" stroke-width="1.2" opacity="0.75"/>')
    for nx, ny, size, nlabel, icon, center in hub_nodes:
        parts.append(_hub_node(nx, ny, size, nlabel, icon, t, center=center))

    widths = [86, 90, 52]
    chip_gap = 4
    row_w = sum(widths) + 2 * chip_gap
    chips_y = lane_top + 232
    for i, chip in enumerate(["blast radius", "ContextGraph", "tenant"]):
        mx = findings_x + (lane_w - row_w) // 2 + sum(widths[:i]) + i * chip_gap
        cw = widths[i]
        parts.append(
            f'<rect x="{mx}" y="{chips_y}" width="{cw}" height="20" rx="6" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{mx + cw / 2}" y="{chips_y + 14}" text-anchor="middle" font-family="Inter,system-ui,sans-serif" font-size="7.5" '
            f'font-weight="700" fill="{t["chip"]}">{_esc(chip)}</text>'
        )

    graph_lines = (
        "one evidence model",
        "agent -> MCP -> package -> CVE",
        "CLI · CI · API · UI · MCP share it",
    )
    for i, line in enumerate(graph_lines):
        parts.append(
            _text(
                findings_x + lane_w // 2,
                lane_top + 264 + i * 16,
                line,
                **{
                    "text-anchor": "middle",
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "9.5" if i == 1 else "8.5",
                    "font-weight": "800" if i == 1 else "600",
                    "fill": t["text"] if i == 1 else t["text_muted"],
                },
            )
        )

    parts.append(
        f'<rect x="{findings_x + inner_pad}" y="{lane_top + lane_h - 32}" width="{findings_inner}" height="22" rx="7" '
        f'fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            findings_x + inner_pad + findings_inner // 2,
            lane_top + lane_h - 16,
            "ContextGraph · same model everywhere",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    # ---- Lane 3: SERVE — one pane of glass (`agent-bom serve`) ----
    out_x = lane_x[3] + 10
    out_card_w = lane_w - 20

    parts.append(_lane_sublabel(out_x + 2, lane_top + 50, "CONTROL PLANE", t))
    glass = [
        ("ui", "Dashboard"),
        ("api", "REST API"),
        ("mcp", "MCP srv"),
        ("fleet", "Fleet"),
        ("audit", "Audit"),
        ("graph", "Graph"),
    ]
    glass_w = (out_card_w - 8) // 3
    for i, (icon, label) in enumerate(glass):
        col, row = i % 3, i // 3
        gx = out_x + col * (glass_w + 4)
        gy = lane_top + 58 + row * 42
        parts.append(f'<rect x="{gx}" y="{gy}" width="{glass_w}" height="36" rx="8" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(_icon_box(gx + 6, gy + 8, ICONS[icon], t, size=20))
        parts.append(
            _text(
                gx + 30,
                gy + 22,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "8", "font-weight": "700", "fill": t["text"]},
            )
        )

    parts.append(_lane_sublabel(out_x + 2, lane_top + 156, "REPORT FORMATS", t))
    for i, (label, color) in enumerate(exports):
        col, row = i % 3, i // 3
        ew = (out_card_w - 8) // 3
        ex = out_x + col * (ew + 4)
        ey = lane_top + 164 + row * 32
        parts.append(
            f'<rect x="{ex}" y="{ey}" width="{ew}" height="26" rx="7" fill="{t["card"]}" stroke="{color}" stroke-width="1.1"/>'
            f'<circle cx="{ex + 10}" cy="{ey + 13}" r="3" fill="{color}"/>'
            f'<text x="{ex + ew / 2 + 4}" y="{ey + 17}" text-anchor="middle" font-family="ui-monospace,monospace" '
            f'font-size="7.5" font-weight="800" fill="{t["text"]}">{_esc(label)}</text>'
        )

    parts.append(_lane_sublabel(out_x + 2, lane_top + 244, "OPTIONAL RUNTIME", t))
    for i, (icon, label, color) in enumerate(runtime):
        rw = (out_card_w - 8) // 3
        rx = out_x + i * (rw + 4)
        ry = lane_top + 252
        parts.append(f'<rect x="{rx}" y="{ry}" width="{rw}" height="36" rx="8" fill="{t["card"]}" stroke="{color}" stroke-width="1.1"/>')
        parts.append(_icon_box(rx + 6, ry + 8, ICONS[icon], t, accent=True, size=20))
        parts.append(
            _text(
                rx + 30,
                ry + 22,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "8", "font-weight": "700", "fill": t["text"]},
            )
        )

    parts.append(
        f'<rect x="{out_x}" y="{lane_top + lane_h - 32}" width="{out_card_w}" height="22" rx="7" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            out_x + out_card_w // 2,
            lane_top + lane_h - 16,
            "agent-bom serve · one pane of glass",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    flow_labels = ["scan", "graph", "serve"]
    for i in range(3):
        gutter_mid = (lane_x[i] + lane_w + lane_x[i + 1]) // 2
        parts.append(
            _lane_flow(
                gutter_mid - 14,
                gutter_mid + 14,
                flow_y,
                flow_labels[i],
                t,
                accent=(i >= 1),
            )
        )

    parts.append(_trust_footer(w, h, t, "read-only · secret redaction · signed evidence · same model everywhere"))
    parts.append("</svg>")
    return "\n".join(parts)


def how_it_works(theme_name: str) -> str:
    """Render the canonical Scan / Centralize / Enforce product lanes."""
    palette = {
        "dark": {
            "bg0": "#0b1220",
            "bg1": "#0f1c24",
            "bg2": "#10261f",
            "lane1_0": "#0f766e",
            "lane1_1": "#0f766e",
            "lane2_0": "#0369a1",
            "lane2_1": "#0369a1",
            "lane3_0": "#b45309",
            "lane3_1": "#b45309",
            "glow1": "#34d399",
            "glow2": "#22d3ee",
            "brand": "#34d399",
            "title": "#f8fafc",
            "muted": "#94a3b8",
            "scan": "#5eead4",
            "scan_bar": "#34d399",
            "scan_cmd": "#67e8f9",
            "central": "#7dd3fc",
            "central_bar": "#38bdf8",
            "enforce": "#fcd34d",
            "enforce_bar": "#fbbf24",
            "divider": "#1e293b",
            "lane_opacity": "0.35",
            "lane_end_opacity": "0.05",
        },
        "light": {
            "bg0": "#f8fafc",
            "bg1": "#f1f5f9",
            "bg2": "#ecfdf5",
            "lane1_0": "#ccfbf1",
            "lane1_1": "#f0fdfa",
            "lane2_0": "#e0f2fe",
            "lane2_1": "#f0f9ff",
            "lane3_0": "#ffedd5",
            "lane3_1": "#fffbeb",
            "glow1": "#14b8a6",
            "glow2": "#0ea5e9",
            "brand": "#0f766e",
            "title": "#0f172a",
            "muted": "#475569",
            "scan": "#0f766e",
            "scan_bar": "#0f766e",
            "scan_cmd": "#0e7490",
            "central": "#0369a1",
            "central_bar": "#0284c7",
            "enforce": "#b45309",
            "enforce_bar": "#d97706",
            "divider": "#e2e8f0",
            "lane_opacity": "0.95",
            "lane_end_opacity": "0.4",
        },
    }[theme_name]

    parts = _svg_open(
        1120,
        420,
        "agent-bom - three product lanes",
        "Scan locally, centralize evidence, enforce runtime - one Finding + UnifiedGraph model.",
    )
    parts.extend(
        [
            "<defs>",
            '<linearGradient id="bg" x1="0" y1="0" x2="1120" y2="420" gradientUnits="userSpaceOnUse">',
            f'<stop offset="0%" stop-color="{palette["bg0"]}"/>',
            f'<stop offset="55%" stop-color="{palette["bg1"]}"/>',
            f'<stop offset="100%" stop-color="{palette["bg2"]}"/>',
            "</linearGradient>",
            '<linearGradient id="lane1" x1="48" y1="140" x2="360" y2="360" gradientUnits="userSpaceOnUse">',
            f'<stop offset="0%" stop-color="{palette["lane1_0"]}" stop-opacity="{palette["lane_opacity"]}"/>',
            f'<stop offset="100%" stop-color="{palette["lane1_1"]}" stop-opacity="{palette["lane_end_opacity"]}"/>',
            "</linearGradient>",
            '<linearGradient id="lane2" x1="392" y1="140" x2="704" y2="360" gradientUnits="userSpaceOnUse">',
            f'<stop offset="0%" stop-color="{palette["lane2_0"]}" stop-opacity="{palette["lane_opacity"]}"/>',
            f'<stop offset="100%" stop-color="{palette["lane2_1"]}" stop-opacity="{palette["lane_end_opacity"]}"/>',
            "</linearGradient>",
            '<linearGradient id="lane3" x1="736" y1="140" x2="1048" y2="360" gradientUnits="userSpaceOnUse">',
            f'<stop offset="0%" stop-color="{palette["lane3_0"]}" stop-opacity="{palette["lane_opacity"]}"/>',
            f'<stop offset="100%" stop-color="{palette["lane3_1"]}" stop-opacity="{palette["lane_end_opacity"]}"/>',
            "</linearGradient>",
            '<filter id="soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="18"/></filter>',
            "</defs>",
            '<rect width="1120" height="420" rx="20" fill="url(#bg)"/>',
            f'<circle cx="180" cy="90" r="120" fill="{palette["glow1"]}" opacity="0.08" filter="url(#soft)"/>',
            f'<circle cx="920" cy="340" r="140" fill="{palette["glow2"]}" opacity="0.07" filter="url(#soft)"/>',
            _text(
                48,
                52,
                "AGENT-BOM",
                **{
                    "font-family": "'IBM Plex Sans','Segoe UI',system-ui,sans-serif",
                    "font-size": "13",
                    "font-weight": "700",
                    "letter-spacing": "0.22em",
                    "fill": palette["brand"],
                },
            ),
            _text(
                48,
                92,
                "One evidence model. Three ways in.",
                **{
                    "font-family": "'IBM Plex Sans','Segoe UI',system-ui,sans-serif",
                    "font-size": "28",
                    "font-weight": "700",
                    "fill": palette["title"],
                },
            ),
            _text(
                48,
                118,
                "Scan / control plane / runtime enforcement. Same Finding + UnifiedGraph everywhere.",
                **{"font-family": "'IBM Plex Sans','Segoe UI',system-ui,sans-serif", "font-size": "14", "fill": palette["muted"]},
            ),
        ]
    )

    lanes = (
        (
            48,
            320,
            "lane1",
            palette["scan_bar"],
            palette["scan"],
            "01  SCAN",
            "Local CLI / CI",
            ("Inventory, findings, fix-first,", "SARIF / SBOM / HTML - no server."),
            "agent-bom scan .",
            palette["scan_cmd"],
        ),
        (
            392,
            320,
            "lane2",
            palette["central_bar"],
            palette["central"],
            "02  CENTRALIZE",
            "Self-hosted plane",
            ("Fleet, graph, compliance,", "audit - your VPC / Postgres."),
            "agent-bom serve",
            palette["central"],
        ),
        (
            736,
            336,
            "lane3",
            palette["enforce_bar"],
            palette["enforce"],
            "03  ENFORCE",
            "Runtime gateway",
            ("Allow / warn / block MCP", "tool calls with signed audit."),
            "agent-bom gateway serve --help",
            palette["enforce"],
        ),
    )
    for x, width, gradient, bar, accent, label, title, body, command, command_color in lanes:
        parts.extend(
            [
                f'<rect x="{x}" y="148" width="{width}" height="200" rx="4" fill="url(#{gradient})"/>',
                f'<rect x="{x}" y="148" width="4" height="200" fill="{bar}"/>',
                _text(
                    x + 24,
                    178,
                    label,
                    **{
                        "font-family": "'IBM Plex Mono',ui-monospace,monospace",
                        "font-size": "11",
                        "font-weight": "700",
                        "letter-spacing": "0.16em",
                        "fill": accent,
                    },
                ),
                _text(
                    x + 24,
                    214,
                    title,
                    **{
                        "font-family": "'IBM Plex Sans',system-ui,sans-serif",
                        "font-size": "22",
                        "font-weight": "700",
                        "fill": palette["title"],
                    },
                ),
                _text(
                    x + 24,
                    242,
                    body[0],
                    **{"font-family": "'IBM Plex Sans',system-ui,sans-serif", "font-size": "13", "fill": palette["muted"]},
                ),
                _text(
                    x + 24,
                    260,
                    body[1],
                    **{"font-family": "'IBM Plex Sans',system-ui,sans-serif", "font-size": "13", "fill": palette["muted"]},
                ),
                _text(
                    x + 24,
                    312,
                    command,
                    **{"font-family": "'IBM Plex Mono',ui-monospace,monospace", "font-size": "12", "fill": command_color},
                ),
            ]
        )

    parts.extend(
        [
            f'<rect x="48" y="372" width="1024" height="1" fill="{palette["divider"]}"/>',
            _text(
                48,
                398,
                "Finding + UnifiedGraph is the spine - CLI, API, UI, and MCP share it.",
                **{"font-family": "'IBM Plex Sans',system-ui,sans-serif", "font-size": "12", "fill": palette["muted"]},
            ),
            "</svg>",
        ]
    )
    return "\n".join(parts)


def workflow(theme_name: str) -> str:
    """Render the end-to-end evidence workflow from source to verified action."""
    t = THEMES[theme_name]
    # README renders this image at roughly 900px. A wide five-column canvas
    # made technically-correct copy land below a comfortable reading size.
    # Keep the canvas close to its rendered width and use vertical layers:
    # sources -> processing -> decisions -> outcomes -> trust boundary.
    width, height = 1120, 1290
    parts = _svg_open(
        width,
        height,
        "agent-bom end-to-end evidence workflow",
        "Sources flow through collection, normalization, correlation, ownership, remediation, verification, and action.",
    )
    parts.append(f'<rect width="{width}" height="{height}" rx="24" fill="{t["bg"]}"/>')
    parts.append(
        _text(
            36,
            45,
            "FROM SOURCE TO VERIFIED ACTION",
            **{
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "15",
                "font-weight": "800",
                "letter-spacing": "0.16em",
                "fill": t["accent"],
            },
        )
    )
    parts.append(
        _text(
            36,
            82,
            "One evidence workflow across every environment",
            **{
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "28",
                "font-weight": "750",
                "fill": t["title"],
            },
        )
    )

    source_cards = (
        ("repo", "Repository + CI", "code · dependencies · IaC · secrets"),
        ("endpoint", "Workstation + endpoint", "apps · processes · agents · MCP"),
        ("cluster", "Images + Kubernetes", "registry · filesystem · workloads"),
        ("cloud", "Cloud + data platforms", "accounts · identity · posture"),
        ("runtime", "MCP + runtime", "servers · tools · live decisions"),
    )
    source_icons = {
        "repo": ICONS["file"],
        "endpoint": ICONS["fleet"],
        "cluster": ICONS["package"],
        "cloud": ICONS["cloud"],
        "runtime": ICONS["tool"],
    }
    left, gap, card_w, source_y, source_h = 36, 14, 340, 128, 112
    parts.append(
        _text(
            left,
            source_y - 14,
            "1 · EVIDENCE SOURCES",
            **{
                "font-family": "ui-monospace,monospace",
                "font-size": "15",
                "font-weight": "800",
                "letter-spacing": "0.13em",
                "fill": t["lane"],
            },
        )
    )
    for index, (key, title, detail) in enumerate(source_cards):
        row, col = divmod(index, 3)
        row_count = 3 if row == 0 else 2
        row_width = row_count * card_w + (row_count - 1) * gap
        x = (width - row_width) / 2 + col * (card_w + gap)
        y = source_y + row * (source_h + gap)
        parts.append(f'<rect x="{x}" y="{y}" width="{card_w}" height="{source_h}" rx="14" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        if key == "cluster":
            parts.append(_simple_icon_mark(x + 16, y + 16, 34, "kubernetes", t, uid=f"wf-{theme_name}-kubernetes"))
        else:
            parts.append(_icon_box(x + 16, y + 16, source_icons[key], t, accent=True, size=34))
        parts.append(
            _text(
                x + 62,
                y + 40,
                title,
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "18",
                    "font-weight": "750",
                    "fill": t["text"],
                },
            )
        )
        parts.append(
            _text(
                x + 16,
                y + 76,
                detail,
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "14",
                    "fill": t["text_muted"],
                },
            )
        )
        if key == "cloud":
            logo_y = y + 80
            for logo_index, vendor in enumerate(("aws", "azure", "gcp", "snowflake", "databricks", "clickhouse")):
                parts.append(
                    _simple_icon_mark(
                        x + 16 + logo_index * 42,
                        logo_y,
                        32,
                        vendor,
                        t,
                        uid=f"wf-{theme_name}-{vendor}",
                    )
                )

    stages = (
        ("01", "COLLECT + SCAN", "Read-only intake", "Scope and completeness stay explicit", "#38bdf8", "bug"),
        ("02", "NORMALIZE", "Finding + UnifiedGraph", "Identity, provenance, and evidence state", "#818cf8", "package"),
        ("03", "CORRELATE + PRIORITIZE", "Reachability + blast radius", "Rank paths with evidence, not raw volume", "#a78bfa", "graph"),
        ("04", "OWN + REMEDIATE", "Owner + SLA + ticket", "Fix, accept risk, or mark a false positive", "#34d399", "tool"),
        ("05", "VERIFY + ACT", "Rescan + terminal state", "Export, centralize, or enforce at runtime", "#fbbf24", "shield"),
    )
    stage_left, stage_w, stage_y, stage_h, stage_gap = 84, 952, 454, 102, 14
    parts.append(
        _text(
            left,
            stage_y - 18,
            "2 · EVIDENCE PIPELINE",
            **{
                "font-family": "ui-monospace,monospace",
                "font-size": "15",
                "font-weight": "800",
                "letter-spacing": "0.13em",
                "fill": t["lane"],
            },
        )
    )
    for index, (number, title, line_one, line_two, accent, icon_key) in enumerate(stages):
        x = stage_left
        y = stage_y + index * (stage_h + stage_gap)
        parts.append(
            f'<rect x="{x}" y="{y}" width="{stage_w}" height="{stage_h}" rx="16" fill="{t["panel"]}" stroke="{accent}" stroke-width="1.6"/>'
        )
        parts.append(
            _text(
                x + 22,
                y + 38,
                number,
                **{
                    "font-family": "ui-monospace,monospace",
                    "font-size": "17",
                    "font-weight": "800",
                    "fill": accent,
                },
            )
        )
        parts.append(_icon_box(x + 70, y + 22, ICONS[icon_key], t, accent=True, size=42))
        parts.append(
            _text(
                x + 130,
                y + 39,
                title,
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "18",
                    "font-weight": "800",
                    "fill": t["text"],
                },
            )
        )
        parts.append(
            _text(
                x + 130,
                y + 72,
                line_one,
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "15",
                    "font-weight": "700",
                    "fill": t["text"],
                },
            )
        )
        parts.append(
            _text(
                x + 470,
                y + 72,
                line_two,
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "15",
                    "fill": t["text_muted"],
                },
            )
        )
        if index < len(stages) - 1:
            mid_x = width / 2
            start_y = y + stage_h
            end_y = y + stage_h + stage_gap
            parts.append(
                f'<line x1="{mid_x}" y1="{start_y + 2}" x2="{mid_x}" y2="{end_y - 5}" '
                f'stroke="{t["arrow_accent"]}" stroke-width="2"/>'
                f'<polygon points="{mid_x},{end_y} {mid_x - 5},{end_y - 7} {mid_x + 5},{end_y - 7}" fill="{t["arrow_accent"]}"/>'
            )

    decision_y = stage_y + len(stages) * (stage_h + stage_gap) + 10
    parts.append(f'<rect x="84" y="{decision_y}" width="952" height="54" rx="12" fill="{t["accent_fill"]}" stroke="{t["accent_stroke"]}"/>')
    parts.append(
        _text(
            width / 2,
            decision_y + 35,
            "3 · INVESTIGATE  ›  PATH  ›  IMPACT  ›  OWNER  ›  FIX  ›  VERIFY",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "16",
                "font-weight": "800",
                "fill": t["accent"],
            },
        )
    )

    outcomes = ("SARIF", "CycloneDX", "SPDX", "HTML + JSON", "Control plane", "Runtime policy")
    chip_y, chip_gap, chip_w = decision_y + 84, 12, 164
    parts.append(
        _text(
            left,
            chip_y - 14,
            "4 · VERIFIED OUTCOMES",
            **{
                "font-family": "ui-monospace,monospace",
                "font-size": "15",
                "font-weight": "800",
                "letter-spacing": "0.13em",
                "fill": t["lane"],
            },
        )
    )
    for index, label in enumerate(outcomes):
        x = left + index * (chip_w + chip_gap)
        parts.append(f'<rect x="{x}" y="{chip_y}" width="{chip_w}" height="52" rx="11" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>')
        parts.append(
            _text(
                x + chip_w / 2,
                chip_y + 33,
                label,
                **{
                    "text-anchor": "middle",
                    "font-family": "ui-monospace,monospace",
                    "font-size": "14",
                    "font-weight": "750",
                    "fill": t["chip"],
                },
            )
        )

    trust_y = chip_y + 80
    parts.append(f'<rect x="36" y="{trust_y}" width="516" height="50" rx="11" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>')
    parts.append(
        _text(
            294,
            trust_y + 32,
            "Raw source + credentials stay local",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "14",
                "font-weight": "700",
                "fill": t["trust"],
            },
        )
    )
    parts.append(f'<rect x="568" y="{trust_y}" width="516" height="50" rx="11" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>')
    parts.append(
        _text(
            826,
            trust_y + 32,
            "Unavailable remains unavailable · partial stays explicit",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "14",
                "font-weight": "700",
                "fill": t["text_muted"],
            },
        )
    )
    parts.append("</svg>")
    return "\n".join(parts)


def architecture(theme_name: str) -> str:
    """Readable layered control-plane map for the README-scale embed."""
    t = THEMES[theme_name]
    w, h = 1120, 1320
    margin_x, band_w = 36, 1048
    parts = _svg_open(
        w,
        h,
        "agent-bom control-plane architecture",
        "Sources enter a local processing engine, become tenant-scoped evidence, and leave through human, agent, and artifact surfaces.",
    )
    parts += [
        f'<rect width="{w}" height="{h}" rx="22" fill="{t["bg"]}"/>',
        _text(
            36,
            48,
            "CONTROL-PLANE ARCHITECTURE",
            **{
                "font-family": "ui-monospace,monospace",
                "font-size": "15",
                "font-weight": "800",
                "letter-spacing": "0.14em",
                "fill": t["accent"],
            },
        ),
        _text(
            36,
            86,
            "Four layers from read-only intake to verified action",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "28", "font-weight": "800", "fill": t["title"]},
        ),
    ]

    def band(y: int, height: int, layer: str, number: str, title: str, boundary: str) -> None:
        accent = ARCH_LAYER_COLORS[layer][1]
        parts.append(
            f'<rect x="{margin_x}" y="{y}" width="{band_w}" height="{height}" rx="16" fill="{t["panel"]}" stroke="{accent}" stroke-width="1.5"/>'
        )
        parts.append(f'<rect x="{margin_x}" y="{y}" width="6" height="{height}" rx="3" fill="{accent}"/>')
        parts.append(
            _text(
                margin_x + 22,
                y + 35,
                f"{number} · {title}",
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "17",
                    "font-weight": "800",
                    "letter-spacing": "0.06em",
                    "fill": accent,
                },
            )
        )
        parts.append(
            _text(
                margin_x + band_w - 22,
                y + 35,
                boundary,
                **{
                    "text-anchor": "end",
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "14",
                    "font-weight": "700",
                    "fill": t["text_muted"],
                },
            )
        )

    def card(
        x: int,
        y: int,
        width: int,
        height: int,
        icon: str,
        title: str,
        detail: str,
        layer: str,
        *,
        highlight: bool = False,
        vendor: str | None = None,
    ) -> None:
        accent = ARCH_LAYER_COLORS[layer][1]
        fill = t["accent_fill"] if highlight else t["card"]
        stroke = accent if highlight else t["card_stroke"]
        parts.append(
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="{"1.6" if highlight else "1"}"/>'
        )
        if vendor is None:
            parts.append(_icon_box(x + 16, y + 18, ICONS[icon], t, accent=highlight, size=38))
        else:
            parts.append(_simple_icon_mark(x + 16, y + 18, 38, vendor, t, uid=f"arch-{theme_name}-{vendor}-{x}-{y}"))
        parts.append(
            _text(
                x + 68,
                y + 39,
                title,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "17", "font-weight": "800", "fill": t["text"]},
            )
        )
        parts.append(
            _text(
                x + 68,
                y + 65,
                detail,
                **{
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "14",
                    "font-weight": "600",
                    "fill": accent if highlight else t["text_muted"],
                },
            )
        )

    # 1. Five source families, arranged 3 + 2 rather than seven tiny columns.
    y1, h1 = 122, 260
    band(y1, h1, "sources", "1", "INTAKE SOURCES", "read-only collectors")
    source_cards = (
        ("package", "Code + supply chain", "repos · CI · packages · secrets", None),
        ("mcp", "Agents + MCP + models", "clients · servers · model files", None),
        ("cloud", "Cloud + data", "AWS · Azure · GCP · Snowflake", "snowflake"),
        ("iac", "Images + infrastructure", "OCI · K8s · IaC · workloads", "kubernetes"),
        ("sbom", "Imported evidence", "CDX · SPDX · SARIF · scans", None),
    )
    card_w, card_h, card_gap = 330, 82, 12
    for index, item in enumerate(source_cards):
        row, col = divmod(index, 3)
        count = 3 if row == 0 else 2
        row_width = count * card_w + (count - 1) * card_gap
        x = (w - row_width) // 2 + col * (card_w + card_gap)
        y = y1 + 54 + row * (card_h + 12)
        icon, title, detail, vendor = item
        card(x, y, card_w, card_h, icon, title, detail, "sources", vendor=vendor)

    parts.append(_tier_down_arrow(w // 2, y1 + h1 + 2, "COLLECT", ARCH_LAYER_COLORS["sources"][1]))

    # 2. Processing is a short sequence, not a wall of independent boxes.
    y2, h2 = 414, 224
    band(y2, h2, "engine", "2", "LOCAL PROCESSING ENGINE", "bounded + failure-honest")
    engine = (
        ("bug", "Scan", "OSV · SAST · posture"),
        ("zap", "Enrich", "NVD · EPSS · KEV"),
        ("graph", "Correlate", "identity · reachability"),
        ("shield", "Prioritize", "blast radius · policy"),
    )
    eng_w = 244
    for index, item in enumerate(engine):
        x = margin_x + 22 + index * (eng_w + 10)
        card(x, y2 + 62, eng_w, 104, *item, "engine")

    parts.append(_tier_down_arrow(w // 2, y2 + h2 + 2, "PERSIST", ARCH_LAYER_COLORS["engine"][1]))

    # 3. Separate the evidence model from the serving plane.
    y3, h3 = 670, 342
    band(y3, h3, "platform", "3", "EVIDENCE + SERVING PLANE", "tenant-scoped · authenticated")
    col_gap, col_w = 18, 497
    left_x, right_x = margin_x + 18, margin_x + 18 + col_w + col_gap
    parts.append(
        _text(
            left_x,
            y3 + 70,
            "EVIDENCE MODEL",
            **{
                "font-family": "ui-monospace,monospace",
                "font-size": "14",
                "font-weight": "800",
                "letter-spacing": "0.1em",
                "fill": ARCH_LAYER_COLORS["platform"][1],
            },
        )
    )
    parts.append(
        _text(
            right_x,
            y3 + 70,
            "CONTROL + DELIVERY",
            **{
                "font-family": "ui-monospace,monospace",
                "font-size": "14",
                "font-weight": "800",
                "letter-spacing": "0.1em",
                "fill": ARCH_LAYER_COLORS["platform"][1],
            },
        )
    )
    evidence = (
        ("finding", "Unified Finding", "scope · completeness · provenance", True),
        ("graph", "UnifiedGraph", "assets · identities · paths", True),
        ("db", "Portable stores", "SQLite · Postgres · Snowflake", False),
    )
    delivery = (
        ("api", "REST API + MCP", f"{REST_OPERATION_COUNT} operations · {MCP_TOOL_COUNT} tools", False),
        ("fleet", "Fleet + scheduler", "endpoints · jobs · change events", False),
        ("gate", "Gateway + policy", "observe · decide · enforce", False),
    )
    for index, (icon, title, detail, highlight) in enumerate(evidence):
        card(left_x, y3 + 88 + index * 74, col_w, 64, icon, title, detail, "platform", highlight=highlight)
    for index, (icon, title, detail, highlight) in enumerate(delivery):
        card(right_x, y3 + 88 + index * 74, col_w, 64, icon, title, detail, "platform", highlight=highlight)

    parts.append(_tier_down_arrow(w // 2, y3 + h3 + 2, "DELIVER", ARCH_LAYER_COLORS["platform"][1]))

    # 4. Three outcome groups keep the audience and artifact story obvious.
    y4, h4 = 1044, 206
    band(y4, h4, "consumers", "4", "CONSUMERS + VERIFIED OUTCOMES", "least-privilege delivery")
    outcomes = (
        ("ui", "People", "CLI · Web UI · operators"),
        ("mcp", "Agents", "MCP · SDK · automation"),
        ("file", "Artifacts", "SBOM · SARIF · OCSF · HTML/JSON"),
    )
    out_w = 330
    for index, item in enumerate(outcomes):
        x = margin_x + 22 + index * (out_w + 10)
        card(x, y4 + 66, out_w, 92, *item, "consumers")

    parts.append(
        _trust_footer(
            w,
            h,
            t,
            "READ-ONLY BY DEFAULT · no target writes · no secret values · self-hosted · signed evidence",
            height=38,
            font_size=12.5,
        )
    )
    parts.append("</svg>")
    return "\n".join(parts)


# Persona band accents — one restrained hue per buyer lane, on neutral cards.
PERSONA_ACCENTS = {
    "dev": ("#a78bfa", "#7c3aed"),
    "appsec": ("#2dd4bf", "#0d9488"),
    "platform": ("#38bdf8", "#0284c7"),
    "grc": ("#fbbf24", "#d97706"),
    "mcp": ("#fb7185", "#e11d48"),
}

# Role badge glyphs on the solid accent badge circle at (18.5, 18): developer
# report-with-check, AppSec shield-with-check, platform layers, GRC
# clipboard/checklist, MCP agent bot. GLYPH / ACCENT tokens are substituted per
# theme when the card is drawn.
PERSONA_BADGES = {
    "dev": (
        '<rect x="16.2" y="14.7" width="4.6" height="6.2" rx="1" fill="GLYPH" stroke="none"/>'
        '<path d="M17.3 17.9l.95.95 1.75-1.75" stroke="ACCENT" stroke-width="1.05"/>'
    ),
    "appsec": (
        '<path d="M18.5 14.3l3.15 1.15v2.1c0 2.1-1.4 3.5-3.15 4-1.75-.5-3.15-1.9-3.15-4v-2.1z" fill="GLYPH" stroke="none"/>'
        '<path d="M17.1 17.95l1 1 1.8-1.8" stroke="ACCENT" stroke-width="1.05"/>'
    ),
    "platform": '<path d="M18.5 15.1l3.1 1.55-3.1 1.55-3.1-1.55z"/><path d="M15.7 18.85l2.8 1.4 2.8-1.4"/>',
    "grc": (
        '<rect x="16.0" y="14.6" width="5.0" height="6.6" rx="0.9" fill="none" stroke="GLYPH" stroke-width="1.05"/>'
        '<path d="M17.2 14.2h2.6v1.2h-2.6z" fill="GLYPH" stroke="none"/>'
        '<path d="M17.1 17.0h2.8 M17.1 18.4h2.8 M17.1 19.8h1.8" stroke="GLYPH" stroke-width="1.0"/>'
    ),
    "mcp": '<rect x="16" y="16.4" width="5" height="3.8" rx="1.1"/><path d="M17.6 18.3h.01 M19.4 18.3h.01 M18.5 14.6v1.8"/>',
}


class PersonaLane(NamedTuple):
    """One buyer lane, rendered as a card and mirrored by the README table.

    ``title`` is the authoritative persona name: the card title, the README
    ``## Who it is for`` row label, and the alt text all use this exact string,
    so the picture and the table under it can never name different sets.
    """

    title: str
    capabilities: str  # "·"-separated tags
    value_title: str
    value_sub: str
    accent_key: str


# The four personas. One entry per README table row, in the same order.
#
# This was five lanes against seven README rows -- the artwork and the table had
# drifted apart, so the picture and the text described different products.
# Consolidated to the four audiences the evidence layer actually serves, with
# "AI engineer" naming the person who builds agents and MCP servers rather than
# the vaguer "AI / MCP owner".
PERSONA_LANES: tuple[PersonaLane, ...] = (
    PersonaLane(
        "AI engineer",
        "agents · MCP servers · models",
        "Agent-native surface",
        f"{REST_OPERATION_COUNT} API ops · {MCP_TOOL_COUNT} MCP tools · SARIF",
        "mcp",
    ),
    PersonaLane(
        "Security engineer",
        "exposure paths · reachability · identities",
        "Triage by reachability",
        "blast radius · CI gates · 15 ecosystems",
        "appsec",
    ),
    PersonaLane(
        "GRC / audit",
        "compliance · evidence · frameworks",
        "Audit-ready exports",
        "control mappings · signed bundles",
        "grc",
    ),
    PersonaLane(
        "Leadership / CISO",
        "posture · coverage · change over time",
        "One correlated view",
        "material risk · trend · explicit gaps",
        "platform",
    ),
)

# Card geometry for the persona band.
#
# Five cards on one 1280px row gave each 211px, and GitHub renders the band at
# ~900px — so every value line sat flush against its pill and several clipped.
# Three per row nearly doubles the card to ~400px, which buys room for readable
# type instead of trading legibility against overflow.
PERSONA_BAND_WIDTH = 1280
PERSONA_BAND_MARGIN_X = 23
PERSONA_BAND_GAP = 14
PERSONA_CARDS_PER_ROW = 3
PERSONA_CARD_WIDTH = (
    PERSONA_BAND_WIDTH - PERSONA_BAND_MARGIN_X * 2 - PERSONA_BAND_GAP * (PERSONA_CARDS_PER_ROW - 1)
) // PERSONA_CARDS_PER_ROW
PERSONA_CARD_PAD_X = 16

# Copy budgets measured by rendering the band at README scale. Text is drawn,
# not wrapped, so an over-long line runs past its pill and into the next card —
# how the 49-char GRC value line shipped overflowing. Widest strings verified to
# stay inside a card: "Security engineers" (title), "Self-hosted control plane"
# (value title). The 39-char sub line that used to sit flush against the pill
# edge was shortened after the box-aware fit audit showed it clipping; 33 is the
# widest that now ships, and the audit fails anything past its box.
PERSONA_TITLE_MAX_CHARS = 24
PERSONA_VALUE_TITLE_MAX_CHARS = 34
PERSONA_VALUE_SUB_MAX_CHARS = 46


def _persona_tag_width(tag: str) -> int:
    """Pill width for one capability tag (label advance plus symmetric padding)."""
    return int(len(tag) * 4.9) + 16


def _persona_tag_row_width(capabilities: str) -> int:
    """Total drawn width of a card's tag row, including the 6px inter-tag gaps."""
    tags = [seg.strip() for seg in capabilities.split("·")]
    return sum(_persona_tag_width(tag) for tag in tags) + 6 * (len(tags) - 1)


def _audit_persona_copy() -> list[str]:
    """Return persona copy that would render past its card at README scale."""
    tag_budget = PERSONA_CARD_WIDTH - PERSONA_CARD_PAD_X * 2
    issues: list[str] = []
    for lane in PERSONA_LANES:
        if len(lane.title) > PERSONA_TITLE_MAX_CHARS:
            issues.append(f"{lane.title!r} title is {len(lane.title)} chars (max {PERSONA_TITLE_MAX_CHARS})")
        if len(lane.value_title) > PERSONA_VALUE_TITLE_MAX_CHARS:
            issues.append(f"{lane.value_title!r} value title is {len(lane.value_title)} chars (max {PERSONA_VALUE_TITLE_MAX_CHARS})")
        if len(lane.value_sub) > PERSONA_VALUE_SUB_MAX_CHARS:
            issues.append(f"{lane.value_sub!r} value line is {len(lane.value_sub)} chars (max {PERSONA_VALUE_SUB_MAX_CHARS})")
        row_width = _persona_tag_row_width(lane.capabilities)
        if row_width > tag_budget:
            issues.append(f"{lane.title!r} tag row is {row_width}px wide (max {tag_budget}px)")
    return issues


def _persona_lane_card(
    x: int,
    y: int,
    w: int,
    h: int,
    persona_title: str,
    persona_sub: str,
    value_title: str,
    value_sub: str,
    accent_key: str,
    theme: str,
    t: dict,
) -> list[str]:
    accent = PERSONA_ACCENTS[accent_key][0 if theme == "dark" else 1]
    tint_opacity = "0.10" if theme == "dark" else "0.07"
    chip_tint_op = "0.12" if theme == "dark" else "0.09"
    parts: list[str] = []

    # Per-persona identity: accent top cap over a neutral card. The accent card
    # sits behind and the body is nudged down so only a colored top edge shows.
    cap = 4
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{accent}"/>')
    parts.append(
        f'<rect x="{x}" y="{y + cap}" width="{w}" height="{h - cap}" rx="12" '
        f'fill="{t["card"]}" stroke="{t["card_stroke"]}" stroke-width="1.4"/>'
    )

    # SaaS-style avatar chip: tinted app-icon square, filled person silhouette,
    # solid accent badge with a reverse-contrast role glyph.
    chip_x, chip_y, chip_size = x + 14, y + 14, 40
    chip_tint = "0.16" if theme == "dark" else "0.10"
    glyph_stroke = "#0f0f13" if theme == "dark" else "#ffffff"
    scale = 32 / 24
    parts.append(
        f'<rect x="{chip_x}" y="{chip_y}" width="{chip_size}" height="{chip_size}" rx="11" fill="{accent}" opacity="{chip_tint}"/>'
        f'<g transform="translate({chip_x + 4},{chip_y + 4}) scale({scale})">'
        f'<circle cx="10.5" cy="7.5" r="3.4" fill="{accent}"/>'
        f'<path d="M4 19.5c0-4 2.9-6 6.5-6s6.5 2 6.5 6z" fill="{accent}"/>'
        f'<circle cx="18.5" cy="18" r="6" fill="{t["card"]}"/>'
        f'<circle cx="18.5" cy="18" r="4.6" fill="{accent}"/>'
        f'<g fill="none" stroke="{glyph_stroke}" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">'
        f"{PERSONA_BADGES[accent_key].replace('GLYPH', glyph_stroke).replace('ACCENT', accent)}</g></g>"
    )
    parts.append(
        _text(
            x + 62,
            y + 40,
            persona_title,
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "15.5", "font-weight": "800", "fill": t["text"]},
        )
    )

    # Capabilities as accent-tinted tags (better structure than a comma run).
    tags = [seg.strip() for seg in persona_sub.split("·")]
    tag_x = x + 14
    tag_y = y + 64
    for tag in tags:
        tag_w = _persona_tag_width(tag)
        parts.append(
            f'<rect x="{tag_x}" y="{tag_y}" width="{tag_w}" height="18" rx="6" '
            f'fill="{accent}" fill-opacity="{chip_tint_op}" stroke="{accent}" stroke-opacity="0.4"/>'
        )
        parts.append(
            _text(
                tag_x + tag_w / 2,
                tag_y + 13,
                tag,
                **{
                    "text-anchor": "middle",
                    "font-family": "Inter,system-ui,sans-serif",
                    "font-size": "8.5",
                    "font-weight": "700",
                    "fill": accent,
                },
            )
        )
        tag_x += tag_w + 6

    divider_y = y + 92
    parts.append(f'<line x1="{x + 16}" y1="{divider_y}" x2="{x + w - 16}" y2="{divider_y}" stroke="{t["card_stroke"]}" stroke-width="1"/>')
    arrow_x = x + w // 2
    parts.append(
        f'<polygon points="{arrow_x},{divider_y + 10} {arrow_x - 5},{divider_y + 3} {arrow_x + 5},{divider_y + 3}" '
        f'fill="{accent}" opacity="0.9"/>'
    )

    value_y = divider_y + 16
    value_h = h - (value_y - y) - 14
    parts.append(f'<rect x="{x + 12}" y="{value_y}" width="{w - 24}" height="{value_h}" rx="8" fill="{accent}" opacity="{tint_opacity}"/>')
    parts.append(
        f'<rect x="{x + 12}" y="{value_y}" width="{w - 24}" height="{value_h}" rx="8" fill="none" stroke="{accent}" opacity="0.4"/>'
    )
    # Accent marker keys the headline value to the persona hue.
    parts.append(f'<rect x="{x + 20}" y="{value_y + 16}" width="3" height="14" rx="1.5" fill="{accent}"/>')
    parts.append(
        _text(
            x + 30,
            value_y + 24,
            value_title,
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "13.5", "font-weight": "800", "fill": t["text"]},
        )
    )
    parts.append(
        _text(
            x + 30,
            value_y + 44,
            value_sub,
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "10", "font-weight": "600", "fill": t["text_muted"]},
        )
    )
    return parts


def persona_value(theme: str) -> str:
    """Compact single-row buyer-lane band — persona -> value proof per card."""
    t = THEMES[theme]
    # Five cards need extra width so titles/tags fit without overflow.
    w, h = PERSONA_BAND_WIDTH, 236
    persona_bg = "#16161d" if theme == "dark" else t["bg"]

    margin_y = 18
    gap = PERSONA_BAND_GAP
    card_w = PERSONA_CARD_WIDTH
    card_h = 174
    per_row = PERSONA_CARDS_PER_ROW
    rows = math.ceil(len(PERSONA_LANES) / per_row)
    h = margin_y * 2 + rows * card_h + (rows - 1) * gap + 44

    parts = _svg_open(w, h, "agent-bom personas and value")
    parts.append(f'<rect width="{w}" height="{h}" rx="12" fill="{persona_bg}"/>')

    for idx, lane in enumerate(PERSONA_LANES):
        row, col = divmod(idx, per_row)
        in_row = min(per_row, len(PERSONA_LANES) - row * per_row)
        # Centre a short final row so the band stays balanced rather than
        # leaving a ragged gap on the right.
        row_w = in_row * card_w + (in_row - 1) * gap
        x = (w - row_w) // 2 + col * (card_w + gap)
        y = margin_y + row * (card_h + gap)
        parts += _persona_lane_card(x, y, card_w, card_h, *lane, theme, t)

    parts.append(
        _trust_footer(
            w,
            h,
            t,
            "SCAN + CI · CENTRALIZE EVIDENCE · ENFORCE AT RUNTIME — one Finding + UnifiedGraph",
        )
    )
    parts.append("</svg>")
    return _scale_type("\n".join(parts), _PERSONA_TYPE_SCALE)


# Average glyph advance for Inter/system-ui at a given font-size, in em. Used to
# estimate rendered text width; deliberately generous so the audit errs toward
# reporting an overflow that turns out to fit rather than passing one that clips.
# Calibrated against the persona band, whose copy budgets were measured by
# actually rendering it: "15 ecosystems · EPSS/KEV · distro-aware" is documented
# as sitting flush inside its pill. At 0.58 the estimator called that 7% over,
# so it would have failed the very design it is meant to protect. These strings
# are dense with narrow glyphs — digits, spaces, "·", "/" — which a single
# average over-weights.
_GLYPH_ADVANCE_EM = 0.54

# GitHub renders README images at roughly 900px wide. These two diagrams are
# authored at 960 and 1280, so their type is downscaled to ~6px on screen —
# below the 10px floor the flow diagrams already hold themselves to, which is
# why they read as unreadable in the README while being correct at full size.
# Scaled as far as `_audit_text_fit` allows. The persona band was relaid out to
# three cards per row to earn that headroom — at five per row a 211px card left
# no space to scale into.
_ARCHITECTURE_TYPE_SCALE = 1.1
_PERSONA_TYPE_SCALE = 1.3


def _scale_type(svg: str, factor: float) -> str:
    """Scale every font-size so the diagram survives GitHub's downscale."""
    return re.sub(
        r'font-size="([\d.]+)"',
        lambda m: f'font-size="{round(float(m.group(1)) * factor, 2)}"',
        svg,
    )


def _audit_text_fit(svg: str, *, margin: int = 4) -> list[str]:
    """Return text runs whose estimated width escapes their containing box.

    An earlier version only bounded text against the canvas edge. That let a
    label grow past the card it sits in while still being "inside the SVG", so
    scaling type up for legibility silently clipped persona chips and outcome
    lines against their own borders — visible in the README, invisible here.

    Each text is now attributed to the tightest ``<rect>`` that contains its
    anchor, and measured against that box. Width is estimated from glyph count,
    so the margin is a small allowance for estimator error, not a tolerance for
    copy that does not fit. The band's widest value line was previously written
    to sit flush against its pill; it was shortened rather than widening this
    number, because raising the margin until the warning disappears silences the
    audit instead of fixing the overflow it found.
    """
    vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)
    if not vb:
        return ["missing viewBox"]
    canvas_w, canvas_h = map(int, vb.groups())

    boxes: list[tuple[float, float, float, float]] = []
    for rect in re.finditer(r'<rect x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"', svg):
        x, y, w, h = (float(v) for v in rect.groups())
        boxes.append((x, y, w, h))

    def container(px: float, py: float) -> tuple[float, float, float, float]:
        """Tightest rect containing the point, else the canvas."""
        best: tuple[float, float, float, float] | None = None
        for x, y, w, h in boxes:
            if x <= px <= x + w and y <= py <= y + h:
                if best is None or w * h < best[2] * best[3]:
                    best = (x, y, w, h)
        return best or (0.0, 0.0, float(canvas_w), float(canvas_h))

    issues: list[str] = []
    for match in re.finditer(r'<text x="([\d.]+)" y="([\d.]+)"[^>]*?font-size="([\d.]+)"[^>]*?>([^<]*)</text>', svg):
        x, y, size, content = (
            float(match.group(1)),
            float(match.group(2)),
            float(match.group(3)),
            match.group(4),
        )
        if not content.strip():
            continue
        run = len(content) * size * _GLYPH_ADVANCE_EM
        anchor = re.search(r'text-anchor="(\w+)"', match.group(0))
        kind = anchor.group(1) if anchor else "start"
        left = x - run / 2 if kind == "middle" else x - run if kind == "end" else x
        bx, _by, bw, _bh = container(x, y)
        if left < bx - margin or left + run > bx + bw + margin:
            issues.append(f"text {content[:28]!r} spans {round(run)}px, escapes box at x={bx} w={bw}")
    return issues


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail when committed SVGs differ from generated output")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    copy_issues = _audit_persona_copy()
    if copy_issues:
        raise SystemExit(f"persona card copy issues: {copy_issues}")
    mapping = {
        "how-it-works-dark.svg": ("dark", how_it_works),
        "how-it-works-light.svg": ("light", how_it_works),
        "architecture-dark.svg": ("dark", architecture),
        "architecture-light.svg": ("light", architecture),
        "persona-value-dark.svg": ("dark", persona_value),
        "persona-value-light.svg": ("light", persona_value),
        "workflow-dark.svg": ("dark", workflow),
        "workflow-light.svg": ("light", workflow),
    }
    for filename, (theme, fn) in mapping.items():
        svg = fn(theme) + "\n"
        issues = _audit_layout(svg)
        if issues:
            raise SystemExit(f"{filename} layout issues: {issues[:5]}")
        if filename.startswith(("workflow-", "architecture-")):
            fit_issues = _audit_text_fit(svg)
            if fit_issues:
                raise SystemExit(f"{filename} text-fit issues: {fit_issues[:5]}")
        github_issues = _audit_github_safe(svg)
        if github_issues:
            raise SystemExit(f"{filename} GitHub SVG issues: {github_issues}")
        path = OUT / filename
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != svg:
                raise SystemExit(f"generated SVG drift: {path}; run {Path(__file__).name}")
            print(f"checked {path}")
        else:
            path.write_text(svg, encoding="utf-8")
            print(f"wrote {path}")


if __name__ == "__main__":
    main()
