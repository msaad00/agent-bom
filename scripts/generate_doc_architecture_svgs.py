#!/usr/bin/env python3
"""Generate README architecture SVGs (how-it-works + control-plane architecture).

Hand-tuned layout with theme tokens — run after changing lane content or counts.
All coordinates are checked to stay inside lane panels (no text or card overflow).
"""

from __future__ import annotations

import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "docs" / "images"
VENDOR_LOGO_DIR = Path(__file__).resolve().parents[1] / "ui" / "public" / "logos"
VENDOR_WORDMARK_DIR = VENDOR_LOGO_DIR / "wordmarks"

CLOUD_VENDOR_LOGOS = (
    ("aws", "AWS", "#232F3E"),
    ("azure", "Azure", "#0078D4"),
    ("gcp", "GCP", "#4285F4"),
    ("snowflake", "Snowflake", "#29B5E8"),
)

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
                "font-size": "7",
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


def _trust_footer(w: int, h: int, t: dict, message: str, *, height: int = 28) -> str:
    y = h - height - 12
    return f'<rect x="24" y="{y}" width="{w - 48}" height="{height}" rx="8" fill="{t["trust_bg"]}" stroke="{t["trust_stroke"]}"/>' + _text(
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


def how_it_works(theme_name: str) -> str:
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
            **{"font-family": "ui-monospace,SFMono-Regular,Menlo,monospace", "font-size": "10", "font-weight": "500", "fill": t["subtitle"]},
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
        parts.append(
            f'<circle cx="{rail_x}" cy="{sy + 14}" r="8.5" fill="{t["card"]}" stroke="{scan_accent}" stroke-width="1.3"/>'
        )
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
            parts.append(
                f'<line x1="{cx}" y1="{cy}" x2="{nx}" y2="{ny}" stroke="{t["panel_stroke"]}" stroke-width="1.2" opacity="0.75"/>'
            )
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
        parts.append(
            f'<rect x="{gx}" y="{gy}" width="{glass_w}" height="36" rx="8" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
        )
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
        parts.append(
            f'<rect x="{rx}" y="{ry}" width="{rw}" height="36" rx="8" fill="{t["card"]}" stroke="{color}" stroke-width="1.1"/>'
        )
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




def architecture(theme_name: str) -> str:
    """Layered control-plane map — visually distinct from the horizontal how-it-works pipeline."""
    t = THEMES[theme_name]
    w, h = 960, 620
    margin_x = 28
    tier_w = w - 2 * margin_x
    icon_size = 24

    sources = [
        ("package", "Supply chain", "15 eco"),
        ("mcp", "Agents & MCP", "29 clients"),
        ("cloud", "Cloud", "4 providers"),
        ("iac", "IaC & OCI", "TF·K8s·img"),
        ("lock", "Secrets", "refs only"),
        ("model", "Models", "13 formats"),
        ("sbom", "SBOM import", "CDX·SPDX"),
    ]
    engine_items = [
        ("bug", "OSV scan", "batch"),
        ("zap", "Enrichment", "NVD·EPSS"),
        ("shield", "Posture", "CIS·MCP"),
        ("graph", "Blast radius", "fusion"),
        ("file", "Policy", "as-code"),
    ]
    evidence_items = [
        ("finding", "Unified Finding", "one schema"),
        ("graph", "UnifiedGraph", "attack paths"),
        ("db", "Stores", "PG·SQLite"),
        ("audit", "Audit chain", "signed"),
    ]
    platform_items = [
        ("api", "REST API", "283 ops"),
        ("gate", "Gateway", "runtime"),
        ("mcp", "MCP server", "70 tools"),
        ("fleet", "Fleet jobs", "Helm·EKS"),
    ]
    people = [("cli", "CLI"), ("ui", "Web UI")]
    agents = [("mcp", "MCP"), ("api", "SDK")]
    artifacts = ["SARIF", "CDX", "SPDX", "OCSF", "HTML", "JSON"]

    tier_y = [78, 192, 300, 448]
    tier_h = [102, 96, 136, 140]
    cx = w // 2

    parts = _svg_open(
        w,
        h,
        "agent-bom control-plane architecture",
        "Layered sources, processing engine, platform, and consumers.",
    )
    parts += [
        f'<rect width="{w}" height="{h}" rx="14" fill="{t["bg"]}"/>',
        f'<rect x="12" y="12" width="{w - 24}" height="{h - 24}" rx="18" fill="none" stroke="#6366f1" stroke-width="2" opacity="0.22"/>',
        f'<rect x="{w - 118}" y="20" width="90" height="22" rx="11" fill="#312e81" opacity="0.85"/>',
        _text(
            w - 73,
            35,
            "LAYERED",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "8",
                "font-weight": "800",
                "letter-spacing": "0.14em",
                "fill": "#c7d2fe",
            },
        ),
        _text(
            margin_x,
            40,
            "Control-plane architecture",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "20", "font-weight": "800", "fill": t["title"]},
        ),
        _text(
            margin_x,
            60,
            "Vertical tiers · sources feed engine · evidence + platform · people + agents consume",
            **{"font-family": "Inter,system-ui,sans-serif", "font-size": "10", "font-weight": "500", "fill": t["subtitle"]},
        ),
    ]

    def _tier_band(y: int, th: int, layer_key: str) -> str:
        _, accent, _text_c = ARCH_LAYER_COLORS[layer_key]
        return (
            f'<rect x="{margin_x}" y="{y}" width="{tier_w}" height="{th}" rx="12" fill="{t["panel"]}" '
            f'stroke="{accent}" stroke-width="1.2" opacity="0.95"/>'
            f'<rect x="{margin_x}" y="{y}" width="{tier_w}" height="3" rx="12" fill="{accent}" opacity="0.55"/>'
        )

    def _tier_chip(
        x: int,
        y: int,
        cw: int,
        ch: int,
        icon: str,
        title: str,
        badge: str,
        layer_key: str,
        *,
        highlight: bool = False,
    ) -> None:
        _, accent, text_c = ARCH_LAYER_COLORS[layer_key]
        fill = t["accent_fill"] if highlight else t["card"]
        stroke = accent if highlight else t["card_stroke"]
        text_x = x + icon_size + 14
        parts.append(
            f'<rect x="{x}" y="{y}" width="{cw}" height="{ch}" rx="8" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{"1.5" if highlight else "1"}"/>'
        )
        parts.append(_icon_box(x + 8, y + (ch - icon_size) // 2, ICONS[icon], t, accent=highlight, size=icon_size))
        parts.append(
            _text(
                text_x,
                y + ch // 2 - 1,
                title,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "8.5", "font-weight": "700", "fill": t["text"]},
            )
        )
        parts.append(
            _text(
                text_x,
                y + ch // 2 + 10,
                badge,
                **{
                    "font-family": "ui-monospace,monospace",
                    "font-size": "6.5",
                    "font-weight": "600",
                    "fill": accent if highlight else t["text_muted"],
                },
            )
        )

    # Tier 1 — sources
    y0, h0 = tier_y[0], tier_h[0]
    parts.append(_tier_band(y0, h0, "sources"))
    parts.append(_arch_tier_label(margin_x + 12, y0 + 10, tier_w - 24, "INTAKE SOURCES", "read-only", "sources", t))
    chip_gap = 8
    chip_h = 44
    chip_w = (tier_w - 24 - (len(sources) - 1) * chip_gap) // len(sources)
    for i, (icon, title, badge) in enumerate(sources):
        cx_chip = margin_x + 12 + i * (chip_w + chip_gap)
        _tier_chip(cx_chip, y0 + 32, chip_w, chip_h, icon, title, badge, "sources")

    parts.append(_tier_down_arrow(cx, y0 + h0 + 2, "INGEST", ARCH_LAYER_COLORS["sources"][1]))

    # Tier 2 — processing engine
    y1, h1 = tier_y[1], tier_h[1]
    parts.append(_tier_band(y1, h1, "engine"))
    parts.append(_arch_tier_label(margin_x + 12, y1 + 10, tier_w - 24, "PROCESSING ENGINE", "local scan", "engine", t))
    eng_gap = 10
    eng_w = (tier_w - 24 - (len(engine_items) - 1) * eng_gap) // len(engine_items)
    for i, (icon, title, badge) in enumerate(engine_items):
        ex = margin_x + 12 + i * (eng_w + eng_gap)
        _tier_chip(ex, y1 + 36, eng_w, 52, icon, title, badge, "engine")

    parts.append(_tier_down_arrow(cx, y1 + h1 + 2, "PROCESS", ARCH_LAYER_COLORS["engine"][1]))

    # Tier 3 — evidence + platform (two columns, 2x2 grids)
    y2, h2 = tier_y[2], tier_h[2]
    parts.append(_tier_band(y2, h2, "platform"))
    parts.append(_arch_tier_label(margin_x + 12, y2 + 10, tier_w - 24, "EVIDENCE & PLATFORM", "auth · self-hosted", "platform", t))
    col_gap = 16
    col_w = (tier_w - 24 - col_gap) // 2
    left_x = margin_x + 12
    right_x = left_x + col_w + col_gap
    mini_gap = 6
    mini_w = (col_w - mini_gap) // 2
    mini_h = 32
    grid_y = y2 + 32

    def _mini_chip(gx: int, gy: int, icon: str, title: str, badge: str, *, highlight: bool = False) -> None:
        _tier_chip(gx, gy, mini_w, mini_h, icon, title, badge, "platform", highlight=highlight)

    for i, (icon, title, badge) in enumerate(evidence_items):
        col, row = i % 2, i // 2
        gx = left_x + col * (mini_w + mini_gap)
        gy = grid_y + row * (mini_h + mini_gap)
        _mini_chip(gx, gy, icon, title, badge, highlight=title in ("Unified Finding", "UnifiedGraph"))

    for i, (icon, title, badge) in enumerate(platform_items):
        col, row = i % 2, i // 2
        gx = right_x + col * (mini_w + mini_gap)
        gy = grid_y + row * (mini_h + mini_gap)
        _mini_chip(gx, gy, icon, title, badge)

    parts.append(
        f'<rect x="{right_x}" y="{y2 + h2 - 24}" width="{col_w}" height="18" rx="6" fill="{t["footer_bg"]}" stroke="{t["footer_stroke"]}"/>'
        + _text(
            right_x + col_w // 2,
            y2 + h2 - 11,
            "OIDC · SAML · SCIM · RBAC",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "6.5",
                "font-weight": "700",
                "fill": t["chip"],
            },
        )
    )

    parts.append(_tier_down_arrow(cx, y2 + h2 + 2, "DELIVER", ARCH_LAYER_COLORS["platform"][1]))

    # Tier 4 — consumers
    y3, h3 = tier_y[3], tier_h[3]
    parts.append(_tier_band(y3, h3, "consumers"))
    parts.append(_arch_tier_label(margin_x + 12, y3 + 10, tier_w - 24, "CONSUMERS & ARTIFACTS", "deliver", "consumers", t))

    cons_col_w = (tier_w - 24 - col_gap) // 2
    cons_left = margin_x + 12
    cons_right = cons_left + cons_col_w + col_gap

    def _consumer_mini(y: int, x: int, cw: int, icon: str, label: str) -> int:
        mh = 30
        parts.append(
            f'<rect x="{x}" y="{y}" width="{cw}" height="{mh}" rx="7" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
        )
        parts.append(_icon_box(x + 10, y + 3, ICONS[icon], t, size=22))
        parts.append(
            _text(
                x + 40,
                y + 19,
                label,
                **{"font-family": "Inter,system-ui,sans-serif", "font-size": "9", "font-weight": "700", "fill": t["text"]},
            )
        )
        return mh

    cy = y3 + 34
    parts.append(
        _text(
            cons_left + cons_col_w // 2,
            cy,
            "PEOPLE",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "800",
                "letter-spacing": "0.1em",
                "fill": ARCH_LAYER_COLORS["consumers"][1],
            },
        )
    )
    cy += 10
    for icon, label in people:
        h_card = _consumer_mini(cy, cons_left, cons_col_w, icon, label)
        cy += h_card + 5

    ay = y3 + 34
    parts.append(
        _text(
            cons_right + cons_col_w // 2,
            ay,
            "AGENTS",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "800",
                "letter-spacing": "0.1em",
                "fill": ARCH_LAYER_COLORS["consumers"][1],
            },
        )
    )
    ay += 10
    for icon, label in agents:
        h_card = _consumer_mini(ay, cons_right, cons_col_w, icon, label)
        ay += h_card + 5

    art_y = y3 + 34
    art_x = margin_x + 12 + (tier_w - 24) * 0.58
    art_w = tier_w - 24 - (tier_w - 24) * 0.58 - 8
    parts.append(
        _text(
            art_x + art_w // 2,
            art_y,
            "ARTIFACTS",
            **{
                "text-anchor": "middle",
                "font-family": "Inter,system-ui,sans-serif",
                "font-size": "7.5",
                "font-weight": "800",
                "letter-spacing": "0.1em",
                "fill": ARCH_LAYER_COLORS["consumers"][1],
            },
        )
    )
    art_y += 10
    chip_cols = 3
    chip_gap = 5
    chip_w = (art_w - (chip_cols - 1) * chip_gap) // chip_cols
    chip_h = 20
    for i, label in enumerate(artifacts):
        col, row = i % chip_cols, i // chip_cols
        ax = art_x + col * (chip_w + chip_gap)
        ay_chip = art_y + row * (chip_h + chip_gap)
        parts.append(
            f'<rect x="{ax}" y="{ay_chip}" width="{chip_w}" height="{chip_h}" rx="5" fill="{t["footer_bg"]}" stroke="{t["card_stroke"]}"/>'
            f'<text x="{ax + chip_w / 2}" y="{ay_chip + 13}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="7" '
            f'font-weight="700" fill="{t["chip"]}">{_esc(label)}</text>'
        )
    parts.append(
        _text(
            art_x + art_w // 2,
            art_y + 2 * (chip_h + chip_gap) + 10,
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


# Persona band accents — one restrained hue per buyer lane, on neutral cards.
PERSONA_ACCENTS = {
    "appsec": ("#2dd4bf", "#0d9488"),
    "platform": ("#38bdf8", "#0284c7"),
    "builders": ("#a78bfa", "#7c3aed"),
    "seceng": ("#fb7185", "#e11d48"),
}

# Role badge glyphs on the solid accent badge circle at (18.5, 18): compliance
# doc-with-check, platform layers, agent bot, security shield-with-check.
# GLYPH / ACCENT tokens are substituted per theme when the card is drawn.
PERSONA_BADGES = {
    "appsec": (
        '<rect x="16.2" y="14.7" width="4.6" height="6.2" rx="1" fill="GLYPH" stroke="none"/>'
        '<path d="M17.3 17.9l.95.95 1.75-1.75" stroke="ACCENT" stroke-width="1.05"/>'
    ),
    "platform": '<path d="M18.5 15.1l3.1 1.55-3.1 1.55-3.1-1.55z"/><path d="M15.7 18.85l2.8 1.4 2.8-1.4"/>',
    "builders": '<rect x="16" y="16.4" width="5" height="3.8" rx="1.1"/><path d="M17.6 18.3h.01 M19.4 18.3h.01 M18.5 14.6v1.8"/>',
    "seceng": (
        '<path d="M18.5 14.3l3.15 1.15v2.1c0 2.1-1.4 3.5-3.15 4-1.75-.5-3.15-1.9-3.15-4v-2.1z" fill="GLYPH" stroke="none"/>'
        '<path d="M17.1 17.95l1 1 1.8-1.8" stroke="ACCENT" stroke-width="1.05"/>'
    ),
}


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
        f'{PERSONA_BADGES[accent_key].replace("GLYPH", glyph_stroke).replace("ACCENT", accent)}</g></g>'
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
        tag_w = int(len(tag) * 4.9) + 16
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
    parts.append(
        f'<line x1="{x + 16}" y1="{divider_y}" x2="{x + w - 16}" y2="{divider_y}" '
        f'stroke="{t["card_stroke"]}" stroke-width="1"/>'
    )
    arrow_x = x + w // 2
    parts.append(
        f'<polygon points="{arrow_x},{divider_y + 10} {arrow_x - 5},{divider_y + 3} {arrow_x + 5},{divider_y + 3}" '
        f'fill="{accent}" opacity="0.9"/>'
    )

    value_y = divider_y + 16
    value_h = h - (value_y - y) - 14
    parts.append(
        f'<rect x="{x + 12}" y="{value_y}" width="{w - 24}" height="{value_h}" rx="8" '
        f'fill="{accent}" opacity="{tint_opacity}"/>'
    )
    parts.append(
        f'<rect x="{x + 12}" y="{value_y}" width="{w - 24}" height="{value_h}" rx="8" '
        f'fill="none" stroke="{accent}" opacity="0.4"/>'
    )
    # Accent marker keys the headline value to the persona hue.
    parts.append(
        f'<rect x="{x + 20}" y="{value_y + 16}" width="3" height="14" rx="1.5" fill="{accent}"/>'
    )
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
    w, h = 1080, 236
    persona_bg = "#16161d" if theme == "dark" else t["bg"]

    cards = [
        ("AppSec / GRC", "SARIF · compliance · audit chain", "Accurate SCA", "15 ecosystems · EPSS/KEV · distro-aware", "appsec"),
        ("Platform / SRE", "fleet sync · Helm · CI · SBOM", "Container coverage", "OCI native · Grype · CIS posture", "platform"),
        ("Agent builders", "MCP inventory · Shield · runtime", "Self-hosted control plane", "your VPC · signed audit · Helm", "builders"),
        ("Security engineers", "findings queue · paths · graph", "Agent-native surface", "283 API ops · 70 MCP tools · SARIF", "seceng"),
    ]

    margin_x, margin_y = 23, 18
    gap = 14
    card_w = (w - margin_x * 2 - gap * 3) // 4
    card_h = 174

    parts = _svg_open(w, h, "agent-bom personas and value")
    parts.append(f'<rect width="{w}" height="{h}" rx="12" fill="{persona_bg}"/>')

    for idx, card in enumerate(cards):
        x = margin_x + idx * (card_w + gap)
        parts += _persona_lane_card(x, margin_y, card_w, card_h, *card, theme, t)

    parts.append(
        _trust_footer(
            w,
            h,
            t,
            "LOCAL SCAN · CONTROL PLANE · RUNTIME — same Finding + UnifiedGraph",
        )
    )
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
