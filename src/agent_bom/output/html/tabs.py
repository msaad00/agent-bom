"""Tab-bar post-processing for the assembled HTML report."""
from __future__ import annotations

# Tab grouping for the report. Each entry: (tab-key, label, [section ids]).
# Only tabs whose sections are actually rendered appear in the tab bar, so a
# small scan collapses to a couple of tabs while a large multi-cloud scan gets
# the full set. Order here is the tab order left-to-right.
_TAB_DEFS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("summary", "Summary", ("summary", "charts")),
    ("agents", "Agents &amp; Servers", ("riskmap", "inventory", "aiinventory")),
    (
        "findings",
        "CVEs &amp; Findings",
        ("attackflow", "vulns", "policyfindings", "exposure-paths", "blast", "remediation"),
    ),
    ("compliance", "CIS &amp; Compliance", ("compliance", "cisbenchmarks", "skillaudit")),
    ("governance", "Trust &amp; Governance", ("trust", "enforcement")),
)


def _apply_tabs(html: str, tab_counts: dict[str, int]) -> str:
    """Reorganise the flat report into JS-driven tabs.

    Tags each ``<section id=...>`` with its ``data-tab`` group, injects a tab
    bar at the top of the container, and relies on CSS (``body.js-tabs``) plus a
    small script (added in the main IIFE) to show one tab at a time. Degrades to
    the full scrollable page when JS is off or when printing.
    """
    present: list[tuple[str, str]] = []
    for tab_key, label, section_ids in _TAB_DEFS:
        has_any = False
        for sid in section_ids:
            needle = f'<section id="{sid}"'
            if needle in html:
                html = html.replace(needle, f'<section id="{sid}" data-tab="{tab_key}"', 1)
                has_any = True
        if has_any:
            present.append((tab_key, label))

    if len(present) < 2:  # nothing worth tabbing
        return html

    buttons = []
    for idx, (tab_key, label) in enumerate(present):
        count = tab_counts.get(tab_key, 0)
        badge = f'<span class="tab-count">{count}</span>' if count else ""
        active = " active" if idx == 0 else ""
        buttons.append(
            f'<button class="tab-btn{active}" data-tab="{tab_key}" '
            f'role="tab">{label}{badge}</button>'
        )
    tab_bar = '<nav class="tab-bar" role="tablist">' + "".join(buttons) + "</nav>\n"

    marker = '<div class="container">\n'
    return html.replace(marker, marker + tab_bar, 1)
