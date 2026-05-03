"""Lock-in matrix for the dashboard splash-kind sweep (#2199).

PR #2196 introduced `kind: "network" | "auth" | "forbidden"` on
`ApiOfflineState` so the splash matches the actual cause of the API
failure (auth/forbidden/network) instead of always reading as "Cannot
connect to the agent-bom API".

This matrix walks every Next.js page that imports `ApiOfflineState` and
asserts:

1. The page imports `ApiAuthError` and/or `ApiForbiddenError` from
   `@/lib/api-errors` so it can classify thrown errors.
2. The page passes `kind={...}` to `ApiOfflineState` (not just `title` /
   `detail`), so the splash gets the right copy on 401/403.

A new dashboard page that mounts the splash without classification fails
this matrix on PR — the error message names the exact file + remediation
so the fix is self-explanatory.

This complements the runtime test of `ApiOfflineState` itself; the
lock-in here is *every page that mounts the splash* must classify, not
just two of them.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI_APP = ROOT / "ui" / "app"

_OFFLINE_STATE_IMPORT = re.compile(r"from\s+['\"]@/components/api-offline-state['\"]")
_KIND_PROP = re.compile(r"<ApiOfflineState[^/>]*\bkind\s*=", re.DOTALL)
_API_ERRORS_IMPORT = re.compile(r"from\s+['\"]@/lib/api-errors['\"]")


def _ui_pages_using_offline_state() -> list[Path]:
    """Return every Next.js page that imports ApiOfflineState."""
    pages: list[Path] = []
    for path in UI_APP.rglob("page.tsx"):
        text = path.read_text(encoding="utf-8")
        if _OFFLINE_STATE_IMPORT.search(text):
            pages.append(path)
    return sorted(pages)


def test_at_least_two_pages_use_the_splash() -> None:
    """Sanity check the discovery walk -- the platform always has multiple
    pages mounting the splash, so a regex regression that found zero pages
    would silently let everything pass."""
    pages = _ui_pages_using_offline_state()
    assert len(pages) >= 2, f"Found {len(pages)} pages importing ApiOfflineState; expected >= 2. The discovery regex may be broken."


def test_every_page_using_offline_state_classifies_error_kind() -> None:
    """Every dashboard page that mounts the splash must classify error kind.

    Pre-#2199 only `app/page.tsx` and `app/security-graph/page.tsx` did
    this; PR #2199 extends it to compliance + vulns. New pages that mount
    the splash without classification fail here at PR time.
    """
    failures: list[str] = []
    for path in _ui_pages_using_offline_state():
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(ROOT))

        if not _API_ERRORS_IMPORT.search(text):
            failures.append(
                f"{rel}: imports `ApiOfflineState` but not `ApiAuthError` / "
                "`ApiForbiddenError` from `@/lib/api-errors`. Pages that mount "
                "the splash must classify thrown errors so 401/403 doesn't "
                "show as 'Cannot connect to the agent-bom API'."
            )
            continue

        if not _KIND_PROP.search(text):
            failures.append(
                f"{rel}: renders <ApiOfflineState> without a `kind={{...}}` "
                "prop. Pass `kind={errorKind}` so 401 -> 'Sign in', 403 -> "
                "'Access denied', and only true network failures show the "
                "'Cannot connect' splash."
            )
            continue

    assert not failures, "Dashboard splash-kind drift detected (#2199 lock-in):\n  " + "\n  ".join(failures)
