"""Snowflake Organization → member accounts roll-up discovery (read-only, opt-in)."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.security import sanitize_error

from .base import CloudDiscoveryError
from .snowflake_common import _env_or_value, _sf

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")

# Substrings that mark an ORGADMIN-privilege / not-in-org failure of
# ``SHOW ORGANIZATION ACCOUNTS`` rather than a transient connection error. Used to
# distinguish "this role can't see the org" (a clean degrade) from "the org has a
# single account". Matched case-insensitively against the sanitized error text.
_SF_ORG_NOT_AUTHORIZED_MARKERS: tuple[str, ...] = (
    "orgadmin",
    "insufficient privileges",
    "not authorized",
    "unsupported feature",
    "does not exist or not authorized",
    "organization",
)


def _org_account_row(r: dict[str, Any]) -> dict[str, Any] | None:
    locator = str(r.get("account_locator", "") or r.get("account_name", "") or r.get("name", "") or "").strip()
    if not locator:
        return None
    return {
        "locator": locator,
        "name": str(r.get("account_name", "") or r.get("name", "") or locator).strip(),
        "region": str(r.get("snowflake_region", "") or r.get("region", "") or "").strip(),
        "edition": str(r.get("edition", "") or "").strip(),
        "is_org_admin": str(r.get("is_org_admin", "") or "").strip().upper() in ("Y", "YES", "TRUE"),
    }


def _org_read_failed(result: dict[str, Any], exc: Exception) -> None:
    message = sanitize_error(exc)
    lowered = message.lower()
    if any(marker in lowered for marker in _SF_ORG_NOT_AUTHORIZED_MARKERS):
        result["status"] = "not_authorized"
        result["warnings"].append(
            "SHOW ORGANIZATION ACCOUNTS requires the ORGADMIN role, which the connected "
            "(read-only) role lacks. Grant ORGADMIN to enumerate the organization, or "
            f"continue single-account scanning (unaffected). Detail: {message}"
        )
    else:
        result["warnings"].append(f"Could not enumerate Snowflake organization accounts: {message}")


def _read_org_accounts(conn: Any, result: dict[str, Any]) -> bool:
    """Fill ``result`` from SHOW ORGANIZATION ACCOUNTS; ``False`` when the read failed."""
    warnings: list[str] = result["warnings"]
    cursor = conn.cursor()
    try:
        # SHOW ORGANIZATION ACCOUNTS requires the ORGADMIN role. The read-only
        # ABOM_READONLY role usually lacks it, so a privilege error here is the
        # expected, graceful degrade — not a scan failure.
        cursor.execute("SHOW ORGANIZATION ACCOUNTS")
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            cap = _sf()._MAX_ORG_ACCOUNTS
            if len(result["accounts"]) >= cap:
                warnings.append(f"Snowflake org enumeration capped at {cap} accounts (set AGENT_BOM_SNOWFLAKE_MAX_ACCOUNTS to raise).")
                break
            r = dict(zip(keys, row))
            item = _org_account_row(r)
            if item is None:
                continue
            org_name = str(r.get("organization_name", "") or "").strip()
            if org_name and not result["org_name"]:
                result["org_name"] = org_name
            result["accounts"].append(item)
    except Exception as exc:  # noqa: BLE001 — missing ORGADMIN / not-in-org degrades cleanly
        _org_read_failed(result, exc)
        return False
    finally:
        cursor.close()
    return True


def _finish_org_result(result: dict[str, Any], resolved_account: str) -> dict[str, Any]:
    if not result["accounts"]:
        # Connected fine and ORGADMIN-capable but the account is standalone.
        result["status"] = "not_in_org"
        if resolved_account not in {a["locator"] for a in result["accounts"]}:
            result["warnings"].append(
                "No organization accounts visible; the account appears standalone. Single-account scanning is unaffected."
            )
        return result

    if not result["org_name"]:
        result["org_name"] = "organization"

    _derive_org_findings(result)
    result["status"] = "ok"
    result["discovery_envelope"] = _sf()._org_discovery_envelope(result["org_name"])
    return result


def discover_organization(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    *,
    force: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    """Enumerate the Snowflake Organization → member accounts roll-up (read-only).

    The Snowflake analogue of the GCP Organization → Folders → Projects and AWS
    Organizations → OU → Account hierarchies: multiple Snowflake accounts roll up
    under a parent ORGANIZATION node so the estate is traversable top-down. Uses
    ``SHOW ORGANIZATION ACCOUNTS`` to read the org name and its member accounts.

    Returns a payload destined for ``report_json`` (carried on the Snowflake
    services payload under ``organization``) with a ``status``:

    - ``"disabled"``       — the org flag is off and ``force`` was not set.
    - ``"sdk_missing"``    — snowflake-connector-python is not installed.
    - ``"not_authorized"`` — the connected role lacks ORGADMIN (the read-only
      ``ABOM_READONLY`` role typically does); single-account scanning still works.
    - ``"not_in_org"``     — the account is standalone (no organization visible).
    - ``"ok"``             — enumeration ran (possibly with per-call warnings).

    Read-only (``SHOW`` only — no writes), opt-in (``AGENT_BOM_SNOWFLAKE_ORG`` or
    ``force``), and crash-safe: SDK absence, missing ORGADMIN, connection / auth /
    SQL errors all degrade to a clear status plus an actionable warning. Never
    raises; a single account graphs exactly as it does today when this no-ops.

    ``now`` (an ISO-8601 string) is injected for the ``discovered_at`` stamp so
    the payload is deterministic under test; callers pass a clock value rather
    than the discoverer reading wall-clock time inline.
    """
    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "org_name": "",
        "accounts": [],
        "findings": [],
        "warnings": [],
        "discovered_at": now or "",
        "discovery_envelope": None,
    }
    if not force and not _sf().org_enabled():
        return result

    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        result["status"] = "sdk_missing"
        result["warnings"] = [
            "snowflake-connector-python is required for Snowflake org inventory. Install with: pip install 'agent-bom[snowflake]'"
        ]
        return result

    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "not_in_org"
        warnings.append("SNOWFLAKE_ACCOUNT not set; cannot enumerate the organization. Single-account scanning is unaffected.")
        return result

    try:
        conn = _sf()._get_connection(account, user, authenticator)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001 — connection failure degrades, never crashes the scan
        warnings.append(f"Could not connect to Snowflake for org inventory: {sanitize_error(exc)}")
        return result

    try:
        if not _read_org_accounts(conn, result):
            return result
    finally:
        conn.close()
    return _finish_org_result(result, resolved_account)


def _derive_org_findings(result: dict[str, Any]) -> None:
    """Flag cheap org-shape posture signals, mirroring the GCP org findings."""
    accounts = result.get("accounts", []) or []
    if len(accounts) > 1:
        result["findings"].append(
            {
                "severity": "info",
                "title": "Multi-account Snowflake organization",
                "detail": (
                    f"{len(accounts)} accounts roll up under organization "
                    f"'{result.get('org_name') or 'organization'}'. Org-wide policies and "
                    "least-privilege should be reviewed across every member account."
                ),
            }
        )
    if accounts and not any(a.get("is_org_admin") for a in accounts):
        result["findings"].append(
            {
                "severity": "low",
                "title": "No ORGADMIN account flagged",
                "detail": ("No member account is marked as the ORGADMIN account; organization-level governance ownership is unclear."),
            }
        )
