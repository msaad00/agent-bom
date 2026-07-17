"""Cloud SDK freshness posture — a non-blocking staleness signal for the
provider SDKs agent-bom uses to read customer cloud estates.

Mirrors the intent of :mod:`agent_bom.vuln_freshness` (which tracks the age of
the local vulnerability cache) but for the *tool's own* cloud SDK layer: are
boto3 / the Azure SDKs / the Google Cloud SDKs / the Snowflake connector
present and at or above the version floor agent-bom is built and tested
against? An SDK below the floor may miss provider services/APIs added in newer
releases, so a cloud scan run against it can silently under-cover the estate —
exactly the "gap that looks like coverage" failure mode the capability surface
exists to prevent.

Design (matches the deterministic, nothing-silent trust posture):

    * **Offline + deterministic.** Compares the *installed* version against a
      bundled recommended floor — it never queries PyPI or a provider for the
      newest release, so the signal is reproducible and air-gap safe. The floor
      mirrors the minimum pinned in the ``[project.optional-dependencies]``
      extras, i.e. the version the cloud connectors are built against.
    * **Never raises.** A missing distribution, an unparseable version, or a
      missing ``packaging`` all degrade to a readable status rather than
      blocking a scan.
    * **Non-blocking.** This is a *signal*, never a gate: it never changes an
      exit code or fails a scan. Surfaced in ``agent-bom capabilities`` /
      ``doctor`` and in ``--agent-mode`` metadata.
    * **Injectable.** :func:`cloud_sdk_posture` accepts an installed-version
      resolver so tests are deterministic and never depend on the runtime
      environment.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

SCHEMA_VERSION = 1

# How far ahead a scheduled retirement is still surfaced as a live "deprecating"
# signal when a legacy SDK is present. Purely cosmetic today (any not-yet-removed
# exposed entry warns); kept as a named constant so the horizon is explicit.
DEPRECATION_HORIZON_DAYS = 365


@dataclass(frozen=True)
class SdkFloor:
    """One provider anchor SDK and the version floor agent-bom targets.

    ``distribution`` is the PyPI distribution name (as importlib.metadata sees
    it); ``floor`` is the minimum version the connectors are built against;
    ``extra`` is the pip extra that installs the provider stack, used only to
    build the remediation hint.
    """

    provider: str
    distribution: str
    floor: str
    extra: str


# Provider → anchor distribution + recommended floor. One representative anchor
# per provider keeps the signal readable; the anchor is the SDK the connector's
# core client comes from. Floors mirror the minimums pinned in the extras in
# pyproject.toml (kept in sync there — the connectors are built against them).
RECOMMENDED_FLOORS: tuple[SdkFloor, ...] = (
    SdkFloor("aws", "boto3", "1.34", "aws"),
    SdkFloor("azure", "azure-identity", "1.15", "azure"),
    SdkFloor("azure", "azure-mgmt-resource", "23.0", "azure"),
    SdkFloor("gcp", "google-cloud-resource-manager", "1.12", "gcp"),
    SdkFloor("snowflake", "snowflake-connector-python", "3.6", "snowflake"),
)


def _installed_version(distribution: str) -> str | None:
    """Return the installed version of ``distribution`` or ``None`` if absent.

    Never raises: a missing package or a broken metadata backend degrades to
    ``None`` (treated as "not installed") rather than propagating.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version(distribution)
        except PackageNotFoundError:
            return None
    except Exception:  # noqa: BLE001 - freshness signal must never raise
        return None


def _below_floor(installed: str, floor: str) -> bool | None:
    """Return True when ``installed`` < ``floor``.

    Returns ``None`` when either version cannot be parsed (or ``packaging`` is
    unavailable) so the caller can surface an honest ``unknown`` rather than a
    false ok/stale verdict.
    """
    try:
        from packaging.version import InvalidVersion, Version
    except Exception:  # noqa: BLE001 - degrade to unknown, never raise
        return None
    try:
        return Version(installed) < Version(floor)
    except InvalidVersion:
        return None
    except Exception:  # noqa: BLE001 - any comparison failure → unknown
        return None


def _make_resolver(
    installed: Callable[[str], str | None] | Mapping[str, str | None] | None,
) -> Callable[[str], str | None]:
    """Normalize the ``installed`` argument into a distribution→version lookup."""
    if installed is None:
        return _installed_version
    if isinstance(installed, Mapping):
        return lambda dist: installed.get(dist)
    return installed


def cloud_sdk_posture(
    *,
    installed: Callable[[str], str | None] | Mapping[str, str | None] | None = None,
    floors: Iterable[SdkFloor] = RECOMMENDED_FLOORS,
    providers_in_scope: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Compute the cloud SDK freshness posture.

    Args:
        installed: Optional resolver or mapping from distribution name to
            installed version (``None`` = not installed). Defaults to reading
            the live environment via ``importlib.metadata``. Injectable so
            tests never depend on what happens to be installed.
        floors: The SDK floors to check (defaults to :data:`RECOMMENDED_FLOORS`).
        providers_in_scope: Optional set of provider ids actually being scanned.
            When given, a *missing* SDK for an in-scope provider becomes a
            warning (the scan will under-cover it); a missing SDK for any other
            provider is only informational. When ``None`` (the general/runtime
            posture) missing SDKs are informational and only an *installed-but-
            outdated* SDK produces a warning — so a user who only scans AWS is
            never nagged about an absent Azure SDK.

    Returns:
        A structured, JSON-serializable posture dict with a per-SDK breakdown,
        an aggregate ``status`` (``ok``/``degraded``), a bounded ``warnings``
        list, and counts. Deterministic for a fixed ``installed`` input.
    """
    resolve = _make_resolver(installed)
    scope: set[str] | None = None
    if providers_in_scope is not None:
        scope = {str(p).strip().lower() for p in providers_in_scope if str(p).strip()}

    sdks: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for floor in floors:
        in_scope: bool | None = None if scope is None else (floor.provider in scope)
        version = resolve(floor.distribution)
        entry: dict[str, Any] = {
            "provider": floor.provider,
            "distribution": floor.distribution,
            "installed_version": version,
            "recommended_floor": floor.floor,
            "installed": version is not None,
            "in_scope": in_scope,
        }

        if version is None:
            entry["status"] = "not_installed"
            entry["message"] = (
                f"{floor.distribution} is not installed — {floor.provider} cloud scanning is "
                f"unavailable; install with `pip install 'agent-bom[{floor.extra}]'`."
            )
            if in_scope:
                warnings.append(
                    {
                        "code": "sdk_missing",
                        "provider": floor.provider,
                        "distribution": floor.distribution,
                        "installed_version": None,
                        "recommended_floor": floor.floor,
                        "message": (
                            f"{floor.provider} scan requested but {floor.distribution} is not "
                            f"installed — coverage for this provider will be empty. Install with "
                            f"`pip install 'agent-bom[{floor.extra}]'`."
                        ),
                    }
                )
        else:
            below = _below_floor(version, floor.floor)
            if below is None:
                entry["status"] = "unknown"
                entry["message"] = (
                    f"could not compare {floor.distribution} {version} against the recommended "
                    f"floor {floor.floor} — treating freshness as unknown."
                )
            elif below:
                entry["status"] = "outdated"
                entry["message"] = (
                    f"{floor.distribution} {version} is below the recommended floor {floor.floor} — "
                    f"newer {floor.provider} services/APIs may be missed. Upgrade with "
                    f"`pip install -U 'agent-bom[{floor.extra}]'`."
                )
                warnings.append(
                    {
                        "code": "sdk_outdated",
                        "provider": floor.provider,
                        "distribution": floor.distribution,
                        "installed_version": version,
                        "recommended_floor": floor.floor,
                        "message": (
                            f"{floor.distribution} {version} is below the recommended floor "
                            f"{floor.floor}; newer {floor.provider} services/APIs may be missed. "
                            f"Upgrade with `pip install -U 'agent-bom[{floor.extra}]'`."
                        ),
                    }
                )
            else:
                entry["status"] = "ok"
                entry["message"] = f"{floor.distribution} {version} meets the recommended floor {floor.floor}."

        sdks.append(entry)

    outdated_count = sum(1 for s in sdks if s["status"] == "outdated")
    missing_in_scope = [s for s in sdks if s["status"] == "not_installed" and s["in_scope"]]
    installed_count = sum(1 for s in sdks if s["installed"])

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "degraded" if warnings else "ok",
        # Honest scope: this is an offline comparison against a bundled floor,
        # not a live "is there a newer release on PyPI" check.
        "check": "installed-version-vs-recommended-floor (offline)",
        "sdks": sdks,
        "warnings": warnings,
        "stale_count": outdated_count,
        "missing_in_scope_count": len(missing_in_scope),
        "installed_count": installed_count,
    }


def cloud_sdk_freshness_summary(
    *,
    installed: Callable[[str], str | None] | Mapping[str, str | None] | None = None,
) -> dict[str, Any]:
    """Return a compact cloud SDK freshness block for ``--agent-mode`` metadata.

    A trimmed view of :func:`cloud_sdk_posture` (no scope): aggregate status,
    counts, and the flat list of warning messages an automation caller acts on.
    """
    posture = cloud_sdk_posture(installed=installed)
    return {
        "status": posture["status"],
        "stale_count": posture["stale_count"],
        "installed_count": posture["installed_count"],
        "outdated": [
            {
                "distribution": s["distribution"],
                "installed_version": s["installed_version"],
                "recommended_floor": s["recommended_floor"],
            }
            for s in posture["sdks"]
            if s["status"] == "outdated"
        ],
        "warnings": [w["message"] for w in posture["warnings"]],
        # Provider-API retirement posture (Azure AD Graph, oauth2client, …):
        # a legacy-SDK exposure signal that complements the version-floor check.
        "deprecations": cloud_api_deprecation_summary(installed=installed),
    }


# ---------------------------------------------------------------------------
# Provider-API deprecation / removal posture
# ---------------------------------------------------------------------------
#
# The version-floor check above answers "is my SDK current?". This second
# signal answers a different, complementary question: "does my install still
# depend on a provider API the vendor has *retired* (or scheduled to retire)?"
# A retired API returns errors (e.g. Azure AD Graph → HTTP 403), so a check that
# still routes through it silently under-covers or fails — the same
# gap-that-looks-like-coverage failure mode.
#
# Modeled as a small, deterministic, offline watchlist keyed by the *legacy*
# distribution that speaks the retired API. agent-bom itself already uses the
# modern replacement for each entry (Azure identities/roles via Azure Resource
# Manager, GCP auth via google-auth), so the honest default posture is "clear".
# The signal fires only when a legacy SDK is actually present in the tree — a
# supply-chain / coverage guard, evaluated against an injected clock so the
# removed / deprecating / clear states are all reproducible.


@dataclass(frozen=True)
class ProviderApiDeprecation:
    """One retired or deprecated provider API on the watchlist.

    Attributes:
        provider: Provider id (``aws`` / ``azure`` / ``gcp`` / ``snowflake``).
        api: Human label of the provider API being retired.
        distribution: The *legacy* PyPI distribution that speaks the retired
            API — the exposure probe. ``None`` means there is no distinct SDK to
            detect (the entry is informational only).
        replacement: The modern SDK/API agent-bom uses instead.
        retirement_date: ISO ``YYYY-MM-DD`` the API stops working, or ``None``
            for a deprecation with no scheduled removal date.
        note: Short, honest description of the impact and agent-bom's posture.
        reference: Official first-party source URL for the retirement.
    """

    provider: str
    api: str
    distribution: str | None
    replacement: str
    retirement_date: str | None
    note: str
    reference: str


# Real, first-party-sourced entries only. Verified against vendor docs; each
# carries its source URL. agent-bom uses the modern replacement for all of
# these, so the shipped posture is "clear" unless a legacy SDK is dragged in.
PROVIDER_API_DEPRECATIONS: tuple[ProviderApiDeprecation, ...] = (
    ProviderApiDeprecation(
        provider="azure",
        api="Azure AD Graph API (graph.windows.net)",
        distribution="azure-graphrbac",
        replacement="Microsoft Graph (azure-identity + msgraph-sdk)",
        # Extended-access apps lose Azure AD Graph access in early September 2025;
        # calls then return HTTP 403. Microsoft Entra blog, ref below.
        retirement_date="2025-09-01",
        note=(
            "Azure AD Graph is retired — dependent apps receive HTTP 403. "
            "agent-bom reads Azure identities/roles via Azure Resource Manager "
            "(azure-mgmt-authorization), so it is clear unless a legacy "
            "azure-graphrbac dependency is present."
        ),
        reference=("https://techcommunity.microsoft.com/blog/microsoft-entra-blog/important-update-azure-ad-graph-api-retirement/4090534"),
    ),
    ProviderApiDeprecation(
        provider="gcp",
        api="oauth2client auth library",
        distribution="oauth2client",
        replacement="google-auth",
        # Deprecated by Google in favor of google-auth; no scheduled removal.
        retirement_date=None,
        note=(
            "oauth2client is deprecated by Google in favor of google-auth. "
            "agent-bom uses google-auth; a transitive oauth2client would be a "
            "supply-chain and coverage risk."
        ),
        reference="https://google-auth.readthedocs.io/en/latest/oauth2client-deprecation.html",
    ),
)


def _as_date(value: date | datetime | None) -> date:
    """Normalize an injected reference time to a ``date`` (UTC ``today`` default)."""
    if value is None:
        return datetime.now(timezone.utc).date()
    if isinstance(value, datetime):
        return value.date()
    return value


def _parse_iso_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def cloud_api_deprecation_posture(
    *,
    now: date | datetime | None = None,
    installed: Callable[[str], str | None] | Mapping[str, str | None] | None = None,
    deprecations: Iterable[ProviderApiDeprecation] = PROVIDER_API_DEPRECATIONS,
    horizon_days: int = DEPRECATION_HORIZON_DAYS,
) -> dict[str, Any]:
    """Compute the provider-API deprecation / removal posture.

    For each watchlist entry the ``distribution`` is probed against the
    installed environment (``exposed``) and the ``retirement_date`` compared to
    ``now``:

    * ``lifecycle`` is ``removed`` once ``now`` is at or past the retirement
      date, otherwise ``deprecating`` (a future-dated or undated deprecation).
    * ``status`` folds in exposure: ``gated`` (removed **and** a legacy SDK is
      installed — the retired API remains reachable), ``at_risk``
      (deprecating and exposed), or ``clear`` (not exposed — agent-bom uses the
      modern replacement).

    Deterministic for a fixed ``now`` + ``installed``; never raises. Non-blocking
    — a signal, never a gate on the process exit code.
    """
    resolve = _make_resolver(installed)
    today = _as_date(now)

    apis: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    gated: list[dict[str, Any]] = []

    for dep in deprecations:
        exposed = dep.distribution is not None and resolve(dep.distribution) is not None
        retire = _parse_iso_date(dep.retirement_date)
        removed = retire is not None and today >= retire
        lifecycle = "removed" if removed else "deprecating"

        days_until = (retire - today).days if retire is not None and not removed else None

        if exposed and removed:
            status = "gated"
        elif exposed:
            status = "at_risk"
        else:
            status = "clear"

        entry = {
            "provider": dep.provider,
            "api": dep.api,
            "distribution": dep.distribution,
            "installed": exposed,
            "replacement": dep.replacement,
            "retirement_date": dep.retirement_date,
            "days_until_retirement": days_until,
            "lifecycle": lifecycle,
            "status": status,
            "reference": dep.reference,
        }

        if status == "gated":
            entry["message"] = (
                f"{dep.api} is retired but reachable via installed {dep.distribution} — "
                f"this is an environment posture signal, not proof that scanner checks use or skip it. "
                f"Migrate to {dep.replacement}."
            )
            warnings.append(
                {
                    "code": "api_removed",
                    "provider": dep.provider,
                    "api": dep.api,
                    "distribution": dep.distribution,
                    "message": entry["message"],
                    "reference": dep.reference,
                }
            )
            gated.append(entry)
        elif status == "at_risk":
            when = f" on {dep.retirement_date}" if dep.retirement_date else ""
            entry["message"] = (
                f"{dep.api} is deprecated{when} and reachable via installed {dep.distribution} — "
                f"migrate to {dep.replacement} before it is removed."
            )
            warnings.append(
                {
                    "code": "api_deprecating",
                    "provider": dep.provider,
                    "api": dep.api,
                    "distribution": dep.distribution,
                    "message": entry["message"],
                    "reference": dep.reference,
                }
            )
        else:
            entry["message"] = (
                f"clear of {dep.api} — agent-bom uses {dep.replacement} (no {dep.distribution} in the tree)."
                if dep.distribution
                else f"clear of {dep.api} — agent-bom uses {dep.replacement}."
            )

        apis.append(entry)

    removed_count = sum(1 for a in apis if a["status"] == "gated")
    at_risk_count = sum(1 for a in apis if a["status"] == "at_risk")

    _ = horizon_days  # reserved: today every not-yet-removed exposed entry warns

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "degraded" if warnings else "ok",
        "check": "installed-legacy-SDK-vs-provider-API-retirement (offline)",
        "apis": apis,
        "warnings": warnings,
        "gated": gated,
        "removed_count": removed_count,
        "at_risk_count": at_risk_count,
    }


def removed_provider_apis(
    *,
    now: date | datetime | None = None,
    installed: Callable[[str], str | None] | Mapping[str, str | None] | None = None,
    deprecations: Iterable[ProviderApiDeprecation] = PROVIDER_API_DEPRECATIONS,
) -> dict[str, dict[str, Any]]:
    """Provider APIs that are retired **and** still reachable via a legacy SDK.

    Returns a mapping ``{api_label: posture_entry}`` for callers that need to
    inspect retired-API exposure. This helper does not itself gate scanner
    execution and its presence is not evidence that a scanner consumed it.

    Empty in a normal agent-bom install (it uses the modern replacements) — this
    is a guard against a legacy SDK being pulled into the environment.
    """
    posture = cloud_api_deprecation_posture(now=now, installed=installed, deprecations=deprecations)
    return {a["api"]: a for a in posture["gated"]}


def cloud_api_deprecation_summary(
    *,
    now: date | datetime | None = None,
    installed: Callable[[str], str | None] | Mapping[str, str | None] | None = None,
) -> dict[str, Any]:
    """Compact provider-API deprecation block for ``--agent-mode`` metadata."""
    posture = cloud_api_deprecation_posture(now=now, installed=installed)
    return {
        "status": posture["status"],
        "removed_count": posture["removed_count"],
        "at_risk_count": posture["at_risk_count"],
        "gated": [a["api"] for a in posture["gated"]],
        "warnings": [w["message"] for w in posture["warnings"]],
    }
